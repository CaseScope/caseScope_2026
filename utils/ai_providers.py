"""Multi-Provider AI Abstraction Layer for CaseScope

Provides a unified interface for LLM generation across:
- Local (Ollama)
- OpenAI-Compatible (custom endpoint)
- OpenAI (official API)
- Claude AI (Anthropic API)

Usage:
    provider = get_llm_provider()
    result = provider.generate("Analyze this event", system="You are a DFIR analyst")
"""

import json
import logging
import re
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

from config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model Capability Profiles
# ---------------------------------------------------------------------------

MODEL_PROFILES = {
    'gpt-4o':            {'context_window': 128000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'gpt-4o-mini':       {'context_window': 128000, 'batch_size': 10, 'timeout': 60,  'max_tokens': 4096, 'tier': 'cloud'},
    'gpt-4-turbo':       {'context_window': 128000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'gpt-4.1':           {'context_window': 1047576,'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'gpt-4.1-mini':      {'context_window': 1047576,'batch_size': 10, 'timeout': 60,  'max_tokens': 4096, 'tier': 'cloud'},
    'gpt-4.1-nano':      {'context_window': 1047576,'batch_size': 10, 'timeout': 45,  'max_tokens': 4096, 'tier': 'cloud'},
    'o1':                {'context_window': 200000, 'batch_size': 10, 'timeout': 180, 'max_tokens': 4096, 'tier': 'cloud'},
    'o3':                {'context_window': 200000, 'batch_size': 10, 'timeout': 180, 'max_tokens': 4096, 'tier': 'cloud'},
    'o3-mini':           {'context_window': 200000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'o4-mini':           {'context_window': 200000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'claude-sonnet-4':   {'context_window': 200000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'claude-3-5-sonnet': {'context_window': 200000, 'batch_size': 10, 'timeout': 120, 'max_tokens': 4096, 'tier': 'cloud'},
    'claude-3-5-haiku':  {'context_window': 200000, 'batch_size': 10, 'timeout': 60,  'max_tokens': 4096, 'tier': 'cloud'},
    'claude-3-opus':     {'context_window': 200000, 'batch_size': 8,  'timeout': 180, 'max_tokens': 4096, 'tier': 'cloud'},
}

_LOCAL_SIZE_TIERS = [
    (re.compile(r'(?:70|72|65)b', re.I), {'context_window': 8192,  'batch_size': 2, 'timeout': 600, 'max_tokens': 2000, 'tier': 'local_xlarge'}),
    (re.compile(r'(?:32|34)b', re.I),    {'context_window': 16384, 'batch_size': 3, 'timeout': 600, 'max_tokens': 2000, 'tier': 'local_large'}),
    (re.compile(r'(?:14|13)b', re.I),    {'context_window': 16384, 'batch_size': 5, 'timeout': 300, 'max_tokens': 2000, 'tier': 'local_medium'}),
    (re.compile(r'(?:7|8)b', re.I),      {'context_window': 16384, 'batch_size': 8, 'timeout': 240, 'max_tokens': 2000, 'tier': 'local_small'}),
    (re.compile(r'(?:3|4)b', re.I),      {'context_window': 16384, 'batch_size': 10,'timeout': 180, 'max_tokens': 2000, 'tier': 'local_tiny'}),
]

_DEFAULT_PROFILE = {'context_window': 16384, 'batch_size': 5, 'timeout': 300, 'max_tokens': 2000, 'tier': 'unknown'}


def get_model_profile(model_name: str) -> Dict[str, Any]:
    """Return capability profile for a model.

    Matching order:
    1. Exact match in MODEL_PROFILES
    2. Substring/prefix match against registry keys
    3. Size-based inference from model name (70b, 32b, 14b, 7b, ...)
    4. Conservative defaults
    """
    if not model_name:
        return dict(_DEFAULT_PROFILE)

    name = model_name.lower()

    if name in MODEL_PROFILES:
        return dict(MODEL_PROFILES[name])

    for key, profile in MODEL_PROFILES.items():
        if key in name or name.startswith(key):
            return dict(profile)

    for pattern, profile in _LOCAL_SIZE_TIERS:
        if pattern.search(name):
            return dict(profile)

    return dict(_DEFAULT_PROFILE)


# ---------------------------------------------------------------------------
# Rate Limit Tracker
# ---------------------------------------------------------------------------

class RateLimitTracker:
    """Tracks API rate limit state from response headers.

    State is persisted to Redis so Celery workers and gunicorn web
    processes share a single view.  Falls back to in-memory when
    Redis is unavailable.
    """

    REDIS_KEY = 'casescope:ai_rate_limit'
    REDIS_TTL = 120  # auto-expire if not updated for 2 min

    def __init__(self):
        self._lock = threading.Lock()
        self._redis = None
        self._redis_checked = False

    def _get_redis(self):
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            import redis
            self._redis = redis.Redis(host='localhost', port=6379, db=0,
                                      decode_responses=True, socket_timeout=1)
            self._redis.ping()
        except Exception:
            self._redis = None
        return self._redis

    def _load(self) -> dict:
        r = self._get_redis()
        if r:
            try:
                raw = r.get(self.REDIS_KEY)
                if raw:
                    return json.loads(raw)
            except Exception:
                pass
        return {}

    def _save(self, data: dict):
        r = self._get_redis()
        if r:
            try:
                r.setex(self.REDIS_KEY, self.REDIS_TTL, json.dumps(data))
            except Exception:
                pass

    # -- header parsing -----------------------------------------------------

    def update_from_openai_headers(self, headers: dict):
        """Parse OpenAI rate-limit headers."""
        with self._lock:
            data = self._load()
            if 'x-ratelimit-limit-tokens' in headers:
                data['token_limit'] = int(headers['x-ratelimit-limit-tokens'])
            if 'x-ratelimit-remaining-tokens' in headers:
                data['tokens_remaining'] = int(headers['x-ratelimit-remaining-tokens'])
            if 'x-ratelimit-reset-tokens' in headers:
                data['tokens_reset_at'] = time.time() + self._parse_duration(
                    headers['x-ratelimit-reset-tokens'])
            if 'x-ratelimit-limit-requests' in headers:
                data['request_limit'] = int(headers['x-ratelimit-limit-requests'])
            if 'x-ratelimit-remaining-requests' in headers:
                data['requests_remaining'] = int(headers['x-ratelimit-remaining-requests'])
            data['last_updated'] = time.time()
            self._save(data)

    def update_from_anthropic_headers(self, headers: dict):
        """Parse Anthropic rate-limit headers."""
        with self._lock:
            data = self._load()
            if 'anthropic-ratelimit-tokens-limit' in headers:
                data['token_limit'] = int(headers['anthropic-ratelimit-tokens-limit'])
            if 'anthropic-ratelimit-tokens-remaining' in headers:
                data['tokens_remaining'] = int(headers['anthropic-ratelimit-tokens-remaining'])
            if 'anthropic-ratelimit-tokens-reset' in headers:
                try:
                    from datetime import datetime, timezone
                    reset_str = headers['anthropic-ratelimit-tokens-reset']
                    dt = datetime.fromisoformat(reset_str.replace('Z', '+00:00'))
                    data['tokens_reset_at'] = dt.timestamp()
                except Exception:
                    data['tokens_reset_at'] = time.time() + 60
            if 'anthropic-ratelimit-requests-limit' in headers:
                data['request_limit'] = int(headers['anthropic-ratelimit-requests-limit'])
            if 'anthropic-ratelimit-requests-remaining' in headers:
                data['requests_remaining'] = int(headers['anthropic-ratelimit-requests-remaining'])
            data['last_updated'] = time.time()
            self._save(data)

    # -- pre-request pacing -------------------------------------------------

    def wait_if_needed(self, estimated_tokens: int = 0):
        """Sleep if remaining budget is too low for the next request."""
        data = self._load()
        remaining = data.get('tokens_remaining')
        limit = data.get('token_limit')
        reset_at = data.get('tokens_reset_at')

        if remaining is None or limit is None:
            return
        if remaining >= estimated_tokens:
            return
        if reset_at is None:
            return

        wait = reset_at - time.time()
        if wait > 0:
            capped = min(wait, 60)
            logger.info(f"[RateLimit] Budget low ({remaining} remaining, "
                        f"need ~{estimated_tokens}). Waiting {capped:.1f}s for reset.")
            time.sleep(capped)

    # -- retry-after parsing ------------------------------------------------

    @staticmethod
    def get_retry_after(response: requests.Response) -> float:
        """Extract wait time from a 429 response."""
        ra = response.headers.get('retry-after', '')
        if ra:
            try:
                return float(ra)
            except ValueError:
                pass

        body = ''
        try:
            body = response.json().get('error', {}).get('message', '')
        except Exception:
            body = response.text
        match = re.search(r'try again in ([\d.]+)s', body, re.IGNORECASE)
        if match:
            return float(match.group(1))
        return 5.0

    # -- status for UI ------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return current rate limit state for UI display."""
        data = self._load()
        token_limit = data.get('token_limit')
        tokens_remaining = data.get('tokens_remaining')
        tokens_reset_at = data.get('tokens_reset_at')

        tokens_used = None
        if token_limit is not None and tokens_remaining is not None:
            tokens_used = token_limit - tokens_remaining

        reset_in = None
        if tokens_reset_at is not None:
            reset_in = max(0, tokens_reset_at - time.time())

        return {
            'token_limit': token_limit,
            'tokens_remaining': tokens_remaining,
            'tokens_used': tokens_used,
            'reset_in_seconds': round(reset_in, 1) if reset_in is not None else None,
            'request_limit': data.get('request_limit'),
            'requests_remaining': data.get('requests_remaining'),
        }

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _parse_duration(s: str) -> float:
        """Parse durations like '6.274s', '1m30s', '500ms'."""
        total = 0.0
        for val, unit in re.findall(r'([\d.]+)(ms|m|s|h)', s):
            v = float(val)
            if unit == 'h':
                total += v * 3600
            elif unit == 'm':
                total += v * 60
            elif unit == 's':
                total += v
            elif unit == 'ms':
                total += v / 1000
        return total if total > 0 else 5.0


_global_rate_tracker = RateLimitTracker()


def get_rate_limit_status() -> Dict[str, Any]:
    """Public accessor for current rate limit state (used by API routes)."""
    return _global_rate_tracker.get_status()


class BaseLLMProvider(ABC):
    """Abstract base for all LLM providers."""

    model: str = ''
    _profile: Optional[Dict[str, Any]] = None

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system: str = None,
        format: str = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> Dict[str, Any]:
        """Generate a text response.

        Returns:
            {'success': bool, 'response': str, 'model': str, ...}
        """

    def _init_profile(self):
        """Resolve and cache the model profile. Call from subclass __init__."""
        self._profile = get_model_profile(self.model)

    def get_provider_display(self) -> str:
        """Human-readable label like 'OpenAI gpt-4o'."""
        from models.system_settings import AIProviderType
        label = AIProviderType.LABELS.get(self.provider_type(), self.provider_type())
        return f"{label} {self.model}" if self.model else label

    def get_rate_limit_info(self) -> Dict[str, Any]:
        """Return rate limit status. Override if provider tracks limits."""
        return {}

    def get_batch_config(self) -> Dict[str, Any]:
        """Return model-aware batch tuning for AI correlation analyzer."""
        p = self._profile or get_model_profile(self.model)
        return {
            'batch_size': p['batch_size'],
            'max_tokens': p['max_tokens'],
            'timeout': p['timeout'],
            'context_window': p['context_window'],
            'tier': p['tier'],
        }

    def generate_json(
        self,
        prompt: str,
        system: str = None,
        temperature: float = 0.3,
    ) -> Dict[str, Any]:
        """Generate and parse a JSON response."""
        result = self.generate(
            prompt=prompt,
            system=system,
            format='json',
            temperature=temperature,
        )
        if not result.get('success'):
            return result

        try:
            parsed = json.loads(result['response'])
            return {'success': True, 'data': parsed, 'model': result.get('model')}
        except json.JSONDecodeError as e:
            logger.warning(f"[LLM] Failed to parse JSON: {e}")
            return {
                'success': False,
                'error': 'Failed to parse JSON response',
                'raw_response': result['response'],
            }

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Check provider connectivity and model availability."""

    @abstractmethod
    def list_models(self) -> List[str]:
        """Return available model names from this provider."""

    @abstractmethod
    def provider_type(self) -> str:
        """Return the provider type identifier."""

    def stream_chat(
        self,
        messages: List[Dict],
        tools: List[Dict] = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ):
        """Stream a chat completion. Yields dicts per chunk.

        Default implementation falls back to a single non-streaming call
        and yields one chunk. Providers override for real streaming.
        """
        user_prompt = ''
        system_prompt = None
        for m in messages:
            if m['role'] == 'system':
                system_prompt = m['content']
            elif m['role'] == 'user':
                user_prompt = m['content']

        result = self.generate(
            prompt=user_prompt,
            system=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        if result.get('success'):
            yield {
                'message': {'role': 'assistant', 'content': result['response']},
                'done': True,
            }
        else:
            yield {'error': result.get('error', 'Generation failed')}


# ---------------------------------------------------------------------------
# Ollama (Local) Provider
# ---------------------------------------------------------------------------

class OllamaProvider(BaseLLMProvider):
    """Local Ollama LLM provider -- preserves existing behaviour."""

    def __init__(self, host: str = None, model: str = None):
        self.host = host or Config.OLLAMA_HOST
        self.model = model or Config.OLLAMA_MODEL
        self._init_profile()
        self.timeout = self._profile['timeout']
        self.wall_clock_timeout = self._profile['timeout'] + 120
        self.max_retries = getattr(Config, 'OLLAMA_MAX_RETRIES', 3)
        self.retry_delay = getattr(Config, 'OLLAMA_RETRY_DELAY', 1.0)

    def provider_type(self) -> str:
        return 'local'

    # -- retry / wall-clock helpers (ported from rag_llm.py) ----------------

    def _retry_request(self, func, *args, **kwargs) -> requests.Response:
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self._request_with_wall_clock(func, *args, **kwargs)
                response.raise_for_status()
                return response
            except _OllamaWallClockTimeout:
                last_exception = requests.exceptions.Timeout(
                    f"Wall-clock timeout ({self.wall_clock_timeout}s) exceeded"
                )
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except requests.exceptions.HTTPError:
                raise
        raise last_exception

    def _request_with_wall_clock(self, func, *args, **kwargs) -> requests.Response:
        result_container: Dict[str, Any] = {}

        def _do():
            try:
                result_container['response'] = func(*args, **kwargs)
            except Exception as e:
                result_container['error'] = e

        thread = threading.Thread(target=_do, daemon=True)
        thread.start()
        thread.join(timeout=self.wall_clock_timeout)

        if thread.is_alive():
            raise _OllamaWallClockTimeout(
                f"Exceeded {self.wall_clock_timeout}s wall-clock timeout"
            )
        if 'error' in result_container:
            raise result_container['error']
        return result_container['response']

    # -- public API ---------------------------------------------------------

    def generate(self, prompt, system=None, format=None,
                 temperature=0.7, max_tokens=2000):
        try:
            num_ctx = self._profile.get('context_window', 32768)
            payload: Dict[str, Any] = {
                'model': self.model,
                'prompt': prompt,
                'stream': False,
                'options': {'temperature': temperature, 'num_predict': max_tokens, 'num_ctx': num_ctx},
            }
            if system:
                payload['system'] = system
            if format == 'json':
                payload['format'] = 'json'

            response = self._retry_request(
                requests.post,
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            data = response.json()
            return {
                'success': True,
                'response': data.get('response', ''),
                'model': data.get('model'),
                'total_duration': data.get('total_duration'),
                'eval_count': data.get('eval_count'),
            }
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timed out after retries'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': f'Cannot connect to Ollama at {self.host}'}
        except Exception as e:
            logger.error(f"[Ollama] Error: {e}")
            return {'success': False, 'error': str(e)}

    def health_check(self):
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            resp.raise_for_status()
            models = resp.json().get('models', [])
            names = [m.get('name') for m in models]
            available = any(self.model in n for n in names)
            return {
                'status': 'healthy' if available else 'model_missing',
                'host': self.host,
                'model': self.model,
                'model_available': available,
                'available_models': names[:10],
            }
        except requests.exceptions.ConnectionError:
            return {'status': 'offline', 'host': self.host,
                    'error': 'Cannot connect to Ollama'}
        except Exception as e:
            return {'status': 'error', 'host': self.host, 'error': str(e)}

    def list_models(self):
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            resp.raise_for_status()
            return [m.get('name') for m in resp.json().get('models', [])]
        except Exception:
            return []

    def stream_chat(self, messages, tools=None, temperature=0.3,
                    max_tokens=4096):
        """Native Ollama streaming via /api/chat."""
        num_ctx = self._profile.get('context_window', 32768)
        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'stream': True,
            'options': {'temperature': temperature, 'num_predict': max_tokens, 'num_ctx': num_ctx},
        }
        if tools:
            payload['tools'] = tools

        try:
            resp = requests.post(
                f"{self.host}/api/chat",
                json=payload,
                stream=True,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        except requests.exceptions.Timeout:
            yield {'error': 'LLM request timed out'}
        except requests.exceptions.ConnectionError:
            yield {'error': f'Cannot connect to Ollama at {self.host}'}
        except Exception as e:
            yield {'error': str(e)}


class _OllamaWallClockTimeout(Exception):
    pass


# ---------------------------------------------------------------------------
# OpenAI-Compatible Provider
# ---------------------------------------------------------------------------

class OpenAICompatibleProvider(BaseLLMProvider):
    """Any endpoint that speaks the OpenAI chat completions protocol."""

    MAX_RETRIES = 3

    def __init__(self, api_url: str, model: str, api_key: str = ''):
        self.api_url = api_url.rstrip('/')
        self.model = model
        self.api_key = api_key
        self._init_profile()
        self.timeout = self._profile['timeout']
        self._rate = _global_rate_tracker

    def provider_type(self) -> str:
        return 'openai_compatible'

    def _headers(self):
        h = {'Content-Type': 'application/json'}
        if self.api_key:
            h['Authorization'] = f'Bearer {self.api_key}'
        return h

    def _chat_url(self):
        base = self.api_url
        if not base.endswith('/v1'):
            base = base.rstrip('/') + '/v1'
        return f"{base}/chat/completions"

    def _models_url(self):
        base = self.api_url
        if not base.endswith('/v1'):
            base = base.rstrip('/') + '/v1'
        return f"{base}/models"

    def _estimate_tokens(self, text: str) -> int:
        return max(200, len(text) // 4)

    def _request_with_retry(self, method, url, **kwargs) -> requests.Response:
        """Make HTTP request with retry-on-429 and pre-request pacing."""
        estimated = self._estimate_tokens(
            json.dumps(kwargs.get('json', {}), default=str))
        self._rate.wait_if_needed(estimated)

        last_err = None
        for attempt in range(self.MAX_RETRIES):
            resp = method(url, **kwargs)
            self._rate.update_from_openai_headers(resp.headers)

            if resp.status_code != 429:
                return resp

            wait = self._rate.get_retry_after(resp)
            capped = min(wait, 60)
            logger.warning(f"[OpenAI-Compat] Rate limited (attempt {attempt+1}/{self.MAX_RETRIES}). "
                           f"Waiting {capped:.1f}s before retry.")
            time.sleep(capped)
            last_err = resp

        return last_err

    def get_rate_limit_info(self) -> Dict[str, Any]:
        return self._rate.get_status()

    def generate(self, prompt, system=None, format=None,
                 temperature=0.7, max_tokens=2000):
        messages = []
        if system:
            messages.append({'role': 'system', 'content': system})
        if format == 'json':
            prompt += '\n\nRespond with valid JSON only.'
        messages.append({'role': 'user', 'content': prompt})

        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
        }

        try:
            resp = self._request_with_retry(
                requests.post,
                self._chat_url(),
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data['choices'][0]['message']['content']
            return {
                'success': True,
                'response': content,
                'model': data.get('model', self.model),
            }
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timed out'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': f'Cannot connect to {self.api_url}'}
        except Exception as e:
            logger.error(f"[OpenAI-Compat] Error: {e}")
            return {'success': False, 'error': str(e)}

    def health_check(self):
        try:
            resp = requests.get(
                self._models_url(),
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            return {'status': 'healthy', 'host': self.api_url, 'model': self.model}
        except Exception as e:
            return {'status': 'error', 'host': self.api_url, 'error': str(e)}

    def list_models(self):
        try:
            resp = requests.get(
                self._models_url(),
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            return [m['id'] for m in data.get('data', [])]
        except Exception:
            return []

    def stream_chat(self, messages, tools=None, temperature=0.3,
                    max_tokens=4096):
        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
            'stream': True,
        }

        try:
            resp = requests.post(
                self._chat_url(),
                headers=self._headers(),
                json=payload,
                stream=True,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            accumulated = ''
            for line in resp.iter_lines():
                if not line:
                    continue
                text = line.decode('utf-8') if isinstance(line, bytes) else line
                if text.startswith('data: '):
                    text = text[6:]
                if text.strip() == '[DONE]':
                    yield {'message': {'role': 'assistant', 'content': ''}, 'done': True}
                    break
                try:
                    chunk = json.loads(text)
                    delta = chunk.get('choices', [{}])[0].get('delta', {})
                    content = delta.get('content', '')
                    if content:
                        accumulated += content
                        yield {'message': {'role': 'assistant', 'content': content}, 'done': False}
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            yield {'error': str(e)}


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------

class OpenAIProvider(BaseLLMProvider):
    """Official OpenAI API provider with rate-limit-aware throttling."""

    API_BASE = 'https://api.openai.com/v1'
    MAX_RETRIES = 3

    def __init__(self, api_key: str, model: str = 'gpt-4o'):
        self.api_key = api_key
        self.model = model
        self._init_profile()
        self.timeout = self._profile['timeout']
        self._rate = _global_rate_tracker

    def provider_type(self) -> str:
        return 'openai'

    def get_rate_limit_info(self) -> Dict[str, Any]:
        return self._rate.get_status()

    def _headers(self):
        return {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
        }

    def _estimate_tokens(self, text: str) -> int:
        return max(200, len(text) // 4)

    def _request_with_retry(self, method, url, **kwargs) -> requests.Response:
        """Make HTTP request with retry-on-429 and pre-request pacing."""
        estimated = self._estimate_tokens(
            json.dumps(kwargs.get('json', {}), default=str))
        self._rate.wait_if_needed(estimated)

        last_err = None
        for attempt in range(self.MAX_RETRIES):
            resp = method(url, **kwargs)
            self._rate.update_from_openai_headers(resp.headers)

            if resp.status_code != 429:
                return resp

            wait = self._rate.get_retry_after(resp)
            capped = min(wait, 60)
            logger.warning(f"[OpenAI] Rate limited (attempt {attempt+1}/{self.MAX_RETRIES}). "
                           f"Waiting {capped:.1f}s before retry.")
            time.sleep(capped)
            last_err = resp

        return last_err

    def generate(self, prompt, system=None, format=None,
                 temperature=0.7, max_tokens=2000):
        messages = []
        if system:
            messages.append({'role': 'system', 'content': system})
        if format == 'json':
            prompt += '\n\nRespond with valid JSON only.'
        messages.append({'role': 'user', 'content': prompt})

        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
        }
        if format == 'json':
            payload['response_format'] = {'type': 'json_object'}

        try:
            resp = self._request_with_retry(
                requests.post,
                f"{self.API_BASE}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data['choices'][0]['message']['content']
            return {
                'success': True,
                'response': content,
                'model': data.get('model', self.model),
                'usage': data.get('usage'),
            }
        except requests.exceptions.HTTPError as e:
            error_body = ''
            try:
                error_body = e.response.json().get('error', {}).get('message', str(e))
            except Exception:
                error_body = str(e)
            logger.error(f"[OpenAI] HTTP error: {error_body}")
            return {'success': False, 'error': f'OpenAI API error: {error_body}'}
        except Exception as e:
            logger.error(f"[OpenAI] Error: {e}")
            return {'success': False, 'error': str(e)}

    def health_check(self):
        try:
            resp = requests.get(
                f"{self.API_BASE}/models",
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            self._rate.update_from_openai_headers(resp.headers)
            return {'status': 'healthy', 'host': 'api.openai.com', 'model': self.model}
        except Exception as e:
            return {'status': 'error', 'host': 'api.openai.com', 'error': str(e)}

    def list_models(self):
        try:
            resp = requests.get(
                f"{self.API_BASE}/models",
                headers=self._headers(),
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            names = sorted([m['id'] for m in data.get('data', [])
                            if any(k in m['id'] for k in ('gpt', 'o1', 'o3', 'o4'))])
            return names
        except Exception:
            return []

    def stream_chat(self, messages, tools=None, temperature=0.3,
                    max_tokens=4096):
        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
            'stream': True,
        }
        try:
            estimated = self._estimate_tokens(json.dumps(payload, default=str))
            self._rate.wait_if_needed(estimated)

            resp = requests.post(
                f"{self.API_BASE}/chat/completions",
                headers=self._headers(),
                json=payload,
                stream=True,
                timeout=self.timeout,
            )
            self._rate.update_from_openai_headers(resp.headers)
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                text = line.decode('utf-8') if isinstance(line, bytes) else line
                if text.startswith('data: '):
                    text = text[6:]
                if text.strip() == '[DONE]':
                    yield {'message': {'role': 'assistant', 'content': ''}, 'done': True}
                    break
                try:
                    chunk = json.loads(text)
                    delta = chunk.get('choices', [{}])[0].get('delta', {})
                    content = delta.get('content', '')
                    if content:
                        yield {'message': {'role': 'assistant', 'content': content}, 'done': False}
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            yield {'error': str(e)}


# ---------------------------------------------------------------------------
# Claude AI (Anthropic) Provider
# ---------------------------------------------------------------------------

class ClaudeProvider(BaseLLMProvider):
    """Anthropic Claude API provider with rate-limit-aware throttling."""

    API_BASE = 'https://api.anthropic.com/v1'
    ANTHROPIC_VERSION = '2023-06-01'
    MAX_RETRIES = 3

    KNOWN_MODELS = [
        'claude-sonnet-4-20250514',
        'claude-3-5-sonnet-20241022',
        'claude-3-5-haiku-20241022',
        'claude-3-opus-20240229',
    ]

    def __init__(self, api_key: str, model: str = 'claude-sonnet-4-20250514'):
        self.api_key = api_key
        self.model = model
        self._init_profile()
        self.timeout = self._profile['timeout']
        self._rate = _global_rate_tracker

    def provider_type(self) -> str:
        return 'claude'

    def get_rate_limit_info(self) -> Dict[str, Any]:
        return self._rate.get_status()

    def _headers(self):
        return {
            'Content-Type': 'application/json',
            'x-api-key': self.api_key,
            'anthropic-version': self.ANTHROPIC_VERSION,
        }

    def _estimate_tokens(self, text: str) -> int:
        return max(200, len(text) // 4)

    def _request_with_retry(self, method, url, **kwargs) -> requests.Response:
        """Make HTTP request with retry-on-429 and pre-request pacing."""
        estimated = self._estimate_tokens(
            json.dumps(kwargs.get('json', {}), default=str))
        self._rate.wait_if_needed(estimated)

        last_err = None
        for attempt in range(self.MAX_RETRIES):
            resp = method(url, **kwargs)
            self._rate.update_from_anthropic_headers(resp.headers)

            if resp.status_code != 429:
                return resp

            wait = self._rate.get_retry_after(resp)
            capped = min(wait, 60)
            logger.warning(f"[Claude] Rate limited (attempt {attempt+1}/{self.MAX_RETRIES}). "
                           f"Waiting {capped:.1f}s before retry.")
            time.sleep(capped)
            last_err = resp

        return last_err

    def generate(self, prompt, system=None, format=None,
                 temperature=0.7, max_tokens=2000):
        messages = [{'role': 'user', 'content': prompt}]
        if format == 'json':
            messages[0]['content'] += '\n\nRespond with valid JSON only.'

        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': messages,
            'max_tokens': max_tokens,
            'temperature': temperature,
        }
        if system:
            payload['system'] = system

        try:
            resp = self._request_with_retry(
                requests.post,
                f"{self.API_BASE}/messages",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            content_blocks = data.get('content', [])
            text = ''.join(
                b.get('text', '') for b in content_blocks if b.get('type') == 'text'
            )
            return {
                'success': True,
                'response': text,
                'model': data.get('model', self.model),
                'usage': data.get('usage'),
            }
        except requests.exceptions.HTTPError as e:
            error_body = ''
            try:
                error_body = e.response.json().get('error', {}).get('message', str(e))
            except Exception:
                error_body = str(e)
            logger.error(f"[Claude] HTTP error: {error_body}")
            return {'success': False, 'error': f'Claude API error: {error_body}'}
        except Exception as e:
            logger.error(f"[Claude] Error: {e}")
            return {'success': False, 'error': str(e)}

    def health_check(self):
        try:
            resp = requests.post(
                f"{self.API_BASE}/messages",
                headers=self._headers(),
                json={
                    'model': self.model,
                    'messages': [{'role': 'user', 'content': 'ping'}],
                    'max_tokens': 5,
                },
                timeout=15,
            )
            resp.raise_for_status()
            self._rate.update_from_anthropic_headers(resp.headers)
            return {'status': 'healthy', 'host': 'api.anthropic.com', 'model': self.model}
        except Exception as e:
            return {'status': 'error', 'host': 'api.anthropic.com', 'error': str(e)}

    def list_models(self):
        return list(self.KNOWN_MODELS)

    def stream_chat(self, messages, tools=None, temperature=0.3,
                    max_tokens=4096):
        system_text = None
        chat_messages = []
        for m in messages:
            if m['role'] == 'system':
                system_text = m['content']
            else:
                chat_messages.append(m)

        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': chat_messages,
            'max_tokens': max_tokens,
            'temperature': temperature,
            'stream': True,
        }
        if system_text:
            payload['system'] = system_text

        try:
            estimated = self._estimate_tokens(json.dumps(payload, default=str))
            self._rate.wait_if_needed(estimated)

            resp = requests.post(
                f"{self.API_BASE}/messages",
                headers=self._headers(),
                json=payload,
                stream=True,
                timeout=self.timeout,
            )
            self._rate.update_from_anthropic_headers(resp.headers)
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                text = line.decode('utf-8') if isinstance(line, bytes) else line
                if text.startswith('data: '):
                    text = text[6:]
                try:
                    event = json.loads(text)
                    etype = event.get('type', '')
                    if etype == 'content_block_delta':
                        delta_text = event.get('delta', {}).get('text', '')
                        if delta_text:
                            yield {'message': {'role': 'assistant', 'content': delta_text}, 'done': False}
                    elif etype == 'message_stop':
                        yield {'message': {'role': 'assistant', 'content': ''}, 'done': True}
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            yield {'error': str(e)}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_provider_instance: Optional[BaseLLMProvider] = None
_provider_lock = threading.Lock()
_provider_settings_hash: Optional[str] = None


def _settings_hash(settings: dict) -> str:
    """Quick hash of provider settings to detect changes."""
    import hashlib
    raw = f"{settings.get('provider_type')}|{settings.get('api_url')}|{settings.get('model_name')}|{bool(settings.get('api_key'))}"
    return hashlib.md5(raw.encode()).hexdigest()


def get_llm_provider(model_override: str = None) -> BaseLLMProvider:
    """Get or create the LLM provider based on current system settings.

    The instance is cached and only recreated when settings change.
    Pass model_override to use a specific model for one-off calls
    (creates a fresh instance, does not affect the cache).
    """
    global _provider_instance, _provider_settings_hash

    from models.system_settings import get_ai_provider_settings, AIProviderType

    settings = get_ai_provider_settings()
    current_hash = _settings_hash(settings)

    if model_override:
        return _build_provider(settings, model_override)

    if _provider_instance is not None and current_hash == _provider_settings_hash:
        return _provider_instance

    with _provider_lock:
        if _provider_instance is not None and current_hash == _provider_settings_hash:
            return _provider_instance
        _provider_instance = _build_provider(settings)
        _provider_settings_hash = current_hash
        return _provider_instance


def invalidate_provider_cache():
    """Force the next get_llm_provider() call to rebuild the provider."""
    global _provider_instance, _provider_settings_hash
    with _provider_lock:
        _provider_instance = None
        _provider_settings_hash = None


def _build_provider(settings: dict, model_override: str = None) -> BaseLLMProvider:
    from models.system_settings import AIProviderType

    ptype = settings.get('provider_type', AIProviderType.LOCAL)
    model = model_override or settings.get('model_name', '')

    if ptype == AIProviderType.OPENAI_COMPATIBLE:
        return OpenAICompatibleProvider(
            api_url=settings.get('api_url', ''),
            model=model or 'default',
            api_key=settings.get('api_key', ''),
        )
    elif ptype == AIProviderType.OPENAI:
        return OpenAIProvider(
            api_key=settings.get('api_key', ''),
            model=model or 'gpt-4o',
        )
    elif ptype == AIProviderType.CLAUDE:
        return ClaudeProvider(
            api_key=settings.get('api_key', ''),
            model=model or 'claude-sonnet-4-20250514',
        )
    else:
        return OllamaProvider(
            host=Config.OLLAMA_HOST,
            model=model or Config.OLLAMA_MODEL,
        )
