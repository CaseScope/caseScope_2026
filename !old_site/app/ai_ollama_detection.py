"""
AI Settings - Ollama Status Module

Retrieves Ollama service status and installed AI model information.
Reports Ollama version, running status, and Mistral/Llama/Qwen model versions.
"""

import subprocess
import logging
import re
from typing import Dict, List

logger = logging.getLogger(__name__)


def get_ollama_status() -> Dict[str, any]:
    """
    Get Ollama service status and version information.
    
    Returns:
        Dictionary containing:
        - installed: bool
        - running: bool
        - version: str
        - error: str (if detection failed)
    """
    result = {
        'installed': False,
        'running': False,
        'version': 'Not Installed',
        'error': None
    }
    
    try:
        # Check if Ollama is installed
        version_result = subprocess.run(
            ['ollama', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if version_result.returncode == 0 and version_result.stdout:
            result['installed'] = True
            # Parse version from output like "ollama version 0.1.17"
            match = re.search(r'ollama version (\d+\.\d+\.\d+)', version_result.stdout)
            if match:
                result['version'] = match.group(1)
            else:
                result['version'] = version_result.stdout.strip()
            
            logger.debug(f"[OLLAMA_STATUS] Ollama version: {result['version']}")
        else:
            logger.warning("[OLLAMA_STATUS] Ollama not installed")
            return result
        
        # Check if Ollama is running (try to list models)
        try:
            list_result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if list_result.returncode == 0:
                result['running'] = True
                logger.debug("[OLLAMA_STATUS] Ollama is running")
            else:
                logger.warning("[OLLAMA_STATUS] Ollama installed but not running")
        except subprocess.TimeoutExpired:
            logger.warning("[OLLAMA_STATUS] Ollama list command timed out - service may not be running")
        except Exception as e:
            logger.warning(f"[OLLAMA_STATUS] Failed to check if Ollama is running: {e}")
    
    except FileNotFoundError:
        logger.warning("[OLLAMA_STATUS] Ollama command not found")
        result['error'] = 'Ollama not found in PATH'
    except Exception as e:
        logger.error(f"[OLLAMA_STATUS] Error checking Ollama status: {e}")
        result['error'] = str(e)
    
    return result


def get_installed_models() -> List[Dict[str, str]]:
    """
    Get installed AI models with full details for display.
    
    Returns:
        List of dicts with model information:
        [
            {
                'name': 'llama3.1:8b-instruct-q4_k_m',
                'family': 'Llama',
                'version': '3.1:8b-instruct-q4_k_m',
                'size': '4.9 GB',
                'vram_tier': '8gb'  # Which VRAM tier this model is for
            },
            ...
        ]
    """
    models = []
    
    try:
        result = subprocess.run(
            ['ollama', 'list'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            logger.warning("[OLLAMA_STATUS] Failed to list models")
            return models
        
        # Parse output (skip header line)
        # Format: NAME                               ID              SIZE      MODIFIED
        lines = result.stdout.strip().split('\n')[1:]
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                model_name_full = parts[0]
                model_size = parts[2] if len(parts) >= 3 else 'Unknown'
                
                # Determine model family and VRAM tier
                model_name_lower = model_name_full.lower()
                family = 'Unknown'
                vram_tier = None
                
                if 'mistral' in model_name_lower:
                    family = 'Mistral'
                    # mistral:7b-instruct-v0.3-q4_K_M = 8gb
                    vram_tier = '8gb'
                
                elif 'llama' in model_name_lower:
                    family = 'Llama'
                    # llama3.1:8b-instruct-q4_k_m = 8gb
                    # llama3.1:8b-instruct-q8_0 = 16gb (higher precision)
                    if 'q8' in model_name_lower or 'q8_0' in model_name_lower:
                        vram_tier = '16gb'
                    else:
                        vram_tier = '8gb'
                
                elif 'qwen' in model_name_lower:
                    family = 'Qwen'
                    # qwen2.5:7b-instruct-q4_k_m = 8gb
                    # qwen2.5:14b-instruct-q4_k_m = 16gb (2x parameters)
                    if '14b' in model_name_lower:
                        vram_tier = '16gb'
                    else:
                        vram_tier = '8gb'
                
                elif 'phi3' in model_name_lower:
                    family = 'Phi3'
                    vram_tier = '8gb'
                
                elif 'gemma' in model_name_lower:
                    family = 'Gemma'
                    vram_tier = '8gb'
                
                elif 'deepseek' in model_name_lower:
                    family = 'Deepseek'
                    # Most deepseek models are large
                    vram_tier = '16gb'
                
                models.append({
                    'name': model_name_full,
                    'family': family,
                    'version': model_name_full.split(':')[1] if ':' in model_name_full else 'latest',
                    'size': model_size,
                    'vram_tier': vram_tier
                })
        
        logger.info(f"[OLLAMA_STATUS] Found {len(models)} models")
    
    except FileNotFoundError:
        logger.warning("[OLLAMA_STATUS] Ollama not found")
    except subprocess.TimeoutExpired:
        logger.warning("[OLLAMA_STATUS] Model list command timed out")
    except Exception as e:
        logger.error(f"[OLLAMA_STATUS] Error getting installed models: {e}")
    
    return models


def get_model_status_summary() -> str:
    """
    Get a human-readable summary of installed models.
    
    Returns:
        String like "5 models installed" or "No models installed"
    """
    models = get_installed_models()
    
    if not models:
        return "No models installed"
    
    return f"{len(models)} models installed"


def get_ai_system_status() -> Dict[str, any]:
    """
    Get complete AI system status for the settings tile.
    
    Returns:
        Dictionary containing:
        - ollama: Dict (status, version)
        - models: List of model dicts with full details
        - model_summary: str (human-readable)
        - ready: bool (Ollama installed + running + models available)
    """
    ollama_status = get_ollama_status()
    models = get_installed_models() if ollama_status['running'] else []
    
    result = {
        'ollama': ollama_status,
        'models': models,
        'model_summary': get_model_status_summary() if ollama_status['running'] else "Ollama not running",
        'ready': ollama_status['installed'] and ollama_status['running'] and len(models) > 0
    }
    
    return result

