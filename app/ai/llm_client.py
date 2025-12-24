"""
LLM client for Ollama
"""

import json
import logging
from typing import Optional, Dict, List
import ollama

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Wrapper for Ollama LLM calls
    """
    
    def __init__(self, chat_model: str, code_model: str):
        self.chat_model = chat_model
        self.code_model = code_model
    
    def generate_opensearch_dsl(self, question: str, index_fields: List[str], 
                                 patterns_context: str = "") -> Dict:
        """
        Convert natural language question to OpenSearch DSL
        """
        prompt = f"""Convert this question to an OpenSearch DSL query.

Available fields in the index:
{', '.join(index_fields)}

Relevant attack patterns for context:
{patterns_context}

Question: {question}

Return ONLY valid JSON DSL query. No explanation, no markdown, just the JSON object.
The query should search the 'search_blob' field for text searches.
Use bool queries with must/should/must_not as appropriate.
For time ranges, use 'normalized_timestamp' field.
For specific hosts, use 'normalized_computer' field.
For event IDs, use 'normalized_event_id' field.
"""
        
        try:
            response = ollama.chat(
                model=self.code_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            logger.error(f"DSL generation failed: {e}")
            # Fallback to simple query_string
            return {
                "query": {
                    "query_string": {
                        "query": question,
                        "fields": ["search_blob"],
                        "default_operator": "AND"
                    }
                }
            }
    
    def analyze_events(self, events: List[Dict], question: str, 
                       patterns_context: str = "") -> str:
        """
        Analyze events and answer questions about them
        """
        events_text = json.dumps(events[:50], indent=2, default=str)  # Limit context
        
        prompt = f"""You are a DFIR analyst. Analyze these events and answer the question.

Relevant attack patterns:
{patterns_context}

Events:
{events_text}

Question: {question}

Provide a clear, concise analysis. Reference specific events by timestamp or ID.
If you see indicators of attack techniques, name them with MITRE ATT&CK IDs.
"""
        
        response = ollama.chat(
            model=self.chat_model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content']
    
    def generate_hunt_queries(self, bad_event: Dict, patterns_context: str) -> List[Dict]:
        """
        Generate hunt queries based on a known bad event
        """
        prompt = f"""You are a threat hunter. Given this malicious event, generate OpenSearch DSL queries to find related activity.

Known bad event:
{json.dumps(bad_event, indent=2, default=str)}

Relevant attack patterns:
{patterns_context}

Generate 5 hunt queries for:
1. Same host, ±15 minute time window
2. Same user (if present), any host, ±1 hour  
3. Similar process/command patterns across all hosts
4. Parent/child process relationships
5. Network connections or lateral movement indicators

Return a JSON array of objects with 'description' and 'dsl' keys.
"""
        
        try:
            response = ollama.chat(
                model=self.code_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            result = json.loads(response['message']['content'])
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'queries' in result:
                return result['queries']
            return []
        except Exception as e:
            logger.error(f"Hunt query generation failed: {e}")
            return []
    
    def extract_iocs(self, text: str) -> Dict:
        """
        Extract IOCs from text
        """
        prompt = f"""Extract all IOCs from this text. Return ONLY valid JSON with these keys:
- ip_addresses (array)
- domains (array)
- urls (array)
- file_hashes (object with md5, sha1, sha256 arrays)
- email_addresses (array)
- file_names (array)
- registry_keys (array)
- cve_ids (array)

Defang indicators where appropriate (e.g., example[.]com).
No duplicates. Empty arrays for categories with no findings.

Text:
{text}
"""
        
        try:
            response = ollama.chat(
                model=self.chat_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            return {
                "ip_addresses": [],
                "domains": [],
                "urls": [],
                "file_hashes": {"md5": [], "sha1": [], "sha256": []},
                "email_addresses": [],
                "file_names": [],
                "registry_keys": [],
                "cve_ids": []
            }
    
    def chat(self, message: str, history: List[Dict], context: str = "") -> str:
        """
        General chat with conversation history
        """
        system_prompt = f"""You are a DFIR assistant for CaseScope. Help analysts investigate security events.
You have access to attack patterns and can help interpret events.

Available context:
{context}

Be concise and technical. Reference MITRE ATT&CK when relevant.
"""
        
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history[-10:])  # Last 10 messages
        messages.append({"role": "user", "content": message})
        
        response = ollama.chat(
            model=self.chat_model,
            messages=messages
        )
        return response['message']['content']

