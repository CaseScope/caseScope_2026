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


def get_installed_models() -> Dict[str, str]:
    """
    Get installed AI models (Mistral, Llama, Qwen, etc.).
    
    Returns:
        Dictionary mapping model family to version:
        {
            'Mistral': '7b-instruct',
            'Llama': '3.2:3b',
            'Qwen': '2.5:7b',
            ...
        }
    """
    models = {}
    
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
        lines = result.stdout.strip().split('\n')[1:]
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 1:
                model_name_full = parts[0].lower()
                
                # Extract model family and version
                if 'mistral' in model_name_full:
                    match = re.search(r'mistral:?(\S*)', model_name_full)
                    if match:
                        version = match.group(1) or 'latest'
                        # Clean up common suffixes
                        version = version.replace('-q4_K_M', '').replace('-latest', '').replace(':', '')
                        models['Mistral'] = version if version else 'latest'
                
                elif 'llama' in model_name_full:
                    match = re.search(r'llama(\S*)', model_name_full)
                    if match:
                        version = match.group(1).lstrip(':').replace('-q4_K_M', '').replace('-latest', '')
                        models['Llama'] = version if version else 'latest'
                
                elif 'qwen' in model_name_full:
                    match = re.search(r'qwen(\S*)', model_name_full)
                    if match:
                        version = match.group(1).lstrip(':').replace('-q4_K_M', '').replace('-latest', '')
                        models['Qwen'] = version if version else 'latest'
                
                elif 'phi3' in model_name_full:
                    match = re.search(r'phi3:?(\S*)', model_name_full)
                    if match:
                        version = match.group(1).replace('-q4_K_M', '').replace('-latest', '')
                        models['Phi3'] = version if version else 'latest'
                
                elif 'gemma' in model_name_full:
                    match = re.search(r'gemma:?(\S*)', model_name_full)
                    if match:
                        version = match.group(1).replace('-q4_K_M', '').replace('-latest', '')
                        models['Gemma'] = version if version else 'latest'
                
                elif 'deepseek' in model_name_full:
                    match = re.search(r'deepseek:?(\S*)', model_name_full)
                    if match:
                        version = match.group(1).replace('-q4_K_M', '').replace('-latest', '')
                        models['Deepseek'] = version if version else 'latest'
        
        logger.info(f"[OLLAMA_STATUS] Found {len(models)} model families: {list(models.keys())}")
    
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
        String like "Mistral (7b), Llama (3.2:3b), Qwen (2.5:7b)" or "No models installed"
    """
    models = get_installed_models()
    
    if not models:
        return "No models installed"
    
    model_strings = [f"{family} ({version})" for family, version in models.items()]
    return ", ".join(model_strings)


def get_ai_system_status() -> Dict[str, any]:
    """
    Get complete AI system status for the settings tile.
    
    Returns:
        Dictionary containing:
        - ollama: Dict (status, version)
        - models: Dict (model family -> version)
        - model_summary: str (human-readable)
        - ready: bool (Ollama installed + running + models available)
    """
    ollama_status = get_ollama_status()
    models = get_installed_models() if ollama_status['running'] else {}
    
    result = {
        'ollama': ollama_status,
        'models': models,
        'model_summary': get_model_status_summary() if ollama_status['running'] else "Ollama not running",
        'ready': ollama_status['installed'] and ollama_status['running'] and len(models) > 0
    }
    
    return result

