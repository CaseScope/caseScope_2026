"""
Hardware Detection Utilities
Detects CPU, GPU, VRAM for AI optimization
"""
import subprocess
import logging
import os
import re

logger = logging.getLogger(__name__)


def detect_gpu_info():
    """Detect NVIDIA GPU and VRAM"""
    try:
        # Try nvidia-smi first (use full path)
        result = subprocess.run(
            ['/usr/bin/nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'],
            capture_output=True, text=True, timeout=5
        )
        
        logger.info(f"[Hardware] nvidia-smi return code: {result.returncode}, output: '{result.stdout.strip()}'")
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            if lines:
                parts = lines[0].split(',')
                if len(parts) >= 2:
                    gpu_name = parts[0].strip()
                    vram_str = parts[1].strip()
                    
                    # Parse VRAM (e.g., "7611 MiB" -> 7.5 GB)
                    vram_match = re.search(r'(\d+)', vram_str)
                    if vram_match:
                        vram_mb = int(vram_match.group(1))
                        vram_gb = round(vram_mb / 1024, 1)
                        
                        gpu_info = {
                            'gpu_detected': True,
                            'gpu_name': gpu_name,
                            'vram_mb': vram_mb,
                            'vram_gb': vram_gb
                        }
                        logger.info(f"[Hardware] GPU detected: {gpu_name} ({vram_gb}GB)")
                        return gpu_info
    except Exception as e:
        logger.error(f"[Hardware] GPU detection exception: {e}")
    
    logger.info("[Hardware] No GPU detected")
    return {'gpu_detected': False, 'gpu_name': None, 'vram_mb': 0, 'vram_gb': 0}


def check_cpu_info():
    """Get CPU information"""
    try:
        result = subprocess.run(['nproc'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            cpu_count = int(result.stdout.strip())
            return {'cpu_count': cpu_count}
    except Exception as e:
        logger.debug(f"[Hardware] CPU detection failed: {e}")
    
    return {'cpu_count': os.cpu_count() or 4}


def check_ollama_cuda_support():
    """Check if Ollama has CUDA libraries"""
    cuda_path = '/usr/local/lib/ollama'
    if os.path.exists(cuda_path):
        for item in os.listdir(cuda_path):
            if 'cuda' in item.lower():
                return True
    return False


def get_hardware_status():
    """Get complete hardware status"""
    gpu = detect_gpu_info()
    cpu = check_cpu_info()
    cuda_libs = check_ollama_cuda_support()
    
    return {
        'gpu': gpu,
        'cpu': cpu,
        'cuda_libs_available': cuda_libs
    }


def suggest_models_for_vram(vram_gb):
    """Suggest models suitable for given VRAM"""
    vram_gb = int(vram_gb)
    
    # Model recommendations by VRAM
    recommendations = {
        4: ['phi-3-mini:3.8b'],
        6: ['phi-3-mini:3.8b', 'gemma-2:9b'],
        8: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b'],
        12: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b', 'llama3.3:70b'],
        16: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b', 'llama3.3:70b', 'mistral-large:123b'],
        24: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b', 'llama3.3:70b', 'mistral-large:123b', 'deepseek-r1:32b'],
        32: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b', 'llama3.3:70b', 'mistral-large:123b', 'deepseek-r1:32b', 'deepseek-r1:70b'],
        48: ['phi-3-mini:3.8b', 'gemma-2:9b', 'qwen2.5:7b', 'llama3.3:70b', 'mistral-large:123b', 'deepseek-r1:32b', 'deepseek-r1:70b', 'deepseek-r1:671b']
    }
    
    # Find closest VRAM tier
    for tier in sorted(recommendations.keys()):
        if vram_gb <= tier:
            return recommendations[tier]
    
    # If VRAM is higher than all tiers, return all models
    return recommendations[48]
