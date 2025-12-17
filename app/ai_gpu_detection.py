"""
AI Settings - GPU Information Module

Retrieves GPU hardware information for the AI Settings tile.
Reports GPU model, VRAM, driver version, and availability.
"""

import subprocess
import logging
import re
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def get_gpu_info() -> Dict[str, any]:
    """
    Get GPU information for AI settings display.
    
    Returns:
        Dictionary containing:
        - gpu_detected: bool
        - gpu_model: str (GPU name)
        - gpu_vram_gb: float (VRAM in GB)
        - driver_version: str
        - cuda_version: str
        - error: str (if detection failed)
    """
    result = {
        'gpu_detected': False,
        'gpu_model': 'No GPU Detected',
        'gpu_vram_gb': 0,
        'driver_version': 'N/A',
        'cuda_version': 'N/A',
        'error': None
    }
    
    try:
        # Try nvidia-smi first (NVIDIA GPUs)
        try:
            nvidia_result = subprocess.run(
                ['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader,nounits'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if nvidia_result.returncode == 0 and nvidia_result.stdout.strip():
                # Parse nvidia-smi output
                line = nvidia_result.stdout.strip().split('\n')[0]  # Get first GPU
                parts = [p.strip() for p in line.split(',')]
                
                if len(parts) >= 3:
                    result['gpu_detected'] = True
                    result['gpu_model'] = parts[0]
                    result['gpu_vram_gb'] = round(float(parts[1]) / 1024, 1)  # Convert MB to GB
                    result['driver_version'] = parts[2]
                    
                    # Try to get CUDA version
                    try:
                        cuda_result = subprocess.run(
                            ['nvidia-smi', '--query-gpu=compute_cap', '--format=csv,noheader'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if cuda_result.returncode == 0 and cuda_result.stdout.strip():
                            compute_cap = cuda_result.stdout.strip()
                            result['cuda_version'] = f"Compute {compute_cap}"
                    except Exception:
                        pass
                    
                    logger.info(f"[GPU_INFO] Detected NVIDIA GPU: {result['gpu_model']} ({result['gpu_vram_gb']}GB VRAM)")
                    return result
        except FileNotFoundError:
            logger.debug("[GPU_INFO] nvidia-smi not found, trying AMD detection...")
        except Exception as e:
            logger.debug(f"[GPU_INFO] NVIDIA detection failed: {e}")
        
        # Try rocm-smi for AMD GPUs
        try:
            rocm_result = subprocess.run(
                ['rocm-smi', '--showproductname', '--showmeminfo', 'vram'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if rocm_result.returncode == 0 and rocm_result.stdout.strip():
                output = rocm_result.stdout
                
                # Parse AMD GPU info
                gpu_match = re.search(r'GPU\[0\].*:\s*(.+)', output)
                vram_match = re.search(r'GPU\[0\].*Total Memory.*:\s*(\d+)', output)
                
                if gpu_match:
                    result['gpu_detected'] = True
                    result['gpu_model'] = gpu_match.group(1).strip()
                    
                    if vram_match:
                        vram_mb = int(vram_match.group(1))
                        result['gpu_vram_gb'] = round(vram_mb / 1024, 1)
                    
                    result['driver_version'] = 'ROCm'
                    logger.info(f"[GPU_INFO] Detected AMD GPU: {result['gpu_model']} ({result['gpu_vram_gb']}GB VRAM)")
                    return result
        except FileNotFoundError:
            logger.debug("[GPU_INFO] rocm-smi not found")
        except Exception as e:
            logger.debug(f"[GPU_INFO] AMD detection failed: {e}")
        
        # No GPU detected
        logger.info("[GPU_INFO] No GPU detected - CPU-only mode")
        
    except Exception as e:
        logger.error(f"[GPU_INFO] GPU detection error: {e}")
        result['error'] = str(e)
    
    return result


def is_gpu_available() -> bool:
    """
    Quick check if a GPU is available.
    
    Returns:
        True if GPU detected, False otherwise
    """
    gpu_info = get_gpu_info()
    return gpu_info['gpu_detected']


def get_gpu_summary() -> str:
    """
    Get a human-readable GPU summary for display.
    
    Returns:
        String like "NVIDIA RTX 3090 (24GB)" or "No GPU"
    """
    gpu_info = get_gpu_info()
    
    if gpu_info['gpu_detected']:
        return f"{gpu_info['gpu_model']} ({gpu_info['gpu_vram_gb']}GB VRAM)"
    else:
        return "No GPU Detected"

