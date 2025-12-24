#!/usr/bin/env python3
"""
Test LLM performance across different hardware configurations
Tests response time and feasibility for CPU vs GPU inference
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ollama


def test_model_performance(model_name: str, test_query: str) -> dict:
    """
    Test a model's performance
    Returns: dict with timing and success info
    """
    print(f"\n🔍 Testing: {model_name}")
    print(f"   Query: {test_query[:50]}...")
    
    try:
        start = time.time()
        
        response = ollama.chat(
            model=model_name,
            messages=[{"role": "user", "content": test_query}],
            options={
                "num_predict": 200,  # Limit tokens for speed test
            }
        )
        
        end = time.time()
        duration = end - start
        
        response_text = response['message']['content']
        tokens = len(response_text.split())
        tokens_per_sec = tokens / duration if duration > 0 else 0
        
        print(f"   ✅ Response time: {duration:.2f}s")
        print(f"   📊 Tokens: {tokens} (~{tokens_per_sec:.1f} tok/s)")
        print(f"   Preview: {response_text[:100]}...")
        
        return {
            'success': True,
            'duration': duration,
            'tokens': tokens,
            'tokens_per_sec': tokens_per_sec,
            'model': model_name
        }
        
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'model': model_name
        }


def check_gpu():
    """Check GPU availability"""
    print("\n" + "="*70)
    print(" GPU Detection")
    print("="*70)
    
    try:
        import subprocess
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'],
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            gpus = result.stdout.strip().split('\n')
            print(f"✅ GPU(s) detected:")
            for i, gpu in enumerate(gpus, 1):
                print(f"   {i}. {gpu}")
            return True, gpus
        else:
            print("❌ No GPU detected (nvidia-smi failed)")
            return False, []
    except FileNotFoundError:
        print("❌ No GPU detected (nvidia-smi not found)")
        return False, []
    except Exception as e:
        print(f"❌ GPU check failed: {e}")
        return False, []


def main():
    print("="*70)
    print(" LLM Hardware Configuration Test")
    print("="*70)
    
    # Check GPU
    has_gpu, gpus = check_gpu()
    
    # Determine scenario
    if has_gpu:
        # Parse VRAM from first GPU
        try:
            vram_str = gpus[0].split(',')[1].strip()
            vram_gb = int(vram_str.split()[0]) // 1024  # Convert MB to GB
            print(f"\n📊 Detected VRAM: ~{vram_gb}GB")
            
            if vram_gb >= 16:
                scenario = "16GB+ GPU"
            elif vram_gb >= 8:
                scenario = "8GB GPU"
            else:
                scenario = "Small GPU (< 8GB)"
        except:
            scenario = "GPU (unknown size)"
    else:
        scenario = "No GPU (CPU only)"
    
    print(f"\n🎯 Detected Scenario: {scenario}")
    
    # Test query
    test_query = "What is process injection in cybersecurity? Provide a brief 2-sentence answer."
    
    print("\n" + "="*70)
    print(" Performance Testing")
    print("="*70)
    
    # Test current models
    results = []
    
    print("\n--- Current Models (7B Q4_K_M) ---")
    results.append(test_model_performance('qwen2.5:7b-instruct-q4_k_m', test_query))
    
    # Check if smaller models are available for CPU scenario
    if not has_gpu:
        print("\n--- Recommended CPU-Optimized Models ---")
        
        # Check for smaller models
        available = ollama.list()
        model_names = []
        if hasattr(available, 'models'):
            model_names = [m.model for m in available.models]
        
        # Suggest testing 3B or smaller
        cpu_models = ['qwen2.5:3b', 'qwen2.5:1.5b', 'phi3:mini']
        
        for model in cpu_models:
            if any(model in name for name in model_names):
                print(f"\n   Found CPU-friendly model: {model}")
                results.append(test_model_performance(model, test_query))
            else:
                print(f"\n   ⚠️  {model} not installed (recommended for CPU)")
                print(f"      Install: ollama pull {model}")
    
    # Summary and recommendations
    print("\n" + "="*70)
    print(" Results & Recommendations")
    print("="*70)
    
    print(f"\n📊 Your System: {scenario}")
    
    successful_tests = [r for r in results if r.get('success')]
    
    if successful_tests:
        print(f"\n⏱️  Performance:")
        for r in successful_tests:
            status = "✅ Good" if r['tokens_per_sec'] > 10 else "⚠️  Slow" if r['tokens_per_sec'] > 3 else "❌ Very Slow"
            print(f"   {r['model']}: {r['duration']:.1f}s ({r['tokens_per_sec']:.1f} tok/s) {status}")
    
    print("\n" + "="*70)
    print(" Recommendations by Scenario")
    print("="*70)
    
    print("""
🖥️  NO GPU (CPU Only):
   Model: qwen2.5:3b or qwen2.5:1.5b or phi3:mini
   Quantization: Q4_K_M or Q5_K_M
   Expected: 3-10 tokens/sec
   Response Time: 10-30 seconds per query
   
   ⚠️  7B models on CPU:
      - Response time: 30-120 seconds
      - High CPU usage
      - Not recommended for production
   
   ✅ Setup:
      ollama pull qwen2.5:3b
      # Update config.py:
      LLM_MODEL_CHAT = 'qwen2.5:3b'
      LLM_MODEL_CODE = 'qwen2.5:3b'

---

🎮 8GB GPU (Tesla P4, RTX 2080, etc):
   Model: qwen2.5:7b-instruct-q4_k_m (CURRENT)
   Quantization: Q4_K_M
   Expected: 20-40 tokens/sec
   Response Time: 3-8 seconds per query
   
   ✅ Current config is optimal for this scenario
   
   Alternative:
      - qwen2.5:7b-instruct-q5_k_m (better quality, ~5.5GB)
      - mixtral:8x7b-instruct-q2_k (very fast, ~8GB)

---

🚀 16GB+ GPU (RTX 3090, 4090, A100, etc):
   Model: qwen2.5:14b-instruct-q4_k_m or qwen2.5:32b
   Quantization: Q5_K_M or Q6_K
   Expected: 30-60 tokens/sec
   Response Time: 2-5 seconds per query
   
   ✅ Setup:
      ollama pull qwen2.5:14b-instruct-q5_k_m
      # Update config.py:
      LLM_MODEL_CHAT = 'qwen2.5:14b-instruct-q5_k_m'
      LLM_MODEL_CODE = 'qwen2.5-coder:14b-instruct-q5_k_m'
   
   Alternative:
      - llama3.1:70b-instruct-q4_k_m (very high quality)
      - mixtral:8x7b-instruct-v0.1-q5_k_m (fast MoE)

---

📝 Token Speed Guidelines:
   - 40+ tok/s:  Excellent (real-time feel)
   - 20-40 tok/s: Good (acceptable delay)
   - 10-20 tok/s: Acceptable (noticeable delay)
   - 3-10 tok/s:  Slow (long wait)
   - < 3 tok/s:   Very Slow (not production ready)
""")
    
    print("="*70)


if __name__ == '__main__':
    main()

