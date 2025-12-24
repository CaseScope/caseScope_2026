# LLM Hardware Configuration Guide

## Overview

CaseScope AI supports three hardware scenarios with different performance characteristics:

1. **No GPU (CPU Only)** - Functional but slow
2. **8GB GPU** - Optimal for most deployments
3. **16GB+ GPU** - Best performance and quality

---

## 🖥️ Scenario 1: No GPU (CPU Only)

### What Happens

When no GPU is detected, Ollama will run models on CPU:
- ✅ **It will work** - LLM inference happens, just slower
- ⚠️ **Response time**: 10-30 seconds (3B model) or 30-120 seconds (7B model)
- ⚠️ **CPU usage**: High (all cores utilized during inference)
- ⚠️ **User experience**: Noticeable delays

### Recommended Configuration

**Models:**
```bash
# Primary recommendation (best balance)
ollama pull qwen2.5:3b

# Alternative (faster, less capable)
ollama pull qwen2.5:1.5b

# Alternative (Microsoft, good quality)
ollama pull phi3:mini
```

**Update `/opt/casescope/app/config.py`:**
```python
LLM_MODEL_CHAT = 'qwen2.5:3b'      # Was: qwen2.5:7b-instruct-q4_k_m
LLM_MODEL_CODE = 'qwen2.5:3b'      # Was: qwen2.5-coder:7b-instruct-q4_k_m
```

### Performance Expectations

| Model | Response Time | Quality | Use Case |
|-------|---------------|---------|----------|
| `qwen2.5:1.5b` | 5-15s | Good | Quick IOC extraction, simple queries |
| `qwen2.5:3b` | 10-30s | Very Good | Analysis, chat, DSL generation |
| `qwen2.5:7b` (not recommended) | 30-120s | Excellent | Too slow for production |

### Hardware Requirements

- **CPU**: 8+ cores recommended
- **RAM**: 16GB minimum (32GB recommended)
- **Storage**: 2-4GB per model

### Production Considerations

**✅ Acceptable for:**
- Low-volume deployments (< 10 queries/hour)
- Batch processing (overnight analysis)
- Non-time-critical tasks

**❌ Not recommended for:**
- Interactive user experiences
- High-volume deployments
- Real-time threat hunting

---

## 🎮 Scenario 2: 8GB GPU (CURRENT SETUP)

### What Happens

With 8GB VRAM, you can run 7B models efficiently:
- ✅ **Fast inference**: 3-8 seconds per query
- ✅ **Excellent quality**: 7B models are production-grade
- ✅ **Good user experience**: Acceptable delays

### Current Configuration (Optimal)

**Models** (already installed):
```bash
qwen2.5:7b-instruct-q4_k_m       # 4.7GB (Chat & Analysis)
qwen2.5-coder:7b-instruct-q4_k_m # 4.7GB (Code Generation)
```

**Config** (`/opt/casescope/app/config.py`):
```python
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_k_m'
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_k_m'
```

### Performance Expectations

| Task | Response Time | Tokens/Sec | Quality |
|------|---------------|------------|---------|
| DSL Generation | 2-4s | 20-40 | Excellent |
| Event Analysis | 3-8s | 20-40 | Excellent |
| IOC Extraction | 2-5s | 20-40 | Excellent |
| Chat/RAG | 3-8s | 20-40 | Excellent |

### Hardware Examples

- Tesla P4 (8GB) ← **Your current GPU**
- RTX 2080 (8GB)
- RTX 3070 (8GB)
- RTX 4060 Ti (8GB)
- AMD RX 6800 (8GB)

### Optional Upgrades

**Better quality (slower):**
```bash
ollama pull qwen2.5:7b-instruct-q5_k_m  # 5.5GB, +10% quality
```

**Faster inference (experimental):**
```bash
ollama pull mixtral:8x7b-instruct-q2_k  # ~8GB, MoE architecture
```

### Production Suitability

**✅ Perfect for:**
- Production deployments
- Interactive threat hunting
- Real-time analysis
- Multiple concurrent users (1-5)

---

## 🚀 Scenario 3: 16GB+ GPU

### What Happens

With 16GB+ VRAM, you can run larger, more capable models:
- ✅ **Very fast inference**: 2-5 seconds per query
- ✅ **Superior quality**: 14B+ models understand complex queries better
- ✅ **Excellent user experience**: Near-instant responses

### Recommended Configuration

**Models:**
```bash
# 14B models (recommended for 16GB)
ollama pull qwen2.5:14b-instruct-q5_k_m        # ~9GB
ollama pull qwen2.5-coder:14b-instruct-q5_k_m  # ~9GB

# 32B models (for 24GB+ VRAM)
ollama pull qwen2.5:32b-instruct-q4_k_m        # ~18GB

# 70B models (for 40GB+ VRAM)
ollama pull llama3.1:70b-instruct-q4_k_m       # ~40GB
```

**Update `/opt/casescope/app/config.py`:**
```python
LLM_MODEL_CHAT = 'qwen2.5:14b-instruct-q5_k_m'
LLM_MODEL_CODE = 'qwen2.5-coder:14b-instruct-q5_k_m'
```

### Performance Expectations

| Model | VRAM | Response Time | Tokens/Sec | Quality |
|-------|------|---------------|------------|---------|
| `qwen2.5:14b-q5_k_m` | ~9GB | 2-5s | 30-60 | Excellent |
| `qwen2.5:32b-q4_k_m` | ~18GB | 3-7s | 25-50 | Outstanding |
| `llama3.1:70b-q4_k_m` | ~40GB | 4-10s | 20-40 | Best-in-class |

### Hardware Examples

**16GB VRAM:**
- RTX 3090 (24GB)
- RTX 4090 (24GB)
- Tesla T4 (16GB)
- AMD MI50 (16GB)

**24GB+ VRAM:**
- RTX 3090 (24GB)
- RTX 4090 (24GB)
- A5000 (24GB)
- A6000 (48GB)

**40GB+ VRAM (Enterprise):**
- A100 (40GB/80GB)
- H100 (80GB)
- Multi-GPU setups

### Production Suitability

**✅ Ideal for:**
- High-volume production
- Enterprise deployments
- Multiple concurrent users (5-20)
- Complex analysis workflows
- Research and development

---

## Decision Matrix

| Scenario | Hardware | Model Size | Response Time | Quality | Cost | Production Ready? |
|----------|----------|------------|---------------|---------|------|-------------------|
| **No GPU** | CPU only | 1.5B-3B | 10-30s | Good | Low | ⚠️ Limited |
| **8GB GPU** | P4, 2080, 3070 | 7B | 3-8s | Excellent | Medium | ✅ Yes |
| **16GB+ GPU** | 3090, 4090, A100 | 14B-70B | 2-7s | Outstanding | High | ✅ Yes |

---

## Testing Your Setup

### 1. Detect Hardware
```bash
cd /opt/casescope
./scripts/detect_hardware.sh
```

### 2. Test Performance
```bash
cd /opt/casescope
sudo -u casescope /opt/casescope/venv/bin/python3 scripts/test_llm_hardware.py
```

### 3. Benchmark Response Time
```bash
cd /opt/casescope
sudo -u casescope /opt/casescope/venv/bin/python3 scripts/test_ai_foundation.py
```

---

## Migration Guide

### Switching to CPU Models (No GPU)

1. **Pull smaller model:**
   ```bash
   ollama pull qwen2.5:3b
   ```

2. **Update config:**
   ```python
   # /opt/casescope/app/config.py
   LLM_MODEL_CHAT = 'qwen2.5:3b'
   LLM_MODEL_CODE = 'qwen2.5:3b'
   ```

3. **Restart Flask:**
   ```bash
   sudo systemctl restart casescope-new
   ```

4. **Test:**
   ```bash
   sudo -u casescope /opt/casescope/venv/bin/python3 scripts/test_ai_foundation.py
   ```

### Upgrading to Larger Models (16GB+ GPU)

1. **Pull larger models:**
   ```bash
   ollama pull qwen2.5:14b-instruct-q5_k_m
   ollama pull qwen2.5-coder:14b-instruct-q5_k_m
   ```

2. **Update config:**
   ```python
   # /opt/casescope/app/config.py
   LLM_MODEL_CHAT = 'qwen2.5:14b-instruct-q5_k_m'
   LLM_MODEL_CODE = 'qwen2.5-coder:14b-instruct-q5_k_m'
   ```

3. **Restart Flask:**
   ```bash
   sudo systemctl restart casescope-new
   ```

4. **Verify VRAM usage:**
   ```bash
   watch -n 1 nvidia-smi
   ```

---

## Troubleshooting

### "Model too large for GPU"

**Symptoms:**
- Ollama error: "failed to allocate memory"
- nvidia-smi shows insufficient VRAM

**Solution:**
```bash
# Use smaller quantization
ollama pull qwen2.5:7b-instruct-q4_k_m  # Instead of q5_k_m or q6_k

# Or use smaller model
ollama pull qwen2.5:3b
```

### "Very slow responses on GPU"

**Check:**
```bash
nvidia-smi
```

**Ensure:**
- GPU is actually being used (check memory usage)
- No other processes consuming VRAM
- Ollama service using GPU (check logs)

**Fix:**
```bash
# Restart Ollama
sudo systemctl restart ollama

# Check Ollama logs
sudo journalctl -u ollama -n 100
```

### "Out of Memory (OOM) errors"

**Symptoms:**
- System crashes during inference
- Ollama process killed

**Solutions:**
1. **Increase system RAM** (if CPU mode)
2. **Use smaller model**
3. **Reduce concurrent requests**
4. **Add swap space** (emergency):
   ```bash
   sudo fallocate -l 8G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

---

## Recommendations Summary

| Your Hardware | Recommended Action |
|---------------|-------------------|
| **No GPU** | Pull `qwen2.5:3b`, update config, expect 10-30s responses |
| **< 8GB GPU** | Stick with current 7B Q4_K_M models, expect 5-10s responses |
| **8GB GPU** | ✅ Current config optimal, expect 3-8s responses |
| **16-24GB GPU** | Upgrade to 14B Q5_K_M models, expect 2-5s responses |
| **24GB+ GPU** | Consider 32B models, expect 3-7s responses |
| **40GB+ GPU** | Use 70B models for best quality, expect 4-10s responses |

---

## Support

For hardware-specific questions:
1. Run `./scripts/detect_hardware.sh`
2. Run `python3 scripts/test_llm_hardware.py`
3. Check performance meets your requirements
4. Adjust model size accordingly

**Rule of thumb:** Model VRAM usage should be < 80% of total VRAM for stable operation.

