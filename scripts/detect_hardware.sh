#!/bin/bash
# Auto-configure CaseScope AI based on available hardware

set -e

echo "========================================="
echo "  CaseScope AI Hardware Detection"
echo "========================================="

# Detect GPU
if command -v nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo "")
    
    if [ -n "$GPU_INFO" ]; then
        GPU_NAME=$(echo "$GPU_INFO" | cut -d',' -f1)
        VRAM_MB=$(echo "$GPU_INFO" | cut -d',' -f2 | tr -d ' MiB')
        VRAM_GB=$((VRAM_MB / 1024))
        
        echo "✅ GPU Detected: $GPU_NAME"
        echo "   VRAM: ${VRAM_GB}GB"
        
        if [ $VRAM_GB -ge 16 ]; then
            SCENARIO="16GB_GPU"
            echo "🚀 Scenario: High-end GPU (16GB+)"
        elif [ $VRAM_GB -ge 8 ]; then
            SCENARIO="8GB_GPU"
            echo "🎮 Scenario: Mid-range GPU (8GB)"
        else
            SCENARIO="SMALL_GPU"
            echo "⚠️  Scenario: Small GPU (<8GB) - Consider smaller models"
        fi
    else
        SCENARIO="NO_GPU"
        echo "❌ No GPU detected"
    fi
else
    SCENARIO="NO_GPU"
    echo "❌ No GPU detected (nvidia-smi not found)"
fi

echo ""
echo "========================================="
echo "  Recommended Configuration"
echo "========================================="

case $SCENARIO in
    "NO_GPU")
        echo "🖥️  CPU-Only Configuration"
        echo ""
        echo "Models to install:"
        echo "  ollama pull qwen2.5:3b"
        echo "  ollama pull qwen2.5:1.5b  # Even faster, less capable"
        echo ""
        echo "Expected Performance:"
        echo "  - Response time: 10-30 seconds"
        echo "  - Tokens/sec: 3-10"
        echo "  - Quality: Good for analysis, moderate for code generation"
        echo ""
        echo "Config.py changes:"
        echo "  LLM_MODEL_CHAT = 'qwen2.5:3b'"
        echo "  LLM_MODEL_CODE = 'qwen2.5:3b'"
        echo ""
        echo "⚠️  WARNING: 7B models will be VERY SLOW on CPU (30-120s per query)"
        ;;
        
    "SMALL_GPU")
        echo "⚡ Small GPU Configuration"
        echo ""
        echo "Models (already optimal):"
        echo "  ✅ qwen2.5:7b-instruct-q4_k_m"
        echo "  ✅ qwen2.5-coder:7b-instruct-q4_k_m"
        echo ""
        echo "Expected Performance:"
        echo "  - Response time: 5-10 seconds"
        echo "  - Tokens/sec: 10-20"
        echo "  - Quality: Good"
        echo ""
        echo "Consider upgrading to 8GB+ GPU for better performance"
        ;;
        
    "8GB_GPU")
        echo "🎮 8GB GPU Configuration (OPTIMAL)"
        echo ""
        echo "Current models are optimal:"
        echo "  ✅ qwen2.5:7b-instruct-q4_k_m"
        echo "  ✅ qwen2.5-coder:7b-instruct-q4_k_m"
        echo ""
        echo "Expected Performance:"
        echo "  - Response time: 3-8 seconds"
        echo "  - Tokens/sec: 20-40"
        echo "  - Quality: Excellent"
        echo ""
        echo "Optional upgrades:"
        echo "  ollama pull qwen2.5:7b-instruct-q5_k_m  # Better quality, ~5.5GB"
        ;;
        
    "16GB_GPU")
        echo "🚀 High-End GPU Configuration"
        echo ""
        echo "Recommended upgrades for better performance:"
        echo "  ollama pull qwen2.5:14b-instruct-q5_k_m"
        echo "  ollama pull qwen2.5-coder:14b-instruct-q5_k_m"
        echo ""
        echo "Expected Performance:"
        echo "  - Response time: 2-5 seconds"
        echo "  - Tokens/sec: 30-60"
        echo "  - Quality: Excellent"
        echo ""
        echo "Config.py changes:"
        echo "  LLM_MODEL_CHAT = 'qwen2.5:14b-instruct-q5_k_m'"
        echo "  LLM_MODEL_CODE = 'qwen2.5-coder:14b-instruct-q5_k_m'"
        echo ""
        echo "Alternative (even better):"
        echo "  ollama pull llama3.1:70b-instruct-q4_k_m  # Requires ~40GB VRAM"
        ;;
esac

echo ""
echo "========================================="
echo "  Test Performance"
echo "========================================="
echo ""
echo "Run: python3 scripts/test_llm_hardware.py"
echo ""

