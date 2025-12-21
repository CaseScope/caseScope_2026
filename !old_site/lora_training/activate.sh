#!/bin/bash
# Quick activation script for LoRA training environment
source /opt/casescope/lora_training/venv/bin/activate
echo "✅ LoRA training environment activated"
echo "   Python: $(which python3)"
echo "   To train: python3 scripts/2_train_lora.py --help"
