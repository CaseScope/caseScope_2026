# LoRA Training for DFIR Models

## Overview

This directory contains the infrastructure for fine-tuning DFIR AI models using LoRA (Low-Rank Adaptation).

**Goal**: Train the models on YOUR verified DFIR reports to learn your specific:
- Timeline format
- Evidence citation style
- MITRE ATT&CK mapping approach
- Hallucination avoidance patterns
- IOC/system reference style

## Why LoRA?

**Without LoRA**:
- ❌ Retrain entire model (requires 2+ GPUs, 40+ GB VRAM)
- ❌ Hundreds of GB of training data
- ❌ Days of training time

**With LoRA**:
- ✅ Train tiny adapter layers (fits in Tesla P4 8GB VRAM)
- ✅ 100-500 examples is enough
- ✅ A few MB of training weights
- ✅ Hours of training, not days

## Training Data Format

Each training example has 3 parts:

```json
{
  "instruction": "Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary.",
  "input": "CASE: 2025-08-12 - Compromised Account\n\nIOCs:\n- tabadmin (username)\n- 172.16.10.25 (IP)\n\nSYSTEMS:\n- CM-DC01 (Domain Controller)\n\nEVENTS:\n- 2025-08-12 07:01:16Z | EventID 4625 | Failed login | User: tabadmin | Source: 172.16.10.25\n- 2025-08-12 07:05:22Z | EventID 4624 | Successful login | User: tabadmin | Source: 172.16.10.25",
  "output": "# DFIR Investigation Report\n\n## Timeline\n\n[2025-08-12 07:01:16Z] — Failed login attempt\nSystem: CM-DC01\nUser/Account: tabadmin\nIOC: 172.16.10.25\nEvidence: EventID 4625, SourceNetworkAddress=172.16.10.25\nMITRE: TA0001 / T1078 Valid Accounts\n\n[2025-08-12 07:05:22Z] — Successful login after failed attempt\nSystem: CM-DC01\nUser/Account: tabadmin\nIOC: 172.16.10.25\nEvidence: EventID 4624, SourceNetworkAddress=172.16.10.25\nMITRE: TA0001 / T1078 Valid Accounts\n\n..."
}
```

## Directory Structure

```
lora_training/
├── README.md                    # This file
├── training_data/
│   ├── template.jsonl           # Empty template for creating examples
│   ├── examples.jsonl           # Your verified training examples (manually created)
│   └── validation.jsonl         # Hold-out set for testing (20% of examples)
├── scripts/
│   ├── 1_setup_environment.sh   # Install Unsloth + dependencies
│   ├── 2_train_lora.py          # Training script (Unsloth)
│   ├── 3_merge_and_export.py    # Merge LoRA weights into Ollama-compatible model
│   └── 4_test_model.py          # Test the trained model
├── models/                      # Saved LoRA adapters
│   └── dfir-llama-lora/         # Trained LoRA weights
└── logs/                        # Training logs
```

## Quick Start

### 1. Create Training Examples (Manual)

```bash
cd /opt/casescope/lora_training/training_data
nano examples.jsonl
```

Add 1 example per line (JSONL format). **Minimum 50 examples, ideal 100-500.**

### 2. Install Unsloth

```bash
cd /opt/casescope/lora_training
bash scripts/1_setup_environment.sh
```

### 3. Train LoRA

```bash
python3 scripts/2_train_lora.py \
  --base_model llama3.1:8b-instruct-q4_K_M \
  --training_data training_data/examples.jsonl \
  --output_dir models/dfir-llama-lora \
  --epochs 3 \
  --batch_size 1 \
  --lora_rank 16
```

### 4. Export to Ollama

```bash
python3 scripts/3_merge_and_export.py \
  --lora_dir models/dfir-llama-lora \
  --output_name dfir-analyst-custom
```

### 5. Use Your Custom Model

```bash
ollama run dfir-analyst-custom "Analyze this case..."
```

## Training Parameters Explained

| Parameter | Value | Why |
|-----------|-------|-----|
| `lora_rank` | 16 | Higher = more expressive, but needs more VRAM (16 is sweet spot for P4) |
| `lora_alpha` | 32 | Usually 2x lora_rank |
| `lora_dropout` | 0.05 | Prevents overfitting (5% dropout) |
| `learning_rate` | 2e-4 | Standard for LoRA (0.0002) |
| `epochs` | 3 | How many times to loop through training data |
| `batch_size` | 1 | Tesla P4 can only fit 1 at a time for 8B models |

## How to Create Good Training Examples

### ✅ DO:
- Use REAL cases you've investigated
- Include actual event IDs, timestamps, IOCs
- Show correct MITRE mappings with evidence
- Demonstrate "NO DATA PRESENT" when appropriate
- Include executive summaries, timelines, IOC tables

### ❌ DON'T:
- Use AI-generated reports as training data (hallucination loops!)
- Include speculative language ("likely", "probably", "may have")
- Reference tools/techniques not in the evidence
- Use incomplete or unproofed reports

## Example Training Data Sources

1. **Your Past DFIR Reports** (manually typed into JSONL format)
2. **Tabletop Exercises** (create synthetic but realistic scenarios)
3. **Public Incident Reports** (with permission, reformat to your style)
4. **CaseScope Cases** (after manual human review and correction)

## Expected Results

After training:
- ✅ Model learns YOUR specific timeline format
- ✅ Model follows YOUR evidence citation style
- ✅ Model uses MITRE mappings the way YOU do
- ✅ Model avoids hallucinations (trained on fact-only examples)
- ✅ Model outputs match your expected structure

## Hardware Requirements

- **Minimum**: Tesla P4 (8GB VRAM) - what you have ✅
- **Recommended**: Any GPU with 8+ GB VRAM
- **Training Time**: 2-6 hours for 100-500 examples

## Monitoring Training

```bash
# Watch training progress
tail -f logs/training.log

# Check GPU usage
watch -n 1 nvidia-smi
```

## Troubleshooting

**CUDA Out of Memory**:
- Reduce `batch_size` to 1
- Reduce `lora_rank` to 8

**Model not learning**:
- Increase `epochs` to 5
- Check training data quality
- Ensure examples are diverse

**Overfitting (memorizing training data)**:
- Reduce `epochs`
- Increase `lora_dropout` to 0.1
- Add more diverse examples

## Support

For issues:
1. Check `/opt/casescope/lora_training/logs/training.log`
2. Verify training data format with `scripts/validate_data.py`
3. Test base model first to ensure Ollama is working

## References

- [Unsloth GitHub](https://github.com/unslothai/unsloth)
- [Axolotl GitHub](https://github.com/axolotl-ai-cloud/axolotl)
- [LoRA Paper](https://arxiv.org/abs/2106.09685)
- [QLoRA Paper](https://arxiv.org/abs/2305.14314)

