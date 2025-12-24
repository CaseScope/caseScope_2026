# LoRA Training Quick Start

## 🎯 What You Need to Do

**Goal**: Train your DFIR AI models on YOUR forensic analysis style using LoRA (Low-Rank Adaptation).

**Why**: The current models use generic system prompts. LoRA training teaches them YOUR specific:
- Timeline format
- Evidence citation style
- MITRE ATT&CK mapping approach
- How to avoid hallucinations
- Your reporting structure

**Time Investment**:
- Creating training data: 4-8 hours (50-200 examples)
- Setup: 30 minutes
- Training: 30 minutes - 2 hours
- Total: 1-2 days

---

## 📋 Step-by-Step Process

### Step 1: Create Training Data (MOST IMPORTANT)

**You need 50-200 manually created examples.**

Each example = 3 parts:
1. **Instruction**: "Generate a DFIR report with timeline, MITRE mapping, and executive summary."
2. **Input**: Case data (IOCs, systems, events)
3. **Output**: YOUR perfect DFIR report

**How to create examples**:

#### Option A: Use the interactive helper (EASIEST)
```bash
cd /opt/casescope/lora_training
python3 scripts/create_example.py
```

This will prompt you for:
- Case data (IOCs, systems, events)
- Your perfect report output

It automatically formats as JSONL and saves to `training_data/examples.jsonl`.

#### Option B: Manual editing
```bash
nano training_data/examples.jsonl
```

Copy the template from `training_data/template.jsonl` and fill it in.

**Important**:
- ✅ Use REAL cases you've investigated
- ✅ Write reports the way YOU would present them
- ✅ Include "NO DATA PRESENT" examples
- ❌ DON'T use AI-generated reports
- ❌ DON'T include speculative language

**Read the detailed guide**: `GUIDE_CREATING_TRAINING_DATA.md`

---

### Step 2: Install Training Environment

```bash
cd /opt/casescope/lora_training
sudo -u casescope bash scripts/1_setup_environment.sh
```

This installs:
- PyTorch with CUDA support
- Unsloth (optimized LoRA training for low VRAM)
- All dependencies

**Time**: ~10-15 minutes (downloads ~5 GB)

---

### Step 3: Train the Model

Activate the training environment:
```bash
cd /opt/casescope/lora_training
source activate.sh
```

Train:
```bash
python3 scripts/2_train_lora.py \
  --base_model unsloth/llama-3.1-8b-instruct-bnb-4bit \
  --training_data training_data/examples.jsonl \
  --output_dir models/dfir-llama-custom \
  --epochs 3
```

**Parameters**:
- `--base_model`: Which base model to fine-tune (LLaMA 3.1 8B recommended)
- `--training_data`: Your examples file
- `--output_dir`: Where to save trained weights
- `--epochs`: How many times to loop through training data (3 is good)

**Time**: 
- 50 examples = ~30 minutes
- 200 examples = ~2 hours

**Monitor**:
```bash
# Watch training log
tail -f logs/training.log

# Watch GPU usage
watch -n 1 nvidia-smi
```

---

### Step 4: Convert to Ollama Format

After training completes, you need to convert the LoRA weights to an Ollama-compatible model.

**Note**: This step is currently manual. You have two options:

#### Option A: Merge LoRA with base model (recommended)

Use Unsloth's merge function to create a standalone model:

```python
from unsloth import FastLanguageModel

# Load base model + LoRA
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="models/dfir-llama-custom",  # Your LoRA adapter
    max_seq_length=2048,
)

# Merge LoRA into base model
model = model.merge_and_unload()

# Save as standard HuggingFace format
model.save_pretrained("models/dfir-llama-merged")
tokenizer.save_pretrained("models/dfir-llama-merged")
```

Then convert to GGUF format for Ollama:
```bash
# Convert to GGUF (requires llama.cpp)
python3 /path/to/llama.cpp/convert.py models/dfir-llama-merged --outfile models/dfir-llama-custom.gguf

# Create Ollama model
ollama create dfir-analyst-custom -f <(cat << EOF
FROM models/dfir-llama-custom.gguf
PARAMETER temperature 0.3
PARAMETER num_ctx 16384
EOF
)
```

#### Option B: Use existing dfir-llama profile + manual prompt editing

For now, use the `dfir-llama:latest` profile we already created and manually refine your system prompt based on what you learn from training examples.

**I can help you set up Option A properly if you want full LoRA integration!**

---

### Step 5: Test Your Custom Model

```bash
ollama run dfir-analyst-custom "Analyze this Windows Event ID 4624..."
```

Compare output to the base `dfir-llama:latest` model.

---

## 📊 Training Data Requirements

| Metric | Minimum | Recommended | Excellent |
|--------|---------|-------------|-----------|
| **Total Examples** | 50 | 100-200 | 500+ |
| **Successful attacks** | 30 | 60 | 150 |
| **"NO DATA PRESENT" examples** | 10 | 20 | 50 |
| **Edge cases** | 5 | 10 | 30 |
| **Multi-system correlation** | 10 | 20 | 50 |

---

## 💡 Pro Tips

1. **Start small**: Create 50 examples, train, test. If good, add 50 more and retrain.

2. **Quality > Quantity**: 50 excellent examples > 500 mediocre ones.

3. **Use real cases**: Your past investigations are GOLD. Use them.

4. **Consistency is key**: Use the same format across all examples.

5. **Test early**: Train on 20 examples first as a proof-of-concept. If it works, continue.

6. **Version control**: Save different versions of `examples.jsonl` (v1, v2, v3) to compare.

7. **Diverse scenarios**: Include:
   - Brute force attacks
   - Phishing
   - Lateral movement
   - Privilege escalation
   - Data exfiltration
   - Ransomware
   - Insider threats

---

## 🐛 Troubleshooting

### "CUDA out of memory"
- Reduce `--batch_size` to 1 (it should already be 1)
- Reduce `--lora_rank` to 8
- Close other GPU applications

### "Model not learning / outputs are bad"
- Increase `--epochs` to 5
- Check training data quality
- Ensure examples are diverse
- Make sure you have 50+ examples

### "Model memorizing training data (overfitting)"
- Reduce `--epochs` to 2
- Increase `--lora_dropout` to 0.1
- Add more diverse examples

### "Training is too slow"
- Check GPU is being used: `nvidia-smi`
- Verify CUDA: `python3 -c "import torch; print(torch.cuda.is_available())"`
- If CPU-only, training will be VERY slow (10-20x slower)

---

## 📚 Next Steps After Training

1. **Generate a test report** using your custom model
2. **Compare** to base model output
3. **Refine** training data based on what you see
4. **Retrain** with improved examples
5. **Iterate** until quality is excellent

---

## ❓ FAQ

**Q: Can I use CaseScope's AI reports as training data?**
A: NO - they haven't been proofed and may contain hallucinations. Only use manually verified reports.

**Q: Can I train on public datasets?**
A: Only if you manually verify and reformat them to match YOUR style. Don't blindly trust external data.

**Q: How long does training take?**
A: 50 examples = ~30 min, 200 examples = ~2 hours on Tesla P4.

**Q: Do I need to retrain all 4 models (Llama, Mistral, DeepSeek, Qwen)?**
A: No - start with Llama 3.1 8B (best balance). Train others later if needed.

**Q: Can I update my training data later?**
A: Yes! Add new examples to `examples.jsonl` and retrain. LoRA is fast enough for iterative improvement.

**Q: What if I only have 10 examples?**
A: Create 40 more synthetic examples (tabletop exercises). Minimum 50 needed for meaningful training.

**Q: Can I share my trained model?**
A: The LoRA adapter is small (a few MB) and shareable. Base model stays on HuggingFace.

---

## 🚀 Ready to Start?

**Step 1**: Read `GUIDE_CREATING_TRAINING_DATA.md`

**Step 2**: Create your first 10 examples using `scripts/create_example.py`

**Step 3**: Run setup: `bash scripts/1_setup_environment.sh`

**Step 4**: Create 40 more examples

**Step 5**: Train: `python3 scripts/2_train_lora.py --training_data training_data/examples.jsonl`

**Questions? Check**:
- `README.md` - Overview and directory structure
- `GUIDE_CREATING_TRAINING_DATA.md` - Detailed guide on creating examples
- Training logs: `logs/training.log`

**Let's train your DFIR AI!** 🔥

