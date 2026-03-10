#!/usr/bin/env python3
"""Train Qwen3-8B LoRA on pattern evidence judgment data.

Uses Unsloth for efficient LoRA training, then exports Q5_K_M GGUF
for direct import into Ollama.

Input:  training_data/pattern_evidence.jsonl  (from build_pattern_evidence_data.py)
Output: GGUF model ready for `ollama create`
"""
import os
import json
import time
import random

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["UNSLOTH_AUTO_ACCEPT"] = "1"

DATA_FILE = "/opt/casescope/training_data/pattern_evidence.jsonl"
MODEL_DIR = "/opt/casescope/lora_training/models/pattern_evidence_qwen3_8b"
ADAPTER_OUT = os.path.join(MODEL_DIR, "adapter")
GGUF_OUT = os.path.join(MODEL_DIR, "gguf")
FINAL_GGUF = os.path.join(MODEL_DIR, "pattern-evidence-qwen3-8b.Q5_K_M.gguf")
MODELFILE_PATH = os.path.join(MODEL_DIR, "Modelfile")

SYSTEM_PROMPT = (
    "You are a senior DFIR analyst. You receive pre-computed "
    "deterministic evidence and provide contextual judgment. "
    "Pay close attention to FAIL checks — they indicate specific "
    "reasons to reduce confidence. Machine accounts, loopback IPs, "
    "and DC activity are usually benign and warrant large negative "
    "adjustments (-15 to -20). HOWEVER, if a USER account (not a "
    "machine account ending in $) is performing privileged operations "
    "like directory replication, that is HIGHLY suspicious regardless "
    "of source host — adjust 0 to +10. Use the full adjustment range. "
    "Respond only with valid JSON."
)

TRAIN_SPLIT = 0.9
RANDOM_SEED = 42


def main():
    import torch
    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer, SFTConfig
    from unsloth.chat_templates import get_chat_template, standardize_sharegpt

    print("=" * 60)
    print("PATTERN EVIDENCE MODEL TRAINING")
    print("=" * 60)

    # Load and split data
    print("\n[1/7] Loading training data...")
    all_data = []
    with open(DATA_FILE) as f:
        for line in f:
            all_data.append(json.loads(line))

    random.seed(RANDOM_SEED)
    random.shuffle(all_data)
    split_idx = int(len(all_data) * TRAIN_SPLIT)
    train_data = all_data[:split_idx]
    val_data = all_data[split_idx:]
    print(f"  Total: {len(all_data)} | Train: {len(train_data)} | Val: {len(val_data)}")

    # Repeat dataset ~10x for small dataset (322 samples -> ~2900 effective)
    # This gives the model enough gradient updates to learn the format
    n_repeats = max(1, 3000 // len(train_data))
    train_data_expanded = train_data * n_repeats
    random.shuffle(train_data_expanded)
    print(f"  Expanded train: {len(train_data_expanded)} ({n_repeats}x repeat)")

    # Load base model
    print("\n[2/7] Loading base model (Qwen3-8B)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Qwen3-8B",
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )
    print(f"  GPU: {torch.cuda.memory_allocated()/1024**3:.1f} GB")

    # Apply LoRA
    print("\n[3/7] Applying LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=32,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=RANDOM_SEED,
    )

    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    # Prepare datasets
    print("\n[4/7] Preparing datasets...")
    train_dataset = Dataset.from_list(train_data_expanded)
    train_dataset = standardize_sharegpt(train_dataset)

    def formatting_func(examples):
        convos = examples["conversations"]
        texts = [tokenizer.apply_chat_template(c, tokenize=False, add_generation_prompt=False) for c in convos]
        return {"text": texts}

    train_dataset = train_dataset.map(formatting_func, batched=True)
    print(f"  Train samples: {len(train_dataset)}")

    # Training config
    batch_size = 2
    grad_accum = 4
    effective_batch = batch_size * grad_accum
    num_epochs = 3
    steps = (len(train_dataset) * num_epochs) // effective_batch
    warmup = min(50, steps // 10)
    print(f"  Effective batch: {effective_batch} | Steps: {steps} | Warmup: {warmup}")

    # Train
    print("\n[5/7] Training...")
    t0 = time.time()

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        args=SFTConfig(
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=grad_accum,
            warmup_steps=warmup,
            max_steps=steps,
            learning_rate=2e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=25,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=RANDOM_SEED,
            output_dir="/tmp/unsloth_pattern_evidence",
            max_seq_length=2048,
            dataset_text_field="text",
            packing=False,
        ),
    )

    checkpoint_dir = "/tmp/unsloth_pattern_evidence/checkpoint-500"
    resume_from = checkpoint_dir if os.path.isdir(checkpoint_dir) else None
    if resume_from:
        print(f"  RESUMING from {resume_from}")
    stats = trainer.train(resume_from_checkpoint=resume_from)
    elapsed = time.time() - t0
    print(f"\n  Training complete in {elapsed/60:.1f} minutes")
    print(f"  Final loss: {stats.training_loss:.4f}")

    # Save adapter
    print("\n[6/7] Saving adapter...")
    os.makedirs(ADAPTER_OUT, exist_ok=True)
    model.save_pretrained(ADAPTER_OUT)
    tokenizer.save_pretrained(ADAPTER_OUT)
    print(f"  Saved to {ADAPTER_OUT}")

    # Export GGUF
    print("\n[7/7] Exporting GGUF Q5_K_M...")
    os.makedirs(GGUF_OUT, exist_ok=True)
    model.save_pretrained_gguf(GGUF_OUT, tokenizer, quantization_method="q5_k_m")

    found = False
    for root, dirs, files in os.walk(GGUF_OUT):
        for f in files:
            if f.endswith('.gguf'):
                src = os.path.join(root, f)
                os.replace(src, FINAL_GGUF)
                sz = os.path.getsize(FINAL_GGUF) / 1024**3
                print(f"  GGUF: {FINAL_GGUF} ({sz:.2f} GB)")
                found = True
                break
        if found:
            break

    if not found:
        parent = os.path.dirname(GGUF_OUT)
        for root2, dirs2, files2 in os.walk(parent):
            for f2 in files2:
                if f2.endswith('.gguf'):
                    src2 = os.path.join(root2, f2)
                    if not found:
                        os.replace(src2, FINAL_GGUF)
                        sz2 = os.path.getsize(FINAL_GGUF) / 1024**3
                        print(f"  GGUF (alt): {FINAL_GGUF} ({sz2:.2f} GB)")
                        found = True

    if not found:
        print("  WARNING: No GGUF file found — check output dirs manually")

    # Write Modelfile for Ollama import
    modelfile_content = f"""FROM {FINAL_GGUF}
PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
SYSTEM \"\"\"{SYSTEM_PROMPT}\"\"\"
"""
    with open(MODELFILE_PATH, 'w') as mf:
        mf.write(modelfile_content)
    print(f"  Modelfile: {MODELFILE_PATH}")

    print(f"\n{'=' * 60}")
    print("TRAINING COMPLETE")
    print(f"{'=' * 60}")
    print(f"\nTo import into Ollama:")
    print(f"  ollama create pattern_qwen3_8b -f {MODELFILE_PATH}")


if __name__ == '__main__':
    main()
