#!/usr/bin/env python3
"""IOC Extraction LoRA training using Unsloth + direct GGUF export."""
import os, json, time
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["UNSLOTH_AUTO_ACCEPT"] = "1"

TRAIN_FILE = "/opt/casescope/training_data/ioc_train.jsonl"
VALID_FILE = "/opt/casescope/training_data/ioc_valid.jsonl"
MODEL_DIR = "/opt/casescope/lora_training/models/ioc_qwen3_8b"
ADAPTER_OUT = os.path.join(MODEL_DIR, "adapter")
GGUF_OUT = os.path.join(MODEL_DIR, "gguf_export")
FINAL_GGUF = os.path.join(MODEL_DIR, "ioc-qwen3-8b.Q5_K_M.gguf")

def main():
    import torch
    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer, SFTConfig
    from unsloth.chat_templates import get_chat_template, standardize_sharegpt

    print("=" * 60)
    print("IOC EXTRACTION MODEL - LoRA Training")
    print("=" * 60)

    print("\n[1/6] Loading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Qwen3-8B",
        max_seq_length=4096,
        dtype=None,
        load_in_4bit=True,
    )
    print(f"  GPU: {torch.cuda.memory_allocated()/1024**3:.1f} GB")

    print("\n[2/6] Applying LoRA...")
    model = FastLanguageModel.get_peft_model(
        model, r=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=64, lora_dropout=0, bias="none",
        use_gradient_checkpointing="unsloth", random_state=42,
    )

    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    print("\n[3/6] Loading training data...")
    train_data = []
    with open(TRAIN_FILE) as f:
        for line in f:
            train_data.append(json.loads(line))

    train_dataset = Dataset.from_list(train_data)
    train_dataset = standardize_sharegpt(train_dataset)

    def formatting_func(examples):
        convos = examples["conversations"]
        texts = [tokenizer.apply_chat_template(c, tokenize=False, add_generation_prompt=False) for c in convos]
        return {"text": texts}

    train_dataset = train_dataset.map(formatting_func, batched=True)
    print(f"  Train samples: {len(train_dataset)}")

    num_epochs = 2
    batch_size = 1
    grad_accum = 8
    effective_batch = batch_size * grad_accum
    steps = (len(train_dataset) * num_epochs) // effective_batch
    print(f"  Epochs: {num_epochs}, Effective batch: {effective_batch}, Steps: {steps}")

    print("\n[4/6] Training...")
    t0 = time.time()

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        args=SFTConfig(
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=grad_accum,
            warmup_steps=10,
            max_steps=steps,
            learning_rate=1e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=10,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            output_dir="/tmp/unsloth_ioc",
            max_seq_length=4096,
            dataset_text_field="text",
            packing=False,
        ),
    )

    stats = trainer.train()
    elapsed = time.time() - t0
    print(f"\n  Training complete in {elapsed/60:.1f} minutes")
    print(f"  Final loss: {stats.training_loss:.4f}")

    print("\n[5/6] Saving adapter...")
    os.makedirs(ADAPTER_OUT, exist_ok=True)
    model.save_pretrained(ADAPTER_OUT)
    tokenizer.save_pretrained(ADAPTER_OUT)
    print(f"  Saved to {ADAPTER_OUT}")

    print("\n[6/6] Exporting GGUF Q5_K_M...")
    os.makedirs(GGUF_OUT, exist_ok=True)
    model.save_pretrained_gguf(GGUF_OUT, tokenizer, quantization_method="q5_k_m")

    found = False
    for root, dirs, files in os.walk(GGUF_OUT):
        for f in files:
            if f.endswith('.gguf'):
                src = os.path.join(root, f)
                os.makedirs(os.path.dirname(FINAL_GGUF), exist_ok=True)
                os.replace(src, FINAL_GGUF)
                sz = os.path.getsize(FINAL_GGUF) / 1024**3
                print(f"\n  GGUF: {FINAL_GGUF} ({sz:.2f} GB)")
                found = True
                break
        if found:
            break

    parent = os.path.dirname(GGUF_OUT)
    for d in os.listdir(parent):
        full = os.path.join(parent, d)
        if d.endswith('_gguf') and os.path.isdir(full) and full != GGUF_OUT:
            for root2, dirs2, files2 in os.walk(full):
                for f2 in files2:
                    if f2.endswith('.gguf'):
                        src2 = os.path.join(root2, f2)
                        if not found:
                            os.replace(src2, FINAL_GGUF)
                            sz2 = os.path.getsize(FINAL_GGUF) / 1024**3
                            print(f"\n  GGUF (alt): {FINAL_GGUF} ({sz2:.2f} GB)")
                            found = True

    if not found:
        print("  WARNING: No GGUF file found - check output dirs manually")
        for root3, dirs3, files3 in os.walk(parent):
            for f3 in files3:
                if f3.endswith('.gguf'):
                    print(f"  Found: {os.path.join(root3, f3)}")

    print("\n" + "=" * 60)
    print("IOC EXTRACTION TRAINING COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
