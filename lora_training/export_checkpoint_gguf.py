#!/usr/bin/env python3
"""Export GGUF from a training checkpoint.

Loads the base model + LoRA adapter from checkpoint, merges, and exports Q5_K_M GGUF.
"""
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["UNSLOTH_AUTO_ACCEPT"] = "1"

CHECKPOINT_DIR = "/tmp/unsloth_pattern_evidence/checkpoint-500"
MODEL_DIR = "/opt/casescope/lora_training/models/pattern_evidence_qwen3_8b"
ADAPTER_OUT = os.path.join(MODEL_DIR, "adapter")
GGUF_OUT = os.path.join(MODEL_DIR, "gguf")
FINAL_GGUF = os.path.join(MODEL_DIR, "pattern-evidence-qwen3-8b.Q5_K_M.gguf")

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

def main():
    import torch
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template

    print("=" * 60)
    print("EXPORT GGUF FROM CHECKPOINT")
    print("=" * 60)

    print("\n[1/5] Loading base model + checkpoint adapter...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Qwen3-8B",
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model, r=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=32, lora_dropout=0, bias="none",
        use_gradient_checkpointing="unsloth", random_state=42,
    )

    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    print("\n[2/5] Loading checkpoint weights...")
    from safetensors.torch import load_file
    state_dict = load_file(os.path.join(CHECKPOINT_DIR, "adapter_model.safetensors"))
    model.load_state_dict(state_dict, strict=False)
    print(f"  Loaded {len(state_dict)} tensors from checkpoint-500")

    print("\n[3/5] Saving adapter...")
    os.makedirs(ADAPTER_OUT, exist_ok=True)
    model.save_pretrained(ADAPTER_OUT)
    tokenizer.save_pretrained(ADAPTER_OUT)
    print(f"  Saved to {ADAPTER_OUT}")

    print("\n[4/5] Exporting GGUF Q5_K_M...")
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
        print("  WARNING: No GGUF file found")

    print("\n[5/5] Writing Modelfile...")
    modelfile = f"""FROM {FINAL_GGUF}
PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
SYSTEM \"\"\"{SYSTEM_PROMPT}\"\"\"
"""
    mf_path = os.path.join(MODEL_DIR, "Modelfile")
    with open(mf_path, 'w') as f:
        f.write(modelfile)
    print(f"  Modelfile: {mf_path}")

    print(f"\n{'=' * 60}")
    print("EXPORT COMPLETE")
    print(f"{'=' * 60}")
    print(f"\nImport into Ollama:")
    print(f"  ollama create pattern_qwen3_8b -f {mf_path}")


if __name__ == '__main__':
    main()
