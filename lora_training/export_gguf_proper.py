#!/usr/bin/env python3
"""Export GGUF from a saved LoRA adapter using PeftModel.from_pretrained.

The previous export script used raw load_state_dict which silently dropped
LoRA weights. This script uses the proper Unsloth/PEFT loading path.
"""
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["UNSLOTH_AUTO_ACCEPT"] = "1"

ADAPTER_DIR = "/tmp/unsloth_pattern_evidence/checkpoint-1083"
MODEL_DIR = "/opt/casescope/lora_training/models/pattern_evidence_qwen3_8b"
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
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template

    print("=" * 60)
    print("EXPORT GGUF — PROPER PEFT LOADING")
    print("=" * 60)

    print(f"\n[1/4] Loading base model + LoRA adapter from {ADAPTER_DIR}...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=ADAPTER_DIR,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )
    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")
    print("  Model loaded with adapter weights applied")

    FastLanguageModel.for_inference(model)

    print("\n[2/4] Exporting GGUF Q5_K_M...")
    os.makedirs(GGUF_OUT, exist_ok=True)
    model.save_pretrained_gguf(GGUF_OUT, tokenizer, quantization_method="q5_k_m")

    found = False
    for root, dirs, files in os.walk(os.path.dirname(GGUF_OUT)):
        for f in files:
            if f.endswith('.gguf') and 'Q5_K_M' in f:
                src = os.path.join(root, f)
                os.replace(src, FINAL_GGUF)
                sz = os.path.getsize(FINAL_GGUF) / 1024**3
                print(f"  GGUF: {FINAL_GGUF} ({sz:.2f} GB)")
                found = True
                break
        if found:
            break

    if not found:
        for root, dirs, files in os.walk(os.path.dirname(GGUF_OUT)):
            for f in files:
                if f.endswith('.gguf'):
                    src = os.path.join(root, f)
                    os.replace(src, FINAL_GGUF)
                    sz = os.path.getsize(FINAL_GGUF) / 1024**3
                    print(f"  GGUF (alt): {FINAL_GGUF} ({sz:.2f} GB)")
                    found = True
                    break
            if found:
                break

    if not found:
        print("  ERROR: No GGUF file produced")
        return

    print("\n[3/4] Writing Modelfile...")
    modelfile = f"""FROM {FINAL_GGUF}
PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
PARAMETER num_predict 512
PARAMETER stop "<|im_end|>"
SYSTEM \"\"\"{SYSTEM_PROMPT}\"\"\"
"""
    mf_path = os.path.join(MODEL_DIR, "Modelfile")
    with open(mf_path, 'w') as f:
        f.write(modelfile)
    print(f"  Modelfile: {mf_path}")

    print("\n[4/4] Verifying hash...")
    import hashlib
    h = hashlib.sha256()
    with open(FINAL_GGUF, 'rb') as fh:
        while True:
            chunk = fh.read(8192)
            if not chunk:
                break
            h.update(chunk)
    print(f"  SHA256: {h.hexdigest()[:40]}")

    print(f"\n{'=' * 60}")
    print("EXPORT COMPLETE")
    print(f"{'=' * 60}")
    print(f"\nImport: ollama create pattern_qwen3_8b -f {mf_path}")


if __name__ == '__main__':
    main()
