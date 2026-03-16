#!/usr/bin/env python3
"""Train, evaluate, and package the IOC extraction LoRA adapter."""

import datetime as dt
import gc
import importlib.util
import json
import math
import os
import subprocess
import sys
import time

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["UNSLOTH_AUTO_ACCEPT"] = "1"

_repo_root = os.path.dirname(os.path.dirname(__file__))

_ioc_contract_spec = importlib.util.spec_from_file_location(
    "ioc_contract_shared",
    os.path.join(_repo_root, "utils", "ioc_contract.py"),
)
_ioc_contract = importlib.util.module_from_spec(_ioc_contract_spec)
_ioc_contract_spec.loader.exec_module(_ioc_contract)

_ioc_eval_spec = importlib.util.spec_from_file_location(
    "ioc_model_eval_shared",
    os.path.join(_repo_root, "utils", "ioc_model_eval.py"),
)
_ioc_eval = importlib.util.module_from_spec(_ioc_eval_spec)
_ioc_eval_spec.loader.exec_module(_ioc_eval)

_ioc_dataset_spec = importlib.util.spec_from_file_location(
    "ioc_training_dataset_shared",
    os.path.join(_repo_root, "utils", "ioc_training_dataset.py"),
)
_ioc_dataset = importlib.util.module_from_spec(_ioc_dataset_spec)
_ioc_dataset_spec.loader.exec_module(_ioc_dataset)

BASE_MODEL = "unsloth/Qwen2.5-14B-Instruct-bnb-4bit"
BASE_MODEL_HF = "Qwen/Qwen2.5-14B-Instruct"
OLLAMA_BASE = "qwen2.5:14b-instruct-q4_k_m"
MODEL_DIR = "/opt/casescope/lora_training/models/ioc_qwen25_14b"
ADAPTER_OUT = os.path.join(MODEL_DIR, "adapter")
ADAPTER_GGUF = os.path.join(MODEL_DIR, "ioc-adapter.gguf")
MODELEVAL_SUMMARY = os.path.join(MODEL_DIR, "evaluation_summary.json")
DEPLOY_MANIFEST = os.path.join(MODEL_DIR, "deployment_manifest.json")
MODELEFILE_PATH = os.path.join(MODEL_DIR, "Modelfile")
LLAMA_CPP_CONVERTER = os.path.expanduser("~/.unsloth/llama.cpp/convert_lora_to_gguf.py")
CHECKPOINT_DIR = "/tmp/unsloth_ioc_14b/checkpoint-50"
MAX_ACCEPTABLE_EVAL_LOSS = float(os.environ.get("IOC_MAX_EVAL_LOSS", "1.75"))
MIN_JSON_RATE = float(os.environ.get("IOC_MIN_JSON_RATE", "0.95"))
MIN_SCHEMA_RATE = float(os.environ.get("IOC_MIN_SCHEMA_RATE", "0.95"))
MIN_MACRO_F1 = float(os.environ.get("IOC_MIN_MACRO_F1", "0.65"))
DEFAULT_NUM_EPOCHS = float(os.environ.get("IOC_NUM_EPOCHS", "3"))
MAX_STEPS_OVERRIDE = int(os.environ.get("IOC_MAX_STEPS", "0"))
SAVE_EVAL_STEPS_OVERRIDE = int(os.environ.get("IOC_EVAL_STEPS", "0"))
IOC_CONTRACT_VERSION = _ioc_contract.IOC_CONTRACT_VERSION
render_ioc_modelfile = _ioc_contract.render_ioc_modelfile
evaluate_ollama_model = _ioc_eval.evaluate_ollama_model
DATASET_MANIFEST_FILE = _ioc_dataset.DATASET_MANIFEST_FILE
TEST_FILE = _ioc_dataset.TEST_FILE
TRAIN_FILE = _ioc_dataset.TRAIN_FILE
VALID_FILE = _ioc_dataset.VALID_FILE


def _load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _prepare_dataset(tokenizer, rows):
    from datasets import Dataset
    from unsloth.chat_templates import standardize_sharegpt

    dataset = Dataset.from_list(rows)
    dataset = standardize_sharegpt(dataset)

    def formatting_func(examples):
        convos = examples["conversations"]
        texts = [
            tokenizer.apply_chat_template(
                convo,
                tokenize=False,
                add_generation_prompt=False,
            )
            for convo in convos
        ]
        return {"text": texts}

    return dataset.map(formatting_func, batched=True)


def _build_versioned_model_name() -> str:
    stamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"casescope-ioc-{stamp}"


def _write_modelfile() -> None:
    with open(MODELEFILE_PATH, "w", encoding="utf-8") as handle:
        handle.write(render_ioc_modelfile(OLLAMA_BASE, ADAPTER_GGUF))


def _save_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main():
    from unsloth import FastLanguageModel
    import torch
    from unsloth.chat_templates import get_chat_template
    from trl import SFTConfig, SFTTrainer

    print("=" * 60)
    print("IOC EXTRACTION - Qwen2.5-14B-Instruct LoRA Training")
    print("=" * 60)

    train_rows = _load_jsonl(TRAIN_FILE)
    valid_rows = _load_jsonl(VALID_FILE)
    dataset_manifest = {}
    if os.path.exists(DATASET_MANIFEST_FILE):
        with open(DATASET_MANIFEST_FILE, "r", encoding="utf-8") as handle:
            dataset_manifest = json.load(handle)

    print(f"\n[1/7] Loading base model: {BASE_MODEL}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=4096,
        dtype=None,
        load_in_4bit=True,
    )
    print(f"  GPU allocated: {torch.cuda.memory_allocated()/1024**3:.1f} GB")

    print("\n[2/7] Applying LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        lora_alpha=32,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    tokenizer = get_chat_template(tokenizer, chat_template="qwen-2.5")

    print("\n[3/7] Preparing train and validation datasets...")
    train_dataset = _prepare_dataset(tokenizer, train_rows)
    valid_dataset = _prepare_dataset(tokenizer, valid_rows)
    print(f"  Train samples: {len(train_dataset)}")
    print(f"  Valid samples: {len(valid_dataset)}")

    num_epochs = DEFAULT_NUM_EPOCHS
    batch_size = 1
    grad_accum = 8
    effective_batch = batch_size * grad_accum
    steps = max(1, int((len(train_dataset) * num_epochs) // effective_batch))
    if MAX_STEPS_OVERRIDE > 0:
        steps = min(steps, MAX_STEPS_OVERRIDE)
    eval_steps = max(1, min(10, steps))
    if SAVE_EVAL_STEPS_OVERRIDE > 0:
        eval_steps = min(steps, SAVE_EVAL_STEPS_OVERRIDE)

    print("\n[4/7] Training with evaluation checkpoints...")
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=valid_dataset,
        args=SFTConfig(
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=1,
            prediction_loss_only=True,
            gradient_accumulation_steps=grad_accum,
            warmup_steps=10,
            max_steps=steps,
            learning_rate=5e-5,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=10,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            output_dir="/tmp/unsloth_ioc_14b",
            dataset_text_field="text",
            max_length=4096,
            packing=False,
            save_strategy="no",
            eval_strategy="no",
        ),
    )

    started_at = time.time()
    if os.path.isdir(CHECKPOINT_DIR):
        print(f"  Resuming from {CHECKPOINT_DIR}")
        stats = trainer.train(resume_from_checkpoint=CHECKPOINT_DIR)
    else:
        stats = trainer.train()
    elapsed = time.time() - started_at
    print(f"  Training complete in {elapsed/60:.1f} minutes")
    print(f"  Training loss: {stats.training_loss:.4f}")
    eval_metrics = {
        "validation_mode": "post_import_ollama_eval",
        "validation_rows": len(valid_rows),
    }

    print("\n[5/7] Saving adapter artifacts...")
    os.makedirs(ADAPTER_OUT, exist_ok=True)
    model.save_pretrained(ADAPTER_OUT)
    tokenizer.save_pretrained(ADAPTER_OUT)
    _write_modelfile()
    print(f"  Adapter directory: {ADAPTER_OUT}")

    gc.collect()
    torch.cuda.empty_cache()

    print("\n[6/7] Converting adapter to GGUF and importing versioned model...")
    convert_cmd = [
        sys.executable,
        LLAMA_CPP_CONVERTER,
        "--base-model-id",
        BASE_MODEL_HF,
        "--outfile",
        ADAPTER_GGUF,
        "--outtype",
        "bf16",
        ADAPTER_OUT,
    ]
    result = subprocess.run(convert_cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"Adapter GGUF conversion failed: {result.stderr[-500:]}")

    versioned_model = _build_versioned_model_name()
    import_result = subprocess.run(
        ["ollama", "create", versioned_model, "-f", MODELEFILE_PATH],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if import_result.returncode != 0:
        raise RuntimeError(f"Ollama import failed: {import_result.stderr}")

    print(f"  Imported Ollama model: {versioned_model}")

    print("\n[7/7] Evaluating imported model on curated holdout...")
    valid_candidate_metrics = evaluate_ollama_model(versioned_model, VALID_FILE)
    candidate_metrics = evaluate_ollama_model(versioned_model, TEST_FILE)
    baseline_name = os.environ.get("IOC_BASELINE_MODEL", "").strip()
    baseline_metrics = None
    if baseline_name:
        try:
            baseline_metrics = evaluate_ollama_model(baseline_name, TEST_FILE)
        except Exception as exc:  # noqa: BLE001
            baseline_metrics = {"model": baseline_name, "error": str(exc)}

    meets_thresholds = (
        valid_candidate_metrics["valid_json_rate"] >= MIN_JSON_RATE
        and valid_candidate_metrics["schema_compliance_rate"] >= MIN_SCHEMA_RATE
        and valid_candidate_metrics["macro_f1"] >= MIN_MACRO_F1
    )
    beats_baseline = True
    if baseline_metrics and "macro_f1" in baseline_metrics:
        beats_baseline = candidate_metrics["macro_f1"] >= baseline_metrics["macro_f1"]

    evaluation_summary = {
        "contract_version": IOC_CONTRACT_VERSION,
        "dataset_manifest": dataset_manifest,
        "train_loss": stats.training_loss,
        "eval_metrics": eval_metrics,
        "candidate_model": versioned_model,
        "validation_metrics": valid_candidate_metrics,
        "candidate_metrics": candidate_metrics,
        "baseline_metrics": baseline_metrics,
        "thresholds": {
            "max_eval_loss": MAX_ACCEPTABLE_EVAL_LOSS,
            "min_json_rate": MIN_JSON_RATE,
            "min_schema_rate": MIN_SCHEMA_RATE,
            "min_macro_f1": MIN_MACRO_F1,
        },
        "approved_for_promotion": meets_thresholds and beats_baseline,
    }
    _save_json(MODELEVAL_SUMMARY, evaluation_summary)
    _save_json(
        DEPLOY_MANIFEST,
        {
            "contract_version": IOC_CONTRACT_VERSION,
            "dataset_manifest": dataset_manifest,
            "base_model": OLLAMA_BASE,
            "adapter_dir": ADAPTER_OUT,
            "adapter_gguf": ADAPTER_GGUF,
            "candidate_model": versioned_model,
            "approved_for_promotion": evaluation_summary["approved_for_promotion"],
            "evaluation_summary": MODELEVAL_SUMMARY,
        },
    )

    print("\n" + "=" * 60)
    print("IOC EXTRACTION TRAINING COMPLETE")
    print(f"  Candidate model: {versioned_model}")
    print(f"  Approved:       {evaluation_summary['approved_for_promotion']}")
    print(f"  Eval summary:   {MODELEVAL_SUMMARY}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
