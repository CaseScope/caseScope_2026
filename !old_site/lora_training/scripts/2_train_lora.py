#!/usr/bin/env python3
"""
LoRA Training Script for DFIR Models
Optimized for Tesla P4 (8GB VRAM) using Unsloth

Usage:
    python3 2_train_lora.py \
        --base_model llama3.1:8b-instruct-q4_K_M \
        --training_data ../training_data/examples.jsonl \
        --output_dir ../models/dfir-llama-lora \
        --epochs 3
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import torch
from datasets import Dataset
from unsloth import FastLanguageModel

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('/opt/casescope/lora_training/logs/training.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def load_training_data(filepath):
    """Load JSONL training data"""
    logger.info(f"Loading training data from {filepath}")
    
    examples = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                example = json.loads(line)
                # Validate required fields (support both formats)
                if 'prompt' in example and 'response' in example:
                    # Convert prompt/response format to instruction/input/output
                    examples.append({
                        'instruction': 'Generate a DFIR investigation report',
                        'input': example['prompt'],
                        'output': example['response']
                    })
                elif all(k in example for k in ['instruction', 'input', 'output']):
                    examples.append(example)
                else:
                    logger.warning(f"Line {line_num}: Missing required fields")
                    continue
            except json.JSONDecodeError as e:
                logger.warning(f"Line {line_num}: Invalid JSON - {e}")
                continue
    
    logger.info(f"✅ Loaded {len(examples)} training examples")
    return examples


def format_prompt(example):
    """Format example into LLaMA 3.1 instruction format"""
    return f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

You are a senior DFIR analyst. Generate professional forensic investigation reports using only the evidence provided.<|eot_id|><|start_header_id|>user<|end_header_id|>

{example['instruction']}

{example['input']}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

{example['output']}<|eot_id|>"""


def main():
    parser = argparse.ArgumentParser(description='Train LoRA adapter for DFIR models')
    parser.add_argument('--base_model', default='unsloth/llama-3.1-8b-instruct-bnb-4bit',
                        help='Base model from HuggingFace (default: LLaMA 3.1 8B 4-bit)')
    parser.add_argument('--training_data', required=True,
                        help='Path to training data (JSONL format)')
    parser.add_argument('--output_dir', default='../models/dfir-lora',
                        help='Output directory for trained model')
    parser.add_argument('--lora_rank', type=int, default=16,
                        help='LoRA rank (higher = more expressive, needs more VRAM)')
    parser.add_argument('--lora_alpha', type=int, default=32,
                        help='LoRA alpha (usually 2x lora_rank)')
    parser.add_argument('--lora_dropout', type=float, default=0.05,
                        help='LoRA dropout (prevents overfitting)')
    parser.add_argument('--learning_rate', type=float, default=2e-4,
                        help='Learning rate (0.0002 is standard for LoRA)')
    parser.add_argument('--epochs', type=int, default=3,
                        help='Number of training epochs')
    parser.add_argument('--batch_size', type=int, default=1,
                        help='Batch size per device (1 for Tesla P4)')
    parser.add_argument('--max_seq_length', type=int, default=2048,
                        help='Maximum sequence length')
    
    args = parser.parse_args()
    
    logger.info("=" * 60)
    logger.info("  LoRA Training for DFIR Models")
    logger.info("=" * 60)
    logger.info(f"Base model: {args.base_model}")
    logger.info(f"Training data: {args.training_data}")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"LoRA rank: {args.lora_rank}")
    logger.info(f"LoRA alpha: {args.lora_alpha}")
    logger.info(f"Learning rate: {args.learning_rate}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info(f"Batch size: {args.batch_size}")
    logger.info("")
    
    # Check CUDA
    if torch.cuda.is_available():
        logger.info(f"✅ CUDA available: {torch.cuda.get_device_name(0)}")
        logger.info(f"   VRAM: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
    else:
        logger.warning("⚠️  CUDA not available - training will be VERY slow")
    logger.info("")
    
    # Load training data
    training_examples = load_training_data(args.training_data)
    if len(training_examples) < 10:
        logger.error("❌ Need at least 10 training examples (50+ recommended)")
        sys.exit(1)
    
    # Format data
    logger.info("📝 Formatting training examples...")
    formatted_data = []
    for ex in training_examples:
        formatted_data.append({
            'text': format_prompt(ex)
        })
    
    dataset = Dataset.from_list(formatted_data)
    logger.info(f"✅ Dataset created: {len(dataset)} examples")
    logger.info("")
    
    # Load base model with 4-bit quantization
    logger.info("🦙 Loading base model...")
    logger.info(f"   Model: {args.base_model}")
    logger.info(f"   Max sequence length: {args.max_seq_length}")
    logger.info(f"   Quantization: 4-bit")
    logger.info(f"   Device: CUDA (auto device_map)")
    
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_length,
        dtype=None,  # Auto-detect (FP16 for Pascal GPU)
        load_in_4bit=True,  # 4-bit quantization for VRAM efficiency
        device_map="auto",  # CRITICAL: Auto device placement for quantized models
    )
    logger.info("✅ Base model loaded")
    logger.info("")
    
    # Apply LoRA
    logger.info("🔧 Applying LoRA...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_rank,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth",  # Saves VRAM
        random_state=42,
    )
    logger.info("✅ LoRA applied")
    logger.info("")
    
    # Calculate training steps
    total_steps = (len(dataset) * args.epochs) // args.batch_size
    logger.info(f"📊 Training plan:")
    logger.info(f"   Examples: {len(dataset)}")
    logger.info(f"   Epochs: {args.epochs}")
    logger.info(f"   Batch size: {args.batch_size}")
    logger.info(f"   Total steps: {total_steps}")
    logger.info("")
    
    # Tokenize dataset
    logger.info("📝 Tokenizing dataset...")
    def tokenize_function(examples):
        return tokenizer(examples["text"], truncation=True, max_length=args.max_seq_length)
    
    tokenized_dataset = dataset.map(tokenize_function, batched=True, remove_columns=["text"])
    logger.info(f"✅ Tokenized {len(tokenized_dataset)} examples")
    logger.info("")
    
    # Setup trainer with simplified args
    from transformers import Trainer, TrainingArguments, DataCollatorForLanguageModeling
    
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=4,  # Effective batch size = 4
            warmup_steps=10,
            num_train_epochs=args.epochs,
            learning_rate=args.learning_rate,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=1,
            optim="adamw_8bit",  # Saves VRAM
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            output_dir=args.output_dir,
            save_strategy="epoch",
            save_total_limit=3,
            report_to="none",  # Disable wandb/tensorboard
        ),
        train_dataset=tokenized_dataset,
        tokenizer=tokenizer,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    )
    
    # Train!
    logger.info("🚀 Starting training...")
    logger.info(f"   This will take ~{total_steps * 2 / 60:.1f} minutes")
    logger.info("")
    
    start_time = datetime.now()
    trainer.train()
    end_time = datetime.now()
    
    training_duration = (end_time - start_time).total_seconds()
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"✅ Training complete!")
    logger.info(f"   Duration: {training_duration / 60:.1f} minutes")
    logger.info(f"   Output: {args.output_dir}")
    logger.info("=" * 60)
    logger.info("")
    
    # Save LoRA adapter
    logger.info("💾 Saving LoRA adapter...")
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    logger.info(f"✅ Saved to {args.output_dir}")
    logger.info("")
    
    logger.info("Next steps:")
    logger.info("1. Test the model: python3 scripts/4_test_model.py")
    logger.info("2. Merge to Ollama: python3 scripts/3_merge_and_export.py")
    logger.info("")


if __name__ == "__main__":
    main()

