#!/usr/bin/env python3
"""
Interactive helper to create training examples
Prompts you for instruction, input, and output, then formats as JSONL
"""

import json
import sys

def main():
    print("=" * 70)
    print("  DFIR Training Example Creator")
    print("=" * 70)
    print()
    print("This will help you create a properly formatted training example.")
    print("Press Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when done with multi-line input.")
    print()
    
    # Instruction
    print("-" * 70)
    print("INSTRUCTION (what should the AI do?):")
    print("Default: 'Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary. Use only the evidence provided.'")
    print()
    instruction_input = input(">>> (press Enter for default): ").strip()
    if not instruction_input:
        instruction = "Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary. Use only the evidence provided."
    else:
        instruction = instruction_input
    print()
    
    # Input (case data)
    print("-" * 70)
    print("INPUT (case data - IOCs, systems, events):")
    print("Example format:")
    print("CASE: 2025-01-15 - Brute Force Attack")
    print()
    print("IOCs:")
    print("- 192.168.1.100 (Attacker IP)")
    print("- tabadmin (Compromised account)")
    print()
    print("SYSTEMS:")
    print("- DC01 (Domain Controller)")
    print()
    print("EVENTS:")
    print("- 2025-01-15 14:32:11Z | EventID 4625 | Failed logon | ...")
    print()
    print("Enter your INPUT (multi-line, Ctrl+D when done):")
    print()
    
    input_lines = []
    try:
        while True:
            line = input()
            input_lines.append(line)
    except EOFError:
        pass
    
    case_input = "\n".join(input_lines).strip()
    
    if not case_input:
        print()
        print("❌ INPUT cannot be empty!")
        sys.exit(1)
    
    print()
    
    # Output (perfect DFIR report)
    print("-" * 70)
    print("OUTPUT (your perfect DFIR report):")
    print("This should be your IDEAL report format with:")
    print("- Executive Summary (3 paragraphs)")
    print("- Timeline (with timestamps, evidence, MITRE)")
    print("- IOCs table")
    print("- MITRE Mapping")
    print("- What/Why/How to Prevent")
    print()
    print("Enter your OUTPUT (multi-line, Ctrl+D when done):")
    print()
    
    output_lines = []
    try:
        while True:
            line = input()
            output_lines.append(line)
    except EOFError:
        pass
    
    report_output = "\n".join(output_lines).strip()
    
    if not report_output:
        print()
        print("❌ OUTPUT cannot be empty!")
        sys.exit(1)
    
    print()
    print("=" * 70)
    
    # Create JSON object
    example = {
        "instruction": instruction,
        "input": case_input,
        "output": report_output
    }
    
    # Format as single-line JSON (JSONL)
    jsonl_line = json.dumps(example, ensure_ascii=False)
    
    # Preview
    print("PREVIEW (first 200 chars):")
    print(jsonl_line[:200] + "...")
    print()
    
    # Save option
    print("=" * 70)
    save = input("Save to training_data/examples.jsonl? (y/n): ").strip().lower()
    
    if save == 'y':
        try:
            with open('/opt/casescope/lora_training/training_data/examples.jsonl', 'a') as f:
                f.write(jsonl_line + "\n")
            print("✅ Example saved!")
            
            # Count total examples
            with open('/opt/casescope/lora_training/training_data/examples.jsonl', 'r') as f:
                count = sum(1 for line in f if line.strip())
            print(f"   Total examples: {count}")
        except Exception as e:
            print(f"❌ Error saving: {e}")
            print()
            print("Manual save - copy this line to examples.jsonl:")
            print(jsonl_line)
    else:
        print()
        print("Copy this line to examples.jsonl manually:")
        print(jsonl_line)
    
    print()
    print("=" * 70)
    print("Create another example? Run this script again.")
    print()


if __name__ == "__main__":
    main()

