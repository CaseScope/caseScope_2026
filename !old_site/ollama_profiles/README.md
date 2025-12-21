# DFIR-Optimized Ollama Model Profiles

This directory contains custom Ollama Modelfiles that create DFIR-specialized AI models with forensic analyst system prompts.

## Purpose

These profiles train the base models to:
- Act as senior DFIR analysts with strict evidence discipline
- Build timelines from correlated events
- Map behaviors to MITRE ATT&CK techniques
- NEVER hallucinate or speculate beyond evidence
- Cite sources for every claim
- Output court-ready forensic reports

## Available Profiles

| Profile | Base Model | Size | Specialization |
|---------|-----------|------|----------------|
| `dfir-llama` | Llama 3.1 8B Instruct Q4 | 4.9 GB | General reasoning + summarization, excellent timelines |
| `dfir-mistral` | Mistral 7B Instruct v0.3 Q4 | 4.4 GB | Sharp formatting, chronological reconstruction |
| `dfir-deepseek` | DeepSeek-Coder V2 16B Lite Q4 | 10 GB | Script/code analysis, PowerShell decoding |
| `dfir-qwen` | Qwen 2.5 7B Q4 | 4.7 GB | Structured reasoning, long lists, low hallucination |

## Installation

### Step 1: Create DFIR Models

```bash
# Navigate to profiles directory
cd /opt/casescope/ollama_profiles

# Create all 4 DFIR models
sudo -u casescope ollama create dfir-llama -f dfir-llama.Modelfile
sudo -u casescope ollama create dfir-mistral -f dfir-mistral.Modelfile
sudo -u casescope ollama create dfir-deepseek -f dfir-deepseek.Modelfile
sudo -u casescope ollama create dfir-qwen -f dfir-qwen.Modelfile
```

### Step 2: Verify Models

```bash
ollama list | grep dfir
```

Expected output:
```
dfir-llama:latest      4.9 GB
dfir-mistral:latest    4.4 GB
dfir-deepseek:latest   10 GB
dfir-qwen:latest       4.7 GB
```

### Step 3: Test a DFIR Model

```bash
ollama run dfir-llama "I need to analyze Windows logon events. How should I approach this?"
```

The model should respond with evidence-focused methodology, not generic advice.

## Usage in CaseScope

To use these DFIR-optimized models in CaseScope AI report generation:

1. **System Settings** → **AI Report Generation**
2. Select one of the DFIR models:
   - `dfir-llama:latest` (RECOMMENDED - best balance)
   - `dfir-mistral:latest` (fast formatting)
   - `dfir-deepseek:latest` (PowerShell-heavy cases)
   - `dfir-qwen:latest` (long IOC lists)
3. Generate reports as normal

## System Prompt Rules

All DFIR profiles enforce these rules:

### Evidence Discipline
- ✅ Every statement cites evidence (event IDs, log entries, timestamps)
- ✅ Missing data = "NO DATA PRESENT" (not speculation)
- ✅ No assumptions beyond what logs show
- ✅ No external threat intel not in the data

### Timeline Construction
- ✅ Exact timestamps (UTC)
- ✅ Chronological order (earliest first)
- ✅ Correlate events by user/IP/file/process
- ✅ Each entry: timestamp + action + system + user + IOC + evidence

### MITRE ATT&CK Mapping
- ✅ Only techniques with clear evidence
- ✅ Format: TACTIC / T#### Technique Name
- ✅ "MITRE not determinable" if unclear
- ✅ Cite specific evidence for each technique

### Malware Analysis
- ❌ NO inferred capabilities without logs
- ❌ NO assumed lateral movement without connection evidence
- ❌ NO assumed exfiltration without transfer evidence
- ✅ "Malware activity not observed in logs" if only IOC references exist

### Output Requirements
- ✅ Plain English executive summaries (no jargon)
- ✅ Technical precision in timelines
- ✅ Clean Markdown formatting
- ✅ Minimum 1200 words for full reports
- ✅ NIST framework references (SP 800-53, 800-61, 800-63B)

## Model Selection Guide

**Choose `dfir-llama` if:**
- General incident response (most common)
- Need strong executive summaries
- Mixed log types (EVTX, firewall, NDJSON)

**Choose `dfir-mistral` if:**
- Short-to-mid context (< 100 events)
- Need fast, terse output
- Chronological reconstruction focus

**Choose `dfir-deepseek` if:**
- PowerShell-heavy attacks
- Obfuscated commands need decoding
- Script-based persistence mechanisms

**Choose `dfir-qwen` if:**
- Long IOC lists (100+)
- Large event datasets (300+)
- Need low-hallucination structured output

## Parameters

All DFIR profiles use these Ollama parameters:

```
temperature: 0.3       # Low creativity = factual output
num_ctx: 16384         # 16K context window
num_predict: 16384     # 16K max output tokens
top_p: 0.9             # Nucleus sampling
top_k: 40              # Top-k sampling
repeat_penalty: 1.1    # Avoid repetition
```

## Updating Profiles

To update a DFIR profile after editing the Modelfile:

```bash
cd /opt/casescope/ollama_profiles
sudo -u casescope ollama create dfir-llama -f dfir-llama.Modelfile
```

This recreates the model with the new system prompt.

## Removing Profiles

To remove a DFIR model:

```bash
ollama rm dfir-llama
```

This deletes the custom model but keeps the base model.

## Advanced: Custom Profiles

To create your own DFIR profile variant:

1. Copy an existing Modelfile:
   ```bash
   cp dfir-llama.Modelfile my-custom-dfir.Modelfile
   ```

2. Edit the `SYSTEM` section with your custom rules

3. Create the model:
   ```bash
   ollama create my-custom-dfir -f my-custom-dfir.Modelfile
   ```

4. Test it:
   ```bash
   ollama run my-custom-dfir "Analyze this logon event..."
   ```

## Notes

- **Disk Space**: DFIR models use the same disk space as base models (no duplication). The Modelfile just adds metadata and system prompts.
- **Performance**: DFIR models have identical speed to base models (system prompts don't affect inference speed).
- **Updates**: If base models are updated (`ollama pull`), recreate DFIR models to use the new base.
- **Compatibility**: These profiles work with Ollama 0.1.26+ (current: 0.3.x).

## Support

For issues or questions:
1. Check CaseScope logs: `/opt/casescope/logs/workers.log`
2. Test model directly: `ollama run dfir-llama`
3. Verify base model exists: `ollama list`
4. Consult APP_MAP.md for AI report generation flow

## License

These Modelfiles are part of CaseScope 2026 and inherit its license.

