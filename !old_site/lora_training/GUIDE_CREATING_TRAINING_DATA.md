# Guide: Creating High-Quality DFIR Training Data

## Overview

**Goal**: Create 50-500 manually verified training examples that teach the AI YOUR forensic analysis style.

**Format**: JSONL (JSON Lines) - one JSON object per line

**Quality over Quantity**: 50 excellent examples > 500 mediocre examples

---

## 📋 Training Example Structure

Each line in `training_data/examples.jsonl` is a JSON object with 3 fields:

```json
{
  "instruction": "What the AI should do",
  "input": "The case data (IOCs, systems, events)",
  "output": "Your perfect DFIR report"
}
```

---

## ✅ Method 1: Use Real Past Cases (RECOMMENDED)

### Step 1: Find a case you've already investigated

Example: You investigated a brute-force attack in August 2024.

### Step 2: Extract the key data

- **IOCs**: Attacker IPs, compromised usernames, malicious files
- **Systems**: Domain controllers, workstations, firewalls
- **Events**: Logon attempts, process executions, network connections

### Step 3: Write YOUR ideal report

This is what you would present to a client or court. Include:
- Timeline with evidence citations
- MITRE ATT&CK mappings
- Executive summary
- Recommendations

### Step 4: Format as JSON

```json
{"instruction": "Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary. Use only the evidence provided.", "input": "CASE: 2024-08-12 - Brute Force Attack on Domain Controller\n\nIOCs:\n- 192.168.1.100 (Attacker IP)\n- tabadmin (Compromised account)\n\nSYSTEMS:\n- DC01 (Domain Controller, Windows Server 2019)\n- WORKSTATION-05 (User workstation, Windows 10)\n\nEVENTS:\n- 2024-08-12 14:32:11Z | EventID 4625 | Failed logon | User: tabadmin | Source: 192.168.1.100 | DC01\n- 2024-08-12 14:32:15Z | EventID 4625 | Failed logon | User: tabadmin | Source: 192.168.1.100 | DC01\n- 2024-08-12 14:35:42Z | EventID 4624 | Successful logon | User: tabadmin | Source: 192.168.1.100 | DC01 | LogonType: 3 (Network)\n- 2024-08-12 14:37:19Z | EventID 4672 | Special privileges assigned | User: tabadmin | DC01\n- 2024-08-12 14:38:05Z | EventID 4648 | Logon using explicit credentials | User: tabadmin | Target: WORKSTATION-05", "output": "# DFIR Investigation Report\n\n## Executive Summary\n\nOn August 12, 2024, an external attacker (192.168.1.100) conducted a brute-force attack against the domain controller DC01, targeting the administrative account 'tabadmin'. After multiple failed attempts, the attacker successfully authenticated at 14:35:42 UTC using network logon (Type 3). The compromised account was then used to gain elevated privileges and initiate a lateral movement attempt to WORKSTATION-05.\n\nThe attack sequence spanned approximately 6 minutes, from initial failed logon at 14:32:11 UTC to lateral movement at 14:38:05 UTC. Evidence indicates the attacker used valid credentials, suggesting either credential theft or successful password guessing.\n\nImpact: One domain administrator account compromised, with evidence of privilege escalation and lateral movement initiation. NO DATA PRESENT regarding data exfiltration or persistence mechanisms.\n\n## Timeline\n\n[2024-08-12 14:32:11Z] — Initial failed logon attempt\nSystem: DC01 (Domain Controller)\nUser/Account: tabadmin\nIOC: 192.168.1.100\nEvidence: EventID 4625, FailureReason=Unknown user name or bad password, SourceNetworkAddress=192.168.1.100\nMITRE: TA0006 / T1110.001 Brute Force: Password Guessing\n\n[2024-08-12 14:32:15Z] — Second failed logon attempt\nSystem: DC01 (Domain Controller)\nUser/Account: tabadmin\nIOC: 192.168.1.100\nEvidence: EventID 4625, FailureReason=Unknown user name or bad password, SourceNetworkAddress=192.168.1.100\nMITRE: TA0006 / T1110.001 Brute Force: Password Guessing\n\n[2024-08-12 14:35:42Z] — Successful logon after brute-force attempts\nSystem: DC01 (Domain Controller)\nUser/Account: tabadmin\nIOC: 192.168.1.100\nEvidence: EventID 4624, LogonType=3 (Network), SourceNetworkAddress=192.168.1.100\nMITRE: TA0001 / T1078.002 Valid Accounts: Domain Accounts\n\n[2024-08-12 14:37:19Z] — Privilege escalation (special privileges assigned)\nSystem: DC01 (Domain Controller)\nUser/Account: tabadmin\nIOC: NO DATA PRESENT\nEvidence: EventID 4672, PrivilegeList=SeDebugPrivilege, SeBackupPrivilege\nMITRE: TA0004 / T1078.002 Valid Accounts: Domain Accounts\n\n[2024-08-12 14:38:05Z] — Lateral movement attempt using explicit credentials\nSystem: DC01 (Domain Controller) → WORKSTATION-05\nUser/Account: tabadmin\nIOC: NO DATA PRESENT\nEvidence: EventID 4648, TargetServerName=WORKSTATION-05, TargetUserName=tabadmin\nMITRE: TA0008 / T1021 Remote Services\n\n## IOCs\n\n| Indicator | Type | Threat Level | Description | First Seen | Systems/Events |\n|-----------|------|--------------|-------------|------------|----------------|\n| 192.168.1.100 | IP Address | High | External attacker source IP | 2024-08-12 14:32:11Z | DC01 / EventID 4625, 4624 |\n| tabadmin | Username | Critical | Compromised domain admin account | 2024-08-12 14:32:11Z | DC01, WORKSTATION-05 / EventID 4625, 4624, 4672, 4648 |\n\n## MITRE Mapping\n\n**Initial Access / Credential Access** — T1110.001 Brute Force: Password Guessing | Evidence: 2024-08-12 14:32:11Z, 14:32:15Z (EventID 4625)\n\n**Initial Access** — T1078.002 Valid Accounts: Domain Accounts | Evidence: 2024-08-12 14:35:42Z (EventID 4624), 14:37:19Z (EventID 4672)\n\n**Lateral Movement** — T1021 Remote Services | Evidence: 2024-08-12 14:38:05Z (EventID 4648)\n\n## What Happened\n\nAn external attacker from IP 192.168.1.100 conducted a brute-force attack against the domain administrator account 'tabadmin' on DC01. After two failed attempts, the attacker successfully authenticated at 14:35:42 UTC using network logon. The attacker then escalated privileges (SeDebugPrivilege, SeBackupPrivilege) and initiated lateral movement to WORKSTATION-05 using explicit credentials.\n\n## Why It Happened\n\nControl gap: Domain administrator account 'tabadmin' was accessible via network logon (Type 3) without multi-factor authentication. Evidence shows the attacker succeeded after only 2 failed attempts, suggesting either weak password or credential theft (insufficient evidence to determine which).\n\n## How to Prevent\n\n**Implement/verify these controls:**\n\n1. **Account Lockout Policy** (NIST SP 800-63B § 5.2.2): Configure account lockout after 5 failed attempts within 15 minutes for all privileged accounts.\n\n2. **Multi-Factor Authentication** (NIST SP 800-63B § 4.2): Require MFA for all administrative accounts, especially for network logon types.\n\n3. **Privileged Access Management** (NIST SP 800-53 AC-6): Restrict domain admin accounts to administrative workstations only. Block network logon from untrusted IPs.\n\n4. **Enhanced Monitoring** (NIST SP 800-53 AU-2, AU-6): Alert on 3+ failed logons within 5 minutes for any privileged account. Alert on EventID 4672 (privilege assignment) for non-interactive logons.\n\n5. **Network Segmentation** (NIST SP 800-53 SC-7): Block external IPs (e.g., 192.168.1.100) from accessing domain controllers. Implement jump boxes for administrative access.\n\n***END OF REPORT***"}
```

**Important**: This is ONE line (no line breaks in the JSON object itself).

---

## ✅ Method 2: Create Synthetic Scenarios (Tabletop Exercises)

### Good for:
- Testing specific MITRE techniques
- Edge cases (e.g., "NO DATA PRESENT" scenarios)
- Rare attack patterns you haven't seen yet

### Example Scenario: Phishing with NO DATA PRESENT gaps

```json
{"instruction": "Generate a DFIR investigation report. Demonstrate proper use of 'NO DATA PRESENT' when evidence is missing.", "input": "CASE: 2025-01-15 - Suspected Phishing\n\nIOCs:\n- malicious.exe (File)\n\nSYSTEMS:\n- LAPTOP-USER42 (Windows 11)\n\nEVENTS:\n- 2025-01-15 09:14:33Z | EventID 4688 | Process created | Process: malicious.exe | User: jsmith | LAPTOP-USER42", "output": "# DFIR Investigation Report\n\n## Executive Summary\n\nOn January 15, 2025, a suspicious executable 'malicious.exe' was executed on LAPTOP-USER42 by user jsmith at 09:14:33 UTC. This is the only evidenced activity. NO DATA PRESENT regarding how the file arrived on the system, network connections made by the process, or persistence mechanisms.\n\nImpact: NO DATA PRESENT - insufficient evidence to determine actual impact. File execution observed, but no subsequent malicious activity logged.\n\n## Timeline\n\n[2025-01-15 09:14:33Z] — Suspicious executable launched\nSystem: LAPTOP-USER42\nUser/Account: jsmith\nIOC: malicious.exe\nEvidence: EventID 4688, ProcessName=malicious.exe, ParentProcess=NO DATA PRESENT\nMITRE: TA0002 / T1204.002 User Execution: Malicious File\n\n## IOCs\n\n| Indicator | Type | Threat Level | Description | First Seen | Systems/Events |\n|-----------|------|--------------|-------------|------------|----------------|\n| malicious.exe | File | Unknown | Suspicious executable (hash: NO DATA PRESENT) | 2025-01-15 09:14:33Z | LAPTOP-USER42 / EventID 4688 |\n\n## MITRE Mapping\n\n**Execution** — T1204.002 User Execution: Malicious File | Evidence: 2025-01-15 09:14:33Z (EventID 4688)\n\n## What Happened\n\nUser jsmith executed a file named 'malicious.exe' on LAPTOP-USER42. NO DATA PRESENT regarding file origin, delivery method, or post-execution behavior.\n\n## Why It Happened\n\nNO DATA PRESENT - insufficient evidence to determine root cause. Possible phishing email, but no email logs provided.\n\n## How to Prevent\n\nImplement/verify these controls:\n\n1. **Enhanced Logging** (NIST SP 800-53 AU-2, AU-12): Enable file creation events (EventID 11), network connection events (EventID 3), and email attachment logging.\n\n2. **Application Control** (NIST SP 800-53 CM-7): Implement AppLocker or Windows Defender Application Control to block execution of unsigned executables outside approved directories.\n\n***END OF REPORT***"}
```

---

## ❌ Common Mistakes to Avoid

### 1. Using AI-Generated Reports as Training Data

**BAD**:
```
❌ Generate report with GPT-4 → Use as training data
```

**Why it's bad**: You're teaching the model to hallucinate like GPT-4 hallucinated.

**GOOD**:
```
✅ Write report yourself → Manually verify every claim → Use as training data
```

---

### 2. Including Speculative Language

**BAD**:
```
"The attacker likely used a keylogger to steal credentials."
```

**GOOD**:
```
"NO DATA PRESENT regarding credential theft mechanism."
```

---

### 3. Inconsistent Formatting

Train the model on ONE format. Don't mix:
- Different timeline styles
- Different MITRE citation formats
- Different evidence citation styles

**Pick a format** (the one in your CaseScope prompt is perfect) **and stick to it**.

---

## 📊 Quality Checklist

Before adding an example to `examples.jsonl`, verify:

- [ ] Every timeline entry cites specific evidence (EventID, log snippet)
- [ ] Every MITRE mapping is supported by observed behavior
- [ ] "NO DATA PRESENT" is used for missing information
- [ ] No speculative language ("likely", "probably", "may have")
- [ ] No external tools/techniques not in the evidence
- [ ] Timestamps are in UTC with exact format
- [ ] Executive summary is plain English (no jargon)
- [ ] Recommendations reference NIST frameworks

---

## 🎯 Recommended Training Set Composition

**Total: 50-200 examples**

| Category | Count | Purpose |
|----------|-------|---------|
| Successful attacks (full timeline) | 30-60 | Teach complete analysis |
| Incomplete evidence (many "NO DATA PRESENT") | 10-20 | Teach restraint |
| Edge cases (rare techniques) | 5-10 | Improve coverage |
| Multi-system lateral movement | 10-20 | Teach correlation |
| Single-event analysis | 5-10 | Teach focus |

---

## 🚀 Quick Start Workflow

### Day 1: Create 10 examples
- Pull 3 past cases from your archives
- Write perfect reports for each
- Create 7 synthetic scenarios (phishing, brute force, lateral movement, etc.)

### Day 2: Create 15 more examples
- Focus on edge cases
- Include "NO DATA PRESENT" scenarios
- Add multi-system correlation examples

### Day 3: Create 25 more examples
- Diversify attack types
- Include various MITRE techniques
- Add different log sources (firewall, EVTX, NDJSON)

### Day 4: Validate dataset
- Run `scripts/validate_data.py` (checks JSON format)
- Review for consistency
- Remove duplicate patterns

### Day 5: Train!
```bash
python3 scripts/2_train_lora.py \
  --training_data training_data/examples.jsonl \
  --epochs 3
```

---

## 📝 Example Creation Template (Copy/Paste)

```json
{"instruction": "Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary. Use only the evidence provided.", "input": "CASE: [YYYY-MM-DD] - [Case Name]\n\nIOCs:\n- [IOC 1]\n- [IOC 2]\n\nSYSTEMS:\n- [System 1] ([OS])\n- [System 2] ([OS])\n\nEVENTS:\n- [YYYY-MM-DD HH:MM:SSZ] | [EventID] | [Description] | [Key fields]\n- [YYYY-MM-DD HH:MM:SSZ] | [EventID] | [Description] | [Key fields]", "output": "[YOUR PERFECT DFIR REPORT HERE]"}
```

---

## 💡 Pro Tips

1. **Start small**: 50 examples is enough for initial training. Add more later if needed.

2. **Test as you go**: After 50 examples, train and test. If quality is good, continue. If not, adjust your examples.

3. **Version control**: Save different versions of `examples.jsonl` (e.g., `examples_v1.jsonl`, `examples_v2.jsonl`) so you can compare training results.

4. **Diverse sources**: Don't just use domain controller logs. Include:
   - Firewall logs
   - EDR logs
   - PowerShell logs
   - Email gateway logs
   - VPN logs

5. **Real-world complexity**: Include cases with:
   - Missing timestamps
   - Conflicting evidence
   - Multiple attackers
   - False positives

---

## ✅ You're Ready When...

- [ ] You have 50+ examples in `examples.jsonl`
- [ ] Every example is manually verified by you
- [ ] No AI-generated content in training data
- [ ] Consistent formatting across all examples
- [ ] Diverse attack scenarios represented
- [ ] "NO DATA PRESENT" examples included

**Now run**: `python3 scripts/2_train_lora.py`

---

## Questions?

1. **"How long does training take?"**
   - 50 examples = ~30 minutes on Tesla P4
   - 200 examples = ~2 hours on Tesla P4

2. **"Can I add more examples later?"**
   - Yes! Train on 50, test, add 50 more, retrain. Iterative improvement.

3. **"What if my model overfits?"**
   - Reduce epochs (try 2 instead of 3)
   - Increase lora_dropout (try 0.1 instead of 0.05)
   - Add more diverse examples

4. **"Can I use public datasets?"**
   - Only if you manually verify and reformat them to match YOUR style.
   - SANS DFIR challenges, CTF write-ups, public incident reports are good sources.

