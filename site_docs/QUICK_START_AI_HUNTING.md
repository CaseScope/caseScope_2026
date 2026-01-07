# Quick Start: AI-Assisted Threat Hunting

**For Analysts** - 5-Minute Guide

---

## How to Access

1. Go to **Dashboard** (home page)
2. Look for **"🤖 Open AI Assistant"** button
3. Click it - modal opens
4. You'll see **🎯 Threat Hunt** tab (it's the default)

---

## Using the Interface

### Quick Hunt (Recommended for First Time)

**Step 1**: Click a suggested question button:
- Click **🔓 Brute Force Attempts**

**Step 2**: Click **🚀 Start Hunt**

**Step 3**: Wait ~20 seconds

**Step 4**: Review results:
- **Hunt Summary**: What was found
- **Patterns Used**: Which intelligence sources matched
- **Findings**: Detection queries executed
- **Evidence Events**: Actual suspicious events

**That's it!** You just used 10,006 threat intelligence patterns to hunt.

---

## Suggested Hunt Questions (One-Click)

| Button | What It Hunts For |
|--------|-------------------|
| 🔓 **Brute Force** | Failed login attempts, password spraying |
| 🔑 **Pass the Hash** | PtH attacks, LogonType 9, NTLM auth |
| ➡️ **Lateral Movement** | RDP, SMB, WMI, PSExec between systems |
| 💾 **Credential Dump** | Mimikatz, LSASS access, SAM dumps |
| 🎫 **Kerberoasting** | TGS requests with RC4, abnormal SPN access |
| 🎯 **Cobalt Strike** | C2 beacons, named pipes, process injection |
| 🔓 **Mimikatz** | Credential theft tool signatures |
| 📜 **PowerShell** | Obfuscated scripts, encoded commands |
| ⬆️ **Priv Escalation** | Token manipulation, UAC bypass |
| 🔒 **Ransomware** | Shadow deletion, mass encryption |

**Just click any button, then click 🚀 Start Hunt!**

---

## Custom Questions

You can also type your own:

### Good Question Examples

✅ "Do you see DCSync attacks?"  
✅ "Find web shells deployed"  
✅ "Look for Golden Ticket usage"  
✅ "Detect BloodHound reconnaissance"  
✅ "Show me suspicious PowerShell"  
✅ "Find AWS credential access"  

### Tips for Better Results

1. **Be specific** - "Find Kerberoasting" > "Find bad stuff"
2. **Use technique names** - "DCSync", "PtH", "Kerberoasting"
3. **Mention tools** - "Mimikatz", "Cobalt Strike", "BloodHound"
4. **Ask follow-ups** - "After credential dumping, find lateral movement"

---

## Understanding Results

### Confidence Levels

- 🔴 **HIGH**: 10+ events found, strong pattern matches → Investigate immediately
- 🟠 **MEDIUM**: 3-9 events found, moderate matches → Review carefully
- 🔵 **LOW**: 1-2 events found, weak matches → May be noise
- ⚪ **NONE**: No events found → Threat not present

### Pattern Sources

When you see patterns like:
- **[ELASTIC]** - Production KQL query from Elastic Security
- **[SPLUNK]** - Production SPL query from Splunk
- **[ATOMIC]** - Real attack example from Red Canary
- **[SIGMA]** - Generic detection rule
- **[MITRE]** - Attack technique description
- **[MITRE CAR]** - Detection analytic with thresholds
- **[DFIR REPORT]** - Real-world incident case study
- **[SPECIALIZED]** - Tool-specific signature

**Higher similarity % = better match to your question**

### Evidence Events

Click "▶ Event Details" to expand full JSON for any event.

Each event shows:
- Event ID (e.g., 4625 = failed logon)
- Computer name
- Username
- Timestamp

---

## Common Hunting Workflows

### Workflow 1: Initial Case Triage (5 minutes)

1. Open AI Assistant → Threat Hunt
2. Run these hunts in order:
   - Click "🔓 Brute Force" → Hunt
   - Click "🔑 Pass the Hash" → Hunt
   - Click "➡️ Lateral Movement" → Hunt
   - Click "💾 Credential Dump" → Hunt
3. Review all results
4. Focus on HIGH confidence findings first

**Result**: Quick threat overview of case

### Workflow 2: Tool-Specific Hunting (2 minutes)

1. Open AI Assistant → Threat Hunt
2. Click tool button:
   - "🎯 Cobalt Strike" OR
   - "🔓 Mimikatz"
3. Review tool signatures found
4. If found → run "➡️ Lateral Movement" to see what came next

**Result**: Confirms tool usage and progression

### Workflow 3: Attack Chain Discovery (10 minutes)

1. Start with broad: "Find lateral movement"
2. Review results → see RDP usage
3. Ask specific: "Show me RDP connections from unusual sources"
4. Review → see credential dumping before RDP
5. Ask: "What happened before credential dumping?"
6. **Result**: Complete attack timeline

---

## Quick Reference

### Where to Find It
**Dashboard → "🤖 Open AI Assistant"**

### What It Does
- Asks 10,006 patterns: "What matches this question?"
- Generates detection queries
- Hunts through your case
- Analyzes findings with AI

### Response Time
- ~20 seconds per hunt

### What You Get
- Confidence score
- AI analysis
- MITRE techniques
- Evidence events
- Detection queries used

---

## Troubleshooting

**"No case selected" error**  
→ Select a case from dropdown first

**No events found but should have matches**  
→ Try different phrasing or use Natural Language Query tab

**Slow response (>30 seconds)**  
→ Normal on CPU, faster with GPU

**Poor quality results**  
→ Try more specific questions with technique/tool names

---

## Example Questions by Category

### Credential Access
- "Do you see credential dumping?"
- "Find Kerberoasting attempts"
- "Detect AS-REP roasting"
- "Look for DCSync attacks"
- "Show me password spraying"

### Lateral Movement
- "Find RDP lateral movement"
- "Detect PSExec usage"
- "Look for WMI lateral movement"
- "Show me pass-the-hash activity"

### Persistence
- "Find scheduled task persistence"
- "Detect registry run key modifications"
- "Look for service creation"
- "Show me web shell deployment"

### Defense Evasion
- "Find PowerShell obfuscation"
- "Detect process injection"
- "Look for LOLBin abuse"
- "Show me masquerading"

### Command & Control
- "Detect Cobalt Strike beacons"
- "Find DNS tunneling"
- "Look for C2 communication"
- "Show me suspicious network connections"

---

## What Makes This Powerful

✅ **No DSL Required** - Just ask questions  
✅ **10,006 Patterns** - World-class threat intelligence  
✅ **Multi-Query Hunt** - Searches from multiple angles  
✅ **Platform-Specific** - Windows, Linux, macOS, Cloud  
✅ **Production Queries** - Splunk SPL + Elastic KQL  
✅ **Real-World Validated** - DFIR Report case studies  
✅ **Tool Signatures** - Cobalt Strike, Mimikatz, etc.  
✅ **Confidence Scoring** - Know what to investigate first  

---

## Need Help?

### Documentation
- `AI_THREAT_HUNTING_INTERFACE.md` - Full interface guide
- `ALL_TIERS_COMPLETE.md` - Pattern sources
- `RAG_SYSTEM.MD` - How RAG works
- `AI_SYSTEM.MD` - AI capabilities

### Support
- Check logs: `/opt/casescope/logs/error.log`
- AI status: Settings → AI Configuration
- Pattern stats: See AI Status page

---

**Ready to hunt? Open the AI Assistant and ask your first question!** 🎯

