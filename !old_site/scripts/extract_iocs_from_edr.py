#!/opt/casescope/venv/bin/python3
"""
Extract IOCs from multiple EDR reports using Mistral
Robust version with better JSON handling and error recovery
"""
import json
import subprocess
import sys
import re

# Add app path for database access
sys.path.insert(0, '/opt/casescope/app')

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Initialize Flask app for database access
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

class Case(db.Model):
    __tablename__ = 'case'
    id = db.Column(db.Integer, primary_key=True)
    edr_report = db.Column(db.Text)

def call_ollama_mistral(prompt_text):
    """Call Ollama Mistral model"""
    try:
        result = subprocess.run(
            ['ollama', 'run', 'mistral'],
            input=prompt_text,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"ERROR: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "ERROR: Timeout expired (>10 minutes)"
    except Exception as e:
        return f"ERROR: {e}"

def fix_json_escapes(json_text):
    """
    Fix common JSON escape issues in file paths
    Windows paths need double backslashes in JSON
    """
    # Fix single backslashes in paths like C:\Windows\system32
    # This is a heuristic: look for patterns like drive:\path or \\path
    
    # First, protect already-escaped backslashes
    json_text = json_text.replace('\\\\', '\x00DOUBLEBACKSLASH\x00')
    
    # Fix common Windows path patterns
    # C:\path -> C:\\path
    json_text = re.sub(r'([A-Za-z]):\\([^\\"]+)', lambda m: m.group(1) + ':\\\\' + m.group(2).replace('\\', '\\\\'), json_text)
    
    # Fix UNC paths \\server\share
    json_text = re.sub(r'\\\\([^\\"]+)\\([^\\"]+)', r'\\\\\\1\\\\\\2', json_text)
    
    # Restore protected double backslashes
    json_text = json_text.replace('\x00DOUBLEBACKSLASH\x00', '\\\\')
    
    return json_text

def extract_json_from_response(response):
    """Extract JSON from Mistral response (may have markdown code blocks)"""
    json_text = response.strip()
    
    # Remove markdown code blocks if present
    if '```json' in json_text:
        # Extract content between ```json and ```
        start = json_text.find('```json') + 7
        end = json_text.find('```', start)
        if end == -1:
            end = len(json_text)
        json_text = json_text[start:end].strip()
    elif json_text.startswith('```'):
        # Generic code block
        lines = json_text.split('\n')
        if len(lines) > 2:
            json_text = '\n'.join(lines[1:-1])
        else:
            json_text = '\n'.join(lines[1:])
    
    # Try to fix common escape issues
    json_text = fix_json_escapes(json_text)
    
    return json_text

def merge_ioc_results(results_list):
    """Merge multiple IOC extraction results into one deduplicated list"""
    merged = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "file_paths": [],
        "file_hashes": {
            "md5": [],
            "sha1": [],
            "sha256": []
        },
        "usernames": [],
        "hostnames": [],
        "network_shares": [],
        "credentials": {
            "usernames": [],
            "passwords": []
        },
        "processes": {
            "executables": [],
            "commands": []
        },
        "ports": [],
        "protocols": [],
        "timestamps_utc": [],
        "ssh_keys": [],
        "registry_keys": [],
        "email_addresses": []
    }
    
    for result in results_list:
        # Merge simple lists
        for key in ['ip_addresses', 'domains', 'urls', 'file_paths', 'usernames', 
                    'hostnames', 'network_shares', 'ports', 'protocols', 
                    'timestamps_utc', 'ssh_keys', 'registry_keys', 'email_addresses']:
            if key in result:
                merged[key].extend(result[key])
        
        # Merge file_hashes
        if 'file_hashes' in result:
            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type in result['file_hashes']:
                    merged['file_hashes'][hash_type].extend(result['file_hashes'][hash_type])
        
        # Merge credentials
        if 'credentials' in result:
            for cred_type in ['usernames', 'passwords']:
                if cred_type in result['credentials']:
                    merged['credentials'][cred_type].extend(result['credentials'][cred_type])
        
        # Merge processes
        if 'processes' in result:
            for proc_type in ['executables', 'commands']:
                if proc_type in result['processes']:
                    merged['processes'][proc_type].extend(result['processes'][proc_type])
    
    # Deduplicate all lists (preserve order)
    def dedupe_list(lst):
        seen = set()
        result = []
        for item in lst:
            if item not in seen and item and item != "None found":
                seen.add(item)
                result.append(item)
        return result
    
    for key in ['ip_addresses', 'domains', 'urls', 'file_paths', 'usernames', 
                'hostnames', 'network_shares', 'ports', 'protocols', 
                'timestamps_utc', 'ssh_keys', 'registry_keys', 'email_addresses']:
        merged[key] = dedupe_list(merged[key])
    
    for hash_type in ['md5', 'sha1', 'sha256']:
        merged['file_hashes'][hash_type] = dedupe_list(merged['file_hashes'][hash_type])
    
    for cred_type in ['usernames', 'passwords']:
        merged['credentials'][cred_type] = dedupe_list(merged['credentials'][cred_type])
    
    for proc_type in ['executables', 'commands']:
        merged['processes'][proc_type] = dedupe_list(merged['processes'][proc_type])
    
    return merged

# Read the prompt template
with open('/opt/casescope/ai_prompts/mistral/mistral_get_iocs.md', 'r') as f:
    prompt_template = f.read()

# Get EDR report from case 27
with app.app_context():
    case = db.session.query(Case).filter_by(id=27).first()
    if not case or not case.edr_report:
        print("ERROR: No EDR report found in case 27")
        sys.exit(1)
    
    edr_report = case.edr_report

# Split by delimiter
reports = edr_report.split('*** NEW REPORT ***')
reports = [r.strip() for r in reports if r.strip()]

print(f"Processing {len(reports)} EDR report(s) from Case 27...")
print("=" * 80)
print()

all_results = []
failed_reports = []

for i, report in enumerate(reports, 1):
    print(f"=== REPORT {i}/{len(reports)} ===")
    print(f"Report length: {len(report)} characters")
    
    # Inject report into prompt template
    full_prompt = prompt_template.replace('[PASTE REPORT HERE]', report)
    
    # Call Mistral
    response = call_ollama_mistral(full_prompt)
    
    # Try to extract JSON from response
    max_retries = 2
    for attempt in range(max_retries):
        try:
            json_text = extract_json_from_response(response)
            result_json = json.loads(json_text)
            all_results.append(result_json)
            
            # Print summary for this report
            print(f"✓ Extracted IOCs (attempt {attempt + 1}):")
            print(f"  - IP Addresses: {len(result_json.get('ip_addresses', []))}")
            print(f"  - Usernames: {len(result_json.get('usernames', []))}")
            print(f"  - Hostnames: {len(result_json.get('hostnames', []))}")
            print(f"  - File Paths: {len(result_json.get('file_paths', []))}")
            print(f"  - File Hashes: {len(result_json.get('file_hashes', {}).get('sha256', []))}")
            print(f"  - Commands: {len(result_json.get('processes', {}).get('commands', []))}")
            break
            
        except json.JSONDecodeError as e:
            if attempt < max_retries - 1:
                print(f"⚠ JSON parse failed (attempt {attempt + 1}), retrying with additional fixes...")
                # Try more aggressive fixes
                json_text = json_text.replace('\\', '\\\\')
                json_text = json_text.replace('\\\\\\\\', '\\\\')
            else:
                print(f"✗ Failed to parse JSON after {max_retries} attempts: {e}")
                print(f"Response preview: {response[:300]}...")
                failed_reports.append(i)
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            failed_reports.append(i)
            break
    
    print()

# Merge all results
if all_results:
    print()
    print("=" * 80)
    print("FINAL AGGREGATED IOCs FROM ALL REPORTS")
    print("=" * 80)
    print()
    
    final_result = merge_ioc_results(all_results)
    
    # Print summary statistics
    print("IOC Summary:")
    print(f"  - IP Addresses: {len(final_result['ip_addresses'])}")
    print(f"  - Domains: {len(final_result['domains'])}")
    print(f"  - URLs: {len(final_result['urls'])}")
    print(f"  - File Paths: {len(final_result['file_paths'])}")
    print(f"  - MD5 Hashes: {len(final_result['file_hashes']['md5'])}")
    print(f"  - SHA1 Hashes: {len(final_result['file_hashes']['sha1'])}")
    print(f"  - SHA256 Hashes: {len(final_result['file_hashes']['sha256'])}")
    print(f"  - Usernames: {len(final_result['usernames'])}")
    print(f"  - Hostnames: {len(final_result['hostnames'])}")
    print(f"  - Network Shares: {len(final_result['network_shares'])}")
    print(f"  - Credentials (usernames): {len(final_result['credentials']['usernames'])}")
    print(f"  - Credentials (passwords): {len(final_result['credentials']['passwords'])}")
    print(f"  - Process Executables: {len(final_result['processes']['executables'])}")
    print(f"  - Process Commands: {len(final_result['processes']['commands'])}")
    print(f"  - Ports: {len(final_result['ports'])}")
    print(f"  - Timestamps: {len(final_result['timestamps_utc'])}")
    print()
    
    if failed_reports:
        print(f"⚠ Note: {len(failed_reports)} report(s) failed to parse: {failed_reports}")
        print()
    
    print("Full IOC List (JSON):")
    print(json.dumps(final_result, indent=2))
    print()
    print("=" * 80)
    print(f"SUCCESS: {len(all_results)}/{len(reports)} reports processed successfully")
    print("=" * 80)
else:
    print()
    print("ERROR: No IOCs extracted from any report")
    sys.exit(1)

