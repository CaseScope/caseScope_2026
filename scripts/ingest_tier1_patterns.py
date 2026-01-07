#!/usr/bin/env python3
"""
Ingest Tier 1 Enhanced Patterns: MITRE CAR, Threat Hunter Playbook, Atomic Red Team
Adds ~1,100 new patterns to the RAG system
"""

import sys
import os
import yaml
import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
from app.ai.vector_store import PatternStore

# Data directory
DATA_DIR = Path('/opt/casescope/data')
CAR_DIR = DATA_DIR / 'car'
PLAYBOOK_DIR = DATA_DIR / 'ThreatHunter-Playbook'
ATOMIC_DIR = DATA_DIR / 'atomic-red-team'


def clone_or_update_repo(repo_url: str, target_dir: Path, repo_name: str):
    """Clone or pull a git repository"""
    if target_dir.exists():
        print(f"  Updating {repo_name}...")
        result = subprocess.run(
            ['git', '-C', str(target_dir), 'pull'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"  ✓ Updated {repo_name}")
        else:
            print(f"  ⚠ Failed to update {repo_name}: {result.stderr}")
    else:
        print(f"  Cloning {repo_name}...")
        result = subprocess.run(
            ['git', 'clone', repo_url, str(target_dir)],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"  ✓ Cloned {repo_name}")
        else:
            print(f"  ✗ Failed to clone {repo_name}: {result.stderr}")
            return False
    return True


def ingest_mitre_car() -> List[Dict]:
    """
    Ingest MITRE CAR analytics
    
    CAR provides analytics with actual detection logic and thresholds
    """
    print("\n=== Ingesting MITRE CAR Analytics ===")
    
    # Clone/update repo
    if not clone_or_update_repo(
        'https://github.com/mitre-attack/car.git',
        CAR_DIR,
        'MITRE CAR'
    ):
        print("  ⚠ Skipping MITRE CAR ingestion")
        return []
    
    records = []
    analytics_dir = CAR_DIR / 'analytics'
    
    if not analytics_dir.exists():
        print(f"  ⚠ Analytics directory not found: {analytics_dir}")
        return []
    
    for yaml_file in analytics_dir.glob('CAR-*.yaml'):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                continue
            
            car_id = data.get('id', yaml_file.stem)
            title = data.get('title', 'Untitled')
            submission_date = data.get('submission_date', '')
            
            # Build content
            content_parts = [
                f"MITRE CAR Analytic: {car_id} - {title}",
                f"Submission Date: {submission_date}"
            ]
            
            # Add hypothesis
            if 'hypothesis' in data:
                content_parts.append(f"Hypothesis: {data['hypothesis']}")
            
            # Add data sources
            if 'data_model_references' in data:
                sources = ', '.join(data['data_model_references'])
                content_parts.append(f"Data Sources: {sources}")
            
            # Add analytics/detection logic
            if 'analytics' in data:
                analytics_text = yaml.dump(data['analytics'], default_flow_style=False)
                content_parts.append(f"Analytics:\n{analytics_text}")
            
            # Add implementations
            if 'implementations' in data:
                impl_count = len(data['implementations'])
                content_parts.append(f"Implementations: {impl_count} available")
                # Add first implementation as example
                if impl_count > 0:
                    impl = data['implementations'][0]
                    if 'code' in impl:
                        content_parts.append(f"Example Implementation:\n{impl['code'][:500]}")
            
            content = '\n'.join(content_parts)
            
            # Build metadata
            metadata = {
                'title': title,
                'car_id': car_id,
                'type': 'analytic',
                'submission_date': submission_date,
                'attack_techniques': data.get('coverage', [])
            }
            
            # Add implementation details
            if 'implementations' in data and len(data['implementations']) > 0:
                metadata['implementation'] = data['implementations'][0].get('code', '')
            
            pattern_id = f"car_{car_id.lower().replace('-', '_')}"
            
            records.append({
                'pattern_id': pattern_id,
                'content': content,
                'metadata': metadata,
                'source': 'mitre_car'
            })
            
        except Exception as e:
            print(f"  ⚠ Failed to parse {yaml_file.name}: {e}")
            continue
    
    print(f"  ✓ Parsed {len(records)} CAR analytics")
    return records


def ingest_threat_hunter_playbook() -> List[Dict]:
    """
    Ingest Threat Hunter Playbook hunts
    
    Provides structured hunting scenarios with step-by-step procedures
    """
    print("\n=== Ingesting Threat Hunter Playbook ===")
    
    # Clone/update repo
    if not clone_or_update_repo(
        'https://github.com/OTRF/ThreatHunter-Playbook.git',
        PLAYBOOK_DIR,
        'Threat Hunter Playbook'
    ):
        print("  ⚠ Skipping Threat Hunter Playbook ingestion")
        return []
    
    records = []
    
    # Hunt markdown files are in docs/hunts or similar
    hunt_paths = [
        PLAYBOOK_DIR / 'docs' / 'hunts',
        PLAYBOOK_DIR / 'docs' / 'notebooks',
        PLAYBOOK_DIR / 'playbooks'
    ]
    
    for hunt_dir in hunt_paths:
        if not hunt_dir.exists():
            continue
        
        for md_file in hunt_dir.rglob('*.md'):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if not content.strip():
                    continue
                
                # Extract title (first heading)
                title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                title = title_match.group(1) if title_match else md_file.stem
                
                # Extract MITRE techniques
                techniques = re.findall(r'T\d{4}(?:\.\d{3})?', content)
                
                # Extract hypothesis section
                hypothesis = ''
                hypothesis_match = re.search(
                    r'#+\s+Hypothesis\s*\n+(.*?)(?=\n#+|\Z)',
                    content,
                    re.DOTALL | re.IGNORECASE
                )
                if hypothesis_match:
                    hypothesis = hypothesis_match.group(1).strip()[:500]
                
                # Build metadata
                metadata = {
                    'title': title,
                    'type': 'hunting_playbook',
                    'techniques': list(set(techniques)),
                    'file': md_file.name
                }
                
                if hypothesis:
                    metadata['hypothesis'] = hypothesis
                
                # Truncate content if too long (keep first 2000 chars)
                if len(content) > 2000:
                    content_preview = content[:2000] + "\n... [truncated]"
                else:
                    content_preview = content
                
                pattern_id = f"playbook_{md_file.stem.lower().replace(' ', '_').replace('-', '_')}"
                
                records.append({
                    'pattern_id': pattern_id,
                    'content': f"Threat Hunting Playbook: {title}\n\n{content_preview}",
                    'metadata': metadata,
                    'source': 'threat_hunter_playbook'
                })
                
            except Exception as e:
                print(f"  ⚠ Failed to parse {md_file.name}: {e}")
                continue
    
    print(f"  ✓ Parsed {len(records)} Threat Hunter Playbook entries")
    return records


def ingest_atomic_red_team() -> List[Dict]:
    """
    Ingest Atomic Red Team tests
    
    Provides adversary emulation tests mapped to MITRE ATT&CK
    """
    print("\n=== Ingesting Atomic Red Team ===")
    
    # Clone/update repo
    if not clone_or_update_repo(
        'https://github.com/redcanaryco/atomic-red-team.git',
        ATOMIC_DIR,
        'Atomic Red Team'
    ):
        print("  ⚠ Skipping Atomic Red Team ingestion")
        return []
    
    records = []
    atomics_dir = ATOMIC_DIR / 'atomics'
    
    if not atomics_dir.exists():
        print(f"  ⚠ Atomics directory not found: {atomics_dir}")
        return []
    
    for technique_dir in atomics_dir.iterdir():
        if not technique_dir.is_dir():
            continue
        
        # Look for technique YAML file (e.g., T1110.001.yaml)
        technique_files = list(technique_dir.glob('T*.yaml')) + list(technique_dir.glob('T*.yml'))
        
        if not technique_files:
            continue
        
        yaml_file = technique_files[0]
        
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                continue
            
            technique_id = data.get('attack_technique', technique_dir.name)
            technique_name = data.get('display_name', '')
            
            # Process each atomic test
            for idx, test in enumerate(data.get('atomic_tests', [])):
                test_name = test.get('name', f'Test {idx + 1}')
                description = test.get('description', '')
                
                # Build content
                content_parts = [
                    f"Atomic Red Team: {technique_id} - {technique_name}",
                    f"Test: {test_name}",
                    f"Description: {description}"
                ]
                
                # Add supported platforms
                if 'supported_platforms' in test:
                    platforms = ', '.join(test['supported_platforms'])
                    content_parts.append(f"Platforms: {platforms}")
                
                # Add executor details
                if 'executor' in test:
                    executor = test['executor']
                    executor_name = executor.get('name', 'unknown')
                    content_parts.append(f"Executor: {executor_name}")
                    
                    # Add command/code
                    if 'command' in executor:
                        command = executor['command']
                        # Truncate if very long
                        if len(command) > 500:
                            command = command[:500] + "\n... [truncated]"
                        content_parts.append(f"Command:\n{command}")
                
                # Add input arguments
                if 'input_arguments' in test:
                    args = list(test['input_arguments'].keys())
                    content_parts.append(f"Input Arguments: {', '.join(args)}")
                
                # Add detection notes
                if 'detection' in data:
                    detection = data['detection']
                    if len(detection) > 500:
                        detection = detection[:500] + "..."
                    content_parts.append(f"Detection Guidance: {detection}")
                
                content = '\n'.join(content_parts)
                
                # Build metadata
                metadata = {
                    'title': test_name,
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'type': 'atomic_test',
                    'platforms': test.get('supported_platforms', [])
                }
                
                # Store executor command for reference
                if 'executor' in test and 'command' in test['executor']:
                    metadata['command'] = test['executor']['command']
                
                pattern_id = f"atomic_{technique_id.lower().replace('.', '_')}_{idx}"
                
                records.append({
                    'pattern_id': pattern_id,
                    'content': content,
                    'metadata': metadata,
                    'source': 'atomic_red_team'
                })
                
        except Exception as e:
            print(f"  ⚠ Failed to parse {yaml_file.name}: {e}")
            continue
    
    print(f"  ✓ Parsed {len(records)} Atomic Red Team tests")
    return records


def main():
    """Main ingestion workflow"""
    print("="*80)
    print("TIER 1 PATTERN INGESTION")
    print("Adding MITRE CAR, Threat Hunter Playbook, and Atomic Red Team")
    print("="*80)
    
    # Ensure data directory exists
    DATA_DIR.mkdir(exist_ok=True)
    
    # Initialize vector store
    print("\nInitializing vector store...")
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    
    # Get current stats
    stats = store.get_stats()
    print(f"Current patterns: {stats['total_patterns']}")
    if stats.get('by_source'):
        for source, count in stats['by_source'].items():
            print(f"  - {source}: {count}")
    
    # Ingest each source
    all_records = []
    
    # 1. MITRE CAR
    car_records = ingest_mitre_car()
    all_records.extend(car_records)
    
    # 2. Threat Hunter Playbook
    playbook_records = ingest_threat_hunter_playbook()
    all_records.extend(playbook_records)
    
    # 3. Atomic Red Team
    atomic_records = ingest_atomic_red_team()
    all_records.extend(atomic_records)
    
    # Insert all records
    if all_records:
        print(f"\n=== Inserting {len(all_records)} new patterns ===")
        
        # Group by source for batch insertion
        by_source = {}
        for record in all_records:
            source = record['source']
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(record)
        
        # Insert each source
        for source, records in by_source.items():
            print(f"\nInserting {len(records)} {source} patterns...")
            store._batch_insert(records, source)
            print(f"✓ Inserted {len(records)} {source} patterns")
    
    # Final stats
    print("\n" + "="*80)
    print("INGESTION COMPLETE")
    print("="*80)
    stats = store.get_stats()
    print(f"Total patterns: {stats['total_patterns']}")
    if stats.get('by_source'):
        for source, count in sorted(stats['by_source'].items()):
            print(f"  - {source}: {count}")
    
    print("\n✓ Tier 1 patterns successfully ingested!")
    print("\nNew sources added:")
    print("  - mitre_car: Analytics with detection logic and thresholds")
    print("  - threat_hunter_playbook: Structured hunting scenarios")
    print("  - atomic_red_team: Adversary emulation tests")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Ingestion interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Error during ingestion: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

