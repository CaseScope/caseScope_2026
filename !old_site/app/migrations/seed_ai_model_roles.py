#!/usr/bin/env python3
"""
Seed AI Model Role Mappings

Creates initial mappings for 8GB and 16GB VRAM tiers.
Run this once to populate the ai_model_role table.

Usage:
    cd /opt/casescope/app
    python3 migrations/seed_ai_model_roles.py
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db
from models import AIModelRole

def seed_model_roles():
    """Seed the ai_model_role table with initial mappings"""
    
    with app.app_context():
        print("=" * 70)
        print("SEEDING AI MODEL ROLE MAPPINGS")
        print("=" * 70)
        print()
        
        # Check if already seeded
        existing = AIModelRole.query.first()
        if existing:
            print("⚠️  WARNING: Table already contains data!")
            response = input("Do you want to clear and re-seed? (yes/no): ")
            if response.lower() != 'yes':
                print("❌ Aborted")
                return
            
            # Clear existing
            AIModelRole.query.delete()
            db.session.commit()
            print("✅ Cleared existing mappings")
            print()
        
        # Define mappings
        # Format: (role, vram_tier, model_name, priority)
        mappings = [
            # ============================================================
            # 8GB VRAM TIER (Q4_K_M quantization)
            # ============================================================
            
            # IOC Extraction - Qwen 7B (best for structured output)
            ('ioc_extraction', '8gb', 'qwen2.5:7b-instruct-q4_k_m', 100),
            
            # Timeline Generation - Qwen 7B (best for long lists)
            ('timeline', '8gb', 'qwen2.5:7b-instruct-q4_k_m', 100),
            
            # Report Generation - Llama 3.1 8B (best for general reasoning)
            ('report', '8gb', 'llama3.1:8b-instruct-q4_k_m', 100),
            
            # AI Search - Llama 3.1 8B (RAG system)
            ('search', '8gb', 'llama3.1:8b-instruct-q4_k_m', 100),
            
            # Event Review - Mistral 7B (fast, efficient)
            ('review', '8gb', 'mistral:7b-instruct-v0.3-q4_K_M', 100),
            
            # ============================================================
            # 16GB VRAM TIER (Larger models / Higher precision)
            # ============================================================
            
            # IOC Extraction - Qwen 14B (2x parameters)
            ('ioc_extraction', '16gb', 'qwen2.5:14b-instruct-q4_k_m', 100),
            
            # Timeline Generation - Qwen 14B (2x parameters)
            ('timeline', '16gb', 'qwen2.5:14b-instruct-q4_k_m', 100),
            
            # Report Generation - Llama 3.1 8B Q8 (higher precision)
            ('report', '16gb', 'llama3.1:8b-instruct-q8_0', 100),
            
            # AI Search - Llama 3.1 8B Q8 (higher precision for RAG)
            ('search', '16gb', 'llama3.1:8b-instruct-q8_0', 100),
            
            # Event Review - Llama 3.1 8B Q8 (higher quality)
            ('review', '16gb', 'llama3.1:8b-instruct-q8_0', 100),
        ]
        
        # Insert mappings
        print("Creating model role mappings...")
        print()
        
        for role, tier, model, priority in mappings:
            mapping = AIModelRole(
                role=role,
                vram_tier=tier,
                model_name=model,
                active=True,
                priority=priority
            )
            db.session.add(mapping)
            print(f"  {tier:5s} | {role:20s} → {model}")
        
        db.session.commit()
        
        print()
        print("=" * 70)
        print("✅ SUCCESS - Seeded {} model role mappings".format(len(mappings)))
        print("=" * 70)
        print()
        print("📊 Summary:")
        print(f"  • 8GB Tier:  5 roles defined")
        print(f"  • 16GB Tier: 5 roles defined")
        print()
        print("The system will now auto-select models based on VRAM setting!")
        print()

if __name__ == '__main__':
    seed_model_roles()

