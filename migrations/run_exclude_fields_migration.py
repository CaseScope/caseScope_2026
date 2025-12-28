#!/usr/bin/env python3
"""
Migration: Add exclude_fields to noise_filter_rules
Allows specifying fields to exclude from pattern matching (critical for EDR/RMM agent URLs)
"""

import sys
import os

# Add project root to path
sys.path.insert(0, '/opt/casescope')
os.chdir('/opt/casescope')

# Must set these before importing Flask app
os.environ['FLASK_ENV'] = 'production'

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://casescope:K3lly!2017@localhost/casescope'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Import models after db init
from models import NoiseFilterRule

def main():
    """Run migration"""
    with app.app_context():
        print("Adding exclude_fields column to noise_filter_rules...")
        
        # Add column
        try:
            db.session.execute(text("""
                ALTER TABLE noise_filter_rules 
                ADD COLUMN exclude_fields VARCHAR(500) DEFAULT NULL
            """))
            db.session.commit()
            print("✓ Column added successfully")
        except Exception as e:
            if 'Duplicate column name' in str(e):
                print("✓ Column already exists")
                db.session.rollback()
            else:
                print(f"✗ Error adding column: {e}")
                return
        
        # Update existing RMM/EDR rules
        print("\nUpdating RMM/EDR rules...")
        
        exclude_list = 'agent.url,agent.id,url,subdomain,agent.type,agent.version'
        
        patterns = [
            '%Huntress%', '%ConnectWise%', '%Datto%', '%Kaseya%', '%N-able%',
            '%SolarWinds%', '%Atera%', '%NinjaOne%', '%ManageEngine%',
            '%CrowdStrike%', '%SentinelOne%', '%Carbon Black%', '%Defender%',
            '%Cortex%', '%Sophos%', '%Trend Micro%', '%McAfee%', '%Symantec%',
            '%ESET%', '%Bitdefender%', '%Malwarebytes%', '%Webroot%'
        ]
        
        count = 0
        for pattern in patterns:
            rules = NoiseFilterRule.query.filter(NoiseFilterRule.name.like(pattern)).all()
            for rule in rules:
                rule.exclude_fields = exclude_list
                count += 1
                print(f"  ✓ Updated: {rule.name}")
        
        db.session.commit()
        
        print(f"\n✓ Migration completed successfully!")
        print(f"✓ Updated {count} RMM/EDR rules with exclude_fields")
        print(f"✓ Excluded fields: {exclude_list}")

if __name__ == '__main__':
    main()

