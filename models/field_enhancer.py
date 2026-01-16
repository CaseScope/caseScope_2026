"""Field Enhancer Models for CaseScope

Provides human-readable descriptions for cryptic field values.
Used to display friendly labels under technical values in hunting tables.

Examples:
- LogonType "2" → "Interactive (local keyboard)"
- SubStatus "0xC000006A" → "Wrong password"
- FailureReason "%%2313" → "Unknown user or bad password"

Loaded once on page load, cached client-side for O(1) lookups.
"""
from datetime import datetime
from models.database import db


class FieldEnhancer(db.Model):
    """Maps field values to human-readable descriptions
    
    Matching logic (applied in order):
    1. artifact_type matches event's artifact_type (or '*' for all)
    2. source_pattern matches source_file (or '*' for all, supports wildcards)
    3. field_path matches the column being displayed (e.g., 'EventData.LogonType')
    4. field_value matches the actual value (e.g., '2', '0xC000006A')
    
    When all match, description is shown under the value in custom columns.
    """
    __tablename__ = 'field_enhancers'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Matching criteria
    artifact_type = db.Column(db.String(50), nullable=False, default='*', index=True)
    source_pattern = db.Column(db.String(255), nullable=False, default='*')
    field_path = db.Column(db.String(255), nullable=False, index=True)
    field_value = db.Column(db.String(255), nullable=False, index=True)
    
    # Enhancement
    description = db.Column(db.Text, nullable=False)
    
    # Metadata
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint to prevent duplicates
    __table_args__ = (
        db.UniqueConstraint('artifact_type', 'source_pattern', 'field_path', 'field_value',
                           name='uq_field_enhancer_match'),
    )
    
    def __repr__(self):
        return f'<FieldEnhancer {self.field_path}={self.field_value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'artifact_type': self.artifact_type,
            'source_pattern': self.source_pattern,
            'field_path': self.field_path,
            'field_value': self.field_value,
            'description': self.description,
            'is_enabled': self.is_enabled
        }


def seed_field_enhancers():
    """Seed default field enhancers for Windows Security events"""
    
    defaults = []
    
    # Windows LogonType values (EventID 4624, 4625, 4634, 4647, 4648)
    logon_types = {
        '0': 'System (used by system account)',
        '2': 'Interactive (local keyboard/screen)',
        '3': 'Network (share, printer, remote)',
        '4': 'Batch (scheduled task)',
        '5': 'Service (service startup)',
        '7': 'Unlock (workstation unlock)',
        '8': 'NetworkCleartext (IIS basic auth)',
        '9': 'NewCredentials (RunAs /netonly)',
        '10': 'RemoteInteractive (RDP/Terminal Services)',
        '11': 'CachedInteractive (cached domain creds)',
        '12': 'CachedRemoteInteractive (cached RDP)',
        '13': 'CachedUnlock (cached unlock)',
    }
    
    for value, desc in logon_types.items():
        defaults.append(FieldEnhancer(
            artifact_type='evtx',
            source_pattern='*Security*',
            field_path='EventData.LogonType',
            field_value=value,
            description=desc
        ))
    
    # Windows SubStatus codes (EventID 4625 - failed logons)
    substatus_codes = {
        '0xC0000064': 'User does not exist',
        '0xC000006A': 'Wrong password',
        '0xC000006D': 'Bad username or password',
        '0xC000006E': 'Account restriction',
        '0xC000006F': 'Outside authorized hours',
        '0xC0000070': 'Unauthorized workstation',
        '0xC0000071': 'Password expired',
        '0xC0000072': 'Account disabled',
        '0xC00000DC': 'Server in wrong state',
        '0xC0000133': 'Clock out of sync with DC',
        '0xC000015B': 'User not granted logon type',
        '0xC000018C': 'Trust relationship failed',
        '0xC0000192': 'Netlogon service not started',
        '0xC0000193': 'Account expired',
        '0xC0000224': 'Must change password at next logon',
        '0xC0000225': 'Windows bug - not a risk',
        '0xC0000234': 'Account locked out',
        '0xC00002EE': 'Failure reason unknown',
        '0xC0000413': 'Auth firewall - machine not allowed',
    }
    
    for value, desc in substatus_codes.items():
        defaults.append(FieldEnhancer(
            artifact_type='evtx',
            source_pattern='*Security*',
            field_path='EventData.SubStatus',
            field_value=value,
            description=desc
        ))
    
    # Windows FailureReason codes (EventID 4625)
    # These use %% prefix format
    failure_reasons = {
        '%%2304': 'Informational/Success',
        '%%2305': 'Target account name incorrect',
        '%%2306': 'Service not running',
        '%%2307': 'Not granted this logon type',
        '%%2308': 'Password expired',
        '%%2309': 'Account disabled',
        '%%2310': 'Account expired',
        '%%2311': 'Account locked',
        '%%2312': 'Outside authorized hours',
        '%%2313': 'Unknown user or bad password',
        '%%2314': 'Account restriction',
    }
    
    for value, desc in failure_reasons.items():
        defaults.append(FieldEnhancer(
            artifact_type='evtx',
            source_pattern='*Security*',
            field_path='EventData.FailureReason',
            field_value=value,
            description=desc
        ))
    
    # Add to database (skip duplicates, handle race conditions)
    added = 0
    for enhancer in defaults:
        try:
            existing = FieldEnhancer.query.filter_by(
                artifact_type=enhancer.artifact_type,
                source_pattern=enhancer.source_pattern,
                field_path=enhancer.field_path,
                field_value=enhancer.field_value
            ).first()
            
            if not existing:
                db.session.add(enhancer)
                db.session.flush()  # Flush to catch unique constraint errors early
                added += 1
        except Exception:
            db.session.rollback()
            # Already exists or other error - skip
            continue
    
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    return added
