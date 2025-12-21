"""
IOC Hunt Database Models
Global IOC hunting across all case events (separate from per-file IOC matching)
"""

from datetime import datetime
from models import db


class IOCHuntJob(db.Model):
    """
    Global IOC hunt jobs - separate from per-file IOC matching.
    
    Tracks progress of on-demand IOC hunts across all case events.
    Unlike IOCMatch (per-file during indexing), this is for manual global hunts.
    """
    __tablename__ = "ioc_hunt_job"
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    task_id = db.Column(db.String(255), nullable=True, index=True)
    status = db.Column(db.String(50), default="pending", index=True)  # pending, running, completed, failed, cancelled
    progress = db.Column(db.Integer, default=0)
    
    # IOC-centric metrics (not event-centric)
    total_iocs = db.Column(db.Integer, default=0)
    processed_iocs = db.Column(db.Integer, default=0)
    match_count = db.Column(db.Integer, default=0)
    total_events_searched = db.Column(db.BigInteger, default=0)  # Total events in the index
    
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    
    # Relationships
    case = db.relationship('Case', backref='ioc_hunt_jobs')
    creator = db.relationship('User', foreign_keys=[created_by])
    matches = db.relationship("IOCHuntMatch", backref="job", lazy="dynamic", cascade="all, delete-orphan")


class IOCHuntMatch(db.Model):
    """
    Global IOC hunt matches - separate from IOCMatch table.
    
    IOCMatch: Per-file processing during indexing (has file_id, updates has_ioc flag)
    IOCHuntMatch: Global on-demand hunts (no file_id, links to hunt job)
    """
    __tablename__ = "ioc_hunt_match"
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("ioc_hunt_job.id", ondelete='CASCADE'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False, index=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey("ioc.id"), nullable=False, index=True)
    
    # Event location
    event_id = db.Column(db.String(255), index=True)
    event_index = db.Column(db.String(255))  # Which OpenSearch index
    
    # Match details
    matched_value = db.Column(db.Text)  # The IOC value that matched
    event_data = db.Column(db.Text, nullable=True)  # JSON snapshot of event (optional)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    ioc = db.relationship('IOC', backref='hunt_matches')
    case = db.relationship('Case')
    
    # Composite indexes for fast lookups
    __table_args__ = (
        db.Index('idx_hunt_job_ioc', 'job_id', 'ioc_id'),
        db.Index('idx_hunt_case_event', 'case_id', 'event_id'),
    )
