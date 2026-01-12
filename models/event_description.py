"""EventDescription Model - Stores EVTX event descriptions from multiple sources"""
from datetime import datetime
from models.database import db


class EventDescription(db.Model):
    """
    EVTX Event descriptions scraped from multiple sources
    Tracks Windows Event Log IDs with descriptions for better analysis
    """
    __tablename__ = 'event_description'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(20), nullable=False, index=True)  # Event ID (e.g., "4624")
    log_source = db.Column(db.String(100), nullable=False, index=True)  # e.g., "Security", "System"
    description = db.Column(db.Text, nullable=False)  # Event description
    category = db.Column(db.String(100))  # Category (e.g., "Account Logon", "Object Access")
    subcategory = db.Column(db.String(100))  # Subcategory if available
    source_website = db.Column(db.String(200))  # Which website this was scraped from
    source_url = db.Column(db.String(500))  # Direct URL to the event description
    
    # Timestamps
    scraped_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Metadata
    description_length = db.Column(db.Integer)  # For selecting most descriptive version
    
    # Unique constraint: one entry per event_id + log_source combination
    __table_args__ = (
        db.UniqueConstraint('event_id', 'log_source', name='uix_event_log'),
    )
    
    def __repr__(self):
        return f'<EventDescription {self.event_id} - {self.log_source}>'
    
    @classmethod
    def get_by_event(cls, event_id, log_source):
        """Get description for a specific event ID and log source"""
        return cls.query.filter_by(
            event_id=str(event_id),
            log_source=log_source
        ).first()
    
    @classmethod
    def get_stats(cls):
        """Get statistics about stored event descriptions"""
        from sqlalchemy import func
        
        total = cls.query.count()
        
        # Count by log source
        by_source = db.session.query(
            cls.log_source,
            func.count(cls.id)
        ).group_by(cls.log_source).all()
        
        # Count by category
        by_category = db.session.query(
            cls.category,
            func.count(cls.id)
        ).group_by(cls.category).all()
        
        # Count by website source
        by_website = db.session.query(
            cls.source_website,
            func.count(cls.id)
        ).group_by(cls.source_website).all()
        
        # Get last updated
        last_updated = db.session.query(func.max(cls.updated_at)).scalar()
        
        return {
            'total': total,
            'by_source': {source: count for source, count in by_source if source},
            'by_category': {cat: count for cat, count in by_category if cat},
            'by_website': {site: count for site, count in by_website if site},
            'last_updated': last_updated.isoformat() if last_updated else None
        }
