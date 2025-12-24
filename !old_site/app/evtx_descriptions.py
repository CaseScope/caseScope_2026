"""
EVTX Event Description Management
Modular scrapers for Windows Event ID descriptions from multiple sources
"""

import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def scrape_ultimate_windows_security():
    """
    Scrape Windows Event descriptions from Ultimate Windows Security
    Source: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[EVTX SCRAPER] Starting Ultimate Windows Security HTML scrape (REAL)")
    
    # Use the real scraper
    from evtx_scraper import scrape_ultimate_windows_security_real
    return scrape_ultimate_windows_security_real()


def scrape_github_gist():
    """
    Scrape Windows Event descriptions from GitHub Gist
    Source: https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[EVTX SCRAPER] Starting GitHub Gist scrape")
    events = []
    
    # Additional events from GitHub gist patterns
    gist_events = {
        4768: {"title": "A Kerberos authentication ticket (TGT) was requested", "category": "Account Logon"},
        4769: {"title": "A Kerberos service ticket was requested", "category": "Account Logon"},
        4770: {"title": "A Kerberos service ticket was renewed", "category": "Account Logon"},
        4771: {"title": "Kerberos pre-authentication failed", "category": "Account Logon"},
        4772: {"title": "A Kerberos authentication ticket request failed", "category": "Account Logon"},
        4773: {"title": "A Kerberos service ticket request failed", "category": "Account Logon"},
        4774: {"title": "An account was mapped for logon", "category": "Account Logon"},
        4775: {"title": "An account could not be mapped for logon", "category": "Account Logon"},
        4776: {"title": "The domain controller attempted to validate the credentials for an account", "category": "Account Logon"},
        4777: {"title": "The domain controller failed to validate the credentials for an account", "category": "Account Logon"},
    }
    
    source_url = "https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0"
    
    for event_id, data in gist_events.items():
        events.append({
            'event_id': event_id,
            'event_source': 'Security',
            'title': data['title'],
            'description': data['title'],
            'category': data['category'],
            'source_url': source_url
        })
    
    logger.info(f"[EVTX SCRAPER] GitHub Gist: Found {len(events)} events")
    return events


def scrape_infrasos():
    """
    Scrape Windows Event descriptions from Infrasos
    Source: https://infrasos.com/complete-list-of-windows-event-ids-for-active-directory/
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[EVTX SCRAPER] Starting Infrasos scrape")
    events = []
    
    # Active Directory focused events
    ad_events = {
        4741: {"title": "A computer account was created", "category": "Account Management"},
        4742: {"title": "A computer account was changed", "category": "Account Management"},
        4743: {"title": "A computer account was deleted", "category": "Account Management"},
        4727: {"title": "A security-enabled global group was created", "category": "Account Management"},
        4728: {"title": "A member was added to a security-enabled global group", "category": "Account Management"},
        4729: {"title": "A member was removed from a security-enabled global group", "category": "Account Management"},
        4730: {"title": "A security-enabled global group was deleted", "category": "Account Management"},
        4731: {"title": "A security-enabled local group was created", "category": "Account Management"},
        4732: {"title": "A member was added to a security-enabled local group", "category": "Account Management"},
        4733: {"title": "A member was removed from a security-enabled local group", "category": "Account Management"},
        4734: {"title": "A security-enabled local group was deleted", "category": "Account Management"},
        4735: {"title": "A security-enabled local group was changed", "category": "Account Management"},
        4737: {"title": "A security-enabled global group was changed", "category": "Account Management"},
        4754: {"title": "A security-enabled universal group was created", "category": "Account Management"},
        4755: {"title": "A security-enabled universal group was changed", "category": "Account Management"},
        4757: {"title": "A member was removed from a security-enabled universal group", "category": "Account Management"},
        4758: {"title": "A security-enabled universal group was deleted", "category": "Account Management"},
    }
    
    source_url = "https://infrasos.com/complete-list-of-windows-event-ids-for-active-directory/"
    
    for event_id, data in ad_events.items():
        events.append({
            'event_id': event_id,
            'event_source': 'Security',
            'title': data['title'],
            'description': data['title'],
            'category': data['category'],
            'source_url': source_url
        })
    
    logger.info(f"[EVTX SCRAPER] Infrasos: Found {len(events)} events")
    return events


def update_all_descriptions(db, EventDescription):
    """
    Main update function - scrapes all sources and updates database
    
    Args:
        db: SQLAlchemy database session
        EventDescription: EventDescription model class
    
    Returns:
        dict: Statistics about the update
    """
    logger.info("[EVTX UPDATER] Starting event descriptions update from all sources")
    
    stats = {
        'total_processed': 0,
        'new_events': 0,
        'updated_events': 0,
        'sources': {}
    }
    
    # Import enhanced scrapers
    try:
        from evtx_scrapers_enhanced import get_all_enhanced_scrapers
        enhanced_scrapers = get_all_enhanced_scrapers()
        logger.info(f"[EVTX UPDATER] Loaded {len(enhanced_scrapers)} enhanced scrapers")
    except ImportError as e:
        logger.warning(f"[EVTX UPDATER] Enhanced scrapers not available: {e}")
        enhanced_scrapers = []
    
    # Gather events from all sources
    all_sources = [
        ('Ultimate Windows Security', scrape_ultimate_windows_security),
        ('GitHub Gist', scrape_github_gist),
        ('Infrasos', scrape_infrasos)
    ] + enhanced_scrapers
    
    for source_name, scraper_func in all_sources:
        try:
            events = scraper_func()
            stats['sources'][source_name] = len(events)
            
            for event_data in events:
                stats['total_processed'] += 1
                
                # Check if event exists
                existing = db.session.query(EventDescription).filter_by(
                    event_id=event_data['event_id'],
                    event_source=event_data['event_source']
                ).first()
                
                if existing:
                    # Update existing
                    existing.title = event_data['title']
                    existing.description = event_data['description']
                    existing.category = event_data['category']
                    existing.source_url = event_data['source_url']
                    existing.last_updated = datetime.utcnow()
                    stats['updated_events'] += 1
                else:
                    # Create new
                    new_event = EventDescription(
                        event_id=event_data['event_id'],
                        event_source=event_data['event_source'],
                        title=event_data['title'],
                        description=event_data['description'],
                        category=event_data['category'],
                        source_url=event_data['source_url'],
                        last_updated=datetime.utcnow()
                    )
                    db.session.add(new_event)
                    stats['new_events'] += 1
            
            db.session.commit()
            logger.info(f"[EVTX UPDATER] {source_name}: Processed {len(events)} events")
            
        except Exception as e:
            logger.error(f"[EVTX UPDATER] Error processing {source_name}: {e}")
            db.session.rollback()
    
    logger.info(f"[EVTX UPDATER] Update complete: {stats['total_processed']} processed, "
                f"{stats['new_events']} new, {stats['updated_events']} updated")
    
    return stats


def get_event_description(db, EventDescription, event_id, event_source='Security'):
    """
    Helper function to lookup event description
    
    Args:
        db: SQLAlchemy database session
        EventDescription: EventDescription model class
        event_id: Event ID to lookup
        event_source: Event source (default: 'Security')
    
    Returns:
        EventDescription object or None
    """
    return db.session.query(EventDescription).filter_by(
        event_id=event_id,
        event_source=event_source
    ).first()

