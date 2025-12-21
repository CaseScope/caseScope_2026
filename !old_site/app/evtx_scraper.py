"""
Real HTML Scraper for EVTX Event Descriptions
Scrapes actual event data from ultimatewindowssecurity.com

Enhanced to scrape all pages and all sources:
- Uses 'default.aspx?i=j' for JSON-like format (all events on one page)
- Scrapes all event IDs, sources, and descriptions
- Handles different event sources (Windows, Sysmon, SharePoint, SQL, Exchange)
"""

import requests
from bs4 import BeautifulSoup
import re
import logging
import time

logger = logging.getLogger(__name__)


def scrape_ultimate_windows_security_real():
    """
    Enhanced scraper that gets ALL events from Ultimate Windows Security
    
    Strategy:
    1. Use the "all events" view which lists everything on one scrollable page
    2. Parse the table structure to extract event_id, source, and description
    3. Detect event source from the first column (Windows, Sysmon, etc.)
    
    URL: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[REAL SCRAPER] Starting Ultimate Windows Security enhanced scrape")
    events = []
    
    # This URL shows ALL events in a single page (no pagination needed)
    # The ?i=j parameter gives us a clean list view
    url = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j"
    
    try:
        logger.info(f"[REAL SCRAPER] Fetching {url}")
        response = requests.get(url, timeout=60)  # Increased timeout for large page
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all links that point to event detail pages
        # Format: <a href="event.aspx?eventid=4624">4624</a>
        event_links = soup.find_all('a', href=re.compile(r'event\.aspx\?eventid=\d+'))
        
        logger.info(f"[REAL SCRAPER] Found {len(event_links)} event links")
        
        # Process each event link
        for link in event_links:
            try:
                # Extract event ID from href
                href = link.get('href', '')
                match = re.search(r'eventid=(\d+)', href)
                if not match:
                    continue
                
                event_id = int(match.group(1))
                
                # Get the parent row to extract description
                row = link.find_parent('tr')
                if not row:
                    continue
                
                cells = row.find_all('td')
                if len(cells) < 3:
                    continue
                
                # Cell 0: Source (Windows, Sysmon, SharePoint, SQL, Exchange)
                source_text = cells[0].get_text(strip=True)
                
                # Map source text to event_source
                event_source = 'Security'  # Default
                category = 'Security'  # Default
                
                if 'Sysmon' in source_text:
                    event_source = 'Sysmon'
                    category = 'Sysmon'
                elif 'SharePoint' in source_text:
                    event_source = 'SharePoint'
                    category = 'SharePoint'
                elif 'SQL' in source_text:
                    event_source = 'SQL Server'
                    category = 'SQL Server'
                elif 'Exchange' in source_text:
                    event_source = 'Exchange'
                    category = 'Exchange'
                elif 'Windows' in source_text:
                    event_source = 'Security'
                    category = 'Security'
                
                # Cell 2: Description (may be a link or plain text)
                desc_link = cells[2].find('a')
                if desc_link:
                    description = desc_link.get_text(strip=True)
                else:
                    description = cells[2].get_text(strip=True)
                
                # Clean up description
                description = description.strip()
                
                if event_id and description:
                    events.append({
                        'event_id': event_id,
                        'event_source': event_source,
                        'title': description,
                        'description': description,
                        'category': category,
                        'source_url': f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
                    })
                    
                    # Log every 100 events
                    if len(events) % 100 == 0:
                        logger.info(f"[REAL SCRAPER] Processed {len(events)} events...")
            
            except Exception as e:
                logger.debug(f"[REAL SCRAPER] Error parsing event link: {e}")
                continue
        
        # Deduplicate events by event_id (keep first occurrence)
        seen = set()
        unique_events = []
        for event in events:
            key = (event['event_id'], event['event_source'])
            if key not in seen:
                seen.add(key)
                unique_events.append(event)
        
        logger.info(f"[REAL SCRAPER] ✓ Successfully scraped {len(unique_events)} unique events (removed {len(events) - len(unique_events)} duplicates)")
        
        # Log breakdown by source
        sources = {}
        for event in unique_events:
            src = event['event_source']
            sources[src] = sources.get(src, 0) + 1
        
        logger.info(f"[REAL SCRAPER] Breakdown by source:")
        for src, count in sources.items():
            logger.info(f"[REAL SCRAPER]   - {src}: {count} events")
        
        return unique_events
    
    except Exception as e:
        logger.error(f"[REAL SCRAPER] Error fetching page: {e}", exc_info=True)
        return []


def get_detailed_event_info(event_id):
    """
    Scrape detailed information for a specific event ID
    Returns category, detailed description, etc.
    """
    url = f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract category, detailed description from the detail page
        # This is more complex and can be added if needed
        
        return {
            'category': 'Security',  # Placeholder
            'detailed_description': None
        }
    
    except Exception as e:
        logger.debug(f"[REAL SCRAPER] Could not fetch detail for event {event_id}: {e}")
        return None

