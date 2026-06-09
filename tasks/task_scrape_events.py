"""
Event Description Scraping Tasks
Background tasks for scraping event descriptions from multiple sources
"""

import logging
from tasks.celery_tasks import celery_app

logger = logging.getLogger(__name__)


class ScrapeCancelled(Exception):
    """Raised when an admin cancels an in-flight description scrape."""


@celery_app.task(name='tasks.scrape_event_descriptions', bind=True)
def scrape_event_descriptions_task(self):
    """
    Scrape event descriptions from all configured sources
    and update the database
    
    Returns dict with statistics about the scraping operation
    """
    # Import Flask app and create context
    from tasks.celery_tasks import get_flask_app
    
    app = get_flask_app()
    
    with app.app_context():
        from models.database import db
        from models.event_description import EventDescription
        from scrapers.event_description_scraper import EventDescriptionScraper
        from utils.async_cancellation import clear_cancellation, is_cancellation_requested
        from utils.global_task_markers import clear_global_task_inflight, mark_global_task_inflight
        
        def _check_cancel():
            if is_cancellation_requested('global_task', 'evtx_scrape'):
                raise ScrapeCancelled('EVTX description scrape cancelled')
        
        try:
            # Refresh the in-flight marker (also covers direct invocations)
            mark_global_task_inflight('evtx_scrape', task_id=self.request.id)
            logger.info("Starting event description scraping task...")
            
            # Update task state
            self.update_state(state='PROGRESS', meta={'status': 'Scraping websites...'})
            
            # Initialize scraper
            scraper = EventDescriptionScraper()
            
            # Scrape all sources
            events = scraper.scrape_all_sources()
            _check_cancel()
            
            # Deduplicate
            events = scraper.deduplicate_events(events)
            
            logger.info(f"Scraped {len(events)} unique events")
            
            # Update task state
            self.update_state(state='PROGRESS', meta={'status': 'Importing to database...'})
            
            # Import to database
            stats = {
                'total_scraped': len(events),
                'added': 0,
                'updated': 0,
                'skipped': 0,
                'errors': 0
            }
            
            for idx, event_data in enumerate(events):
                if idx % 200 == 0:
                    _check_cancel()
                try:
                    # Check if event already exists
                    existing = EventDescription.query.filter_by(
                        event_id=event_data['event_id'],
                        log_source=event_data['log_source']
                    ).first()
                    
                    if existing:
                        if existing.manually_set:
                            stats['skipped'] += 1
                            continue

                        # Update if new description is longer/better
                        if event_data['description_length'] > (existing.description_length or 0):
                            existing.description = event_data['description']
                            existing.category = event_data.get('category')
                            existing.source_website = event_data['source_website']
                            existing.source_url = event_data['source_url']
                            existing.description_length = event_data['description_length']
                            existing.manually_set = False
                            stats['updated'] += 1
                        else:
                            stats['skipped'] += 1
                    else:
                        # Add new event
                        new_event = EventDescription(
                            event_id=event_data['event_id'],
                            log_source=event_data['log_source'],
                            description=event_data['description'],
                            category=event_data.get('category'),
                            source_website=event_data['source_website'],
                            source_url=event_data['source_url'],
                            description_length=event_data['description_length']
                        )
                        db.session.add(new_event)
                        stats['added'] += 1
                    
                    # Commit in batches for performance
                    if (stats['added'] + stats['updated']) % 100 == 0:
                        db.session.commit()
                        logger.info(f"Progress: {stats['added']} added, {stats['updated']} updated")
                    
                except Exception as e:
                    logger.error(f"Error importing event {event_data.get('event_id')}: {e}")
                    stats['errors'] += 1
                    db.session.rollback()
            
            # Final commit
            db.session.commit()
            
            logger.info(f"Event description scraping completed: {stats}")
            
            return stats
            
        except ScrapeCancelled:
            logger.info("Event description scraping cancelled by analyst")
            db.session.rollback()
            return {'cancelled': True, 'added': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
        except Exception as e:
            logger.error(f"Event description scraping task failed: {e}")
            import traceback
            traceback.print_exc()
            raise
        finally:
            clear_cancellation('global_task', 'evtx_scrape')
            clear_global_task_inflight('evtx_scrape')
