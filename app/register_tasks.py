"""
Task Registration
Import all task modules to ensure they're registered with Celery
"""

# Import tasks to register them
try:
    from tasks import task_file_upload
    print("✓ Registered file upload tasks")
except Exception as e:
    print(f"⚠ Could not load task_file_upload: {e}")

try:
    from tasks import task_scrape_events
    print("✓ Registered event scraping tasks")
except Exception as e:
    print(f"⚠ Could not load task_scrape_events: {e}")

try:
    from tasks import task_discover_systems
    print("✓ Registered system discovery tasks")
except Exception as e:
    print(f"⚠ Could not load task_discover_systems: {e}")

