#!/usr/bin/env python3
"""
CaseScope 2026 v1.0.0 - WSGI Entry Point
For production deployment with Gunicorn
"""

from main import app

if __name__ == "__main__":
    app.run()

