"""
WSGI Entry Point for CaseScope 2026
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from main import app

if __name__ == '__main__':
    app.run()
