#!/usr/bin/env python3
"""Development server runner for CaseScope"""
import ssl
from app import app
from config import Config

if __name__ == '__main__':
    # Create SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(Config.SSL_CERT, Config.SSL_KEY)
    
    print(f"\n🚀 CaseScope 2026 v{app.config['VERSION']}")
    print(f"   Running on https://{Config.HOST}:{Config.PORT}")
    print(f"   Press Ctrl+C to stop\n")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        ssl_context=ssl_context,
        debug=True
    )
