#!/usr/bin/env python3
"""Generate Ed25519 keypair for license signing.

This script generates a keypair for the CaseScope licensing system.
Run this on your ACTIVATION SERVER, not on client machines.

Usage:
    python generate_license_keypair.py

Output:
    - license_private_key.pem: Keep this SECURE on your activation server
    - license_public_key.txt: Embed this in CaseScope client (validator.py)
"""

import base64
import json
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: cryptography package not installed.")
    print("Install with: pip install cryptography>=42.0.0")
    sys.exit(1)


def generate_keypair():
    """Generate Ed25519 keypair."""
    print("=" * 60)
    print("CaseScope License Keypair Generator")
    print("=" * 60)
    print()
    
    # Generate private key
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize private key (PEM format for storage)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get raw public key bytes (for embedding in client)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(public_bytes).decode()
    
    # Save private key
    private_key_file = 'license_private_key.pem'
    with open(private_key_file, 'wb') as f:
        f.write(private_pem)
    os.chmod(private_key_file, 0o600)  # Restrict permissions
    
    print(f"[+] Private key saved to: {private_key_file}")
    print("    KEEP THIS FILE SECURE! It can sign any license.")
    print()
    
    # Save public key
    public_key_file = 'license_public_key.txt'
    with open(public_key_file, 'w') as f:
        f.write(f"# CaseScope License Public Key\n")
        f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Embed this in utils/licensing/validator.py\n")
        f.write(f"#\n")
        f.write(f"_PUBLIC_KEY_B64 = '{public_b64}'\n")
    
    print(f"[+] Public key saved to: {public_key_file}")
    print()
    print("-" * 60)
    print("PUBLIC KEY (embed in validator.py):")
    print("-" * 60)
    print(f"_PUBLIC_KEY_B64 = '{public_b64}'")
    print()
    print("-" * 60)
    print("NEXT STEPS:")
    print("-" * 60)
    print("1. Copy license_private_key.pem to your activation server")
    print("2. Update _PUBLIC_KEY_B64 in utils/licensing/validator.py")
    print("3. Use generate_license.py to create signed licenses")
    print()


if __name__ == '__main__':
    generate_keypair()
