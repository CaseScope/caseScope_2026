"""Machine Fingerprinting Module

Generates stable machine fingerprints for license binding.
Combines multiple hardware identifiers to create a unique machine ID.
"""

import hashlib
import logging
import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Path to store the installation UUID (survives reboots, not reinstalls)
INSTALLATION_UUID_PATH = '/opt/casescope/.installation_id'


class MachineFingerprint:
    """
    Generates and validates machine fingerprints.
    
    Uses multiple hardware identifiers:
    1. Machine UUID (from SMBIOS/DMI)
    2. Primary disk serial number
    3. First non-virtual MAC address
    4. CPU model string hash
    5. Installation UUID (generated on first run)
    
    Matching requires 3 of 5 components to match (allows hardware changes).
    """
    
    # Minimum components required for a valid match
    REQUIRED_MATCHES = 3
    TOTAL_COMPONENTS = 5
    
    @classmethod
    def get_fingerprint(cls) -> Dict[str, str]:
        """
        Collect all fingerprint components.
        
        Returns:
            dict: Component name -> hash value mappings
        """
        components = {}
        
        # 1. Machine UUID
        machine_uuid = cls._get_machine_uuid()
        if machine_uuid:
            components['machine_uuid'] = cls._hash_component(machine_uuid)
        
        # 2. Disk serial
        disk_serial = cls._get_disk_serial()
        if disk_serial:
            components['disk_serial'] = cls._hash_component(disk_serial)
        
        # 3. MAC address
        mac_address = cls._get_mac_address()
        if mac_address:
            components['mac_address'] = cls._hash_component(mac_address)
        
        # 4. CPU model
        cpu_model = cls._get_cpu_model()
        if cpu_model:
            components['cpu_model'] = cls._hash_component(cpu_model)
        
        # 5. Installation UUID
        installation_id = cls._get_or_create_installation_id()
        if installation_id:
            components['installation_id'] = cls._hash_component(installation_id)
        
        return components
    
    @classmethod
    def get_fingerprint_hash(cls) -> str:
        """
        Generate a combined fingerprint hash.
        
        This is the hash that gets stored in the license file.
        
        Returns:
            str: SHA-256 hash of all component hashes combined
        """
        components = cls.get_fingerprint()
        
        # Sort by key for deterministic ordering
        sorted_values = [components[k] for k in sorted(components.keys())]
        combined = '|'.join(sorted_values)
        
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @classmethod
    def get_fingerprint_for_activation(cls) -> Dict[str, any]:
        """
        Get fingerprint data formatted for activation request.
        
        Returns:
            dict: Fingerprint data to send to activation server
        """
        components = cls.get_fingerprint()
        
        return {
            'fingerprint_hash': cls.get_fingerprint_hash(),
            'components': components,
            'component_count': len(components)
        }
    
    @classmethod
    def match_fingerprint(cls, stored_components: Dict[str, str]) -> Tuple[bool, int, List[str]]:
        """
        Check if current machine matches stored fingerprint.
        
        Args:
            stored_components: Component hashes from the license file
            
        Returns:
            tuple: (is_valid, match_count, matched_components)
        """
        current = cls.get_fingerprint()
        
        matched = []
        for key, stored_hash in stored_components.items():
            if key in current and current[key] == stored_hash:
                matched.append(key)
        
        match_count = len(matched)
        is_valid = match_count >= cls.REQUIRED_MATCHES
        
        logger.info(f"[Fingerprint] Match result: {match_count}/{cls.TOTAL_COMPONENTS} "
                   f"components matched (need {cls.REQUIRED_MATCHES})")
        
        return is_valid, match_count, matched
    
    @classmethod
    def _hash_component(cls, value: str) -> str:
        """Hash a component value with SHA-256."""
        return hashlib.sha256(value.encode()).hexdigest()[:32]
    
    @classmethod
    def _get_machine_uuid(cls) -> Optional[str]:
        """Get machine UUID from SMBIOS/DMI."""
        try:
            # Try reading from /sys/class/dmi/id/product_uuid (requires root)
            uuid_path = '/sys/class/dmi/id/product_uuid'
            if os.path.exists(uuid_path):
                try:
                    with open(uuid_path, 'r') as f:
                        return f.read().strip().upper()
                except PermissionError:
                    pass
            
            # Try dmidecode (requires root/sudo)
            try:
                result = subprocess.run(
                    ['sudo', 'dmidecode', '-s', 'system-uuid'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().upper()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Fallback: Use /etc/machine-id (Linux-specific, stable across reboots)
            machine_id_path = '/etc/machine-id'
            if os.path.exists(machine_id_path):
                with open(machine_id_path, 'r') as f:
                    return f.read().strip()
            
            return None
            
        except Exception as e:
            logger.warning(f"[Fingerprint] Failed to get machine UUID: {e}")
            return None
    
    @classmethod
    def _get_disk_serial(cls) -> Optional[str]:
        """Get primary disk serial number."""
        try:
            # Try lsblk to get disk serial
            result = subprocess.run(
                ['lsblk', '-o', 'NAME,SERIAL', '-d', '-n'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        name, serial = parts[0], parts[1]
                        # Skip loop devices and empty serials
                        if not name.startswith('loop') and serial and serial != 'None':
                            return serial
            
            # Try hdparm as fallback
            try:
                result = subprocess.run(
                    ['sudo', 'hdparm', '-I', '/dev/sda'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Serial Number:' in line:
                            return line.split(':')[1].strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return None
            
        except Exception as e:
            logger.warning(f"[Fingerprint] Failed to get disk serial: {e}")
            return None
    
    @classmethod
    def _get_mac_address(cls) -> Optional[str]:
        """Get first non-virtual MAC address."""
        try:
            # Read from /sys/class/net/
            net_path = Path('/sys/class/net')
            
            for iface in sorted(net_path.iterdir()):
                name = iface.name
                
                # Skip loopback and virtual interfaces
                if name == 'lo' or name.startswith('veth') or name.startswith('docker') or name.startswith('br-'):
                    continue
                
                # Check if it's a physical device
                device_path = iface / 'device'
                if not device_path.exists():
                    continue
                
                # Read MAC address
                address_path = iface / 'address'
                if address_path.exists():
                    with open(address_path, 'r') as f:
                        mac = f.read().strip().upper()
                        # Skip null/broadcast MACs
                        if mac and mac != '00:00:00:00:00:00' and mac != 'FF:FF:FF:FF:FF:FF':
                            return mac
            
            # Fallback: use uuid.getnode() which returns MAC as integer
            node = uuid.getnode()
            mac = ':'.join(f'{(node >> i) & 0xFF:02X}' for i in range(0, 48, 8))[::-1]
            return mac
            
        except Exception as e:
            logger.warning(f"[Fingerprint] Failed to get MAC address: {e}")
            return None
    
    @classmethod
    def _get_cpu_model(cls) -> Optional[str]:
        """Get CPU model string."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        # Extract model name, normalize whitespace
                        model = line.split(':')[1].strip()
                        model = re.sub(r'\s+', ' ', model)
                        return model
            
            return None
            
        except Exception as e:
            logger.warning(f"[Fingerprint] Failed to get CPU model: {e}")
            return None
    
    @classmethod
    def _get_or_create_installation_id(cls) -> str:
        """
        Get or create installation UUID.
        
        This ID is generated on first run and persists across reboots.
        A reinstall will generate a new ID.
        """
        try:
            if os.path.exists(INSTALLATION_UUID_PATH):
                with open(INSTALLATION_UUID_PATH, 'r') as f:
                    existing_id = f.read().strip()
                    if existing_id:
                        return existing_id
            
            # Generate new installation ID
            new_id = str(uuid.uuid4())
            
            # Save it
            with open(INSTALLATION_UUID_PATH, 'w') as f:
                f.write(new_id)
            
            # Set appropriate permissions
            os.chmod(INSTALLATION_UUID_PATH, 0o644)
            
            logger.info(f"[Fingerprint] Generated new installation ID")
            return new_id
            
        except Exception as e:
            logger.warning(f"[Fingerprint] Failed to get/create installation ID: {e}")
            # Generate a runtime ID as fallback (won't persist)
            return str(uuid.uuid4())
    
    @classmethod
    def get_debug_info(cls) -> Dict[str, any]:
        """
        Get detailed fingerprint info for debugging.
        
        Returns:
            dict: Raw values and hashes for all components
        """
        return {
            'machine_uuid': {
                'raw': cls._get_machine_uuid(),
                'hash': cls._hash_component(cls._get_machine_uuid() or '')
            },
            'disk_serial': {
                'raw': cls._get_disk_serial(),
                'hash': cls._hash_component(cls._get_disk_serial() or '')
            },
            'mac_address': {
                'raw': cls._get_mac_address(),
                'hash': cls._hash_component(cls._get_mac_address() or '')
            },
            'cpu_model': {
                'raw': cls._get_cpu_model(),
                'hash': cls._hash_component(cls._get_cpu_model() or '')
            },
            'installation_id': {
                'raw': cls._get_or_create_installation_id(),
                'hash': cls._hash_component(cls._get_or_create_installation_id() or '')
            },
            'combined_hash': cls.get_fingerprint_hash()
        }
