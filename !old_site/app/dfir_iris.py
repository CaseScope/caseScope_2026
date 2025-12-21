"""DFIR-IRIS Integration Module"""
import requests
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
# Debug logging removed for production (was: logger.setLevel(logging.DEBUG))


class DFIRIrisClient:
    """Client for DFIR-IRIS API"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Optional[Dict]:
        """Make API request"""
        try:
            # DFIR-IRIS API v2 uses /api/v2/ prefix
            if not endpoint.startswith('/'):
                endpoint = '/' + endpoint
            url = f"{self.url}{endpoint}"
            
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data,
                timeout=30,
                verify=False  # Disable SSL verification for self-signed certs
            )
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            # Log detailed error including response body if available
            error_detail = str(e)
            try:
                if hasattr(e, 'response') and e.response is not None:
                    error_detail = f"{e} | Response: {e.response.text}"
            except:
                pass
            logger.error(f"[DFIR-IRIS] API request failed: {error_detail}")
            logger.error(f"[DFIR-IRIS] Request: {method} {url} | Data: {data}")
            return None
    
    def get_or_create_customer(self, company_name: str) -> Optional[int]:
        """Get or create customer (company) in DFIR-IRIS"""
        # List customers
        result = self._request('GET', '/manage/customers/list')
        if not result or 'data' not in result:
            return None
        
        # Check if customer exists
        for customer in result['data']:
            if customer.get('customer_name', '').lower() == company_name.lower():
                logger.info(f"[DFIR-IRIS] Customer found: {company_name} (ID: {customer['customer_id']})")
                return customer['customer_id']
        
        # Create customer
        data = {'customer_name': company_name}
        result = self._request('POST', '/manage/customers/add', data)
        if result and 'data' in result:
            customer_id = result['data'].get('customer_id')
            logger.info(f"[DFIR-IRIS] Customer created: {company_name} (ID: {customer_id})")
            return customer_id
        
        return None
    
    def get_or_create_case(self, customer_id: int, case_name: str, case_description: str = '', company_name: str = '') -> Optional[int]:
        """Get or create case in DFIR-IRIS"""
        # List cases
        result = self._request('GET', '/manage/cases/list')
        if not result or 'data' not in result:
            return None
        
        # Check if case exists - DFIR-IRIS uses client_name (string) not customer_id (int)
        logger.info(f"[DFIR-IRIS] Searching for case containing '{case_name}' with company '{company_name}'")
        for idx, case in enumerate(result['data']):
            # Log the first case structure for debugging
            if idx == 0:
                logger.info(f"[DFIR-IRIS] Sample case structure: {list(case.keys())}")
            
            # DFIR-IRIS stores company as 'client_name' (string), not customer_id
            case_client_name = case.get('client_name', '').lower()
            case_name_in_iris = case.get('case_name', '')
            
            # DFIR-IRIS adds prefix like "#12 - " to case names, so check if our case name is in theirs
            case_name_lower = case_name_in_iris.lower()
            our_case_name_lower = case_name.lower()
            
            logger.debug(f"[DFIR-IRIS] Comparing: case_name='{case_name_lower}' contains '{our_case_name_lower}'? client='{case_client_name}' vs '{company_name.lower()}'")
            
            # Match if our case name is contained in DFIR-IRIS case name AND client matches
            if (our_case_name_lower in case_name_lower and 
                case_client_name == company_name.lower()):
                logger.info(f"[DFIR-IRIS] Case found: {case_name_in_iris} (ID: {case['case_id']})")
                return case['case_id']
        
        logger.info(f"[DFIR-IRIS] No matching case found, will create new case")
        
        # Create case - DFIR-IRIS requires case_soc_id (unique identifier)
        # Generate a unique SOC ID based on case name and timestamp
        import time
        soc_id = f"CS-{int(time.time())}"
        
        data = {
            'case_name': case_name,
            'case_description': case_description or f'Case created from CaseScope: {case_name}',
            'case_customer': customer_id,  # Changed from 'customer_id' to 'case_customer'
            'case_soc_id': soc_id,  # Required field
            'case_classification': 36  # ID 36 = 'other:other' (catch-all classification)
        }
        result = self._request('POST', '/manage/cases/add', data)
        if result and 'data' in result:
            case_id = result['data'].get('case_id')
            logger.info(f"[DFIR-IRIS] Case created: {case_name} (ID: {case_id}, SOC ID: {soc_id})")
            
            # Grant current user full access to the case (fixes "No case found" error)
            try:
                # Get current user
                whoami = self._request('GET', '/user/whoami')
                if whoami and 'data' in whoami:
                    user_id = whoami['data'].get('user_id')
                    if user_id:
                        # Grant full access to this user for the case
                        access_data = {
                            'user_id': user_id,
                            'access_level': 4,  # Full access
                            'cid': case_id
                        }
                        self._request('POST', f'/manage/cases/access/add', access_data)
                        logger.info(f"[DFIR-IRIS] Granted user {user_id} access to case {case_id}")
            except Exception as e:
                logger.warning(f"[DFIR-IRIS] Failed to grant user access (case may still work): {e}")
            
            return case_id
        
        return None
    
    def sync_case_status(self, case_id: int, status: str) -> bool:
        """Sync case status (open/closed)"""
        # DFIR-IRIS uses state_id: 3=Open, 11=Closed (may vary by instance)
        state_id = 11 if status.lower() == 'closed' else 3
        
        data = {'state_id': state_id, 'cid': case_id}
        result = self._request('POST', f'/manage/cases/update', data)
        
        if result:
            logger.info(f"[DFIR-IRIS] Case status synced: {case_id} -> {status}")
            return True
        return False
    
    def get_case_iocs(self, case_id: int) -> List[Dict]:
        """Get all IOCs for a case from DFIR-IRIS"""
        result = self._request('GET', f'/case/ioc/list?cid={case_id}')
        if result and 'data' in result and 'ioc' in result['data']:
            return result['data']['ioc']
        return []
    
    def get_asset_types(self) -> List[Dict]:
        """Get available asset types from DFIR-IRIS"""
        result = self._request('GET', '/manage/asset-type/list')
        if result and 'data' in result:
            return result['data']
        return []
    
    def get_case_assets(self, case_id: int) -> List[Dict]:
        """Get all assets for a case from DFIR-IRIS"""
        result = self._request('GET', f'/case/assets/list?cid={case_id}')
        if result and 'data' in result:
            # DFIR-IRIS returns data.assets array
            if isinstance(result['data'], dict) and 'assets' in result['data']:
                return result['data']['assets']
            elif isinstance(result['data'], list):
                return result['data']
        return []
    
    def create_asset(self, case_id: int, asset_name: str, asset_type_id: int, 
                    asset_description: str = '', asset_ip: str = '', 
                    asset_domain: str = '') -> Optional[int]:
        """Create asset in DFIR-IRIS case"""
        data = {
            'asset_name': asset_name,
            'asset_type_id': asset_type_id,
            'analysis_status_id': 1,  # REQUIRED: 1 = Unspecified (default for auto-created assets)
            'asset_description': asset_description or f'Hostname from CaseScope: {asset_name}',
            'asset_tags': 'casescope,auto-created',
            'cid': case_id
        }
        
        # Only add IP and domain if they have values (DFIR-IRIS might not like empty strings)
        if asset_ip:
            data['asset_ip'] = asset_ip
        if asset_domain:
            data['asset_domain'] = asset_domain
        
        result = self._request('POST', '/case/assets/add', data)
        if result and 'data' in result:
            asset_id = result['data'].get('asset_id')
            logger.info(f"[DFIR-IRIS] Asset created: {asset_name} (ID: {asset_id})")
            return asset_id
        return None
    
    def get_or_create_asset(self, case_id: int, hostname: str) -> Optional[int]:
        """Get existing asset or create if doesn't exist (for Windows hostnames)"""
        # Get existing assets
        existing_assets = self.get_case_assets(case_id)
        
        # Check if asset already exists (case-insensitive)
        hostname_lower = hostname.lower()
        for asset in existing_assets:
            if asset.get('asset_name', '').lower() == hostname_lower:
                logger.debug(f"[DFIR-IRIS] Asset exists: {hostname} (ID: {asset.get('asset_id')})")
                return asset.get('asset_id')
        
        # Get asset types and find "Windows - Computer"
        asset_types = self.get_asset_types()
        windows_computer_type_id = None
        
        for asset_type in asset_types:
            type_name = asset_type.get('asset_name', '')
            if 'windows' in type_name.lower() and 'computer' in type_name.lower():
                windows_computer_type_id = asset_type.get('asset_id')
                break
        
        if not windows_computer_type_id:
            logger.warning("[DFIR-IRIS] 'Windows - Computer' asset type not found, using default")
            # Fallback to first available type or ID 1
            windows_computer_type_id = asset_types[0].get('asset_id') if asset_types else 1
        
        # Create asset
        return self.create_asset(case_id, hostname, windows_computer_type_id)
    
    def sync_ioc(self, case_id: int, ioc_value: str, ioc_type: str, description: str = '', threat_level: str = 'medium') -> Optional[int]:
        """Sync IOC to DFIR-IRIS (create or update)"""
        # Check if IOC already exists
        existing_iocs = self.get_case_iocs(case_id)
        for ioc in existing_iocs:
            if ioc.get('ioc_value') == ioc_value:
                # Update existing
                update_data = {
                    'ioc_description': description,
                    'ioc_type_id': self._get_ioc_type_id(ioc_type),
                    'ioc_tags': threat_level,
                    'ioc_tlp_id': 2,
                    'cid': case_id
                }
                self._request('POST', f'/case/ioc/update/{ioc["ioc_id"]}', update_data)
                logger.info(f"[DFIR-IRIS] IOC updated: {ioc_value}")
                return ioc['ioc_id']
        
        # Create new IOC - DFIR-IRIS requires specific fields
        data = {
            'ioc_value': ioc_value,
            'ioc_type_id': self._get_ioc_type_id(ioc_type),
            'ioc_description': description,
            'ioc_tags': threat_level,
            'ioc_tlp_id': 2,  # TLP:GREEN (1=WHITE, 2=GREEN, 3=AMBER, 4=RED)
            'cid': case_id
        }
        result = self._request('POST', f'/case/ioc/add', data)
        if result and 'data' in result:
            ioc_id = result['data'].get('ioc_id')
            logger.info(f"[DFIR-IRIS] IOC created: {ioc_value} (ID: {ioc_id})")
            return ioc_id
        
        return None
    
    def _get_ioc_type_id(self, ioc_type: str) -> int:
        """Map CaseScope IOC types to DFIR-IRIS type IDs"""
        type_map = {
            'ip': 76,           # ip-any
            'hostname': 69,     # hostname
            'domain': 20,       # domain
            'url': 141,         # url
            'username': 133,    # target-user
            'email': 22,        # email
            'hash': 90,         # md5 (generic hash fallback)
            'md5': 90,          # md5
            'sha1': 111,        # sha1
            'sha256': 113,      # sha256
            'command': 96,      # other
            'filename': 37,     # filename
            'port': 106,        # port
            'registry': 109,    # regkey
            'malware': 89       # malware-type
        }
        return type_map.get(ioc_type.lower(), 96)  # Default to 'other' if unknown
    
    def sync_timeline_event(self, case_id: int, event_data: Dict, casescope_event_id: str, asset_cache: Dict[str, int] = None) -> Optional[int]:
        """Sync timeline event to DFIR-IRIS"""
        timestamp = event_data.get('timestamp')
        title = event_data.get('title')
        description = event_data.get('description', '')
        computer_name = event_data.get('computer_name', '')
        raw_data = event_data.get('raw_data', {})
        ioc_ids = event_data.get('ioc_ids', [])
        
        # Initialize cache if not provided
        if asset_cache is None:
            asset_cache = {}
        
        # Format timestamp for DFIR-IRIS (MUST remove timezone offset from timestamp)
        # DFIR-IRIS wants: event_date='2025-10-24T18:41:50.290448' (no TZ) + event_tz='+00:00' (separate field)
        if timestamp:
            # Remove 'Z' suffix
            if timestamp.endswith('Z'):
                timestamp = timestamp[:-1]
            # Remove +HH:MM or -HH:MM timezone offset
            if 'T' in timestamp:
                date_part, time_part = timestamp.split('T', 1)
                if '+' in time_part:
                    time_part = time_part.split('+')[0]
                elif '-' in time_part and time_part.count('-') > 0:
                    # Check if it's a timezone (has colon after dash)
                    parts = time_part.split('-')
                    if len(parts) > 1 and ':' in parts[-1]:
                        time_part = '-'.join(parts[:-1])
                timestamp = f"{date_part}T{time_part}"
            
            # Ensure microseconds format (.mmmmmm)
            if '.' not in timestamp:
                timestamp = f"{timestamp}.000000"
            else:
                base_time, fractional = timestamp.rsplit('.', 1)
                fractional = fractional.ljust(6, '0')[:6]
                timestamp = f"{base_time}.{fractional}"
        
        # Format title: description - computer_name
        formatted_title = f"{title} - {computer_name}" if computer_name else title
        
        # Get or create asset for hostname (using cache to avoid duplicates)
        asset_ids = []
        if computer_name:
            # Strip domain suffix and clean hostname
            hostname = computer_name.split('.')[0] if '.' in computer_name else computer_name
            hostname = hostname.strip().upper()  # Normalize to uppercase for cache matching
            
            if hostname:
                try:
                    # Check cache first
                    if hostname in asset_cache:
                        asset_ids.append(asset_cache[hostname])
                        logger.debug(f"[DFIR-IRIS] Using cached asset: {hostname} (ID: {asset_cache[hostname]})")
                    else:
                        # Not in cache - query/create
                        asset_id = self.get_or_create_asset(case_id, hostname)
                        if asset_id:
                            asset_ids.append(asset_id)
                            asset_cache[hostname] = asset_id  # Cache it
                except Exception as e:
                    logger.warning(f"[DFIR-IRIS] Failed to create/link asset {hostname}: {e}")
        
        # Check if event exists by CaseScope ID (stored in event_tags)
        result = self._request('GET', f'/case/timeline/events/list?cid={case_id}')
        if result and 'data' in result and 'timeline' in result['data']:
            for event in result['data']['timeline']:
                # Check if this event is from CaseScope by matching the unique ID in tags
                event_tags = event.get('event_tags', '')
                if f'casescope_id:{casescope_event_id}' in event_tags:
                    # Event already exists - skip to avoid duplicates
                    event_id = event.get('event_id')
                    logger.info(f"[DFIR-IRIS] Timeline event already exists (ID: {event_id}), skipping")
                    return event_id
        
        # Create new timeline event
        data = {
            'event_title': formatted_title,
            'event_date': timestamp,
            'event_tz': '+00:00',  # Required field - UTC timezone offset format
            'event_category_id': 1,  # Required field - 1=Unspecified (raw forensic events)
            'event_assets': asset_ids,  # Link to hostname asset
            'event_source': 'Pushed from CaseScope',
            'event_content': f'Event from CaseScope\n\nComputer: {computer_name}\nTimestamp: {timestamp}',
            'event_raw': json.dumps(raw_data, indent=2),  # Full event data in raw field
            'event_iocs': ioc_ids,  # Note: plural 'event_iocs' not 'event_ioc'
            'event_in_summary': True,  # Show in case summary
            'event_tags': f'casescope_id:{casescope_event_id}',
            'cid': case_id
        }
        
        result = self._request('POST', f'/case/timeline/events/add', data)
        if result and 'data' in result:
            event_id = result['data'].get('event_id')
            logger.info(f"[DFIR-IRIS] Timeline event created: {event_id}")
            return event_id
        
        return None
    
    def remove_timeline_event(self, case_id: int, casescope_event_id: str) -> bool:
        """Remove timeline event from DFIR-IRIS"""
        # Find event by CaseScope ID - DFIR-IRIS returns data.timeline array
        result = self._request('GET', f'/case/timeline/events/list?cid={case_id}')
        if not result or 'data' not in result or 'timeline' not in result['data']:
            return False
        
        for event in result['data']['timeline']:
            if casescope_event_id in event.get('event_tags', ''):
                event_id = event.get('event_id')
                delete_data = {'cid': case_id}
                if self._request('POST', f'/case/timeline/events/delete/{event_id}', delete_data):
                    logger.info(f"[DFIR-IRIS] Timeline event removed: {event_id}")
                    return True
        
        return False
    
    def get_datastore_parent_folder(self, case_id: int, folder_name: str = 'Evidences') -> Optional[int]:
        """Get the parent folder ID from datastore tree for file uploads
        
        DFIR-IRIS requires uploads to specify a parent folder ID.
        This gets the folder ID for 'Evidences' (or other folder) in the case's datastore.
        """
        try:
            # Get datastore tree for the case
            # Try multiple possible endpoints (based on browser network capture)
            endpoints_to_try = [
                f'/tree?cid={case_id}',  # Root level - likely correct based on browser
                f'/datastore/tree?cid={case_id}',
                f'/case/datastore/tree?cid={case_id}',
                f'/manage/datastore/tree?cid={case_id}',
            ]
            
            result = None
            for endpoint in endpoints_to_try:
                try:
                    result = self._request('GET', endpoint)
                    if result and 'data' in result:
                        logger.info(f"[DFIR-IRIS] Got datastore tree from: {endpoint}")
                        break
                except:
                    continue
            
            if not result:
                result = self._request('GET', f'/datastore/tree?cid={case_id}')
            
            if not result or 'data' not in result:
                logger.warning(f"[DFIR-IRIS] Could not get datastore tree for case {case_id}")
                return None
            
            # Search for the folder (typically 'Evidences', 'Images', or root)
            tree_data = result['data']
            
            # Try to find the specified folder
            def find_folder(node, target_name):
                """Recursively search tree for folder"""
                if isinstance(node, dict):
                    # Check if this node matches
                    if node.get('text', '').lower() == target_name.lower():
                        return node.get('a_attr', {}).get('data-file-id')
                    
                    # Search children
                    if 'children' in node:
                        for child in node['children']:
                            result = find_folder(child, target_name)
                            if result:
                                return result
                
                elif isinstance(node, list):
                    for item in node:
                        result = find_folder(item, target_name)
                        if result:
                            return result
                
                return None
            
            folder_id = find_folder(tree_data, folder_name)
            
            if folder_id:
                logger.info(f"[DFIR-IRIS] Found '{folder_name}' folder ID: {folder_id}")
                return folder_id
            else:
                # Try to get root folder ID as fallback
                if isinstance(tree_data, list) and len(tree_data) > 0:
                    root_id = tree_data[0].get('a_attr', {}).get('data-file-id')
                    if root_id:
                        logger.info(f"[DFIR-IRIS] Using root folder ID: {root_id}")
                        return root_id
                
                logger.warning(f"[DFIR-IRIS] Could not find folder '{folder_name}' in datastore tree")
                return None
                
        except Exception as e:
            logger.error(f"[DFIR-IRIS] Error getting datastore folder: {e}", exc_info=True)
            return None
    
    def upload_evidence_file(self, case_id: int, file_path: str, filename: str, description: str = '') -> Optional[int]:
        """Upload file to DFIR-IRIS datastore
        
        Endpoint: POST /datastore/file/add/{parent_folder_id}?cid={case_id}
        
        Note: The tree endpoint to get folder IDs is session-based (not API accessible).
        We'll try multiple upload strategies:
        1. Try common folder IDs (root case folder, standard subfolder IDs)
        2. Try without specifying a folder (let DFIR-IRIS decide)
        """
        import os
        
        logger.info(f"[DFIR-IRIS] Uploading file to datastore: {filename} for case {case_id}")
        
        # Check file exists
        if not os.path.exists(file_path):
            logger.error(f"[DFIR-IRIS] File not found: {file_path}")
            return None
        
        file_size = os.path.getsize(file_path)
        size_mb = round(file_size / (1024 * 1024), 2)
        logger.info(f"[DFIR-IRIS] File size: {size_mb}MB")
        
        # Try getting folder ID (may fail if endpoint is session-based)
        parent_folder_id = self.get_datastore_parent_folder(case_id, 'Evidences')
        
        # If we can't get folder ID, try common folder ID patterns
        folder_ids_to_try = []
        if parent_folder_id:
            folder_ids_to_try.append(parent_folder_id)
        
        # Add common folder ID guesses (case_id * 3 + offset patterns observed in browser)
        # From browser: case 24 used folder ID 31 (could be a pattern)
        folder_ids_to_try.extend([
            case_id * 2 - 17,  # Pattern guess: 24*2-17=31
            case_id + 7,  # 24+7=31
            1,  # Root folder
            case_id,  # Case ID itself
        ])
        
        logger.info(f"[DFIR-IRIS] Trying folder IDs: {folder_ids_to_try}")
        
        # Try each folder ID
        for folder_id in folder_ids_to_try:
            try:
                url = f"{self.url}/datastore/file/add/{folder_id}?cid={case_id}"
                logger.info(f"[DFIR-IRIS] Attempt: {url}")
                
                with open(file_path, 'rb') as f:
                    # DFIR-IRIS requires 'file_content' (not 'file') per official API docs
                    files = {'file_content': (filename, f, 'application/octet-stream')}
                    data = {
                        'file_original_name': filename,  # Required
                        'file_description': description or '',
                        'file_password': '',  # Empty if no password
                        'file_tags': 'casescope',
                        'file_is_evidence': 'y',  # 'y' or 'n' (not 'on')
                        'file_is_ioc': 'n'
                    }
                    
                    response = requests.post(
                        url,
                        headers={'Authorization': f'Bearer {self.api_key}'},
                        files=files,
                        data=data,
                        timeout=120,
                        verify=False
                    )
                    
                    logger.info(f"[DFIR-IRIS] Response: {response.status_code}")
                    
                    if response.status_code == 200:
                        result = response.json() if response.text else {}
                        
                        if result.get('status') == 'success' and 'data' in result:
                            file_id = result['data'].get('file_id')
                            file_uuid = result['data'].get('file_uuid')
                            logger.info(f"[DFIR-IRIS] ✓ File uploaded! (Folder: {folder_id}, File ID: {file_id}, UUID: {file_uuid})")
                            return file_id
                    elif response.status_code == 404:
                        logger.debug(f"[DFIR-IRIS] Folder {folder_id} not found, trying next...")
                        continue
                    else:
                        logger.warning(f"[DFIR-IRIS] Folder {folder_id} failed: {response.status_code} - {response.text[:200]}")
                        continue
                        
            except Exception as e:
                logger.warning(f"[DFIR-IRIS] Folder {folder_id} error: {e}")
                continue
        
        # All attempts failed
        logger.error(f"[DFIR-IRIS] ✗ All upload attempts failed for {filename}")
        return None


def sync_case_to_dfir_iris(db_session, opensearch_client, case_id: int, iris_client: DFIRIrisClient) -> Dict[str, Any]:
    """
    Sync a case and its data to DFIR-IRIS
    
    Args:
        db_session: Database session
        opensearch_client: OpenSearch client
        case_id: Case ID to sync
        iris_client: DFIR-IRIS client instance
    
    Returns:
        Dict with sync results
    """
    from models import Case, IOC, TimelineTag
    
    results = {
        'success': False,
        'customer_id': None,
        'case_id': None,
        'iocs_synced': 0,
        'events_synced': 0,
        'events_removed': 0,
        'errors': []
    }
    
    # Get case
    case = db_session.query(Case).filter_by(id=case_id).first()
    if not case:
        results['errors'].append('Case not found')
        return results
    
    try:
        # 1. Get or create customer (company)
        company_name = case.company or 'Unknown Company'
        customer_id = iris_client.get_or_create_customer(company_name)
        if not customer_id:
            results['errors'].append('Failed to get/create customer')
            return results
        results['customer_id'] = customer_id
        
        # 2. Get or create case
        iris_case_id = iris_client.get_or_create_case(customer_id, case.name, case.description or '', company_name)
        if not iris_case_id:
            results['errors'].append('Failed to get/create case')
            return results
        results['case_id'] = iris_case_id
        
        # 3. Sync case status (optional - don't block if endpoint not available)
        try:
            iris_client.sync_case_status(iris_case_id, case.status or 'Open')
        except Exception as e:
            logger.warning(f"[DFIR-IRIS] Failed to sync case status (non-critical): {e}")
        
        # 4. Sync IOCs
        iocs = db_session.query(IOC).filter_by(case_id=case_id, is_active=True).all()
        for ioc in iocs:
            ioc_id = iris_client.sync_ioc(
                iris_case_id,
                ioc.ioc_value,
                ioc.ioc_type,
                ioc.description or '',
                ioc.threat_level or 'medium'
            )
            if ioc_id:
                results['iocs_synced'] += 1
        
        # 5. Sync timeline events
        tagged_events = db_session.query(TimelineTag).filter_by(case_id=case_id).all()
        
        # Cache for assets created/found during this sync (to avoid re-querying DFIR-IRIS)
        asset_cache = {}  # {hostname: asset_id}
        
        for tag in tagged_events:
            # Get event from OpenSearch
            try:
                event = opensearch_client.get(index=tag.index_name, id=tag.event_id)
                if event and '_source' in event:
                    event_source = event['_source']
                    
                    # Map CaseScope IOCs to DFIR-IRIS IOC IDs
                    ioc_iris_ids = []
                    try:
                        # Get IOCs from OpenSearch event data (primary source after v1.13+)
                        matched_iocs = event_source.get('matched_iocs', [])
                        ioc_details = event_source.get('ioc_details', [])
                        
                        # Extract IOC values from both fields
                        ioc_values = set()
                        
                        # matched_iocs is list of IOC values
                        if isinstance(matched_iocs, list):
                            ioc_values.update(matched_iocs)
                        
                        # ioc_details is list of dicts with 'value' and 'type'
                        if isinstance(ioc_details, list):
                            for ioc_detail in ioc_details:
                                if isinstance(ioc_detail, dict) and 'value' in ioc_detail:
                                    ioc_values.add(ioc_detail['value'])
                        
                        if ioc_values:
                            # Get all IRIS IOCs for this case (cache for efficiency)
                            iris_iocs = iris_client.get_case_iocs(iris_case_id)
                            
                            # For each matched IOC value, find its IRIS ID
                            for ioc_value in ioc_values:
                                # Find matching IOC in IRIS by value
                                for iris_ioc in iris_iocs:
                                    if iris_ioc.get('ioc_value') == ioc_value:
                                        ioc_id = iris_ioc.get('ioc_id')
                                        if ioc_id and ioc_id not in ioc_iris_ids:
                                            ioc_iris_ids.append(ioc_id)
                                        break
                        
                        logger.debug(f"[DFIR-IRIS] Event {tag.event_id}: Found {len(ioc_values)} IOC values, mapped to {len(ioc_iris_ids)} IRIS IOC IDs")
                    except Exception as e:
                        logger.warning(f"[DFIR-IRIS] Failed to map IOCs for event {tag.event_id}: {e}")
                    
                    # Extract event details
                    event_data = {
                        'timestamp': event_source.get('normalized_timestamp') or event_source.get('@timestamp'),
                        'title': event_source.get('event_title') or event_source.get('event_description', 'Event'),
                        'computer_name': event_source.get('normalized_computer', ''),
                        'raw_data': event_source,
                        'ioc_ids': ioc_iris_ids
                    }
                    
                    iris_event_id = iris_client.sync_timeline_event(
                        iris_case_id,
                        event_data,
                        f"{tag.index_name}:{tag.event_id}",
                        asset_cache  # Pass asset cache to avoid duplicate creations
                    )
                    if iris_event_id:
                        results['events_synced'] += 1
            except Exception as e:
                logger.error(f"[DFIR-IRIS] Failed to sync event {tag.event_id}: {e}")
        
        # 6. Remove untagged events from DFIR-IRIS
        # Get all timeline events from DFIR-IRIS
        timeline_result = iris_client._request('GET', f'/cases/{iris_case_id}/timeline')
        if timeline_result and 'data' in timeline_result:
            for iris_event in timeline_result['data']:
                if iris_event.get('event_source') == 'Pushed from CaseScope':
                    # Check if this event is still tagged in CaseScope
                    event_tags = iris_event.get('event_tags', '')
                    if 'casescope_id:' in event_tags:
                        casescope_id = event_tags.split('casescope_id:')[1].split()[0]
                        
                        # Check if still tagged
                        index_name, event_id = casescope_id.split(':', 1)
                        still_tagged = db_session.query(TimelineTag).filter_by(
                            case_id=case_id,
                            index_name=index_name,
                            event_id=event_id
                        ).first()
                        
                        if not still_tagged:
                            if iris_client.remove_timeline_event(iris_case_id, casescope_id):
                                results['events_removed'] += 1
        
        results['success'] = True
        logger.info(f"[DFIR-IRIS] Sync complete: Case {case_id} -> IRIS {iris_case_id}")
        
    except Exception as e:
        logger.error(f"[DFIR-IRIS] Sync failed: {e}", exc_info=True)
        results['errors'].append(str(e))
    
    return results

