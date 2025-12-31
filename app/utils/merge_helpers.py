"""
Merge Helper Utilities
Provides functions for auto-merge and manual combine operations
"""

import re
from datetime import datetime
from typing import Optional, List, Tuple


def is_blank(value) -> bool:
    """
    Check if value is considered blank/default
    
    Returns True if:
    - None
    - Empty string
    - Whitespace only
    - Single dash '-'
    
    Args:
        value: Any value to check
        
    Returns:
        bool: True if blank, False otherwise
    """
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return stripped == '' or stripped == '-'
    return False


def normalize_hostname(hostname: str) -> str:
    """
    Normalize hostname - strip FQDN to NetBIOS name, uppercase
    
    Examples:
        server01.domain.local -> SERVER01
        SERVER01 -> SERVER01
        workstation-99.corp.com -> WORKSTATION-99
    
    Args:
        hostname: Hostname to normalize
        
    Returns:
        str: Normalized hostname (uppercase, no domain)
    """
    if not hostname:
        return ""
    
    # Strip FQDN - take everything before first dot
    if '.' in hostname:
        hostname = hostname.split('.')[0]
    
    # Normalize to uppercase for consistent matching
    return hostname.upper().strip()


def normalize_username(username: str) -> str:
    """
    Normalize username - strip domain prefix if present, lowercase
    
    Examples:
        DOMAIN\\user -> user
        user@domain.com -> user
        user -> user
    
    Args:
        username: Username to normalize
        
    Returns:
        str: Normalized username (lowercase, no domain)
    """
    if not username:
        return ""
    
    # Strip domain prefix (DOMAIN\user or DOMAIN/user)
    if '\\' in username:
        username = username.split('\\', 1)[1]
    elif '/' in username and not '@' in username:  # Don't split email addresses
        username = username.split('/', 1)[1]
    
    # Strip email domain (user@domain.com)
    if '@' in username:
        username = username.split('@', 1)[0]
    
    # Normalize to lowercase for consistent matching
    return username.lower().strip()


def extract_domain_from_username(username: str) -> Optional[str]:
    """
    Extract domain from username if present
    
    Examples:
        DOMAIN\\user -> DOMAIN
        user@domain.com -> domain.com
        user -> None
    
    Args:
        username: Username to parse
        
    Returns:
        Optional[str]: Domain name or None
    """
    if not username:
        return None
    
    # Check for DOMAIN\user format
    if '\\' in username:
        return username.split('\\', 1)[0].strip()
    
    # Check for DOMAIN/user format
    if '/' in username and '@' not in username:
        return username.split('/', 1)[0].strip()
    
    # Check for user@domain.com format
    if '@' in username:
        return username.split('@', 1)[1].strip()
    
    return None


def check_in_analyst_notes(notes: Optional[str], search_value: str) -> bool:
    """
    Check if a value already exists in analyst notes (case-insensitive)
    
    Args:
        notes: Analyst notes text to search
        search_value: Value to look for
        
    Returns:
        bool: True if found, False otherwise
    """
    if not notes or not search_value:
        return False
    
    return search_value.lower() in notes.lower()


def collect_unique_ips(existing_ips: List[str], new_ip: Optional[str]) -> List[str]:
    """
    Add new IP to list of IPs if not already present (case-insensitive)
    
    Args:
        existing_ips: List of existing IP addresses
        new_ip: New IP to add
        
    Returns:
        List[str]: Updated list of unique IPs
    """
    if not new_ip or is_blank(new_ip):
        return existing_ips
    
    new_ip = new_ip.strip()
    
    # Check if IP already in list (case-insensitive)
    if not any(ip.lower() == new_ip.lower() for ip in existing_ips):
        existing_ips.append(new_ip)
    
    return existing_ips


def extract_ips_from_notes(notes: Optional[str]) -> List[str]:
    """
    Extract IP addresses from analyst notes
    
    Looks for the "## Known IP Addresses" section and extracts IPs
    
    Args:
        notes: Analyst notes text
        
    Returns:
        List[str]: List of IP addresses found
    """
    if not notes:
        return []
    
    ips = []
    
    # Look for IP addresses in the Known IP Addresses section
    in_ip_section = False
    for line in notes.split('\n'):
        line = line.strip()
        
        # Check if we're entering the IP section
        if '## Known IP Addresses' in line:
            in_ip_section = True
            continue
        
        # Check if we're leaving the IP section (next markdown header)
        if in_ip_section and line.startswith('##'):
            break
        
        # Extract IP from line if in IP section
        if in_ip_section and line.startswith('-'):
            # Format: "- 192.168.1.5 (first seen: 2024-12-30)"
            # Extract IP using regex
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            if ip_match:
                ips.append(ip_match.group(1))
    
    return ips


def format_ip_section(ips: List[str], latest_ip: Optional[str] = None) -> str:
    """
    Format the Known IP Addresses section for analyst notes
    
    Args:
        ips: List of known IP addresses
        latest_ip: Most recent IP (highlighted as current)
        
    Returns:
        str: Formatted markdown section
    """
    if not ips:
        return ""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    section = "\n## Known IP Addresses\n"
    for ip in ips:
        if ip == latest_ip:
            section += f"- {ip} (current as of {timestamp})\n"
        else:
            section += f"- {ip}\n"
    
    return section


def format_merge_note(
    merge_type: str,
    source_name: str,
    source_id: Optional[int] = None,
    fields_merged: Optional[dict] = None,
    extra_info: Optional[str] = None
) -> str:
    """
    Format a merge entry for analyst notes (markdown)
    
    Args:
        merge_type: 'auto' or 'manual'
        source_name: Name of the item being merged (e.g., hostname, username)
        source_id: ID of the source item (for manual merges)
        fields_merged: Dict of field_name: value that were merged
        extra_info: Additional context (e.g., domain, IP)
        
    Returns:
        str: Formatted markdown merge note
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if merge_type == 'auto':
        note = f"- {timestamp}: Also seen as **{source_name}**"
        if extra_info:
            note += f" ({extra_info})"
    else:  # manual
        note = f"- {timestamp}: Merged from **{source_name}**"
        if source_id:
            note += f" (ID #{source_id})"
        
        if fields_merged:
            for field, value in fields_merged.items():
                note += f"\n  - `{field}`: {value}"
    
    return note


def update_analyst_notes_with_merge(
    current_notes: Optional[str],
    merge_type: str,
    source_name: str,
    source_id: Optional[int] = None,
    fields_merged: Optional[dict] = None,
    extra_info: Optional[str] = None
) -> str:
    """
    Add merge information to analyst notes in organized markdown format
    
    Creates/updates these sections:
    - ## Auto-Merge History
    - ## Manual Merge History
    - ## Original Notes
    
    Args:
        current_notes: Existing analyst notes
        merge_type: 'auto' or 'manual'
        source_name: Name of merged item
        source_id: ID of merged item (for manual)
        fields_merged: Fields that were merged
        extra_info: Additional context
        
    Returns:
        str: Updated analyst notes
    """
    merge_note = format_merge_note(merge_type, source_name, source_id, fields_merged, extra_info)
    
    # If no existing notes, create structure
    if not current_notes or is_blank(current_notes):
        if merge_type == 'auto':
            return f"## Auto-Merge History\n{merge_note}\n"
        else:
            return f"## Manual Merge History\n{merge_note}\n"
    
    # Parse existing notes to find/create appropriate section
    lines = current_notes.split('\n')
    result_lines = []
    
    auto_section_found = False
    manual_section_found = False
    original_section_found = False
    section_added = False
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check for section headers
        if line.strip() == '## Auto-Merge History':
            auto_section_found = True
            result_lines.append(line)
            
            # If this is an auto-merge, add the note here
            if merge_type == 'auto' and not section_added:
                # Find where this section ends (next ## or end of notes)
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('##'):
                    result_lines.append(lines[i])
                    i += 1
                result_lines.append(merge_note)
                section_added = True
                i -= 1  # Back up one since we'll increment at end of loop
            
        elif line.strip() == '## Manual Merge History':
            manual_section_found = True
            result_lines.append(line)
            
            # If this is a manual merge, add the note here
            if merge_type == 'manual' and not section_added:
                # Find where this section ends
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('##'):
                    result_lines.append(lines[i])
                    i += 1
                result_lines.append(merge_note)
                section_added = True
                i -= 1
            
        elif line.strip() == '## Original Notes':
            original_section_found = True
            result_lines.append(line)
            
        else:
            result_lines.append(line)
        
        i += 1
    
    # If section wasn't found, add it
    if not section_added:
        # Add before "## Original Notes" if it exists, otherwise at end
        if original_section_found:
            # Find where to insert
            insert_idx = None
            for idx, line in enumerate(result_lines):
                if line.strip() == '## Original Notes':
                    insert_idx = idx
                    break
            
            if insert_idx is not None:
                if merge_type == 'auto':
                    result_lines.insert(insert_idx, merge_note)
                    result_lines.insert(insert_idx, '## Auto-Merge History')
                else:
                    result_lines.insert(insert_idx, merge_note)
                    result_lines.insert(insert_idx, '## Manual Merge History')
        else:
            # Add at end
            if merge_type == 'auto':
                result_lines.append('\n## Auto-Merge History')
                result_lines.append(merge_note)
            else:
                result_lines.append('\n## Manual Merge History')
                result_lines.append(merge_note)
    
    return '\n'.join(result_lines)


def append_original_notes(notes: str, original_notes: Optional[str]) -> str:
    """
    Append original analyst notes from child item to parent
    
    Args:
        notes: Current notes (with merge history)
        original_notes: Original notes from child item
        
    Returns:
        str: Updated notes with original notes appended
    """
    if not original_notes or is_blank(original_notes):
        return notes
    
    # Check if we already have an Original Notes section
    if '## Original Notes' in notes:
        # Append to existing section
        return notes + f"\n\n### From merged item:\n{original_notes.strip()}"
    else:
        # Create new section
        return notes + f"\n\n## Original Notes\n{original_notes.strip()}"


def find_or_merge_system(db, case_id, hostname, domain_name=None, ip_address=None, 
                          system_type=None, compromised=None, source='manual',
                          description=None, analyst_notes=None, created_by=None, updated_by=None, logger=None):
    """
    Find existing system by normalized hostname or create new one
    Auto-merges duplicates (FQDN variants) into parent (NetBIOS) version
    
    Args:
        db: Database session
        case_id: Case ID
        hostname: System hostname (may include domain)
        domain_name: Domain name (if separate)
        ip_address: IP address
        system_type: System type
        compromised: Compromised status
        source: Source of discovery
        description: Description text
        analyst_notes: Analyst notes
        created_by: User ID who created
        updated_by: User ID who updated
        logger: Logger instance (optional)
        
    Returns:
        KnownSystem: Existing (updated) or new system object
    """
    from models import KnownSystem
    from datetime import datetime
    
    if not hostname:
        return None
    
    # Normalize hostname (strip FQDN, uppercase)
    normalized = normalize_hostname(hostname)
    
    # Check for existing parent (normalized NetBIOS version)
    existing = KnownSystem.query.filter(
        KnownSystem.case_id == case_id,
        db.func.upper(KnownSystem.hostname) == normalized
    ).first()
    
    if existing:
        # Found parent - check if this is a new variant
        variant_to_add = hostname if hostname.upper() != existing.hostname.upper() else None
        
        # Collect existing IPs from analyst notes
        existing_ips = extract_ips_from_notes(existing.analyst_notes)
        
        # Add current IP if present
        if existing.ip_address and not is_blank(existing.ip_address):
            existing_ips = collect_unique_ips(existing_ips, existing.ip_address)
        
        # Add new IP if present and different
        if ip_address and not is_blank(ip_address):
            existing_ips = collect_unique_ips(existing_ips, ip_address)
            
            # If new IP is different from current, update current
            if existing.ip_address != ip_address:
                existing.ip_address = ip_address
        
        # Build extra info for merge note
        extra_info_parts = []
        if domain_name and domain_name != existing.domain_name:
            extra_info_parts.append(f"domain: {domain_name}")
        if ip_address and not is_blank(ip_address):
            extra_info_parts.append(f"IP: {ip_address}")
        
        extra_info = ", ".join(extra_info_parts) if extra_info_parts else None
        
        # Add auto-merge note if this is a new variant
        if variant_to_add and not check_in_analyst_notes(existing.analyst_notes, variant_to_add):
            existing.analyst_notes = update_analyst_notes_with_merge(
                existing.analyst_notes,
                merge_type='auto',
                source_name=variant_to_add,
                extra_info=extra_info
            )
            
            if logger:
                logger.info(f"[Auto-Merge] System '{variant_to_add}' merged into '{existing.hostname}' (ID: {existing.id})")
        
        # Update parent fields if blank
        if is_blank(existing.domain_name) and domain_name and not is_blank(domain_name):
            existing.domain_name = domain_name
        
        if is_blank(existing.description) and description and not is_blank(description):
            existing.description = description
        
        # For compromised status, prioritize 'yes' > 'no' > 'unknown'
        if compromised:
            priority_order = {'yes': 3, 'no': 2, 'unknown': 1}
            current_priority = priority_order.get(existing.compromised, 0)
            new_priority = priority_order.get(compromised, 0)
            if new_priority > current_priority:
                existing.compromised = compromised
        
        # Update IP section in analyst notes if we have multiple IPs
        if len(existing_ips) > 1:
            # Remove old IP section if present
            notes_lines = (existing.analyst_notes or "").split('\n')
            filtered_lines = []
            skip_section = False
            
            for line in notes_lines:
                if '## Known IP Addresses' in line:
                    skip_section = True
                    continue
                elif skip_section and line.strip().startswith('##'):
                    skip_section = False
                
                if not skip_section:
                    filtered_lines.append(line)
            
            # Add updated IP section
            existing.analyst_notes = '\n'.join(filtered_lines)
            if not existing.analyst_notes.endswith('\n'):
                existing.analyst_notes += '\n'
            existing.analyst_notes += format_ip_section(existing_ips, latest_ip=ip_address)
        
        # Update timestamps
        if updated_by:
            existing.updated_by = updated_by
        
        db.session.flush()
        return existing
    
    else:
        # Create new system (no match found)
        new_system = KnownSystem(
            case_id=case_id,
            hostname=normalized,  # Store normalized version as canonical
            domain_name=domain_name if not is_blank(domain_name) else None,
            ip_address=ip_address if not is_blank(ip_address) else None,
            system_type=system_type or 'workstation',
            compromised=compromised or 'unknown',
            source=source,
            description=description if not is_blank(description) else None,
            analyst_notes=analyst_notes if not is_blank(analyst_notes) else None,
            created_by=created_by,
            updated_by=updated_by or created_by
        )
        
        db.session.add(new_system)
        db.session.flush()  # Get ID
        
        if logger:
            logger.info(f"[Auto-Merge] New system created: '{new_system.hostname}' (ID: {new_system.id})")
        
        return new_system


def find_or_merge_user(db, case_id, username, domain_name=None, sid=None, user_type=None,
                        compromised=None, source='manual', description=None, analyst_notes=None,
                        created_by=None, updated_by=None, logger=None):
    """
    Find existing user by normalized username or create new one
    Auto-merges duplicates (domain\\user variants) into parent (user) version
    
    SID VALIDATION: If username matches but SID differs, creates NEW user (different person)
    
    Args:
        db: Database session
        case_id: Case ID
        username: Username (may include domain prefix)
        domain_name: Domain name (if separate)
        sid: Security Identifier
        user_type: User type (domain, local, unknown)
        compromised: Compromised status
        source: Source of discovery
        description: Description text
        analyst_notes: Analyst notes
        created_by: User ID who created
        updated_by: User ID who updated
        logger: Logger instance (optional)
        
    Returns:
        KnownUser: Existing (updated) or new user object
    """
    from models import KnownUser
    from datetime import datetime
    
    if not username:
        return None
    
    # CRITICAL: Validate username is not a system/service account
    # Computer accounts ending with $
    if username.endswith('$'):
        if logger:
            logger.info(f"[VALIDATION] Rejected computer account in merge function: {username}")
        return None
    
    # Service accounts (QuickBooks, IIS, etc.)
    username_lower = username.lower()
    if 'serviceuser' in username_lower or 'apppool' in username_lower or username_lower == 'localsystem':
        if logger:
            logger.info(f"[VALIDATION] Rejected service account in merge function: {username}")
        return None
    
    # Extract domain from username if present
    extracted_domain = extract_domain_from_username(username)
    if extracted_domain and not domain_name:
        domain_name = extracted_domain
    
    # Normalize username (strip domain, lowercase)
    normalized = normalize_username(username)
    
    # Find all users with this normalized username (might be multiple with different SIDs)
    candidates = KnownUser.query.filter(
        KnownUser.case_id == case_id,
        db.func.lower(KnownUser.username) == normalized
    ).all()
    
    # If SID provided, check for SID match first
    if sid and not is_blank(sid):
        for user in candidates:
            if user.sid and user.sid == sid:
                # Found exact match by SID - merge into this one
                variant_to_add = username if username.lower() != user.username.lower() else None
                
                # Build extra info for merge note
                extra_info_parts = []
                if domain_name and domain_name != user.domain_name:
                    extra_info_parts.append(f"domain: {domain_name}")
                
                extra_info = ", ".join(extra_info_parts) if extra_info_parts else None
                
                # Add auto-merge note if this is a new variant
                if variant_to_add and not check_in_analyst_notes(user.analyst_notes, variant_to_add):
                    user.analyst_notes = update_analyst_notes_with_merge(
                        user.analyst_notes,
                        merge_type='auto',
                        source_name=variant_to_add,
                        extra_info=extra_info
                    )
                    
                    if logger:
                        logger.info(f"[Auto-Merge] User '{variant_to_add}' merged into '{user.username}' (ID: {user.id}) - SID match")
                
                # Update parent fields if blank
                if is_blank(user.domain_name) and domain_name and not is_blank(domain_name):
                    user.domain_name = domain_name
                
                if is_blank(user.description) and description and not is_blank(description):
                    user.description = description
                
                # For compromised status, prioritize 'yes' > 'no'
                if compromised:
                    priority_order = {'yes': 2, 'no': 1}
                    current_priority = priority_order.get(user.compromised, 0)
                    new_priority = priority_order.get(compromised, 0)
                    if new_priority > current_priority:
                        user.compromised = compromised
                
                # Update timestamps
                if updated_by:
                    user.updated_by = updated_by
                
                db.session.flush()
                return user
        
        # SID provided but no match found - check if any candidate has a DIFFERENT SID
        for user in candidates:
            if user.sid and user.sid != sid:
                # Same username, DIFFERENT SID = DIFFERENT person
                # Create new user (fall through to creation logic below)
                if logger:
                    logger.info(f"[Auto-Merge] Username '{normalized}' exists with different SID - creating new user")
                break
    
    # No SID provided or no SID match - check for username-only match
    if len(candidates) == 1 and (not sid or is_blank(sid) or not candidates[0].sid):
        # Single match and no SID conflict - merge
        user = candidates[0]
        variant_to_add = username if username.lower() != user.username.lower() else None
        
        # Build extra info for merge note
        extra_info_parts = []
        if domain_name and domain_name != user.domain_name:
            extra_info_parts.append(f"domain: {domain_name}")
        if sid and not is_blank(sid):
            extra_info_parts.append(f"SID: {sid}")
        
        extra_info = ", ".join(extra_info_parts) if extra_info_parts else None
        
        # Add auto-merge note if this is a new variant
        if variant_to_add and not check_in_analyst_notes(user.analyst_notes, variant_to_add):
            user.analyst_notes = update_analyst_notes_with_merge(
                user.analyst_notes,
                merge_type='auto',
                source_name=variant_to_add,
                extra_info=extra_info
            )
            
            if logger:
                logger.info(f"[Auto-Merge] User '{variant_to_add}' merged into '{user.username}' (ID: {user.id})")
        
        # Update parent fields if blank
        if is_blank(user.sid) and sid and not is_blank(sid):
            user.sid = sid
        
        if is_blank(user.domain_name) and domain_name and not is_blank(domain_name):
            user.domain_name = domain_name
        
        if is_blank(user.description) and description and not is_blank(description):
            user.description = description
        
        # For compromised status, prioritize 'yes' > 'no'
        if compromised:
            priority_order = {'yes': 2, 'no': 1}
            current_priority = priority_order.get(user.compromised, 0)
            new_priority = priority_order.get(compromised, 0)
            if new_priority > current_priority:
                user.compromised = compromised
        
        # Update timestamps
        if updated_by:
            user.updated_by = updated_by
        
        db.session.flush()
        return user
    
    # Create new user (no match or SID conflict)
    # FINAL BULLETPROOF CHECK: Verify username is valid before creating object
    if normalized.endswith('$'):
        if logger:
            logger.info(f"[FINAL SAFETY] Blocked computer account in KnownUser creation: {normalized}")
        return None
    
    if 'serviceuser' in normalized.lower():
        if logger:
            logger.info(f"[FINAL SAFETY] Blocked service account in KnownUser creation: {normalized}")
        return None
    
    new_user = KnownUser(
        case_id=case_id,
        username=normalized,  # Store normalized version
        domain_name=domain_name if not is_blank(domain_name) else None,
        sid=sid if not is_blank(sid) else None,
        user_type=user_type or 'unknown',
        compromised=compromised or 'no',
        source=source,
        description=description if not is_blank(description) else None,
        analyst_notes=analyst_notes if not is_blank(analyst_notes) else None,
        created_by=created_by,
        updated_by=updated_by or created_by
    )
    
    db.session.add(new_user)
    db.session.flush()  # Get ID
    
    if logger:
        logger.info(f"[Auto-Merge] New user created: '{new_user.username}' (ID: {new_user.id})")
    
    return new_user


def should_warn_before_combine(items: List[dict], item_type: str) -> Tuple[bool, List[str]]:
    """
    Determine if user should be warned before manual combine
    
    Warns if items have:
    - Different types (system_type, user_type)
    - Different compromised status
    
    Args:
        items: List of items to be combined (dicts with type/compromised fields)
        item_type: 'system', 'user', or 'ioc'
        
    Returns:
        Tuple[bool, List[str]]: (should_warn, list of warning messages)
    """
    if len(items) < 2:
        return False, []
    
    warnings = []
    
    if item_type == 'system':
        # Check system_type consistency
        types = set(item.get('system_type') for item in items if item.get('system_type'))
        if len(types) > 1:
            warnings.append(f"Mixing different system types: {', '.join(types)}")
        
        # Check compromised status
        compromised_values = set(item.get('compromised') for item in items if item.get('compromised'))
        if len(compromised_values) > 1:
            warnings.append(f"Mixing different compromised statuses: {', '.join(compromised_values)}")
    
    elif item_type == 'user':
        # Check user_type consistency
        types = set(item.get('user_type') for item in items if item.get('user_type'))
        if len(types) > 1:
            warnings.append(f"Mixing different user types: {', '.join(types)}")
        
        # Check compromised status
        compromised_values = set(item.get('compromised') for item in items if item.get('compromised'))
        if len(compromised_values) > 1:
            warnings.append(f"Mixing different compromised statuses: {', '.join(compromised_values)}")
    
    elif item_type == 'ioc':
        # Check IOC type consistency
        types = set(item.get('type') for item in items if item.get('type'))
        if len(types) > 1:
            warnings.append(f"Mixing different IOC types: {', '.join(types)}")
        
        # Check threat level
        threat_levels = set(item.get('threat_level') for item in items if item.get('threat_level'))
        if len(threat_levels) > 1:
            warnings.append(f"Mixing different threat levels: {', '.join(threat_levels)}")
    
    return len(warnings) > 0, warnings

