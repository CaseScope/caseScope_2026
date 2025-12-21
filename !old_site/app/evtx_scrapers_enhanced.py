"""
Enhanced EVTX Event Description Scrapers
Adds support for:
1. MyEventLog.com - Community event database
2. Microsoft Learn - Sysmon events  
3. Microsoft Learn - Security audit events
"""

import requests
from bs4 import BeautifulSoup
import re
import logging
import time

logger = logging.getLogger(__name__)


def scrape_myeventlog_com():
    """
    Scrape Windows Event descriptions from MyEventLog.com
    Source: https://www.myeventlog.com/search/browse
    
    This site has extensive coverage of event sources including:
    - Windows Security events
    - Application events
    - System events  
    - Various Microsoft products (Exchange, SQL, SharePoint)
    - Third-party applications
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[MYEVENTLOG] Starting MyEventLog.com scrape")
    events = []
    
    base_url = "https://www.myeventlog.com"
    browse_url = f"{base_url}/search/browse"
    
    try:
        logger.info(f"[MYEVENTLOG] Fetching browse page: {browse_url}")
        response = requests.get(browse_url, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all event source links
        # These are typically in a list or table format
        source_links = soup.find_all('a', href=re.compile(r'/search/show/\?source='))
        
        logger.info(f"[MYEVENTLOG] Found {len(source_links)} event sources")
        
        # Limit to prevent excessive scraping - focus on major sources
        major_sources = [
            'Security', 'System', 'Application', 'Microsoft-Windows-Security-Auditing',
            'Microsoft-Windows-Sysmon', 'MSExchange', 'MSSQLSERVER', 
            'Microsoft-Windows-PowerShell', 'Microsoft-Windows-TaskScheduler',
            'Active Directory', 'DNS', 'DHCP'
        ]
        
        processed_sources = 0
        for link in source_links:
            try:
                source_text = link.get_text(strip=True)
                
                # Only process major sources
                if not any(major in source_text for major in major_sources):
                    continue
                
                href = link.get('href', '')
                if not href:
                    continue
                
                # Fetch the source page
                source_url = f"{base_url}{href}" if href.startswith('/') else href
                
                logger.info(f"[MYEVENTLOG] Scraping source: {source_text}")
                
                source_response = requests.get(source_url, timeout=30)
                source_response.raise_for_status()
                
                source_soup = BeautifulSoup(source_response.text, 'html.parser')
                
                # Find event entries on the source page
                event_rows = source_soup.find_all('tr')
                
                for row in event_rows:
                    cells = row.find_all('td')
                    if len(cells) < 2:
                        continue
                    
                    # Try to extract event ID and description
                    event_id_text = cells[0].get_text(strip=True)
                    
                    # Check if first cell contains a number (event ID)
                    event_id_match = re.match(r'^(\d+)$', event_id_text)
                    if not event_id_match:
                        continue
                    
                    event_id = int(event_id_match.group(1))
                    description = cells[1].get_text(strip=True)
                    
                    if event_id and description:
                        events.append({
                            'event_id': event_id,
                            'event_source': source_text,
                            'title': description,
                            'description': description,
                            'category': source_text,
                            'source_url': source_url
                        })
                
                processed_sources += 1
                
                # Rate limiting
                time.sleep(1)
                
                # Limit to prevent excessive load
                if processed_sources >= 10:
                    logger.info(f"[MYEVENTLOG] Reached source limit (10), stopping")
                    break
                    
            except Exception as e:
                logger.debug(f"[MYEVENTLOG] Error processing source {source_text}: {e}")
                continue
        
        logger.info(f"[MYEVENTLOG] ✓ Scraped {len(events)} events from {processed_sources} sources")
        return events
    
    except Exception as e:
        logger.error(f"[MYEVENTLOG] Error: {e}", exc_info=True)
        return []


def scrape_microsoft_sysmon():
    """
    Scrape Sysmon event descriptions from Microsoft Learn
    Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    
    Sysmon Event IDs:
    - Event ID 1: Process creation
    - Event ID 2: File creation time changed
    - Event ID 3: Network connection
    - Event ID 4: Sysmon service state changed
    - Event ID 5: Process terminated
    - Event ID 6: Driver loaded
    - Event ID 7: Image loaded
    - Event ID 8: CreateRemoteThread
    - Event ID 9: RawAccessRead
    - Event ID 10: ProcessAccess
    - Event ID 11: FileCreate
    - Event ID 12: RegistryEvent (Object create and delete)
    - Event ID 13: RegistryEvent (Value Set)
    - Event ID 14: RegistryEvent (Key and Value Rename)
    - Event ID 15: FileCreateStreamHash
    - Event ID 16: ServiceConfigurationChange
    - Event ID 17: PipeEvent (Pipe Created)
    - Event ID 18: PipeEvent (Pipe Connected)
    - Event ID 19: WmiEvent (WmiEventFilter activity detected)
    - Event ID 20: WmiEvent (WmiEventConsumer activity detected)
    - Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
    - Event ID 22: DNSEvent (DNS query)
    - Event ID 23: FileDelete (File Delete archived)
    - Event ID 24: ClipboardChange (New content in the clipboard)
    - Event ID 25: ProcessTampering (Process image change)
    - Event ID 26: FileDeleteDetected (File Delete logged)
    - Event ID 27: FileBlockExecutable
    - Event ID 28: FileBlockShredding
    - Event ID 29: FileExecutableDetected
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[SYSMON] Adding Sysmon event descriptions from Microsoft documentation")
    
    sysmon_events = {
        1: {
            "title": "Process Create",
            "description": "The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier."
        },
        2: {
            "title": "File creation time changed",
            "description": "File creation time is changed to help detect malware that modifies file timestamps to evade detection. Modification of file creation timestamp is a technique commonly used by malware to cover its tracks."
        },
        3: {
            "title": "Network connection detected",
            "description": "The network connection event logs TCP/UDP connections on the machine. It logs connection source process, IP addresses, port numbers, hostnames and port names."
        },
        4: {
            "title": "Sysmon service state changed",
            "description": "The service state change event reports the state of the Sysmon service (started or stopped)."
        },
        5: {
            "title": "Process terminated",
            "description": "The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process."
        },
        6: {
            "title": "Driver loaded",
            "description": "The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information."
        },
        7: {
            "title": "Image loaded",
            "description": "The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the '-l' option."
        },
        8: {
            "title": "CreateRemoteThread detected",
            "description": "The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes."
        },
        9: {
            "title": "RawAccessRead detected",
            "description": "The RawAccessRead event detects when a process conducts reading operations from the drive using the \\\\.\\ denotation."
        },
        10: {
            "title": "Process accessed",
            "description": "The process accessed event reports when a process opens another process, an operation that's often followed by information queries or reading and writing the address space of the target process."
        },
        11: {
            "title": "File created",
            "description": "File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder."
        },
        12: {
            "title": "Registry object added or deleted",
            "description": "Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations."
        },
        13: {
            "title": "Registry value set",
            "description": "This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD."
        },
        14: {
            "title": "Registry object renamed",
            "description": "Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed."
        },
        15: {
            "title": "File stream created",
            "description": "This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned."
        },
        16: {
            "title": "Service configuration change",
            "description": "This event logs changes in the Sysmon configuration - for example when the filtering rules are updated."
        },
        17: {
            "title": "Pipe Created",
            "description": "This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication."
        },
        18: {
            "title": "Pipe Connected",
            "description": "This event logs when a named pipe connection is made between a client and a server."
        },
        19: {
            "title": "WMI Event Filter activity detected",
            "description": "This event logs the registration of WMI filters, which are used by attackers to execute payloads triggered by specific system events."
        },
        20: {
            "title": "WMI Event Consumer activity detected",
            "description": "This event logs the registration of WMI consumers, which can execute commands or scripts in response to WMI events."
        },
        21: {
            "title": "WMI Event Consumer To Filter activity detected",
            "description": "This event logs the binding of WMI consumers to WMI filters, establishing event-triggered execution."
        },
        22: {
            "title": "DNS query",
            "description": "This event generates when a process executes a DNS query, whether the result is successful or fails, cached or not."
        },
        23: {
            "title": "File Delete archived",
            "description": "A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory."
        },
        24: {
            "title": "Clipboard changed",
            "description": "This event generates when the system clipboard contents change. It captures text clipboard contents."
        },
        25: {
            "title": "Process Tampering",
            "description": "This event logs process image changes, which can indicate process hollowing or other injection techniques."
        },
        26: {
            "title": "File Delete logged",
            "description": "A file was deleted. This event logs the file delete without archiving the file."
        },
        27: {
            "title": "File Block Executable",
            "description": "This event logs when Sysmon detects and blocks the creation of executable files in specified locations."
        },
        28: {
            "title": "File Block Shredding",
            "description": "This event logs when Sysmon detects and blocks file shredding operations."
        },
        29: {
            "title": "File Executable Detected",
            "description": "This event logs when an executable file is detected being written to disk."
        }
    }
    
    events = []
    source_url_base = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
    
    for event_id, data in sysmon_events.items():
        events.append({
            'event_id': event_id,
            'event_source': 'Microsoft-Windows-Sysmon/Operational',
            'title': data['title'],
            'description': data['description'],
            'category': 'Sysmon',
            'source_url': source_url_base
        })
    
    logger.info(f"[SYSMON] ✓ Added {len(events)} Sysmon events from Microsoft documentation")
    return events


def scrape_microsoft_security_auditing():
    """
    Scrape security audit event descriptions from Microsoft Learn
    Source: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/
    
    Comprehensive coverage of Windows Security audit events:
    - Account Logon (4768-4777)
    - Account Management (4720-4767)
    - Logon/Logoff (4624, 4625, 4634, 4647, 4648, 4672, etc.)
    - Object Access
    - Policy Change
    - Privilege Use
    - System
    - DS Access
    
    Returns: List of dicts with event_id, title, description, category, source_url
    """
    logger.info("[MS SECURITY] Adding Microsoft Security Auditing events")
    
    # Comprehensive Windows Security Audit Events
    # Source: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/
    security_events = {
        # Account Logon Events
        4768: {
            "title": "A Kerberos authentication ticket (TGT) was requested",
            "description": "This event generates every time the Key Distribution Center issues a Kerberos Ticket Granting Ticket (TGT). This event is generated only on domain controllers.",
            "category": "Account Logon"
        },
        4769: {
            "title": "A Kerberos service ticket was requested",
            "description": "This event generates every time access is requested to a network resource, such as a file share, and a Kerberos service ticket is requested. This event is generated on domain controllers.",
            "category": "Account Logon"
        },
        4770: {
            "title": "A Kerberos service ticket was renewed",
            "description": "This event generates when a Kerberos service ticket is renewed. This typically happens when the ticket lifetime expires and the user continues to access resources.",
            "category": "Account Logon"
        },
        4771: {
            "title": "Kerberos pre-authentication failed",
            "description": "This event generates on a domain controller when Kerberos pre-authentication fails. Pre-authentication failure often indicates an incorrect password or a potential brute force attack.",
            "category": "Account Logon"
        },
        4772: {
            "title": "A Kerberos authentication ticket request failed",
            "description": "This event generates when a request for a Kerberos authentication ticket (TGT) fails. This could indicate account lockout, disabled account, or other authentication issues.",
            "category": "Account Logon"
        },
        4773: {
            "title": "A Kerberos service ticket request failed",
            "description": "This event generates when a Kerberos service ticket request fails. This typically means the requested service principal name (SPN) does not exist.",
            "category": "Account Logon"
        },
        4774: {
            "title": "An account was mapped for logon",
            "description": "This event is generated when an account is mapped for logon. This happens during Kerberos authentication when a certificate is mapped to a user account.",
            "category": "Account Logon"
        },
        4775: {
            "title": "An account could not be mapped for logon",
            "description": "This event is generated when an attempt to map an account for logon fails, often due to certificate mapping issues.",
            "category": "Account Logon"
        },
        4776: {
            "title": "The computer attempted to validate the credentials for an account",
            "description": "This event is generated on the computer that attempted to validate credentials for an account (NTLM authentication). This happens for both domain and local accounts.",
            "category": "Account Logon"
        },
        4777: {
            "title": "The domain controller failed to validate the credentials for an account",
            "description": "This event generates when NTLM authentication fails, typically due to an incorrect password.",
            "category": "Account Logon"
        },
        
        # Logon/Logoff Events  
        4624: {
            "title": "An account was successfully logged on",
            "description": "This event is generated when a logon session is created. It is generated on the computer that was accessed. Logon Type indicates the kind of logon (Interactive, Network, Batch, Service, etc.).",
            "category": "Logon/Logoff"
        },
        4625: {
            "title": "An account failed to log on",
            "description": "This event is generated when a logon request fails. The Failure Code and Sub Status fields provide detailed information about why the logon attempt failed.",
            "category": "Logon/Logoff"
        },
        4634: {
            "title": "An account was logged off",
            "description": "This event is generated when a logon session is destroyed. It is generated on the computer where the session was ended.",
            "category": "Logon/Logoff"
        },
        4647: {
            "title": "User initiated logoff",
            "description": "This event is generated when a logoff is initiated by the user. It provides information about who logged off and when.",
            "category": "Logon/Logoff"
        },
        4648: {
            "title": "A logon was attempted using explicit credentials",
            "description": "This event is generated when a process attempts to log on an account by explicitly specifying that account's credentials (RunAs, NET USE, etc.).",
            "category": "Logon/Logoff"
        },
        4672: {
            "title": "Special privileges assigned to new logon",
            "description": "This event is generated when an account logs on with super user privileges (administrator-level). It shows which special privileges were assigned.",
            "category": "Logon/Logoff"
        },
        
        # Account Management Events
        4720: {
            "title": "A user account was created",
            "description": "This event generates when a new user account is created. It provides information about who created the account and the account attributes.",
            "category": "Account Management"
        },
        4722: {
            "title": "A user account was enabled",
            "description": "This event generates when a user account that was previously disabled is enabled.",
            "category": "Account Management"
        },
        4723: {
            "title": "An attempt was made to change an account's password",
            "description": "This event is generated when a password change is attempted for a user account.",
            "category": "Account Management"
        },
        4724: {
            "title": "An attempt was made to reset an account's password",
            "description": "This event is generated when a password reset is attempted for a user account (administrative password reset).",
            "category": "Account Management"
        },
        4725: {
            "title": "A user account was disabled",
            "description": "This event generates when a user account is disabled. Disabled accounts cannot be used for authentication.",
            "category": "Account Management"
        },
        4726: {
            "title": "A user account was deleted",
            "description": "This event generates when a user account is deleted from Active Directory or the local SAM database.",
            "category": "Account Management"
        },
        4738: {
            "title": "A user account was changed",
            "description": "This event generates when a user account is changed. It shows which attributes were modified.",
            "category": "Account Management"
        },
        4740: {
            "title": "A user account was locked out",
            "description": "This event is generated when a user account is locked out due to too many failed logon attempts.",
            "category": "Account Management"
        },
        4767: {
            "title": "A user account was unlocked",
            "description": "This event is generated when a locked user account is unlocked by an administrator.",
            "category": "Account Management"
        },
        
        # Security Group Management
        4727: {
            "title": "A security-enabled global group was created",
            "description": "This event generates when a new security-enabled global group is created in Active Directory.",
            "category": "Account Management"
        },
        4728: {
            "title": "A member was added to a security-enabled global group",
            "description": "This event generates when a member is added to a security-enabled global group.",
            "category": "Account Management"
        },
        4729: {
            "title": "A member was removed from a security-enabled global group",
            "description": "This event generates when a member is removed from a security-enabled global group.",
            "category": "Account Management"
        },
        4730: {
            "title": "A security-enabled global group was deleted",
            "description": "This event generates when a security-enabled global group is deleted from Active Directory.",
            "category": "Account Management"
        },
        4731: {
            "title": "A security-enabled local group was created",
            "description": "This event generates when a new security-enabled local group is created.",
            "category": "Account Management"
        },
        4732: {
            "title": "A member was added to a security-enabled local group",
            "description": "This event generates when a member is added to a security-enabled local group. This is critical for tracking Administrators group changes.",
            "category": "Account Management"
        },
        4733: {
            "title": "A member was removed from a security-enabled local group",
            "description": "This event generates when a member is removed from a security-enabled local group.",
            "category": "Account Management"
        },
        4734: {
            "title": "A security-enabled local group was deleted",
            "description": "This event generates when a security-enabled local group is deleted.",
            "category": "Account Management"
        },
        4735: {
            "title": "A security-enabled local group was changed",
            "description": "This event generates when a security-enabled local group is modified.",
            "category": "Account Management"
        },
        4737: {
            "title": "A security-enabled global group was changed",
            "description": "This event generates when a security-enabled global group is modified.",
            "category": "Account Management"
        },
        4754: {
            "title": "A security-enabled universal group was created",
            "description": "This event generates when a new security-enabled universal group is created in Active Directory.",
            "category": "Account Management"
        },
        4755: {
            "title": "A security-enabled universal group was changed",
            "description": "This event generates when a security-enabled universal group is modified.",
            "category": "Account Management"
        },
        4756: {
            "title": "A member was added to a security-enabled universal group",
            "description": "This event generates when a member is added to a security-enabled universal group.",
            "category": "Account Management"
        },
        4757: {
            "title": "A member was removed from a security-enabled universal group",
            "description": "This event generates when a member is removed from a security-enabled universal group.",
            "category": "Account Management"
        },
        4758: {
            "title": "A security-enabled universal group was deleted",
            "description": "This event generates when a security-enabled universal group is deleted from Active Directory.",
            "category": "Account Management"
        },
        
        # Computer Account Management
        4741: {
            "title": "A computer account was created",
            "description": "This event generates when a new computer account is created in Active Directory.",
            "category": "Account Management"
        },
        4742: {
            "title": "A computer account was changed",
            "description": "This event generates when a computer account is modified in Active Directory.",
            "category": "Account Management"
        },
        4743: {
            "title": "A computer account was deleted",
            "description": "This event generates when a computer account is deleted from Active Directory.",
            "category": "Account Management"
        },
        
        # Object Access Events
        4656: {
            "title": "A handle to an object was requested",
            "description": "This event generates when a handle is requested for an object (file, registry key, etc.). It shows what permissions were requested.",
            "category": "Object Access"
        },
        4658: {
            "title": "The handle to an object was closed",
            "description": "This event generates when a handle to an object is closed.",
            "category": "Object Access"
        },
        4660: {
            "title": "An object was deleted",
            "description": "This event generates when an object (file, registry key, etc.) is deleted.",
            "category": "Object Access"
        },
        4663: {
            "title": "An attempt was made to access an object",
            "description": "This event generates when an attempt is made to access an object (file, registry key, etc.). It shows what type of access was attempted.",
            "category": "Object Access"
        },
        4670: {
            "title": "Permissions on an object were changed",
            "description": "This event generates when permissions on an object (file, registry key, etc.) are modified.",
            "category": "Object Access"
        },
        
        # System Events
        4608: {
            "title": "Windows is starting up",
            "description": "This event is generated during system startup. It's one of the first security events logged after boot.",
            "category": "System"
        },
        4609: {
            "title": "Windows is shutting down",
            "description": "This event is generated during system shutdown.",
            "category": "System"
        },
        4616: {
            "title": "The system time was changed",
            "description": "This event generates when the system time is changed. This can indicate attempts to hide malicious activity by tampering with logs.",
            "category": "System"
        },
        
        # Policy Change Events
        4719: {
            "title": "System audit policy was changed",
            "description": "This event generates when system audit policy changes are made. Attackers may disable auditing to hide their activities.",
            "category": "Policy Change"
        },
        4739: {
            "title": "Domain Policy was changed",
            "description": "This event generates when domain policy is modified.",
            "category": "Policy Change"
        },
        4765: {
            "title": "SID History was added to an account",
            "description": "This event generates when SID History is added to an account. This can be used by attackers for privilege escalation.",
            "category": "Account Management"
        },
        
        # Special Logon Events
        4964: {
            "title": "Special groups have been assigned to a new logon",
            "description": "This event generates when special groups are assigned to a new logon session.",
            "category": "Logon/Logoff"
        },
        
        # Service Events
        4697: {
            "title": "A service was installed in the system",
            "description": "This event generates when a new service is installed. Many malware families install themselves as services.",
            "category": "System"
        },
        
        # Scheduled Task Events
        4698: {
            "title": "A scheduled task was created",
            "description": "This event generates when a scheduled task is created. Attackers often use scheduled tasks for persistence.",
            "category": "Object Access"
        },
        4699: {
            "title": "A scheduled task was deleted",
            "description": "This event generates when a scheduled task is deleted.",
            "category": "Object Access"
        },
        4700: {
            "title": "A scheduled task was enabled",
            "description": "This event generates when a scheduled task is enabled.",
            "category": "Object Access"
        },
        4701: {
            "title": "A scheduled task was disabled",
            "description": "This event generates when a scheduled task is disabled.",
            "category": "Object Access"
        },
        4702: {
            "title": "A scheduled task was updated",
            "description": "This event generates when a scheduled task is modified.",
            "category": "Object Access"
        }
    }
    
    events = []
    
    for event_id, data in security_events.items():
        events.append({
            'event_id': event_id,
            'event_source': 'Security',
            'title': data['title'],
            'description': data['description'],
            'category': data['category'],
            'source_url': f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}"
        })
    
    logger.info(f"[MS SECURITY] ✓ Added {len(events)} Microsoft Security Auditing events")
    return events


def get_all_enhanced_scrapers():
    """
    Returns all enhanced scrapers as a list of (name, function) tuples
    
    Usage:
        for name, scraper in get_all_enhanced_scrapers():
            events = scraper()
    """
    return [
        ('MyEventLog.com', scrape_myeventlog_com),
        ('Microsoft Sysmon', scrape_microsoft_sysmon),
        ('Microsoft Security Auditing', scrape_microsoft_security_auditing)
    ]

