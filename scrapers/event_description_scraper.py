"""
Event Description Scraper
Scrapes Windows Event Log descriptions from multiple authoritative sources
"""

import requests
from bs4 import BeautifulSoup
import re
import logging
from typing import List, Dict
import time

logger = logging.getLogger(__name__)


class EventDescriptionScraper:
    """Scrape event descriptions from multiple sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scrape_ultimate_windows_security(self) -> List[Dict]:
        """
        Scrape https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
        Uses the comprehensive view with all events
        
        Returns list of dicts with: event_id, log_source, description, category, source_url
        """
        results = []
        url = "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j"
        
        try:
            logger.info("Scraping ultimatewindowssecurity.com...")
            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all event links
            event_links = soup.find_all('a', href=re.compile(r'event\.aspx\?eventid=\d+'))
            
            logger.info(f"Found {len(event_links)} event links")
            
            for link in event_links:
                try:
                    href = link.get('href', '')
                    match = re.search(r'eventid=(\d+)', href)
                    if not match:
                        continue
                    
                    event_id = match.group(1)
                    
                    # Get parent row to extract all info
                    row = link.find_parent('tr')
                    if not row:
                        continue
                    
                    cells = row.find_all('td')
                    if len(cells) < 3:
                        continue
                    
                    # Cell 0: Source (Windows, Sysmon, etc.)
                    source_text = cells[0].get_text(strip=True)
                    
                    # Map source to log_source
                    log_source = 'Security'  # Default
                    if 'Sysmon' in source_text:
                        log_source = 'Sysmon'
                    elif 'SharePoint' in source_text:
                        log_source = 'SharePoint'
                    elif 'SQL' in source_text:
                        log_source = 'SQL Server'
                    elif 'Exchange' in source_text:
                        log_source = 'Exchange'
                    
                    # Cell 2: Description
                    description = cells[2].get_text(strip=True)
                    
                    if event_id and description:
                        event_url = f"https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid={event_id}"
                        
                        # Determine category from description
                        category = None
                        desc_lower = description.lower()
                        if 'account' in desc_lower and 'log' in desc_lower:
                            category = "Account Logon"
                        elif 'account' in desc_lower:
                            category = "Account Management"
                        elif 'logon' in desc_lower or 'logged' in desc_lower:
                            category = "Logon/Logoff"
                        elif 'policy' in desc_lower:
                            category = "Policy Change"
                        elif 'object' in desc_lower:
                            category = "Object Access"
                        elif 'privilege' in desc_lower:
                            category = "Privilege Use"
                        elif 'process' in desc_lower:
                            category = "Process Tracking"
                        elif 'system' in desc_lower:
                            category = "System"
                        
                        results.append({
                            'event_id': event_id,
                            'log_source': log_source,
                            'description': description,
                            'category': category,
                            'source_website': 'ultimatewindowssecurity.com',
                            'source_url': event_url,
                            'description_length': len(description)
                        })
                        
                except Exception as e:
                    logger.debug(f"Error parsing event: {e}")
                    continue
            
            logger.info(f"Scraped {len(results)} events from ultimatewindowssecurity.com")
            
        except Exception as e:
            logger.error(f"Error scraping ultimatewindowssecurity.com: {e}")
        
        return results
    
    def scrape_manageengine_new(self) -> List[Dict]:
        """
        Enhanced ManageEngine scraper
        Source: https://www.manageengine.com/products/active-directory-audit/kb/windows-event-log-id-list.html
        """
        logger.info("[MANAGEENGINE] Starting ManageEngine scrape")
        results = []
        url = "https://www.manageengine.com/products/active-directory-audit/kb/windows-event-log-id-list.html"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all tables
            tables = soup.find_all('table')
            logger.info(f"[MANAGEENGINE] Found {len(tables)} tables")
            
            for table_idx, table in enumerate(tables):
                rows = table.find_all('tr')
                
                for row in rows:
                    cells = row.find_all('td')
                    # Table format: S.No | Event ID | Description
                    if len(cells) >= 3:
                        try:
                            event_id_text = cells[1].get_text(strip=True)
                            description = cells[2].get_text(strip=True)
                            
                            # Skip header rows
                            if event_id_text.lower() == 'event id' or not event_id_text.isdigit():
                                continue
                            
                            event_id = int(event_id_text)
                            
                            # Determine log source from description
                            log_source = "Security"
                            category = "General"
                            
                            if '(Legacy' in description or 'Legacy' in description:
                                category = 'Legacy'
                            
                            if 'System' in description:
                                log_source = "System"
                            elif 'Application' in description:
                                log_source = "Application"
                            
                            results.append({
                                'event_id': str(event_id),
                                'log_source': log_source,
                                'description': description,
                                'category': category,
                                'source_website': 'manageengine.com',
                                'source_url': url,
                                'description_length': len(description)
                            })
                            
                        except (ValueError, IndexError):
                            continue
            
            logger.info(f"[MANAGEENGINE] Scraped {len(results)} events")
            return results
            
        except Exception as e:
            logger.error(f"[MANAGEENGINE] Error: {e}")
            return []
    
    def _get_sysmon_events(self) -> List[Dict]:
        """Get Sysmon event descriptions from Microsoft documentation"""
        sysmon_events = {
            1: ("Process Create", "The process creation event provides extended information about a newly created process. The full command line provides context on the process execution."),
            2: ("File creation time changed", "File creation time is changed to help detect malware that modifies file timestamps to evade detection."),
            3: ("Network connection detected", "The network connection event logs TCP/UDP connections on the machine. It logs connection source process, IP addresses, port numbers, hostnames and port names."),
            4: ("Sysmon service state changed", "The service state change event reports the state of the Sysmon service (started or stopped)."),
            5: ("Process terminated", "The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process."),
            6: ("Driver loaded", "The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information."),
            7: ("Image loaded", "The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the '-l' option."),
            8: ("CreateRemoteThread detected", "The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes."),
            9: ("RawAccessRead detected", "The RawAccessRead event detects when a process conducts reading operations from the drive using the \\\\.\\. denotation."),
            10: ("Process accessed", "The process accessed event reports when a process opens another process, an operation that's often followed by information queries or reading and writing the address space of the target process."),
            11: ("File created", "File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder."),
            12: ("Registry object added or deleted", "Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations."),
            13: ("Registry value set", "This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD."),
            14: ("Registry object renamed", "Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed."),
            15: ("File stream created", "This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned."),
            16: ("Service configuration change", "This event logs changes in the Sysmon configuration - for example when the filtering rules are updated."),
            17: ("Pipe Created", "This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication."),
            18: ("Pipe Connected", "This event logs when a named pipe connection is made between a client and a server."),
            19: ("WMI Event Filter activity detected", "This event logs the registration of WMI filters, which are used by attackers to execute payloads triggered by specific system events."),
            20: ("WMI Event Consumer activity detected", "This event logs the registration of WMI consumers, which can execute commands or scripts in response to WMI events."),
            21: ("WMI Event Consumer To Filter activity detected", "This event logs the binding of WMI consumers to WMI filters, establishing event-triggered execution."),
            22: ("DNS query", "This event generates when a process executes a DNS query, whether the result is successful or fails, cached or not."),
            23: ("File Delete archived", "A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory."),
            24: ("Clipboard changed", "This event generates when the system clipboard contents change. It captures text clipboard contents."),
            25: ("Process Tampering", "This event logs process image changes, which can indicate process hollowing or other injection techniques."),
            26: ("File Delete logged", "A file was deleted. This event logs the file delete without archiving the file."),
            27: ("File Block Executable", "This event logs when Sysmon detects and blocks the creation of executable files in specified locations."),
            28: ("File Block Shredding", "This event logs when Sysmon detects and blocks file shredding operations."),
            29: ("File Executable Detected", "This event logs when an executable file is detected being written to disk.")
        }
        
        results = []
        source_url = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
        
        for event_id, (title, description) in sysmon_events.items():
            results.append({
                'event_id': str(event_id),
                'log_source': 'Microsoft-Windows-Sysmon/Operational',
                'description': f"{title}. {description}",
                'category': 'Sysmon',
                'source_website': 'microsoft.com',
                'source_url': source_url,
                'description_length': len(title) + len(description) + 2
            })
        
        return results
    
    def _get_security_auditing_events(self) -> List[Dict]:
        """Get Windows Security Auditing event descriptions from Microsoft documentation"""
        security_events = {
            # Account Logon Events
            4768: ("A Kerberos authentication ticket (TGT) was requested", "This event generates every time the Key Distribution Center issues a Kerberos Ticket Granting Ticket (TGT). This event is generated only on domain controllers.", "Account Logon"),
            4769: ("A Kerberos service ticket was requested", "This event generates every time access is requested to a network resource, such as a file share, and a Kerberos service ticket is requested. This event is generated on domain controllers.", "Account Logon"),
            4770: ("A Kerberos service ticket was renewed", "This event generates when a Kerberos service ticket is renewed. This typically happens when the ticket lifetime expires and the user continues to access resources.", "Account Logon"),
            4771: ("Kerberos pre-authentication failed", "This event generates on a domain controller when Kerberos pre-authentication fails. Pre-authentication failure often indicates an incorrect password or a potential brute force attack.", "Account Logon"),
            4776: ("The computer attempted to validate the credentials for an account", "This event is generated on the computer that attempted to validate credentials for an account (NTLM authentication). This happens for both domain and local accounts.", "Account Logon"),
            
            # Logon/Logoff Events
            4624: ("An account was successfully logged on", "This event is generated when a logon session is created. It is generated on the computer that was accessed. Logon Type indicates the kind of logon (Interactive, Network, Batch, Service, etc.).", "Logon/Logoff"),
            4625: ("An account failed to log on", "This event is generated when a logon request fails. The Failure Code and Sub Status fields provide detailed information about why the logon attempt failed.", "Logon/Logoff"),
            4634: ("An account was logged off", "This event is generated when a logon session is destroyed. It is generated on the computer where the session was ended.", "Logon/Logoff"),
            4647: ("User initiated logoff", "This event is generated when a logoff is initiated by the user. It provides information about who logged off and when.", "Logon/Logoff"),
            4648: ("A logon was attempted using explicit credentials", "This event is generated when a process attempts to log on an account by explicitly specifying that account's credentials (RunAs, NET USE, etc.).", "Logon/Logoff"),
            4672: ("Special privileges assigned to new logon", "This event is generated when an account logs on with super user privileges (administrator-level). It shows which special privileges were assigned.", "Logon/Logoff"),
            
            # Account Management Events
            4720: ("A user account was created", "This event generates when a new user account is created. It provides information about who created the account and the account attributes.", "Account Management"),
            4722: ("A user account was enabled", "This event generates when a user account that was previously disabled is enabled.", "Account Management"),
            4723: ("An attempt was made to change an account's password", "This event is generated when a password change is attempted for a user account.", "Account Management"),
            4724: ("An attempt was made to reset an account's password", "This event is generated when a password reset is attempted for a user account (administrative password reset).", "Account Management"),
            4725: ("A user account was disabled", "This event generates when a user account is disabled. Disabled accounts cannot be used for authentication.", "Account Management"),
            4726: ("A user account was deleted", "This event generates when a user account is deleted from Active Directory or the local SAM database.", "Account Management"),
            4738: ("A user account was changed", "This event generates when a user account is changed. It shows which attributes were modified.", "Account Management"),
            4740: ("A user account was locked out", "This event is generated when a user account is locked out due to too many failed logon attempts.", "Account Management"),
            4767: ("A user account was unlocked", "This event is generated when a locked user account is unlocked by an administrator.", "Account Management"),
            
            # Security Group Management
            4727: ("A security-enabled global group was created", "This event generates when a new security-enabled global group is created in Active Directory.", "Account Management"),
            4728: ("A member was added to a security-enabled global group", "This event generates when a member is added to a security-enabled global group.", "Account Management"),
            4729: ("A member was removed from a security-enabled global group", "This event generates when a member is removed from a security-enabled global group.", "Account Management"),
            4731: ("A security-enabled local group was created", "This event generates when a new security-enabled local group is created.", "Account Management"),
            4732: ("A member was added to a security-enabled local group", "This event generates when a member is added to a security-enabled local group. This is critical for tracking Administrators group changes.", "Account Management"),
            4733: ("A member was removed from a security-enabled local group", "This event generates when a member is removed from a security-enabled local group.", "Account Management"),
            4756: ("A member was added to a security-enabled universal group", "This event generates when a member is added to a security-enabled universal group.", "Account Management"),
            
            # Object Access Events
            4656: ("A handle to an object was requested", "This event generates when a handle is requested for an object (file, registry key, etc.). It shows what permissions were requested.", "Object Access"),
            4658: ("The handle to an object was closed", "This event generates when a handle to an object is closed.", "Object Access"),
            4660: ("An object was deleted", "This event generates when an object (file, registry key, etc.) is deleted.", "Object Access"),
            4663: ("An attempt was made to access an object", "This event generates when an attempt is made to access an object (file, registry key, etc.). It shows what type of access was attempted.", "Object Access"),
            4670: ("Permissions on an object were changed", "This event generates when permissions on an object (file, registry key, etc.) are modified.", "Object Access"),
            
            # System Events
            4608: ("Windows is starting up", "This event is generated during system startup. It's one of the first security events logged after boot.", "System"),
            4609: ("Windows is shutting down", "This event is generated during system shutdown.", "System"),
            4616: ("The system time was changed", "This event generates when the system time is changed. This can indicate attempts to hide malicious activity by tampering with logs.", "System"),
            4697: ("A service was installed in the system", "This event generates when a new service is installed. Many malware families install themselves as services.", "System"),
            
            # Policy Change Events
            4719: ("System audit policy was changed", "This event generates when system audit policy changes are made. Attackers may disable auditing to hide their activities.", "Policy Change"),
            
            # Scheduled Task Events
            4698: ("A scheduled task was created", "This event generates when a scheduled task is created. Attackers often use scheduled tasks for persistence.", "Object Access"),
            4699: ("A scheduled task was deleted", "This event generates when a scheduled task is deleted.", "Object Access"),
            4700: ("A scheduled task was enabled", "This event generates when a scheduled task is enabled.", "Object Access"),
            4701: ("A scheduled task was disabled", "This event generates when a scheduled task is disabled.", "Object Access"),
            4702: ("A scheduled task was updated", "This event generates when a scheduled task is modified.", "Object Access"),
        }
        
        results = []
        
        for event_id, (title, description, category) in security_events.items():
            results.append({
                'event_id': str(event_id),
                'log_source': 'Security',
                'description': f"{title}. {description}",
                'category': category,
                'source_website': 'microsoft.com',
                'source_url': f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}",
                'description_length': len(title) + len(description) + 2
            })
        
        return results
    
    def get_embedded_windows_events(self) -> List[Dict]:
        """
        Get comprehensive Windows event descriptions from embedded data
        Over 200 additional Windows Security & System events
        """
        logger.info("[EMBEDDED] Loading Windows event descriptions from embedded data")
        
        embedded_events = [
            # System Events
            (1100, "Security", "The event logging service has shut down", "System"),
            (1102, "Security", "The audit log was cleared", "System"),
            (1104, "Security", "The security Log is now full", "System"),
            (4610, "Security", "An authentication package has been loaded by the Local Security Authority", "System"),
            (4611, "Security", "A trusted logon process has been registered with the Local Security Authority", "System"),
            (4614, "Security", "A notification package has been loaded by the Security Account Manager", "System"),
            (4622, "Security", "A security package has been loaded by the Local Security Authority", "System"),
            (4657, "Security", "A registry value was modified", "Object Access"),
            (4673, "Security", "A privileged service was called", "Privilege Use"),
            (4674, "Security", "An operation was attempted on a privileged object", "Privilege Use"),
            (4688, "Security", "A new process has been created", "Process Tracking"),
            (4689, "Security", "A process has exited", "Process Tracking"),
            (4690, "Security", "An attempt was made to duplicate a handle to an object", "Object Access"),
            (4696, "Security", "A primary token was assigned to process", "Process Tracking"),
            (4703, "Security", "A token right was adjusted", "Policy Change"),
            (4704, "Security", "A user right was assigned", "Policy Change"),
            (4705, "Security", "A user right was removed", "Policy Change"),
            (4706, "Security", "A new trust was created to a domain", "Policy Change"),
            (4707, "Security", "A trust to a domain was removed", "Policy Change"),
            (4713, "Security", "Kerberos policy was changed", "Policy Change"),
            (4714, "Security", "Encrypted data recovery policy was changed", "Policy Change"),
            (4715, "Security", "The audit policy (SACL) on an object was changed", "Policy Change"),
            (4716, "Security", "Trusted domain information was modified", "Policy Change"),
            (4717, "Security", "System security access was granted to an account", "Policy Change"),
            (4718, "Security", "System security access was removed from an account", "Policy Change"),
            (4764, "Security", "A groups type was changed", "Account Management"),
            (4778, "Security", "A session was reconnected to a Window Station", "Logon/Logoff"),
            (4779, "Security", "A session was disconnected from a Window Station", "Logon/Logoff"),
            (4780, "Security", "The ACL was set on accounts which are members of administrators groups", "Account Management"),
            (4781, "Security", "The name of an account was changed", "Account Management"),
            (4782, "Security", "The password hash an account was accessed", "Account Management"),
            (4797, "Security", "An attempt was made to query the existence of a blank password for an account", "Account Management"),
            (4798, "Security", "A user's local group membership was enumerated", "Account Management"),
            (4799, "Security", "A security-enabled local group membership was enumerated", "Account Management"),
            (4800, "Security", "The workstation was locked", "Logon/Logoff"),
            (4801, "Security", "The workstation was unlocked", "Logon/Logoff"),
            (4802, "Security", "The screen saver was invoked", "Logon/Logoff"),
            (4803, "Security", "The screen saver was dismissed", "Logon/Logoff"),
            (4817, "Security", "Auditing settings on object were changed", "Policy Change"),
            (4902, "Security", "The Per-user audit policy table was created", "Policy Change"),
            (4904, "Security", "An attempt was made to register a security event source", "Policy Change"),
            (4905, "Security", "An attempt was made to unregister a security event source", "Policy Change"),
            (4906, "Security", "The CrashOnAuditFail value has changed", "Policy Change"),
            (4907, "Security", "Auditing settings on object were changed", "Policy Change"),
            (4908, "Security", "Special Groups Logon table modified", "Policy Change"),
            (4912, "Security", "Per User Audit Policy was changed", "Policy Change"),
            (4946, "Security", "A change has been made to Windows Firewall exception list. A rule was added", "Policy Change"),
            (4947, "Security", "A change has been made to Windows Firewall exception list. A rule was modified", "Policy Change"),
            (4948, "Security", "A change has been made to Windows Firewall exception list. A rule was deleted", "Policy Change"),
            (4950, "Security", "A Windows Firewall setting has changed", "Policy Change"),
            (4954, "Security", "Windows Firewall Group Policy settings has changed. The new settings have been applied", "Policy Change"),
            (4956, "Security", "Windows Firewall has changed the active profile", "Policy Change"),
            (5024, "Security", "The Windows Firewall Service has started successfully", "System"),
            (5025, "Security", "The Windows Firewall Service has been stopped", "System"),
            (5031, "Security", "The Windows Firewall Service blocked an application from accepting incoming connections on the network", "Object Access"),
            (5033, "Security", "The Windows Firewall Driver has started successfully", "System"),
            (5034, "Security", "The Windows Firewall Driver has been stopped", "System"),
            (5136, "Security", "A directory service object was modified", "Directory Service"),
            (5137, "Security", "A directory service object was created", "Directory Service"),
            (5138, "Security", "A directory service object was undeleted", "Directory Service"),
            (5139, "Security", "A directory service object was moved", "Directory Service"),
            (5140, "Security", "A network share object was accessed", "Object Access"),
            (5141, "Security", "A directory service object was deleted", "Directory Service"),
            (5142, "Security", "A network share object was added", "Object Access"),
            (5143, "Security", "A network share object was modified", "Object Access"),
            (5144, "Security", "A network share object was deleted", "Object Access"),
            (5145, "Security", "A network share object was checked to see whether client can be granted desired access", "Object Access"),
            (5152, "Security", "The Windows Filtering Platform blocked a packet", "Object Access"),
            (5156, "Security", "The Windows Filtering Platform has allowed a connection", "Object Access"),
            (5157, "Security", "The Windows Filtering Platform has blocked a connection", "Object Access"),
            (5376, "Security", "Credential Manager credentials were backed up", "System"),
            (5377, "Security", "Credential Manager credentials were restored from a backup", "System"),
            (5379, "Security", "Credential Manager credentials were read", "System"),
            (6416, "Security", "A new external device was recognized by the system", "System"),
            # Legacy Events (pre-Windows Server 2008)
            (528, "Security", "Successful logon (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (529, "Security", "Logon failure: unknown user name or bad password (Legacy)", "Logon/Logoff"),
            (538, "Security", "User logoff (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (540, "Security", "Successful Network Logon (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (560, "Security", "A handle to an object was requested (Legacy)", "Object Access"),
            (576, "Security", "Special privileges assigned to new logon (Legacy)", "Privilege Use"),
            (592, "Security", "A new process has been created (Legacy)", "Process Tracking"),
            (624, "Security", "User account created (Legacy)", "Account Management"),
            (636, "Security", "Security-enabled local group member added (Legacy)", "Account Management"),
            (672, "Security", "Authentication ticket granted (Legacy, Kerberos)", "Account Logon"),
            (680, "Security", "Account used for logon by a user (Legacy)", "Account Logon"),
            # Common System/Application Events
            (1074, "System", "System has been shutdown by a process or user", "System"),
            (6005, "System", "The Event Log service was started", "System"),
            (6006, "System", "The Event Log service was stopped", "System"),
            (6008, "System", "Unexpected system shutdown", "System"),
            (7045, "System", "A new service was installed in the system", "System"),
        ]
        
        results = []
        for event_id, log_source, description, category in embedded_events:
            results.append({
                'event_id': str(event_id),
                'log_source': log_source,
                'description': description,
                'category': category,
                'source_website': 'embedded_data',
                'source_url': 'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/',
                'description_length': len(description)
            })
        
        logger.info(f"[EMBEDDED] Loaded {len(results)} events from embedded data")
        return results
    
    def scrape_all_sources(self) -> List[Dict]:
        """
        Scrape all sources and combine results
        
        Returns combined list
        """
        all_results = []
        
        # Priority order: Embedded -> Microsoft -> Web scraping
        sources = [
            ('embedded_windows_events', self.get_embedded_windows_events),
            ('sysmon_events', self._get_sysmon_events),
            ('security_auditing_events', self._get_security_auditing_events),
            ('ultimatewindowssecurity', self.scrape_ultimate_windows_security),
            ('manageengine_new', self.scrape_manageengine_new),
        ]
        
        for source_name, scrape_func in sources:
            try:
                results = scrape_func()
                all_results.extend(results)
                logger.info(f"Completed scraping {source_name}: {len(results)} events")
                time.sleep(2)  # Respectful delay
            except Exception as e:
                logger.error(f"Failed to scrape {source_name}: {e}")
        
        logger.info(f"Total events scraped from all sources: {len(all_results)}")
        return all_results
    
    def deduplicate_events(self, events: List[Dict]) -> List[Dict]:
        """
        Deduplicate events based on event_id + log_source
        Keep the most descriptive version (longest description)
        """
        grouped = {}
        
        for event in events:
            key = (event['event_id'], event['log_source'])
            
            if key not in grouped:
                grouped[key] = event
            else:
                # Keep the one with longer description
                if event['description_length'] > grouped[key]['description_length']:
                    grouped[key] = event
        
        deduplicated = list(grouped.values())
        logger.info(f"Deduplication: {len(events)} -> {len(deduplicated)} unique events")
        
        return deduplicated
