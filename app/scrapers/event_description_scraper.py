"""
Event Description Scraper
Scrapes Windows Event Log descriptions from multiple authoritative sources
Enhanced with working scrapers from old_site
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
        # Use the comprehensive view that shows ALL events on one page
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
            import traceback
            traceback.print_exc()
        
        return results
    
    def scrape_myeventlog(self) -> List[Dict]:
        """
        Scrape https://www.myeventlog.com/search/browse
        
        Returns list of dicts with: event_id, log_source, description, source_url
        """
        results = []
        base_url = "https://www.myeventlog.com"
        browse_url = f"{base_url}/search/browse"
        
        try:
            logger.info("Scraping myeventlog.com...")
            response = self.session.get(browse_url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find event source links
            source_links = soup.find_all('a', href=re.compile(r'/search/show/\?source='))
            
            logger.info(f"Found {len(source_links)} event sources on myeventlog.com")
            
            # Focus on major sources
            major_sources = [
                'Security', 'System', 'Application', 'Microsoft-Windows-Security-Auditing',
                'Microsoft-Windows-Sysmon', 'PowerShell', 'TaskScheduler'
            ]
            
            processed_sources = 0
            for link in source_links:
                try:
                    source_text = link.get_text(strip=True)
                    
                    # Only process first 10 sources or major ones
                    if processed_sources >= 10 and not any(major in source_text for major in major_sources):
                        continue
                    
                    href = link.get('href', '')
                    if not href:
                        continue
                    
                    source_url = f"{base_url}{href}" if href.startswith('/') else href
                    
                    logger.info(f"Scraping myeventlog source: {source_text}")
                    
                    source_response = self.session.get(source_url, timeout=30)
                    source_response.raise_for_status()
                    
                    source_soup = BeautifulSoup(source_response.content, 'html.parser')
                    
                    # Find event entries
                    event_rows = source_soup.find_all('tr')
                    
                    for row in event_rows:
                        cells = row.find_all('td')
                        if len(cells) < 2:
                            continue
                        
                        event_id_text = cells[0].get_text(strip=True)
                        event_id_match = re.match(r'^(\d+)$', event_id_text)
                        
                        if not event_id_match:
                            continue
                        
                        event_id = event_id_match.group(1)
                        description = cells[1].get_text(strip=True)
                        
                        if event_id and description:
                            results.append({
                                'event_id': event_id,
                                'log_source': source_text if source_text else 'Security',
                                'description': description,
                                'category': source_text,
                                'source_website': 'myeventlog.com',
                                'source_url': source_url,
                                'description_length': len(description)
                            })
                    
                    processed_sources += 1
                    time.sleep(1)  # Rate limiting
                    
                    if processed_sources >= 10:
                        break
                        
                except Exception as e:
                    logger.debug(f"Error processing source {source_text}: {e}")
                    continue
            
            logger.info(f"Scraped {len(results)} events from myeventlog.com")
            
        except Exception as e:
            logger.error(f"Error scraping myeventlog.com: {e}")
            import traceback
            traceback.print_exc()
        
        return results
    
    def scrape_manageengine_new(self) -> List[Dict]:
        """
        Enhanced ManageEngine scraper from updated script
        Source: https://www.manageengine.com/products/active-directory-audit/kb/windows-event-log-id-list.html
        """
        logger.info("[MANAGEENGINE] Starting ManageEngine scrape (new method)")
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
                logger.info(f"[MANAGEENGINE] Table {table_idx + 1}: {len(rows)} rows")
                
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
                            
                            # Determine log source from description or default to Security
                            log_source = "Security"
                            category = "General"
                            
                            if '(Legacy' in description or 'Legacy' in description:
                                category = 'Legacy'
                            
                            # Check for other log sources in description
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
                            
                        except (ValueError, IndexError) as e:
                            logger.debug(f"[MANAGEENGINE] Error parsing row: {e}")
                            continue
            
            logger.info(f"[MANAGEENGINE] ✓ Scraped {len(results)} events")
            return results
            
        except Exception as e:
            logger.error(f"[MANAGEENGINE] Error: {e}", exc_info=True)
            return []
    
    def scrape_manageengine(self) -> List[Dict]:
        """
        Add Microsoft Sysmon and Security Auditing events from documentation
        These are well-documented events that don't need web scraping
        
        Returns list of dicts with: event_id, log_source, description, source_url
        """
        results = []
        
        # Add Sysmon events (29 events from Microsoft documentation)
        results.extend(self._get_sysmon_events())
        
        # Add Microsoft Security Auditing events (comprehensive set)
        results.extend(self._get_security_auditing_events())
        
        logger.info(f"Added {len(results)} events from Microsoft documentation")
        
        return results
    
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
            4772: ("A Kerberos authentication ticket request failed", "This event generates when a request for a Kerberos authentication ticket (TGT) fails. This could indicate account lockout, disabled account, or other authentication issues.", "Account Logon"),
            4773: ("A Kerberos service ticket request failed", "This event generates when a Kerberos service ticket request fails. This typically means the requested service principal name (SPN) does not exist.", "Account Logon"),
            4774: ("An account was mapped for logon", "This event is generated when an account is mapped for logon. This happens during Kerberos authentication when a certificate is mapped to a user account.", "Account Logon"),
            4775: ("An account could not be mapped for logon", "This event is generated when an attempt to map an account for logon fails, often due to certificate mapping issues.", "Account Logon"),
            4776: ("The computer attempted to validate the credentials for an account", "This event is generated on the computer that attempted to validate credentials for an account (NTLM authentication). This happens for both domain and local accounts.", "Account Logon"),
            4777: ("The domain controller failed to validate the credentials for an account", "This event generates when NTLM authentication fails, typically due to an incorrect password.", "Account Logon"),
            
            # Logon/Logoff Events
            4624: ("An account was successfully logged on", "This event is generated when a logon session is created. It is generated on the computer that was accessed. Logon Type indicates the kind of logon (Interactive, Network, Batch, Service, etc.).", "Logon/Logoff"),
            4625: ("An account failed to log on", "This event is generated when a logon request fails. The Failure Code and Sub Status fields provide detailed information about why the logon attempt failed.", "Logon/Logoff"),
            4634: ("An account was logged off", "This event is generated when a logon session is destroyed. It is generated on the computer where the session was ended.", "Logon/Logoff"),
            4647: ("User initiated logoff", "This event is generated when a logoff is initiated by the user. It provides information about who logged off and when.", "Logon/Logoff"),
            4648: ("A logon was attempted using explicit credentials", "This event is generated when a process attempts to log on an account by explicitly specifying that account's credentials (RunAs, NET USE, etc.).", "Logon/Logoff"),
            4672: ("Special privileges assigned to new logon", "This event is generated when an account logs on with super user privileges (administrator-level). It shows which special privileges were assigned.", "Logon/Logoff"),
            4964: ("Special groups have been assigned to a new logon", "This event generates when special groups are assigned to a new logon session.", "Logon/Logoff"),
            
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
            4765: ("SID History was added to an account", "This event generates when SID History is added to an account. This can be used by attackers for privilege escalation.", "Account Management"),
            
            # Security Group Management
            4727: ("A security-enabled global group was created", "This event generates when a new security-enabled global group is created in Active Directory.", "Account Management"),
            4728: ("A member was added to a security-enabled global group", "This event generates when a member is added to a security-enabled global group.", "Account Management"),
            4729: ("A member was removed from a security-enabled global group", "This event generates when a member is removed from a security-enabled global group.", "Account Management"),
            4730: ("A security-enabled global group was deleted", "This event generates when a security-enabled global group is deleted from Active Directory.", "Account Management"),
            4731: ("A security-enabled local group was created", "This event generates when a new security-enabled local group is created.", "Account Management"),
            4732: ("A member was added to a security-enabled local group", "This event generates when a member is added to a security-enabled local group. This is critical for tracking Administrators group changes.", "Account Management"),
            4733: ("A member was removed from a security-enabled local group", "This event generates when a member is removed from a security-enabled local group.", "Account Management"),
            4734: ("A security-enabled local group was deleted", "This event generates when a security-enabled local group is deleted.", "Account Management"),
            4735: ("A security-enabled local group was changed", "This event generates when a security-enabled local group is modified.", "Account Management"),
            4737: ("A security-enabled global group was changed", "This event generates when a security-enabled global group is modified.", "Account Management"),
            4754: ("A security-enabled universal group was created", "This event generates when a new security-enabled universal group is created in Active Directory.", "Account Management"),
            4755: ("A security-enabled universal group was changed", "This event generates when a security-enabled universal group is modified.", "Account Management"),
            4756: ("A member was added to a security-enabled universal group", "This event generates when a member is added to a security-enabled universal group.", "Account Management"),
            4757: ("A member was removed from a security-enabled universal group", "This event generates when a member is removed from a security-enabled universal group.", "Account Management"),
            4758: ("A security-enabled universal group was deleted", "This event generates when a security-enabled universal group is deleted from Active Directory.", "Account Management"),
            
            # Computer Account Management
            4741: ("A computer account was created", "This event generates when a new computer account is created in Active Directory.", "Account Management"),
            4742: ("A computer account was changed", "This event generates when a computer account is modified in Active Directory.", "Account Management"),
            4743: ("A computer account was deleted", "This event generates when a computer account is deleted from Active Directory.", "Account Management"),
            
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
            4739: ("Domain Policy was changed", "This event generates when domain policy is modified.", "Policy Change"),
            
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
        Source: Compiled from ultimatewindowssecurity.com and manageengine.com
        Over 200 additional Windows Security & System events
        """
        logger.info("[EMBEDDED] Loading Windows event descriptions from embedded data")
        
        # This is a curated list of Windows events from the old_site script
        # These are stable, documented events that don't require web scraping
        embedded_events = [
            # System Events
            (1100, "Security", "The event logging service has shut down", "System"),
            (1101, "Security", "Audit events have been dropped by the transport", "System"),
            (1102, "Security", "The audit log was cleared", "System"),
            (1104, "Security", "The security Log is now full", "System"),
            (1105, "Security", "Event log automatic backup", "System"),
            (1108, "Security", "The event logging service encountered an error", "System"),
            (4610, "Security", "An authentication package has been loaded by the Local Security Authority", "System"),
            (4611, "Security", "A trusted logon process has been registered with the Local Security Authority", "System"),
            (4612, "Security", "Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits", "System"),
            (4614, "Security", "A notification package has been loaded by the Security Account Manager", "System"),
            (4615, "Security", "Invalid use of LPC port", "System"),
            (4618, "Security", "A monitored security event pattern has occurred", "System"),
            (4621, "Security", "Administrator recovered system from CrashOnAuditFail", "System"),
            (4622, "Security", "A security package has been loaded by the Local Security Authority", "System"),
            (4626, "Security", "User/Device claims information", "Logon/Logoff"),
            (4627, "Security", "Group membership information", "Logon/Logoff"),
            (4646, "Security", "IKE DoS-prevention mode started", "System"),
            (4649, "Security", "A replay attack was detected", "System"),
            (4650, "Security", "An IPsec Main Mode security association was established", "System"),
            (4651, "Security", "An IPsec Main Mode security association was established", "System"),
            (4652, "Security", "An IPsec Main Mode negotiation failed", "System"),
            (4653, "Security", "An IPsec Main Mode negotiation failed", "System"),
            (4654, "Security", "An IPsec Quick Mode negotiation failed", "System"),
            (4655, "Security", "An IPsec Main Mode security association ended", "System"),
            (4657, "Security", "A registry value was modified", "Object Access"),
            (4658, "Security", "The handle to an object was closed", "Object Access"),
            (4659, "Security", "A handle to an object was requested with intent to delete", "Object Access"),
            (4661, "Security", "A handle to an object was requested", "Object Access"),
            (4662, "Security", "An operation was performed on an object", "Object Access"),
            (4664, "Security", "An attempt was made to create a hard link", "Object Access"),
            (4665, "Security", "An attempt was made to create an application client context", "Object Access"),
            (4666, "Security", "An application attempted an operation", "Object Access"),
            (4667, "Security", "An application client context was deleted", "Object Access"),
            (4668, "Security", "An application was initialized", "Object Access"),
            (4671, "Security", "An application attempted to access a blocked ordinal through the TBS", "Object Access"),
            (4673, "Security", "A privileged service was called", "Privilege Use"),
            (4674, "Security", "An operation was attempted on a privileged object", "Privilege Use"),
            (4675, "Security", "SIDs were filtered", "Logon/Logoff"),
            (4688, "Security", "A new process has been created", "Process Tracking"),
            (4689, "Security", "A process has exited", "Process Tracking"),
            (4690, "Security", "An attempt was made to duplicate a handle to an object", "Object Access"),
            (4691, "Security", "Indirect access to an object was requested", "Object Access"),
            (4692, "Security", "Backup of data protection master key was attempted", "System"),
            (4693, "Security", "Recovery of data protection master key was attempted", "System"),
            (4694, "Security", "Protection of auditable protected data was attempted", "System"),
            (4695, "Security", "Unprotection of auditable protected data was attempted", "System"),
            (4696, "Security", "A primary token was assigned to process", "Process Tracking"),
            (4703, "Security", "A token right was adjusted", "Policy Change"),
            (4704, "Security", "A user right was assigned", "Policy Change"),
            (4705, "Security", "A user right was removed", "Policy Change"),
            (4706, "Security", "A new trust was created to a domain", "Policy Change"),
            (4707, "Security", "A trust to a domain was removed", "Policy Change"),
            (4709, "Security", "IPsec Services was started", "System"),
            (4710, "Security", "IPsec Services was disabled", "System"),
            (4711, "Security", "PAStore Engine", "System"),
            (4712, "Security", "IPsec Services encountered a potentially serious failure", "System"),
            (4713, "Security", "Kerberos policy was changed", "Policy Change"),
            (4714, "Security", "Encrypted data recovery policy was changed", "Policy Change"),
            (4715, "Security", "The audit policy (SACL) on an object was changed", "Policy Change"),
            (4716, "Security", "Trusted domain information was modified", "Policy Change"),
            (4717, "Security", "System security access was granted to an account", "Policy Change"),
            (4718, "Security", "System security access was removed from an account", "Policy Change"),
            (4764, "Security", "A groups type was changed", "Account Management"),
            (4766, "Security", "An attempt to add SID History to an account failed", "Account Management"),
            (4778, "Security", "A session was reconnected to a Window Station", "Logon/Logoff"),
            (4779, "Security", "A session was disconnected from a Window Station", "Logon/Logoff"),
            (4780, "Security", "The ACL was set on accounts which are members of administrators groups", "Account Management"),
            (4781, "Security", "The name of an account was changed", "Account Management"),
            (4782, "Security", "The password hash an account was accessed", "Account Management"),
            (4783, "Security", "A basic application group was created", "Account Management"),
            (4784, "Security", "A basic application group was changed", "Account Management"),
            (4785, "Security", "A member was added to a basic application group", "Account Management"),
            (4786, "Security", "A member was removed from a basic application group", "Account Management"),
            (4787, "Security", "A non-member was added to a basic application group", "Account Management"),
            (4788, "Security", "A non-member was removed from a basic application group", "Account Management"),
            (4789, "Security", "A basic application group was deleted", "Account Management"),
            (4790, "Security", "An LDAP query group was created", "Account Management"),
            (4791, "Security", "A basic application group was changed", "Account Management"),
            (4792, "Security", "An LDAP query group was deleted", "Account Management"),
            (4793, "Security", "The Password Policy Checking API was called", "System"),
            (4794, "Security", "An attempt was made to set the Directory Services Restore Mode administrator password", "Account Management"),
            (4797, "Security", "An attempt was made to query the existence of a blank password for an account", "Account Management"),
            (4798, "Security", "A user's local group membership was enumerated", "Account Management"),
            (4799, "Security", "A security-enabled local group membership was enumerated", "Account Management"),
            (4800, "Security", "The workstation was locked", "Logon/Logoff"),
            (4801, "Security", "The workstation was unlocked", "Logon/Logoff"),
            (4802, "Security", "The screen saver was invoked", "Logon/Logoff"),
            (4803, "Security", "The screen saver was dismissed", "Logon/Logoff"),
            (4816, "Security", "RPC detected an integrity violation while decrypting an incoming message", "System"),
            (4817, "Security", "Auditing settings on object were changed", "Policy Change"),
            (4818, "Security", "Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy", "Policy Change"),
            (4819, "Security", "Central Access Policies on the machine have been changed", "Policy Change"),
            (4820, "Security", "A Kerberos Ticket-granting-ticket (TGT) was denied because the device does not meet the access control restrictions", "Account Logon"),
            (4821, "Security", "A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions", "Account Logon"),
            (4822, "Security", "NTLM authentication failed because the account was a member of the Protected User group", "Account Logon"),
            (4823, "Security", "NTLM authentication failed because access control restrictions are required", "Account Logon"),
            (4824, "Security", "Kerberos preauthentication by using DES or RC4 failed because the account was a member of the Protected User group", "Account Logon"),
            (4825, "Security", "A user was denied the access to Remote Desktop", "Logon/Logoff"),
            (4826, "Security", "Boot Configuration Data loaded", "System"),
            (4830, "Security", "SID History was removed from an account", "Account Management"),
            (4864, "Security", "A namespace collision was detected", "Directory Service"),
            (4865, "Security", "A trusted forest information entry was added", "Directory Service"),
            (4866, "Security", "A trusted forest information entry was removed", "Directory Service"),
            (4867, "Security", "A trusted forest information entry was modified", "Directory Service"),
            (4902, "Security", "The Per-user audit policy table was created", "Policy Change"),
            (4904, "Security", "An attempt was made to register a security event source", "Policy Change"),
            (4905, "Security", "An attempt was made to unregister a security event source", "Policy Change"),
            (4906, "Security", "The CrashOnAuditFail value has changed", "Policy Change"),
            (4907, "Security", "Auditing settings on object were changed", "Policy Change"),
            (4908, "Security", "Special Groups Logon table modified", "Policy Change"),
            (4909, "Security", "The local policy settings for the TBS were changed", "Policy Change"),
            (4910, "Security", "The group policy settings for the TBS were changed", "Policy Change"),
            (4911, "Security", "Resource attributes of the object were changed", "Object Access"),
            (4912, "Security", "Per User Audit Policy was changed", "Policy Change"),
            (4913, "Security", "Central Access Policy on the object was changed", "Policy Change"),
            (4928, "Security", "An Active Directory replica source naming context was established", "Directory Service"),
            (4929, "Security", "An Active Directory replica source naming context was removed", "Directory Service"),
            (4930, "Security", "An Active Directory replica source naming context was modified", "Directory Service"),
            (4931, "Security", "An Active Directory replica destination naming context was modified", "Directory Service"),
            (4932, "Security", "Synchronization of a replica of an Active Directory naming context has begun", "Directory Service"),
            (4933, "Security", "Synchronization of a replica of an Active Directory naming context has ended", "Directory Service"),
            (4934, "Security", "Attributes of an Active Directory object were replicated", "Directory Service"),
            (4935, "Security", "Replication failure begins", "Directory Service"),
            (4936, "Security", "Replication failure ends", "Directory Service"),
            (4937, "Security", "A lingering object was removed from a replica", "Directory Service"),
            (4944, "Security", "The following policy was active when the Windows Firewall started", "Policy Change"),
            (4945, "Security", "A rule was listed when the Windows Firewall started", "Policy Change"),
            (4946, "Security", "A change has been made to Windows Firewall exception list. A rule was added", "Policy Change"),
            (4947, "Security", "A change has been made to Windows Firewall exception list. A rule was modified", "Policy Change"),
            (4948, "Security", "A change has been made to Windows Firewall exception list. A rule was deleted", "Policy Change"),
            (4949, "Security", "Windows Firewall settings were restored to the default values", "Policy Change"),
            (4950, "Security", "A Windows Firewall setting has changed", "Policy Change"),
            (4951, "Security", "A rule has been ignored because its major version number was not recognized by Windows Firewall", "Policy Change"),
            (4952, "Security", "Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall", "Policy Change"),
            (4953, "Security", "A rule has been ignored by Windows Firewall because it could not parse the rule", "Policy Change"),
            (4954, "Security", "Windows Firewall Group Policy settings has changed. The new settings have been applied", "Policy Change"),
            (4956, "Security", "Windows Firewall has changed the active profile", "Policy Change"),
            (4957, "Security", "Windows Firewall did not apply the following rule", "Policy Change"),
            (4958, "Security", "Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer", "Policy Change"),
            (4964, "Security", "Special groups have been assigned to a new logon", "Logon/Logoff"),
            (5024, "Security", "The Windows Firewall Service has started successfully", "System"),
            (5025, "Security", "The Windows Firewall Service has been stopped", "System"),
            (5027, "Security", "The Windows Firewall Service was unable to retrieve the security policy from the local storage", "System"),
            (5028, "Security", "The Windows Firewall Service was unable to parse the new security policy", "System"),
            (5029, "Security", "The Windows Firewall Service failed to initialize the driver", "System"),
            (5030, "Security", "The Windows Firewall Service failed to start", "System"),
            (5031, "Security", "The Windows Firewall Service blocked an application from accepting incoming connections on the network", "Object Access"),
            (5032, "Security", "Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network", "System"),
            (5033, "Security", "The Windows Firewall Driver has started successfully", "System"),
            (5034, "Security", "The Windows Firewall Driver has been stopped", "System"),
            (5035, "Security", "The Windows Firewall Driver failed to start", "System"),
            (5037, "Security", "The Windows Firewall Driver detected critical runtime error. Terminating", "System"),
            (5038, "Security", "Code integrity determined that the image hash of a file is not valid", "System"),
            (5039, "Security", "A registry key was virtualized", "Object Access"),
            (5051, "Security", "A file was virtualized", "Object Access"),
            (5056, "Security", "A cryptographic self test was performed", "System"),
            (5057, "Security", "A cryptographic primitive operation failed", "System"),
            (5058, "Security", "Key file operation", "System"),
            (5059, "Security", "Key migration operation", "System"),
            (5060, "Security", "Verification operation failed", "System"),
            (5061, "Security", "Cryptographic operation", "System"),
            (5062, "Security", "A kernel-mode cryptographic self test was performed", "System"),
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
            (5154, "Security", "The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections", "Object Access"),
            (5155, "Security", "The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections", "Object Access"),
            (5156, "Security", "The Windows Filtering Platform has allowed a connection", "Object Access"),
            (5157, "Security", "The Windows Filtering Platform has blocked a connection", "Object Access"),
            (5158, "Security", "The Windows Filtering Platform has permitted a bind to a local port", "Object Access"),
            (5159, "Security", "The Windows Filtering Platform has blocked a bind to a local port", "Object Access"),
            (5168, "Security", "Spn check for SMB/SMB2 fails", "Object Access"),
            (5376, "Security", "Credential Manager credentials were backed up", "System"),
            (5377, "Security", "Credential Manager credentials were restored from a backup", "System"),
            (5378, "Security", "The requested credentials delegation was disallowed by policy", "Logon/Logoff"),
            (5379, "Security", "Credential Manager credentials were read", "System"),
            (5632, "Security", "A request was made to authenticate to a wireless network", "Logon/Logoff"),
            (5633, "Security", "A request was made to authenticate to a wired network", "Logon/Logoff"),
            (5712, "Security", "A Remote Procedure Call (RPC) was attempted", "Object Access"),
            (5888, "Security", "An object in the COM+ Catalog was modified", "Object Access"),
            (5889, "Security", "An object was deleted from the COM+ Catalog", "Object Access"),
            (5890, "Security", "An object was added to the COM+ Catalog", "Object Access"),
            (6144, "Security", "Security policy in the group policy objects has been applied successfully", "Policy Change"),
            (6145, "Security", "One or more errors occured while processing security policy in the group policy objects", "Policy Change"),
            (6272, "Security", "Network Policy Server granted access to a user", "Logon/Logoff"),
            (6273, "Security", "Network Policy Server denied access to a user", "Logon/Logoff"),
            (6274, "Security", "Network Policy Server discarded the request for a user", "Logon/Logoff"),
            (6275, "Security", "Network Policy Server discarded the accounting request for a user", "Logon/Logoff"),
            (6276, "Security", "Network Policy Server quarantined a user", "Logon/Logoff"),
            (6277, "Security", "Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy", "Logon/Logoff"),
            (6278, "Security", "Network Policy Server granted full access to a user because the host met the defined health policy", "Logon/Logoff"),
            (6279, "Security", "Network Policy Server locked the user account due to repeated failed authentication attempts", "Logon/Logoff"),
            (6280, "Security", "Network Policy Server unlocked the user account", "Logon/Logoff"),
            (6281, "Security", "Code Integrity determined that the page hashes of an image file are not valid", "System"),
            (6416, "Security", "A new external device was recognized by the system", "System"),
            (6419, "Security", "A request was made to disable a device", "System"),
            (6420, "Security", "A device was disabled", "System"),
            (6421, "Security", "A request was made to enable a device", "System"),
            (6422, "Security", "A device was enabled", "System"),
            (6423, "Security", "The installation of this device is forbidden by system policy", "System"),
            (6424, "Security", "The installation of this device was allowed, after having previously been forbidden by policy", "System"),
            (8191, "Security", "Highest System-Defined Audit Message Value", "System"),
            # Legacy Events (pre-Windows Server 2008)
            (512, "Security", "Windows NT is starting up (Legacy)", "System"),
            (513, "Security", "Windows NT is shutting down (Legacy)", "System"),
            (514, "Security", "An authentication package was loaded by the Local Security Authority (Legacy)", "System"),
            (515, "Security", "Trusted logon process has been registered with the Local Security Authority (Legacy)", "System"),
            (516, "Security", "Extranet lockout - user account locked out due to bad password submissions (Legacy)", "Account Logon"),
            (517, "Security", "The audit log was cleared (Legacy)", "System"),
            (528, "Security", "Successful logon (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (529, "Security", "Logon failure: unknown user name or bad password (Legacy)", "Logon/Logoff"),
            (530, "Security", "Logon failure: account logon time restriction violation (Legacy)", "Logon/Logoff"),
            (531, "Security", "Logon failure: account currently disabled (Legacy)", "Logon/Logoff"),
            (532, "Security", "Logon failure: account expired (Legacy)", "Logon/Logoff"),
            (533, "Security", "Logon failure: account not allowed to log on at this computer (Legacy)", "Logon/Logoff"),
            (534, "Security", "Logon failure: the user has not been granted the requested logon type at this machine (Legacy)", "Logon/Logoff"),
            (535, "Security", "Logon failure: the specified account's password has expired (Legacy)", "Logon/Logoff"),
            (536, "Security", "Logon failure: NetLogon service is not active (Legacy)", "Logon/Logoff"),
            (537, "Security", "Logon failure: unknown reason or internal error (Legacy)", "Logon/Logoff"),
            (538, "Security", "User logoff (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (539, "Security", "Logon failure: account locked out (Legacy)", "Logon/Logoff"),
            (540, "Security", "Successful Network Logon (Legacy, pre-Windows Server 2008)", "Logon/Logoff"),
            (551, "Security", "User initiated logoff (Legacy)", "Logon/Logoff"),
            (552, "Security", "Logon attempt using explicit credentials (Legacy)", "Logon/Logoff"),
            (560, "Security", "A handle to an object was requested (Legacy)", "Object Access"),
            (563, "Security", "An object was opened for deletion (Legacy)", "Object Access"),
            (564, "Security", "An object was deleted (Legacy)", "Object Access"),
            (567, "Security", "An attempt was made to access an object (Legacy)", "Object Access"),
            (576, "Security", "Special privileges assigned to new logon (Legacy)", "Privilege Use"),
            (577, "Security", "Privileged service called (Legacy)", "Privilege Use"),
            (592, "Security", "A new process has been created (Legacy)", "Process Tracking"),
            (593, "Security", "A process exited (Legacy)", "Process Tracking"),
            (624, "Security", "User account created (Legacy)", "Account Management"),
            (625, "Security", "User account password changed (Legacy)", "Account Management"),
            (626, "Security", "User account enabled (Legacy)", "Account Management"),
            (627, "Security", "Password change attempt by account (Legacy)", "Account Management"),
            (628, "Security", "User account password set (Legacy)", "Account Management"),
            (629, "Security", "User account disabled (Legacy)", "Account Management"),
            (630, "Security", "User account deleted (Legacy)", "Account Management"),
            (631, "Security", "Security-enabled global group created (Legacy)", "Account Management"),
            (632, "Security", "Security-enabled global group member added (Legacy)", "Account Management"),
            (633, "Security", "Security-enabled global group member removed (Legacy)", "Account Management"),
            (634, "Security", "Security-enabled global group deleted (Legacy)", "Account Management"),
            (635, "Security", "Security-enabled local group created (Legacy)", "Account Management"),
            (636, "Security", "Security-enabled local group member added (Legacy)", "Account Management"),
            (637, "Security", "Security-enabled local group member removed (Legacy)", "Account Management"),
            (638, "Security", "Security-enabled local group deleted (Legacy)", "Account Management"),
            (642, "Security", "User account changed (Legacy)", "Account Management"),
            (643, "Security", "Domain Policy changed (Legacy)", "Policy Change"),
            (644, "Security", "User account locked out (Legacy)", "Account Management"),
            (645, "Security", "Computer account created (Legacy)", "Account Management"),
            (646, "Security", "Computer account changed (Legacy)", "Account Management"),
            (647, "Security", "Computer account deleted (Legacy)", "Account Management"),
            (672, "Security", "Authentication ticket granted (Legacy, Kerberos)", "Account Logon"),
            (673, "Security", "Service ticket granted (Legacy, Kerberos)", "Account Logon"),
            (674, "Security", "Ticket granting ticket renewed (Legacy, Kerberos)", "Account Logon"),
            (675, "Security", "Pre-authentication failed (Legacy, Kerberos)", "Account Logon"),
            (676, "Security", "Authentication ticket request failed (Legacy, Kerberos)", "Account Logon"),
            (677, "Security", "Service ticket request failed (Legacy, Kerberos)", "Account Logon"),
            (680, "Security", "Account used for logon by a user (Legacy)", "Account Logon"),
            (681, "Security", "Logon attempt failed (Legacy)", "Account Logon"),
            (682, "Security", "A user has reconnected to a disconnected Terminal Services session (Legacy)", "Logon/Logoff"),
            (683, "Security", "A user disconnected from a Terminal Services session (Legacy)", "Logon/Logoff"),
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
        
        logger.info(f"[EMBEDDED] ✓ Loaded {len(results)} events from embedded data")
        return results
    
    def scrape_all_sources(self) -> List[Dict]:
        """
        Scrape all sources and combine results
        
        Returns combined list
        """
        all_results = []
        
        # Load all sources (embedded + hardcoded + web scraping)
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
                    logger.info(f"Replacing event {event['event_id']} from {grouped[key]['source_website']} "
                              f"with version from {event['source_website']} (more descriptive)")
                    grouped[key] = event
        
        deduplicated = list(grouped.values())
        logger.info(f"Deduplication: {len(events)} -> {len(deduplicated)} unique events")
        
        return deduplicated
