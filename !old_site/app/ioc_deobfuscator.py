"""
IOC Deobfuscation Module

Handles deobfuscation (defanging removal) of IOCs commonly used in security reports
to prevent accidental clicks or execution.

Common obfuscation patterns:
- hxxp:// or hXXp:// → http://
- hxxps:// or hXXps:// → https://
- [.] or (.) or {.} → .
- [:] or (:) or {:} → :
- [://] → ://
- [@] or (@) or {@} → @
"""

import re
from typing import Tuple, Optional


def deobfuscate_ioc(ioc: str) -> Tuple[str, bool]:
    """
    Deobfuscate (defang) an IOC.
    
    Args:
        ioc: The potentially obfuscated IOC string
    
    Returns:
        Tuple of (deobfuscated_ioc, was_obfuscated)
        - deobfuscated_ioc: The cleaned IOC
        - was_obfuscated: True if any deobfuscation was performed
    """
    if not ioc or not isinstance(ioc, str):
        return ioc, False
    
    original = ioc
    ioc = ioc.strip()
    
    # Track if we made any changes
    was_obfuscated = False
    
    # 1. Fix protocol obfuscation: hxxp:// → http://, hxxps:// → https://
    if re.search(r'hxx?ps?://', ioc, re.IGNORECASE):
        ioc = re.sub(r'hxxps?://', 'https://', ioc, flags=re.IGNORECASE)
        ioc = re.sub(r'hxxp://', 'http://', ioc, flags=re.IGNORECASE)
        was_obfuscated = True
    
    # 2. Fix bracketed dots: [.] → .
    if '[.]' in ioc or '[dot]' in ioc:
        ioc = ioc.replace('[.]', '.')
        ioc = ioc.replace('[dot]', '.')
        was_obfuscated = True
    
    # 3. Fix parenthesized dots: (.) → .
    if '(.)' in ioc or '(dot)' in ioc:
        ioc = ioc.replace('(.)', '.')
        ioc = ioc.replace('(dot)', '.')
        was_obfuscated = True
    
    # 4. Fix curly braced dots: {.} → .
    if '{.}' in ioc or '{dot}' in ioc:
        ioc = ioc.replace('{.}', '.')
        ioc = ioc.replace('{dot}', '.')
        was_obfuscated = True
    
    # 5. Fix bracketed colons: [:] → :
    if '[:]' in ioc:
        ioc = ioc.replace('[:]', ':')
        was_obfuscated = True
    
    # 6. Fix bracketed protocol separator: [://] → ://
    if '[://]' in ioc:
        ioc = ioc.replace('[://]', '://')
        was_obfuscated = True
    
    # 7. Fix bracketed @ in emails: [@] → @
    if '[@]' in ioc or '(@)' in ioc or '{@}' in ioc:
        ioc = ioc.replace('[@]', '@')
        ioc = ioc.replace('(@)', '@')
        ioc = ioc.replace('{@}', '@')
        was_obfuscated = True
    
    # 8. Fix escaped dots in domains/IPs: somesite\.com → somesite.com
    if r'\.' in ioc:
        ioc = ioc.replace(r'\.', '.')
        was_obfuscated = True
    
    # 9. Fix space obfuscation in URLs: http:// example .com → http://example.com
    # Only do this if it looks like a URL
    if '://' in ioc and ' ' in ioc:
        # Remove spaces around dots
        ioc = re.sub(r'\s*\.\s*', '.', ioc)
        # Remove spaces after ://
        ioc = re.sub(r'://\s+', '://', ioc)
        was_obfuscated = True
    
    return ioc, was_obfuscated


def deobfuscate_ioc_dict(iocs: dict) -> dict:
    """
    Deobfuscate all IOCs in a nested dictionary structure.
    Adds 'original' field for obfuscated IOCs.
    
    Args:
        iocs: Dictionary of IOCs from extraction
    
    Returns:
        New dictionary with deobfuscated IOCs and 'original' annotations
    """
    deobfuscated = {}
    
    for category, values in iocs.items():
        if isinstance(values, list):
            # Simple list of IOCs
            deobfuscated[category] = []
            for ioc in values:
                if not ioc:
                    continue
                clean_ioc, was_obfuscated = deobfuscate_ioc(str(ioc))
                if was_obfuscated:
                    # Store as dict with original value
                    deobfuscated[category].append({
                        'value': clean_ioc,
                        'original': str(ioc)
                    })
                else:
                    # Store as string (no change)
                    deobfuscated[category].append(clean_ioc)
        
        elif isinstance(values, dict):
            # Nested structure (file_hashes, credentials, processes)
            deobfuscated[category] = {}
            for sub_category, sub_values in values.items():
                if isinstance(sub_values, list):
                    deobfuscated[category][sub_category] = []
                    for ioc in sub_values:
                        if not ioc:
                            continue
                        clean_ioc, was_obfuscated = deobfuscate_ioc(str(ioc))
                        if was_obfuscated:
                            deobfuscated[category][sub_category].append({
                                'value': clean_ioc,
                                'original': str(ioc)
                            })
                        else:
                            deobfuscated[category][sub_category].append(clean_ioc)
                else:
                    deobfuscated[category][sub_category] = sub_values
        else:
            deobfuscated[category] = values
    
    return deobfuscated


def get_ioc_value(ioc) -> str:
    """
    Extract the actual IOC value from either a string or dict with 'value' key.
    
    Args:
        ioc: Either a string or dict with 'value' key
    
    Returns:
        The IOC value as a string
    """
    if isinstance(ioc, dict):
        return ioc.get('value', '')
    return str(ioc) if ioc else ''


def get_ioc_original(ioc) -> Optional[str]:
    """
    Get the original obfuscated value if it exists.
    
    Args:
        ioc: Either a string or dict with 'original' key
    
    Returns:
        The original obfuscated value, or None if not obfuscated
    """
    if isinstance(ioc, dict):
        return ioc.get('original')
    return None


