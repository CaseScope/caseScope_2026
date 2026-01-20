"""Noise Keyword Matching Utilities for CaseScope

Provides ClickHouse SQL clause builders for noise filter keyword matching.
Supports both token-based matching (hasTokenCaseInsensitive) for clean keywords
and substring matching (positionCaseInsensitive) for keywords with separators.

Separator characters include: . - / \ : @ and whitespace
These characters cause hasTokenCaseInsensitive() to fail, so we automatically
switch to positionCaseInsensitive() when they're detected.

Example:
    'ltsvc' -> hasTokenCaseInsensitive (fast, token-based)
    'huntress.io' -> positionCaseInsensitive (substring, works with separators)
"""
import re
import logging

logger = logging.getLogger(__name__)

# Pattern to detect separator characters that break hasTokenCaseInsensitive
# Matches any non-alphanumeric character
SEPARATOR_PATTERN = re.compile(r'[^a-zA-Z0-9]')


def has_separator(keyword: str) -> bool:
    """Check if keyword contains separator characters
    
    Separators include: . - / \ : @ space and any non-alphanumeric character.
    These characters cause ClickHouse hasTokenCaseInsensitive() to fail.
    
    Args:
        keyword: The keyword to check
        
    Returns:
        True if keyword contains separators, False otherwise
    """
    return bool(SEPARATOR_PATTERN.search(keyword))


def build_keyword_clause(keywords: list, column: str = 'raw_json') -> str:
    """Build ClickHouse OR clause for keyword matching
    
    Automatically selects the appropriate matching function:
    - hasTokenCaseInsensitive() for clean alphanumeric tokens (fast, indexed)
    - positionCaseInsensitive() for keywords with separators (substring match)
    
    Args:
        keywords: List of keywords to match (any match = true)
        column: Column to search in (default: raw_json)
        
    Returns:
        SQL clause string like "(hasTokenCaseInsensitive(col, 'kw1') OR positionCaseInsensitive(col, 'kw2') > 0)"
    """
    if not keywords:
        return ""
    
    clauses = []
    for keyword in keywords:
        # Escape single quotes for SQL
        escaped = keyword.replace("'", "''")
        
        if has_separator(keyword):
            # Use substring matching for keywords with separators
            clauses.append(f"positionCaseInsensitive({column}, '{escaped}') > 0")
        else:
            # Use fast token matching for clean keywords
            clauses.append(f"hasTokenCaseInsensitive({column}, '{escaped}')")
    
    return f"({' OR '.join(clauses)})"


def build_keyword_not_clause(keywords: list, column: str = 'raw_json') -> str:
    """Build ClickHouse NOT clause for keyword exclusion
    
    Automatically selects the appropriate matching function:
    - NOT hasTokenCaseInsensitive() for clean alphanumeric tokens
    - positionCaseInsensitive() = 0 for keywords with separators
    
    Args:
        keywords: List of keywords - event excluded if ANY found
        column: Column to search in (default: raw_json)
        
    Returns:
        SQL clause string like "NOT hasTokenCaseInsensitive(col, 'kw1') AND positionCaseInsensitive(col, 'kw2') = 0"
    """
    if not keywords:
        return ""
    
    clauses = []
    for keyword in keywords:
        # Escape single quotes for SQL
        escaped = keyword.replace("'", "''")
        
        if has_separator(keyword):
            # Use substring matching for keywords with separators
            # positionCaseInsensitive returns 0 if not found
            clauses.append(f"positionCaseInsensitive({column}, '{escaped}') = 0")
        else:
            # Use fast token matching for clean keywords
            clauses.append(f"NOT hasTokenCaseInsensitive({column}, '{escaped}')")
    
    return " AND ".join(clauses)
