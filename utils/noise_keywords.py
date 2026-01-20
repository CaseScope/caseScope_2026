"""Noise Keyword Matching Utilities for CaseScope

Provides ClickHouse SQL clause builders for noise filter keyword matching.
Supports both token-based matching (hasTokenCaseInsensitive) for clean keywords
and substring matching (positionCaseInsensitive) for keywords with separators.

Searches both raw_json and search_blob by default to catch all event data.

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

# Default columns to search for noise matching
DEFAULT_SEARCH_COLUMNS = ['raw_json', 'search_blob']


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


def _build_keyword_match(keyword: str, column: str) -> str:
    """Build a single keyword match clause for one column"""
    escaped = keyword.replace("'", "''")
    
    if has_separator(keyword):
        return f"positionCaseInsensitive({column}, '{escaped}') > 0"
    else:
        return f"hasTokenCaseInsensitive({column}, '{escaped}')"


def _build_keyword_not_match(keyword: str, column: str) -> str:
    """Build a single keyword NOT match clause for one column"""
    escaped = keyword.replace("'", "''")
    
    if has_separator(keyword):
        return f"positionCaseInsensitive({column}, '{escaped}') = 0"
    else:
        return f"NOT hasTokenCaseInsensitive({column}, '{escaped}')"


def build_keyword_clause(keywords: list, columns = None) -> str:
    """Build ClickHouse OR clause for keyword matching across multiple columns
    
    Automatically selects the appropriate matching function:
    - hasTokenCaseInsensitive() for clean alphanumeric tokens (fast, indexed)
    - positionCaseInsensitive() for keywords with separators (substring match)
    
    Searches both raw_json and search_blob by default to catch all event data.
    
    Args:
        keywords: List of keywords to match (any match = true)
        columns: List of columns to search, or single column string
                 (default: ['raw_json', 'search_blob'])
        
    Returns:
        SQL clause string matching if ANY keyword found in ANY column
    """
    if not keywords:
        return ""
    
    if columns is None:
        columns = DEFAULT_SEARCH_COLUMNS
    elif isinstance(columns, str):
        # Handle legacy single column string - convert to list with both columns
        columns = DEFAULT_SEARCH_COLUMNS
    
    # For each keyword, check all columns (keyword found in ANY column = match)
    keyword_clauses = []
    for keyword in keywords:
        column_matches = [_build_keyword_match(keyword, col) for col in columns]
        keyword_clauses.append(f"({' OR '.join(column_matches)})")
    
    # Any keyword match = overall match
    return f"({' OR '.join(keyword_clauses)})"


def build_keyword_not_clause(keywords: list, columns = None) -> str:
    """Build ClickHouse NOT clause for keyword exclusion across multiple columns
    
    Automatically selects the appropriate matching function:
    - NOT hasTokenCaseInsensitive() for clean alphanumeric tokens
    - positionCaseInsensitive() = 0 for keywords with separators
    
    Searches both raw_json and search_blob by default.
    Keyword must NOT be found in ANY column to pass the exclusion.
    
    Args:
        keywords: List of keywords - event excluded if ANY keyword found in ANY column
        columns: List of columns to search, or single column string
                 (default: ['raw_json', 'search_blob'])
        
    Returns:
        SQL clause string excluding if ANY keyword found in ANY column
    """
    if not keywords:
        return ""
    
    if columns is None:
        columns = DEFAULT_SEARCH_COLUMNS
    elif isinstance(columns, str):
        # Handle legacy single column string - convert to list with both columns
        columns = DEFAULT_SEARCH_COLUMNS
    
    # For each keyword, must NOT be in ANY column
    keyword_clauses = []
    for keyword in keywords:
        # All columns must NOT contain the keyword
        column_not_matches = [_build_keyword_not_match(keyword, col) for col in columns]
        keyword_clauses.append(f"({' AND '.join(column_not_matches)})")
    
    # ALL exclusion keywords must pass (none of them found)
    return " AND ".join(keyword_clauses)
