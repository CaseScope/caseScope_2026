"""
Automated Threat Detection Module
Runs pre-defined patterns against full case dataset using OpenSearch aggregations
"""

from .patterns import DETECTION_PATTERNS
from .detector import PatternDetector

__all__ = ['DETECTION_PATTERNS', 'PatternDetector']

