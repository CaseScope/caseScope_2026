"""Feature Availability Handler for CaseScope Enhanced Analysis System

Centralized feature availability checking for determining analysis mode.
Provides graceful degradation when AI or OpenCTI are unavailable.

Operating Modes:
- A: No OpenCTI, No AI - Rule-based only
- B: No OpenCTI, AI enabled - AI reasoning without threat intel
- C: OpenCTI enabled, No AI - Threat intel without AI reasoning  
- D: OpenCTI enabled, AI enabled - Full capabilities
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from functools import lru_cache

from config import Config

logger = logging.getLogger(__name__)


class FeatureAvailability:
    """
    Centralized feature availability checking.
    
    Determines what analysis capabilities are available based on:
    - Configuration settings
    - Service connectivity (Ollama, OpenCTI)
    """
    
    # Cache duration for connectivity checks
    CACHE_DURATION_SECONDS = 60
    
    # Cached results
    _ai_check_time: Optional[datetime] = None
    _ai_available: Optional[bool] = None
    _opencti_check_time: Optional[datetime] = None
    _opencti_available: Optional[bool] = None
    
    @classmethod
    def is_ai_enabled(cls) -> bool:
        """
        Check if AI is available.
        
        Checks:
        1. AI_ANALYSIS_ENABLED in config
        2. analysis.ai_enabled in system_settings
        3. Ollama service connectivity
        
        Returns:
            bool: True if AI can be used
        """
        # Check if cache is still valid
        if cls._ai_check_time and cls._ai_available is not None:
            if datetime.utcnow() - cls._ai_check_time < timedelta(seconds=cls.CACHE_DURATION_SECONDS):
                return cls._ai_available
        
        cls._ai_check_time = datetime.utcnow()
        
        # Check config
        if not getattr(Config, 'AI_ANALYSIS_ENABLED', False):
            cls._ai_available = False
            return False
        
        # Check system settings
        try:
            from models.system_settings import SystemSettings, SettingKeys
            if not SystemSettings.get(SettingKeys.AI_ANALYSIS_ENABLED, True):
                cls._ai_available = False
                return False
        except Exception:
            pass  # System settings may not be available
        
        # Check Ollama connectivity
        try:
            from utils.rag_llm import OllamaClient
            client = OllamaClient()
            
            # Quick health check
            available = client.ping() if hasattr(client, 'ping') else True
            cls._ai_available = available
            return available
            
        except Exception as e:
            logger.warning(f"[FeatureAvailability] AI check failed: {e}")
            cls._ai_available = False
            return False
    
    @classmethod
    def is_opencti_enabled(cls) -> bool:
        """
        Check if OpenCTI is available.
        
        Checks:
        1. OPENCTI_ENABLED in config
        2. analysis.opencti_enabled in system_settings
        3. OpenCTI API connectivity
        
        Returns:
            bool: True if OpenCTI can be used
        """
        # Check if cache is still valid
        if cls._opencti_check_time and cls._opencti_available is not None:
            if datetime.utcnow() - cls._opencti_check_time < timedelta(seconds=cls.CACHE_DURATION_SECONDS):
                return cls._opencti_available
        
        cls._opencti_check_time = datetime.utcnow()
        
        # Check config
        if not getattr(Config, 'OPENCTI_ENABLED', False):
            cls._opencti_available = False
            return False
        
        # Check system settings
        try:
            from models.system_settings import SystemSettings, SettingKeys
            if not SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False):
                cls._opencti_available = False
                return False
        except Exception:
            pass  # System settings may not be available
        
        # Check OpenCTI connectivity
        try:
            from utils.opencti import get_opencti_client
            client = get_opencti_client()
            
            if not client:
                cls._opencti_available = False
                return False
            
            available = client.ping()
            cls._opencti_available = available
            return available
            
        except Exception as e:
            logger.warning(f"[FeatureAvailability] OpenCTI check failed: {e}")
            cls._opencti_available = False
            return False
    
    @classmethod
    def get_analysis_mode(cls) -> str:
        """
        Determine current analysis mode.
        
        Returns:
            str: 'A', 'B', 'C', or 'D'
            
        Mode determination:
        - A: No OpenCTI, No AI
        - B: No OpenCTI, AI enabled
        - C: OpenCTI enabled, No AI
        - D: OpenCTI enabled, AI enabled
        """
        ai_enabled = cls.is_ai_enabled()
        opencti_enabled = cls.is_opencti_enabled()
        
        if opencti_enabled and ai_enabled:
            return 'D'
        elif opencti_enabled and not ai_enabled:
            return 'C'
        elif not opencti_enabled and ai_enabled:
            return 'B'
        else:
            return 'A'
    
    @classmethod
    def get_available_capabilities(cls) -> Dict[str, Any]:
        """
        Get detailed capability breakdown.
        
        Returns:
            dict: {
                'mode': str,  # A, B, C, D
                'ai_reasoning': bool,
                'ai_explanations': bool,
                'threat_intel_enrichment': bool,
                'sigma_gap_rules': bool,
                'threat_actor_context': bool,
                'ioc_enrichment': bool,
                'behavioral_profiling': bool,  # Always available
                'gap_detection': bool,  # Always available
                'hayabusa_correlation': bool  # Always available
            }
        """
        mode = cls.get_analysis_mode()
        ai_enabled = mode in ['B', 'D']
        opencti_enabled = mode in ['C', 'D']
        
        return {
            'mode': mode,
            'mode_description': cls.get_mode_description(mode),
            
            # AI capabilities
            'ai_reasoning': ai_enabled,
            'ai_explanations': ai_enabled,
            'ai_confidence_scoring': ai_enabled,
            'ai_false_positive_assessment': ai_enabled,
            
            # OpenCTI capabilities
            'threat_intel_enrichment': opencti_enabled,
            'sigma_gap_rules': opencti_enabled,
            'threat_actor_context': opencti_enabled,
            'ioc_enrichment': opencti_enabled,
            'campaign_context': opencti_enabled,
            
            # Always available capabilities
            'behavioral_profiling': True,
            'peer_clustering': True,
            'gap_detection': True,
            'hayabusa_correlation': True,
            'rule_based_scoring': True,
            'suggested_actions': True
        }
    
    @classmethod
    def get_mode_description(cls, mode: str) -> str:
        """Get human-readable description of analysis mode"""
        descriptions = {
            'A': 'Rule-based analysis with behavioral profiling (No AI, No OpenCTI)',
            'B': 'AI-enhanced analysis with reasoning (No OpenCTI)',
            'C': 'Threat intelligence enriched analysis (No AI)',
            'D': 'Full analysis with AI reasoning and threat intelligence'
        }
        return descriptions.get(mode, 'Unknown mode')
    
    @classmethod
    def clear_cache(cls):
        """Clear cached availability checks"""
        cls._ai_check_time = None
        cls._ai_available = None
        cls._opencti_check_time = None
        cls._opencti_available = None
    
    @classmethod
    def get_status_summary(cls) -> Dict[str, Any]:
        """
        Get a summary of current system status.
        
        Useful for UI display and debugging.
        """
        mode = cls.get_analysis_mode()
        capabilities = cls.get_available_capabilities()
        
        return {
            'mode': mode,
            'mode_description': cls.get_mode_description(mode),
            'ai_status': {
                'enabled': capabilities['ai_reasoning'],
                'config_enabled': getattr(Config, 'AI_ANALYSIS_ENABLED', False),
                'last_checked': cls._ai_check_time.isoformat() if cls._ai_check_time else None
            },
            'opencti_status': {
                'enabled': capabilities['threat_intel_enrichment'],
                'config_enabled': getattr(Config, 'OPENCTI_ENABLED', False),
                'last_checked': cls._opencti_check_time.isoformat() if cls._opencti_check_time else None
            },
            'capabilities_summary': {
                'ai_features': sum(1 for k, v in capabilities.items() 
                                   if k.startswith('ai_') and v),
                'opencti_features': sum(1 for k, v in capabilities.items() 
                                        if k in ['threat_intel_enrichment', 'sigma_gap_rules', 
                                                'threat_actor_context', 'ioc_enrichment', 
                                                'campaign_context'] and v),
                'core_features': 6  # Always available
            }
        }


def get_analysis_mode() -> str:
    """Convenience function to get current analysis mode"""
    return FeatureAvailability.get_analysis_mode()


def get_capabilities() -> Dict[str, Any]:
    """Convenience function to get available capabilities"""
    return FeatureAvailability.get_available_capabilities()


def is_ai_available() -> bool:
    """Convenience function to check AI availability"""
    return FeatureAvailability.is_ai_enabled()


def is_opencti_available() -> bool:
    """Convenience function to check OpenCTI availability"""
    return FeatureAvailability.is_opencti_enabled()


class AnalysisModeContext:
    """
    Context manager for analysis mode tracking.
    
    Usage:
        with AnalysisModeContext() as mode_ctx:
            if mode_ctx.has_ai:
                # Do AI analysis
            if mode_ctx.has_opencti:
                # Do OpenCTI enrichment
    """
    
    def __init__(self, force_mode: str = None):
        """
        Args:
            force_mode: Optional mode to force (for testing)
        """
        self.force_mode = force_mode
        self._mode = None
        self._capabilities = None
    
    def __enter__(self):
        if self.force_mode:
            self._mode = self.force_mode
            self._capabilities = self._get_forced_capabilities(self.force_mode)
        else:
            self._mode = FeatureAvailability.get_analysis_mode()
            self._capabilities = FeatureAvailability.get_available_capabilities()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def _get_forced_capabilities(self, mode: str) -> Dict[str, Any]:
        """Get capabilities for a forced mode"""
        ai_enabled = mode in ['B', 'D']
        opencti_enabled = mode in ['C', 'D']
        
        return {
            'mode': mode,
            'ai_reasoning': ai_enabled,
            'ai_explanations': ai_enabled,
            'threat_intel_enrichment': opencti_enabled,
            'sigma_gap_rules': opencti_enabled,
            'threat_actor_context': opencti_enabled,
            'ioc_enrichment': opencti_enabled,
            'behavioral_profiling': True,
            'gap_detection': True,
            'hayabusa_correlation': True,
            'rule_based_scoring': True
        }
    
    @property
    def mode(self) -> str:
        return self._mode
    
    @property
    def has_ai(self) -> bool:
        return self._mode in ['B', 'D']
    
    @property
    def has_opencti(self) -> bool:
        return self._mode in ['C', 'D']
    
    @property
    def capabilities(self) -> Dict[str, Any]:
        return self._capabilities
    
    def can(self, capability: str) -> bool:
        """Check if a specific capability is available"""
        return self._capabilities.get(capability, False)
