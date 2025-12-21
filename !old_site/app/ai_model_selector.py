#!/usr/bin/env python3
"""
AI Model Selector - Auto-selects models based on VRAM tier

This module provides a centralized way to select AI models based on:
1. The role/purpose (IOC extraction, timeline, report, etc.)
2. Available VRAM (8GB, 16GB, 32GB+)

Usage:
    from ai_model_selector import get_ai_model
    
    model = get_ai_model('ioc_extraction')
    # Returns: 'qwen2.5:7b-instruct-q4_k_m' on 8GB
    #       or 'qwen2.5:14b-instruct-q4_k_m' on 16GB+

Author: CaseScope 2025
Version: 2.0.0
"""

from typing import Optional
import logging

logger = logging.getLogger(__name__)


def get_ai_model(role: str) -> str:
    """
    Get the appropriate AI model for a role based on available VRAM.
    
    Auto-selects from database mappings based on:
    - User's VRAM setting (ai_gpu_vram in SystemSettings)
    - The requested role (ioc_extraction, timeline, report, search)
    - Active model mappings in AIModelRole table
    
    Args:
        role: The AI task role
              - 'ioc_extraction': Extract IOCs from text
              - 'timeline': Generate case timelines
              - 'report': Generate DFIR reports
              - 'search': AI-powered event search
              - 'review': Single event AI review
    
    Returns:
        str: Ollama model name (e.g., 'qwen2.5:14b-instruct-q4_k_m')
    
    Fallback:
        If no mapping found, returns 'llama3.1:8b-instruct-q4_k_m' (safe default)
    
    Example:
        >>> get_ai_model('ioc_extraction')
        'qwen2.5:7b-instruct-q4_k_m'  # on 8GB VRAM
        
        >>> get_ai_model('timeline')
        'qwen2.5:14b-instruct-q4_k_m'  # on 16GB VRAM
    """
    from models import db, AIModelRole, SystemSettings
    
    try:
        # Get VRAM setting from database
        vram_setting = db.session.query(SystemSettings).filter_by(
            setting_key='ai_gpu_vram'
        ).first()
        
        vram_gb = int(vram_setting.setting_value) if vram_setting else 8
        
        # Determine VRAM tier
        if vram_gb >= 16:
            tier = '16gb'
        else:
            tier = '8gb'
        
        # Query for active model mapping
        mapping = db.session.query(AIModelRole).filter_by(
            role=role,
            vram_tier=tier,
            active=True
        ).order_by(AIModelRole.priority.desc()).first()
        
        if mapping:
            logger.info(f"[AI_MODEL_SELECTOR] Role='{role}', VRAM={vram_gb}GB, Tier='{tier}', Model='{mapping.model_name}'")
            return mapping.model_name
        
        # Fallback: try to find any active mapping for this role (any tier)
        fallback = db.session.query(AIModelRole).filter_by(
            role=role,
            active=True
        ).order_by(AIModelRole.priority.desc()).first()
        
        if fallback:
            logger.warning(f"[AI_MODEL_SELECTOR] No mapping for role='{role}' tier='{tier}', using fallback: '{fallback.model_name}'")
            return fallback.model_name
        
        # Ultimate fallback: Llama 3.1 8B
        logger.warning(f"[AI_MODEL_SELECTOR] No mapping found for role='{role}', using default: 'llama3.1:8b-instruct-q4_k_m'")
        return 'llama3.1:8b-instruct-q4_k_m'
        
    except Exception as e:
        logger.error(f"[AI_MODEL_SELECTOR] Error selecting model for role='{role}': {e}")
        # Safe fallback on any error
        return 'llama3.1:8b-instruct-q4_k_m'


def get_vram_tier() -> str:
    """
    Get the current VRAM tier based on system settings.
    
    Returns:
        str: '8gb', '16gb', or '32gb'
    """
    from models import db, SystemSettings
    
    try:
        vram_setting = db.session.query(SystemSettings).filter_by(
            setting_key='ai_gpu_vram'
        ).first()
        
        vram_gb = int(vram_setting.setting_value) if vram_setting else 8
        
        if vram_gb >= 32:
            return '32gb'
        elif vram_gb >= 16:
            return '16gb'
        else:
            return '8gb'
    except:
        return '8gb'


def list_available_roles() -> list:
    """
    List all available AI roles with their current model assignments.
    
    Returns:
        list: List of dicts with role, tier, and model info
    """
    from models import db, AIModelRole
    
    tier = get_vram_tier()
    
    roles = db.session.query(AIModelRole).filter_by(
        vram_tier=tier,
        active=True
    ).order_by(AIModelRole.role, AIModelRole.priority.desc()).all()
    
    return [{
        'role': r.role,
        'vram_tier': r.vram_tier,
        'model_name': r.model_name,
        'priority': r.priority
    } for r in roles]


if __name__ == '__main__':
    # Test the selector
    from main import app
    
    with app.app_context():
        print("AI Model Selector Test")
        print("=" * 60)
        print(f"Current VRAM Tier: {get_vram_tier()}")
        print()
        print("Model Assignments:")
        for role in ['ioc_extraction', 'timeline', 'report', 'search', 'review']:
            model = get_ai_model(role)
            print(f"  {role:20s} → {model}")

