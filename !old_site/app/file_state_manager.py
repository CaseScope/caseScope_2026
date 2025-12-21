"""
File State Manager

Manages file processing state transitions and flag updates.
Ensures consistent state management across all processing operations.

Author: System
Date: 2025-12-18
Version: 2.2.0
"""

import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# Valid state transitions
VALID_TRANSITIONS = {
    # Initial upload flow
    'New': ['Indexing', 'Failed'],
    'Indexing': ['Indexed', 'Hidden', 'Failed'],
    'Indexed': ['SIGMA Hunting', 'IOC Hunting', 'Hidden', 'Failed'],  # SIGMA for EVTX, IOC for non-EVTX
    'SIGMA Hunting': ['SIGMA Checked', 'Failed'],
    'SIGMA Checked': ['IOC Hunting', 'Failed'],
    'IOC Hunting': ['IOC Checked', 'Failed'],
    'IOC Checked': ['Noise Checking', 'Failed'],
    'Noise Checking': ['Noise Checked', 'Hidden', 'Failed'],
    'Noise Checked': ['Completed', 'Hidden', 'Failed'],
    
    # Re-operations (from Completed)
    'Completed': ['Reindexing', 'SIGMA Hunting', 'IOC Hunting', 'Noise Checking', 'Failed'],
    'Reindexing': ['Indexed', 'Hidden', 'Failed'],
    
    # Terminal states
    'Failed': ['Indexing', 'Reindexing'],  # Can retry from failed
    'Hidden': [],  # Terminal state (can be unhidden via UI)
}


def validate_transition(from_state: str, to_state: str) -> bool:
    """
    Validate if a state transition is allowed.
    
    Args:
        from_state: Current state
        to_state: Desired new state
        
    Returns:
        bool: True if transition is valid
    """
    if from_state not in VALID_TRANSITIONS:
        logger.warning(f"[STATE] Unknown from_state: {from_state}")
        return True  # Allow unknown states (backward compatibility)
    
    valid_next_states = VALID_TRANSITIONS[from_state]
    is_valid = to_state in valid_next_states
    
    if not is_valid:
        logger.warning(f"[STATE] Invalid transition: {from_state} -> {to_state}. "
                      f"Valid transitions from {from_state}: {valid_next_states}")
    
    return is_valid


def transition_state(case_file, new_state: str, validate: bool = True) -> bool:
    """
    Transition file to new state with optional validation.
    
    Args:
        case_file: CaseFile instance
        new_state: Desired state
        validate: If True, validate transition is allowed
        
    Returns:
        bool: True if transition successful
    """
    old_state = case_file.file_state
    
    if validate and not validate_transition(old_state, new_state):
        logger.error(f"[STATE] Blocked invalid transition for file {case_file.id}: "
                    f"{old_state} -> {new_state}")
        return False
    
    case_file.file_state = new_state
    logger.info(f"[STATE] File {case_file.id} transitioned: {old_state} -> {new_state}")
    return True


def start_indexing(case_file) -> None:
    """
    Initialize file for indexing operation.
    
    Sets:
    - file_state = 'Indexing'
    - indexing_status = 'Indexing' (legacy field, for backward compatibility)
    - is_new = False
    """
    transition_state(case_file, 'Indexing')
    case_file.indexing_status = 'Indexing'  # v2.2.1: Also update legacy field
    case_file.is_new = False
    logger.info(f"[STATE] File {case_file.id} started indexing")


def complete_indexing(case_file, event_count: int) -> None:
    """
    Mark indexing as complete.
    
    Args:
        case_file: CaseFile instance
        event_count: Number of events indexed
        
    Sets:
    - file_state = 'Indexed' or 'Hidden' (if 0 events)
    - indexing_status = 'Completed' (legacy field, for backward compatibility)
    - is_indexed = True
    - is_hidden = True (if 0 events)
    """
    if event_count == 0:
        transition_state(case_file, 'Hidden')
        case_file.indexing_status = 'Completed'  # v2.2.1: Also update legacy field
        case_file.is_hidden = True
        logger.info(f"[STATE] File {case_file.id} hidden (0 events)")
    else:
        transition_state(case_file, 'Indexed')
        case_file.indexing_status = 'Completed'  # v2.2.1: Also update legacy field
        case_file.is_indexed = True
        logger.info(f"[STATE] File {case_file.id} indexed ({event_count:,} events)")


def start_sigma_hunting(case_file) -> None:
    """Start SIGMA detection phase."""
    transition_state(case_file, 'SIGMA Hunting')
    logger.info(f"[STATE] File {case_file.id} started SIGMA hunting")


def complete_sigma_hunting(case_file) -> None:
    """Complete SIGMA detection phase."""
    transition_state(case_file, 'SIGMA Checked')
    case_file.sigma_hunted = True
    logger.info(f"[STATE] File {case_file.id} completed SIGMA hunting")


def start_ioc_hunting(case_file) -> None:
    """Start IOC hunting phase."""
    transition_state(case_file, 'IOC Hunting')
    logger.info(f"[STATE] File {case_file.id} started IOC hunting")


def complete_ioc_hunting(case_file) -> None:
    """Complete IOC hunting phase."""
    transition_state(case_file, 'IOC Checked')
    case_file.ioc_hunted = True
    logger.info(f"[STATE] File {case_file.id} completed IOC hunting")


def start_noise_checking(case_file) -> None:
    """Start known-good/noise checking phase."""
    transition_state(case_file, 'Noise Checking')
    logger.info(f"[STATE] File {case_file.id} started noise checking")


def complete_noise_checking(case_file, marked_as_noise: bool = False) -> None:
    """
    Complete noise checking phase.
    
    Args:
        case_file: CaseFile instance
        marked_as_noise: If True, file matched noise patterns and should be hidden
    """
    if marked_as_noise:
        transition_state(case_file, 'Hidden')
        case_file.is_hidden = True
        logger.info(f"[STATE] File {case_file.id} hidden (matched noise patterns)")
    else:
        transition_state(case_file, 'Noise Checked')
        case_file.known_good = True
        case_file.known_noise = True
        logger.info(f"[STATE] File {case_file.id} completed noise checking")


def finalize_processing(case_file) -> None:
    """
    Finalize file processing if all phases complete.
    
    Checks is_completed property and sets state to 'Completed' if ready.
    """
    if case_file.is_completed:
        transition_state(case_file, 'Completed')
        logger.info(f"[STATE] File {case_file.id} marked as completed")
    else:
        logger.debug(f"[STATE] File {case_file.id} not yet completed: "
                    f"indexed={case_file.is_indexed}, "
                    f"sigma={case_file.sigma_hunted}, "
                    f"ioc={case_file.ioc_hunted}, "
                    f"good={case_file.known_good}, "
                    f"noise={case_file.known_noise}")


def mark_failed(case_file, error_message: str = None) -> None:
    """
    Mark file as failed.
    
    Args:
        case_file: CaseFile instance
        error_message: Optional error message
    """
    transition_state(case_file, 'Failed', validate=False)  # Can fail from any state
    case_file.indexing_status = 'Failed'  # v2.2.1: Also update legacy field
    case_file.failed = True
    if error_message:
        case_file.error_message = error_message[:500]  # Truncate to 500 chars
    logger.error(f"[STATE] File {case_file.id} marked as failed: {error_message}")


def start_reindex(case_file) -> None:
    """
    Initialize file for re-index operation.
    
    Saves current state and resets all flags except metadata.
    """
    # Save current state for potential restoration
    case_file.previous_state = case_file.file_state
    
    # Reset all processing flags
    case_file.is_indexed = False
    case_file.sigma_hunted = False
    case_file.ioc_hunted = False
    case_file.known_good = False
    case_file.known_noise = False
    case_file.failed = False
    case_file.is_hidden = False
    
    # Set state
    transition_state(case_file, 'Reindexing', validate=False)
    
    logger.info(f"[STATE] File {case_file.id} started reindex "
               f"(saved previous_state={case_file.previous_state})")


def start_partial_operation(case_file, operation: str) -> None:
    """
    Start a partial re-operation (re-sigma, re-ioc, re-noise).
    
    Args:
        case_file: CaseFile instance
        operation: 'sigma', 'ioc', or 'noise'
    """
    # Save current state
    case_file.previous_state = case_file.file_state
    
    # Reset only relevant flags
    if operation == 'sigma':
        case_file.sigma_hunted = False
        transition_state(case_file, 'SIGMA Hunting', validate=False)
    elif operation == 'ioc':
        case_file.ioc_hunted = False
        transition_state(case_file, 'IOC Hunting', validate=False)
    elif operation == 'noise':
        case_file.known_good = False
        case_file.known_noise = False
        case_file.is_hidden = False
        transition_state(case_file, 'Noise Checking', validate=False)
    
    case_file.failed = False
    
    logger.info(f"[STATE] File {case_file.id} started partial {operation} operation "
               f"(saved previous_state={case_file.previous_state})")


def complete_partial_operation(case_file, operation: str, marked_as_hidden: bool = False) -> None:
    """
    Complete a partial re-operation and restore previous state.
    
    Args:
        case_file: CaseFile instance
        operation: 'sigma', 'ioc', or 'noise'
        marked_as_hidden: If True (noise only), file was hidden
    """
    if marked_as_hidden and operation == 'noise':
        # File matched noise patterns, stays hidden
        transition_state(case_file, 'Hidden', validate=False)
        case_file.is_hidden = True
    elif case_file.previous_state:
        # Restore previous state
        transition_state(case_file, case_file.previous_state, validate=False)
        logger.info(f"[STATE] File {case_file.id} restored to {case_file.previous_state} "
                   f"after {operation} operation")
    else:
        # No previous state saved, finalize
        finalize_processing(case_file)
    
    # Clear previous state
    case_file.previous_state = None


def reset_file_state(case_file) -> None:
    """
    Reset file to New state (for testing/development).
    
    WARNING: This resets ALL flags. Only use for testing.
    """
    case_file.is_new = True
    case_file.is_indexed = False
    case_file.sigma_hunted = False
    case_file.ioc_hunted = False
    case_file.known_good = False
    case_file.known_noise = False
    case_file.is_hidden = False
    case_file.failed = False
    case_file.file_state = 'New'
    case_file.previous_state = None
    case_file.celery_task_id = None
    
    logger.warning(f"[STATE] File {case_file.id} reset to New state")


def get_state_summary(case_file) -> Dict:
    """
    Get a summary of file's current state and flags.
    
    Returns:
        dict: State summary for debugging/logging
    """
    return {
        'file_id': case_file.id,
        'filename': case_file.original_filename,
        'file_state': case_file.file_state,
        'previous_state': case_file.previous_state,
        'flags': {
            'is_new': case_file.is_new,
            'is_indexed': case_file.is_indexed,
            'sigma_hunted': case_file.sigma_hunted,
            'ioc_hunted': case_file.ioc_hunted,
            'known_good': case_file.known_good,
            'known_noise': case_file.known_noise,
            'is_hidden': case_file.is_hidden,
            'failed': case_file.failed,
        },
        'is_completed': case_file.is_completed,
        'is_queued': case_file.is_queued,
        'event_count': case_file.event_count,
    }

