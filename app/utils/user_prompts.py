"""
User Decision Prompts - NEW_FILE_UPLOAD.ND Implementation
Handles user decisions for failed files, duplicates, and validation errors
"""

from typing import Dict, List
from datetime import datetime


class UserDecision:
    """Base class for user decision tracking"""
    
    def __init__(self, prompt_type: str, context: Dict):
        self.prompt_type = prompt_type
        self.context = context
        self.decision = None
        self.timestamp = datetime.utcnow()
    
    def set_decision(self, decision: str):
        """Record user's decision"""
        self.decision = decision
        self.timestamp = datetime.utcnow()


class FailedFilePrompt(UserDecision):
    """
    Prompt for failed file moves to upload folder
    Options: SKIP (delete during cleanup) or PRESERVE (move to storage, skip processing)
    """
    
    def __init__(self, filename: str, error: str):
        super().__init__('failed_file', {
            'filename': filename,
            'error': error
        })
    
    def get_prompt_data(self) -> Dict:
        return {
            'type': 'failed_file',
            'title': 'Failed File Upload',
            'message': f'File "{self.context["filename"]}" failed to upload',
            'details': f'Error: {self.context["error"]}',
            'options': [
                {'value': 'SKIP', 'label': 'Skip (delete during cleanup)', 'class': 'btn-warning'},
                {'value': 'PRESERVE', 'label': 'Preserve (move to storage, skip processing)', 'class': 'btn-primary'}
            ]
        }


class DuplicateFilePrompt(UserDecision):
    """
    Prompt for duplicate file detection
    File has same SHA256 as existing file
    """
    
    def __init__(self, filename: str, file_hash: str, existing_file: Dict):
        super().__init__('duplicate_file', {
            'filename': filename,
            'file_hash': file_hash,
            'existing_file': existing_file
        })
    
    def get_prompt_data(self) -> Dict:
        existing = self.context['existing_file']
        return {
            'type': 'duplicate_file',
            'title': 'Duplicate File Detected',
            'message': f'File "{self.context["filename"]}" is a duplicate',
            'details': f'SHA256: {self.context["file_hash"]}<br>Matches existing file: {existing["original_filename"]}<br>Uploaded: {existing.get("uploaded_at", "Unknown")}',
            'options': [
                {'value': 'SKIP', 'label': 'Skip (delete duplicate)', 'class': 'btn-primary'},
                {'value': 'INDEX', 'label': 'Index Anyway (original may be corrupted)', 'class': 'btn-warning'}
            ]
        }


class HashMismatchPrompt(UserDecision):
    """
    Prompt for SHA256 mismatch after file move
    Options: CONTINUE (keep file, log discrepancy) or ABORT (manual fix required)
    """
    
    def __init__(self, filename: str, original_hash: str, verified_hash: str, storage_path: str):
        super().__init__('hash_mismatch', {
            'filename': filename,
            'original_hash': original_hash,
            'verified_hash': verified_hash,
            'storage_path': storage_path
        })
    
    def get_prompt_data(self) -> Dict:
        return {
            'type': 'hash_mismatch',
            'title': 'File Validation Error',
            'message': f'SHA256 mismatch detected for "{self.context["filename"]}"',
            'details': f'Original hash: {self.context["original_hash"]}<br>Verified hash: {self.context["verified_hash"]}<br>File may be corrupted during move.',
            'options': [
                {'value': 'CONTINUE', 'label': 'Continue (keep file, log discrepancy)', 'class': 'btn-warning'},
                {'value': 'ABORT', 'label': 'Abort (stop processing, manual fix required)', 'class': 'btn-error'}
            ]
        }


class MoveFailurePrompt(UserDecision):
    """
    Prompt for file move failure
    Options: SKIP (delete during cleanup) or ABORT (manual fix required)
    """
    
    def __init__(self, filename: str, error: str):
        super().__init__('move_failure', {
            'filename': filename,
            'error': error
        })
    
    def get_prompt_data(self) -> Dict:
        return {
            'type': 'move_failure',
            'title': 'File Move Failed',
            'message': f'Failed to move "{self.context["filename"]}" to storage',
            'details': f'Error: {self.context["error"]}',
            'options': [
                {'value': 'SKIP', 'label': 'Skip (delete during cleanup)', 'class': 'btn-warning'},
                {'value': 'ABORT', 'label': 'Abort (stop processing, manual fix)', 'class': 'btn-error'}
            ]
        }


class PromptManager:
    """Manages collection of user prompts during ingestion"""
    
    def __init__(self):
        self.prompts: List[UserDecision] = []
    
    def add_prompt(self, prompt: UserDecision):
        """Add a prompt to the queue"""
        self.prompts.append(prompt)
    
    def has_pending_prompts(self) -> bool:
        """Check if there are prompts waiting for user decision"""
        return any(p.decision is None for p in self.prompts)
    
    def get_pending_prompts(self) -> List[Dict]:
        """Get all prompts waiting for decision"""
        return [
            {
                'id': idx,
                **p.get_prompt_data()
            }
            for idx, p in enumerate(self.prompts)
            if p.decision is None
        ]
    
    def record_decision(self, prompt_id: int, decision: str):
        """Record user's decision for a prompt"""
        if 0 <= prompt_id < len(self.prompts):
            self.prompts[prompt_id].set_decision(decision)
    
    def get_decisions_log(self) -> List[Dict]:
        """Get log of all decisions made"""
        return [
            {
                'type': p.prompt_type,
                'context': p.context,
                'decision': p.decision,
                'timestamp': p.timestamp.isoformat()
            }
            for p in self.prompts
            if p.decision is not None
        ]

