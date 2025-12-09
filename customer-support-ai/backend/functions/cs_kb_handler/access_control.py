"""
Multi-layer Access Control for Vector Search and Document-level Security
Prevents cross-user access and privacy violations in knowledge base queries
"""

import json
import logging
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class VectorSearchAccessControl:
    """Multi-layer access control for vector search operations"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # User context isolation
        self.user_contexts = {}
        
        # Access patterns tracking
        self.access_patterns = {}
    
    def clear_user_context(self, user_id: str):
        """Clear user context when user logs out or new user logs in"""
        if user_id in self.user_contexts:
            del self.user_contexts[user_id]
        if user_id in self.access_patterns:
            del self.access_patterns[user_id]
        
    def validate_access_request(self, user_id: str, user_type: str, query: str, 
                              source_ids: List[str]) -> Tuple[bool, str, Dict]:
        """
        Validate access request with multi-layer controls
        Returns: (is_allowed, reason, access_metadata)
        """
        access_metadata = {
            'user_id': user_id,
            'user_type': user_type,
            'query_hash': hashlib.sha256(query.encode()).hexdigest()[:16],
            'source_ids': source_ids,
            'timestamp': datetime.now().isoformat(),
            'access_checks': []
        }
        
        # Layer 1: Query context isolation
        if not self._validate_query_context(user_id, query):
            return False, "Query context validation failed", access_metadata
        
        access_metadata['access_checks'].append('query_context_validation')
        
        # Layer 2: Cross-user access detection
        if self._detect_cross_user_access_attempt(user_id, query):
            return False, "Cross-user access attempt detected", access_metadata
        
        access_metadata['access_checks'].append('cross_user_access_check')
        
        # Layer 3: Data source authorization
        authorized_sources = self._get_authorized_sources(user_id, user_type)
        if not all(source_id in authorized_sources for source_id in source_ids):
            return False, "Access denied to one or more data sources", access_metadata
        
        access_metadata['access_checks'].append('data_source_authorization')
        
        # Record access pattern
        self._record_access_pattern(user_id, query, source_ids)
        
        return True, "Access granted", access_metadata
    
    def _validate_query_context(self, user_id: str, query: str) -> bool:
        """Validate query context for user isolation"""
        
        # Initialize user context if not exists
        if user_id not in self.user_contexts:
            self.user_contexts[user_id] = {
                'query_history': [],
                'context_hash': hashlib.sha256(user_id.encode()).hexdigest()[:8]
            }
        
        user_context = self.user_contexts[user_id]
        
        # Check for context injection attempts
        suspicious_patterns = [
            r'user[_\s]*id\s*[:=]\s*["\']?(?!' + user_id + r')[^"\'\s]+',
            r'context[_\s]*user\s*[:=]',
            r'access[_\s]*as[_\s]*user',
            r'impersonate[_\s]*user',
            r'switch[_\s]*user'
        ]
        
        import re
        query_lower = query.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query_lower):
                logger.warning(f"Suspicious context injection pattern detected: {pattern}")
                return False
        
        # Record query in user context
        user_context['query_history'].append({
            'query_hash': hashlib.sha256(query.encode()).hexdigest()[:16],
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only last 100 queries
        if len(user_context['query_history']) > 100:
            user_context['query_history'] = user_context['query_history'][-100:]
        
        return True
    
    def _detect_cross_user_access_attempt(self, user_id: str, query: str) -> bool:
        """Detect attempts to access other users' data"""
        
        # Patterns that might indicate cross-user access attempts
        cross_user_patterns = [
            r'user[_\s]*(?:id|name|email)\s*[:=]\s*["\']?(?!' + user_id + r')[^"\'\s]+',
            r'other[_\s]*user',
            r'all[_\s]*users?',
            r'list[_\s]*users?',
            r'user[_\s]*data[_\s]*for',
            r'access[_\s]*user[_\s]*\w+',
            r'show[_\s]*user[_\s]*\w+'
        ]
        
        import re
        query_lower = query.lower()
        
        for pattern in cross_user_patterns:
            if re.search(pattern, query_lower):
                logger.warning(f"Cross-user access pattern detected for user {user_id}: {pattern}")
                return True
        
        return False
    
    def _get_authorized_sources(self, user_id: str, user_type: str) -> List[str]:
        """Get list of authorized data sources for user"""
        import os
        
        external_source = os.environ.get('EXTERNAL_SOURCE_ID', '')
        internal_source = os.environ.get('INTERNAL_SOURCE_ID', '')
        
        # Base authorization by user type
        if user_type == 'external':
            authorized = [external_source] if external_source else []
        elif user_type == 'internal':
            authorized = [external_source, internal_source] if external_source and internal_source else []
        else:
            authorized = []
        
        return authorized
    
    def _record_access_pattern(self, user_id: str, query: str, source_ids: List[str]):
        """Record access pattern for monitoring"""
        
        if user_id not in self.access_patterns:
            self.access_patterns[user_id] = []
        
        pattern = {
            'timestamp': datetime.now().isoformat(),
            'query_hash': hashlib.sha256(query.encode()).hexdigest()[:16],
            'source_ids': source_ids,
            'query_length': len(query)
        }
        
        self.access_patterns[user_id].append(pattern)
        
        # Keep only last 1000 access patterns per user
        if len(self.access_patterns[user_id]) > 1000:
            self.access_patterns[user_id] = self.access_patterns[user_id][-1000:]

class PrivacyViolationDetector:
    """Detect privacy violations and cross-user access attempts"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.violation_patterns = {}
        
    def detect_privacy_violation(self, user_id: str, query: str, results: List[Dict], user_type: str = None) -> Tuple[bool, str, Dict]:
        """
        Detect privacy violations in query and results
        Returns: (violation_detected, violation_type, violation_data)
        """
        violation_data = {
            'user_id': user_id,
            'query_hash': hashlib.sha256(query.encode()).hexdigest()[:16],
            'results_count': len(results),
            'timestamp': datetime.now().isoformat(),
            'violation_checks': []
        }
        
        # Check 1: Query-based privacy violations
        query_violation = self._check_query_privacy_violation(query)
        if query_violation:
            violation_data['query_violation'] = query_violation
            return True, "Query privacy violation", violation_data
        
        violation_data['violation_checks'].append('query_privacy_check')
        
        # Check 2: Result-based privacy violations
        result_violation = self._check_result_privacy_violation(results, user_id, user_type)
        if result_violation:
            violation_data['result_violation'] = result_violation
            return True, "Result privacy violation", violation_data
        
        violation_data['violation_checks'].append('result_privacy_check')
        
        # Check 3: Cross-user data leakage
        cross_user_leakage = self._check_cross_user_leakage(results, user_id)
        if cross_user_leakage:
            violation_data['cross_user_leakage'] = cross_user_leakage
            return True, "Cross-user data leakage", violation_data
        
        violation_data['violation_checks'].append('cross_user_leakage_check')
        
        return False, "No privacy violation detected", violation_data
    
    def _check_query_privacy_violation(self, query: str) -> Optional[Dict]:
        """Check for privacy violations in the query"""
        
        privacy_violation_patterns = [
            r'personal[_\s]*(?:information|data|details)',
            r'private[_\s]*(?:information|data|details)',
            r'confidential[_\s]*(?:information|data|details)',
            r'user[_\s]*(?:credentials|passwords|tokens)',
            r'email[_\s]*addresses?',
            r'phone[_\s]*numbers?',
            r'social[_\s]*security',
            r'credit[_\s]*card',
            r'financial[_\s]*information'
        ]
        
        import re
        query_lower = query.lower()
        
        for pattern in privacy_violation_patterns:
            if re.search(pattern, query_lower):
                return {
                    'pattern': pattern,
                    'query_excerpt': query[:100] + '...' if len(query) > 100 else query
                }
        
        return None
    
    def _check_result_privacy_violation(self, results: List[Dict], user_id: str, user_type: str = None) -> Optional[Dict]:
        """Check for privacy violations in the results"""
        
        # Internal users can see email addresses in internal documents
        if user_type == 'internal':
            return None
        
        violation_indicators = []
        
        for i, result in enumerate(results):
            content = result.get('content', {}).get('text', '')
            
            # Check for PII patterns in results
            pii_patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'  # Phone
            ]
            
            import re
            for pattern in pii_patterns:
                if re.search(pattern, content):
                    violation_indicators.append({
                        'result_index': i,
                        'pattern_type': pattern,
                        'content_excerpt': content[:100] + '...' if len(content) > 100 else content
                    })
        
        return violation_indicators if violation_indicators else None
    
    def _check_cross_user_leakage(self, results: List[Dict], user_id: str) -> Optional[Dict]:
        """Check for cross-user data leakage in results"""
        
        leakage_indicators = []
        
        for i, result in enumerate(results):
            content = result.get('content', {}).get('text', '')
            metadata = result.get('metadata', {})
            
            # Check if result contains references to other users
            import re
            
            # Look for user ID patterns that don't match current user
            user_id_patterns = [
                r'user[_\s]*id\s*[:=]\s*["\']?([^"\'\s]+)',
                r'user[_\s]*name\s*[:=]\s*["\']?([^"\'\s]+)',
                r'created[_\s]*by\s*[:=]\s*["\']?([^"\'\s]+)'
            ]
            
            for pattern in user_id_patterns:
                matches = re.findall(pattern, content.lower())
                for match in matches:
                    if match != user_id.lower():
                        leakage_indicators.append({
                            'result_index': i,
                            'other_user_reference': match,
                            'pattern': pattern
                        })
        
        return leakage_indicators if leakage_indicators else None

# Global instances
access_control = None
privacy_detector = None

def get_access_control(config: Dict = None) -> VectorSearchAccessControl:
    """Get or create global access control instance"""
    global access_control
    if access_control is None:
        access_control = VectorSearchAccessControl(config)
    return access_control

def get_privacy_detector(config: Dict = None) -> PrivacyViolationDetector:
    """Get or create global privacy detector instance"""
    global privacy_detector
    if privacy_detector is None:
        privacy_detector = PrivacyViolationDetector(config)
    return privacy_detector