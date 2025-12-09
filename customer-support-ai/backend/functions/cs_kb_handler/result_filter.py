"""
Query Result Filtering and Validation
Secondary security layer for filtering and validating LLM responses
"""

import re
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class ResultFilter:
    """Filter and validate query results for security and compliance"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Sensitive data patterns
        self.sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone number
            r'\b(?:password|pwd|secret|key|token)[\s:=]+\S+\b',  # Credentials
        ]
        
        # Prohibited content patterns
        self.prohibited_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',  # JavaScript URLs
            r'on\w+\s*=',  # Event handlers
            r'eval\s*\(',  # Eval functions
            r'exec\s*\(',  # Exec functions
        ]
        
        # Internal information patterns (for external users)
        self.internal_patterns = [
            r'\b(?:internal|confidential|restricted|private)\b',
            r'\b(?:employee|staff|team member)\s+(?:id|number|code)\b',
            r'\b(?:salary|compensation|budget)\b',
            r'\b(?:server|database|api)\s+(?:password|credential)\b',
        ]
    
    def filter_result(self, result: str, user_type: str, user_id: str) -> Tuple[str, Dict]:
        """
        Filter and validate query result
        Returns: (filtered_result, filter_metadata)
        """
        if not result:
            return result, {"status": "empty_result"}
        
        original_length = len(result)
        filter_metadata = {
            "original_length": original_length,
            "user_type": user_type,
            "user_id": user_id,
            "filters_applied": [],
            "sensitive_data_found": False,
            "prohibited_content_found": False,
            "internal_data_leaked": False
        }
        
        # Apply filters in sequence
        filtered_result = result
        
        # 1. Remove sensitive data
        filtered_result, sensitive_found = self._filter_sensitive_data(filtered_result)
        if sensitive_found:
            filter_metadata["sensitive_data_found"] = True
            filter_metadata["filters_applied"].append("sensitive_data_removal")
        
        # 2. Remove prohibited content
        filtered_result, prohibited_found = self._filter_prohibited_content(filtered_result)
        if prohibited_found:
            filter_metadata["prohibited_content_found"] = True
            filter_metadata["filters_applied"].append("prohibited_content_removal")
        
        # 3. Filter internal information for external users
        if user_type == "external":
            filtered_result, internal_found = self._filter_internal_content(filtered_result)
            if internal_found:
                filter_metadata["internal_data_leaked"] = True
                filter_metadata["filters_applied"].append("internal_content_removal")
        
        # 4. Validate result quality
        quality_score = self._validate_result_quality(filtered_result)
        filter_metadata["quality_score"] = quality_score
        
        # 5. Apply length limits
        filtered_result = self._apply_length_limits(filtered_result)
        
        filter_metadata["final_length"] = len(filtered_result)
        filter_metadata["reduction_percentage"] = (
            (original_length - len(filtered_result)) / original_length * 100
            if original_length > 0 else 0
        )
        
        # Log filtering activity
        self._log_filtering_activity(filter_metadata)
        
        return filtered_result, filter_metadata
    
    def _filter_sensitive_data(self, text: str) -> Tuple[str, bool]:
        """Remove sensitive data patterns"""
        found_sensitive = False
        filtered_text = text
        
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern, filtered_text, re.IGNORECASE)
            if matches:
                found_sensitive = True
                filtered_text = re.sub(pattern, '[REDACTED]', filtered_text, flags=re.IGNORECASE)
                logger.warning(f"Sensitive data pattern found and redacted: {pattern}")
        
        return filtered_text, found_sensitive
    
    def _filter_prohibited_content(self, text: str) -> Tuple[str, bool]:
        """Remove prohibited content patterns"""
        found_prohibited = False
        filtered_text = text
        
        for pattern in self.prohibited_patterns:
            matches = re.findall(pattern, filtered_text, re.IGNORECASE | re.DOTALL)
            if matches:
                found_prohibited = True
                filtered_text = re.sub(pattern, '[CONTENT REMOVED]', filtered_text, flags=re.IGNORECASE | re.DOTALL)
                logger.warning(f"Prohibited content found and removed: {pattern}")
        
        return filtered_text, found_prohibited
    
    def _filter_internal_content(self, text: str) -> Tuple[str, bool]:
        """Remove internal information for external users"""
        found_internal = False
        filtered_text = text
        
        for pattern in self.internal_patterns:
            matches = re.findall(pattern, filtered_text, re.IGNORECASE)
            if matches:
                found_internal = True
                # Replace with generic message
                filtered_text = re.sub(
                    pattern, 
                    '[INTERNAL INFORMATION - CONTACT SUPPORT]', 
                    filtered_text, 
                    flags=re.IGNORECASE
                )
                logger.warning(f"Internal content found and filtered for external user: {pattern}")
        
        return filtered_text, found_internal
    
    def _validate_result_quality(self, text: str) -> float:
        """Validate the quality of the filtered result"""
        if not text or len(text.strip()) < 10:
            return 0.0
        
        # Check for meaningful content
        words = text.split()
        if len(words) < 3:
            return 0.2
        
        # Check for excessive redactions
        redaction_count = text.count('[REDACTED]') + text.count('[CONTENT REMOVED]')
        total_words = len(words)
        
        if total_words > 0:
            redaction_ratio = redaction_count / total_words
            if redaction_ratio > 0.5:  # More than 50% redacted
                return 0.3
            elif redaction_ratio > 0.3:  # More than 30% redacted
                return 0.6
        
        # Check for coherence (basic heuristic)
        sentences = text.split('.')
        if len(sentences) > 1:
            return 0.9
        
        return 0.8
    
    def _apply_length_limits(self, text: str) -> str:
        """Apply length limits to the result"""
        max_length = self.config.get('max_result_length', 2000)
        
        if len(text) > max_length:
            # Truncate at word boundary
            truncated = text[:max_length]
            last_space = truncated.rfind(' ')
            if last_space > max_length * 0.8:  # If we can find a space in the last 20%
                truncated = truncated[:last_space]
            
            truncated += "... [Response truncated for security]"
            return truncated
        
        return text
    
    def _log_filtering_activity(self, metadata: Dict):
        """Log filtering activity for security monitoring"""
        if metadata["filters_applied"]:
            logger.warning(
                f"Result filtering applied for user {metadata['user_id']} "
                f"(type: {metadata['user_type']}): {metadata['filters_applied']}"
            )
        
        if metadata["quality_score"] < 0.5:
            logger.warning(
                f"Low quality result after filtering for user {metadata['user_id']}: "
                f"score={metadata['quality_score']}"
            )

class ResultValidator:
    """Validate query results against security policies"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
    
    def validate_result(self, result: str, context: str, user_type: str) -> Tuple[bool, str, Dict]:
        """
        Validate query result against security policies
        Returns: (is_valid, reason, validation_data)
        """
        validation_data = {
            "result_length": len(result),
            "context_length": len(context),
            "user_type": user_type,
            "validation_checks": []
        }
        
        # Check 1: Minimum content requirement
        if len(result.strip()) < 10:
            return False, "Result too short or empty", validation_data
        
        validation_data["validation_checks"].append("minimum_length_check")
        
        # Check 2: Maximum content limit
        max_length = self.config.get('max_result_length', 2000)
        if len(result) > max_length * 1.5:  # Allow some buffer before filtering
            return False, "Result exceeds maximum length", validation_data
        
        validation_data["validation_checks"].append("maximum_length_check")
        
        # Check 3: Context relevance (basic check)
        if context and len(context) > 50:
            # Simple relevance check - ensure result isn't completely unrelated
            context_words = set(context.lower().split())
            result_words = set(result.lower().split())
            
            # Check for some overlap
            overlap = len(context_words.intersection(result_words))
            if overlap < 2:  # Very basic relevance check
                logger.warning("Low context relevance detected")
        
        validation_data["validation_checks"].append("context_relevance_check")
        
        # Check 4: User type appropriate content
        if user_type == "external":
            # Additional checks for external users
            internal_keywords = ['internal', 'confidential', 'restricted', 'employee']
            result_lower = result.lower()
            
            for keyword in internal_keywords:
                if keyword in result_lower:
                    logger.warning(f"Potential internal content for external user: {keyword}")
        
        validation_data["validation_checks"].append("user_type_content_check")
        
        return True, "Validation passed", validation_data

# Global instances
result_filter = None
result_validator = None

def get_result_filter(config: Dict = None) -> ResultFilter:
    """Get or create global result filter instance"""
    global result_filter
    if result_filter is None:
        result_filter = ResultFilter(config)
    return result_filter

def get_result_validator(config: Dict = None) -> ResultValidator:
    """Get or create global result validator instance"""
    global result_validator
    if result_validator is None:
        result_validator = ResultValidator(config)
    return result_validator