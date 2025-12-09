import boto3
import json
import hashlib
import hmac
import time
import re
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from metrics_store import get_metrics_store

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Security validation utilities for Customer Support AI"""
    
    def __init__(self):
        self.ssm = boto3.client('ssm')
        self.metrics_store = get_metrics_store()
        self._security_config = None
        self._rate_limits = {}
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration from Parameter Store with fallback to defaults"""
        if self._security_config is None:
            # Default security config (fallback)
            default_config = {
                "max_query_length": 1000,
                "rate_limit_per_user": 100
            }
            
            try:
                response = self.ssm.get_parameter(
                    Name='/customer-support-ai/security/config',
                    WithDecryption=True
                )
                ssm_config = json.loads(response['Parameter']['Value'])
                # Merge SSM config with defaults
                self._security_config = {**default_config, **ssm_config}
                logger.info("Loaded security config from SSM Parameter Store")
            except Exception as e:
                logger.warning(f"Failed to get security config from SSM, using defaults: {e}")
                self._security_config = default_config
        return self._security_config
    
    def validate_input(self, query_text: str, user_type: str) -> Tuple[bool, str]:
        """Validate user input for security threats"""
        
        # Check query length
        config = self.get_security_config()
        max_length = config.get('max_query_length', 1000)
        
        if len(query_text) > max_length:
            return False, f"Query too long. Maximum {max_length} characters allowed."
        
        # Check for actual SQL injection patterns (not just SQL keywords)
        sql_injection_patterns = [
            r"';\s*(DROP|DELETE|INSERT|UPDATE)",
            r"\bOR\s+\d+\s*=\s*\d+",
            r"\bUNION\s+SELECT\b",
            r"--\s*$",
            r"/\*.*\*/",
            r"\bEXEC\s*\(",
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, query_text, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {pattern}")
                return False, "Invalid characters detected in query."
        
        # Check for XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:\s*",
            r"on(load|error|click)\s*=",
            r"<iframe[^>]*src",
            r"<object[^>]*data",
            r"<embed[^>]*src"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, query_text, re.IGNORECASE):
                logger.warning(f"Potential XSS detected: {pattern}")
                return False, "Invalid content detected in query."
        
        # Validate user type
        valid_user_types = ['internal', 'external']
        if user_type.lower() not in valid_user_types:
            return False, "Invalid user type specified."
        
        # Check for excessive special characters (potential encoding attacks)
        special_char_ratio = sum(1 for c in query_text if not c.isalnum() and not c.isspace()) / len(query_text)
        if special_char_ratio > 0.3:  # More than 30% special characters
            logger.warning(f"High special character ratio: {special_char_ratio}")
            return False, "Query contains too many special characters."
        
        return True, "Valid input"
    

    
    def check_rate_limit(self, user_id: str, ip_address: str = None) -> Tuple[bool, str]:
        """Check rate limiting for user/IP"""
        
        current_time = int(time.time())
        config = self.get_security_config()
        rate_limit = config.get('rate_limit_per_user', 100)
        window_size = 3600  # 1 hour
        
        # Clean old entries
        cutoff_time = current_time - window_size
        self._rate_limits = {
            key: timestamps for key, timestamps in self._rate_limits.items()
            if any(ts > cutoff_time for ts in timestamps)
        }
        
        # Update timestamps for this user/IP
        for identifier in [user_id, ip_address]:
            if identifier:
                if identifier not in self._rate_limits:
                    self._rate_limits[identifier] = []
                
                # Remove old timestamps
                self._rate_limits[identifier] = [
                    ts for ts in self._rate_limits[identifier] if ts > cutoff_time
                ]
                
                # Check rate limit
                if len(self._rate_limits[identifier]) >= rate_limit:
                    return False, f"Rate limit exceeded. Maximum {rate_limit} requests per hour."
                
                # Add current timestamp
                self._rate_limits[identifier].append(current_time)
        
        return True, "Within rate limit"
    
    def sanitize_output(self, response_text: str) -> str:
        """Sanitize output to prevent information leakage"""
        
        # Remove potential sensitive patterns
        sensitive_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]'),  # SSN
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD-REDACTED]'),  # Credit card
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL-REDACTED]'),  # Email
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE-REDACTED]'),  # Phone
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP-REDACTED]'),  # IP Address
            (r'aws_access_key_id|aws_secret_access_key|password|token', '[CREDENTIAL-REDACTED]')  # Credentials
        ]
        
        sanitized_text = response_text
        for pattern, replacement in sensitive_patterns:
            sanitized_text = re.sub(pattern, replacement, sanitized_text, flags=re.IGNORECASE)
        
        return sanitized_text
    

    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security events for monitoring"""
        
        security_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details,
            'source': 'customer-support-ai'
        }
        
        # Log to CloudWatch with structured format
        logger.info(f"SECURITY_EVENT: {json.dumps(security_log)}")
        
        # Store in metrics store
        try:
            self.metrics_store.record_query(
                details.get('user_id', 'unknown'),
                {'event_type': event_type, 'severity': severity, 'timestamp': security_log['timestamp']}
            )
        except Exception as e:
            logger.warning(f"Failed to store security event: {e}")
        
        # Send to CloudWatch custom metric if critical
        if severity in ['HIGH', 'CRITICAL']:
            try:
                cloudwatch = boto3.client('cloudwatch')
                cloudwatch.put_metric_data(
                    Namespace='CustomerSupportAI/Security',
                    MetricData=[
                        {
                            'MetricName': f'SecurityEvent_{event_type}',
                            'Value': 1,
                            'Unit': 'Count',
                            'Dimensions': [
                                {
                                    'Name': 'Severity',
                                    'Value': severity
                                }
                            ]
                        }
                    ]
                )
            except Exception as e:
                logger.error(f"Failed to send security metric: {e}")


class InputSanitizer:
    """Input sanitization utilities"""
    
    @staticmethod
    def sanitize_query(query: str) -> str:
        """Sanitize user query input"""
        
        # Remove null bytes
        query = query.replace('\x00', '')
        
        # Normalize whitespace
        query = ' '.join(query.split())
        
        # Remove control characters except newlines and tabs
        query = ''.join(char for char in query if ord(char) >= 32 or char in '\n\t')
        
        # Limit length
        if len(query) > 1000:
            query = query[:1000]
        
        return query.strip()
    
    @staticmethod
    def sanitize_user_type(user_type: str) -> str:
        """Sanitize user type input"""
        
        # Convert to lowercase and strip
        user_type = user_type.lower().strip()
        
        # Only allow alphanumeric characters
        user_type = re.sub(r'[^a-z]', '', user_type)
        
        return user_type


class SecurityHeaders:
    """Security headers for HTTP responses"""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }