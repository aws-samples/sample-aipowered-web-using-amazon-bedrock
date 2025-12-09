"""
Bedrock Query Pattern Analysis and Rate Limiting
Monitors for bulk extraction attempts and suspicious query patterns
"""

import json
import logging
import time
import re
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
from metrics_store import get_metrics_store

logger = logging.getLogger(__name__)

class BedrockQueryMonitor:
    """Monitor Bedrock queries for suspicious patterns and rate limiting"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.metrics_store = get_metrics_store()
        self.query_history = defaultdict(deque)  # user_id -> deque of timestamps
        self.pattern_violations = defaultdict(int)  # user_id -> violation count
        self.token_usage = defaultdict(deque)  # user_id -> deque of (timestamp, tokens)
        
        # Load configuration
        self.bulk_threshold = self.config.get('bulk_extraction_threshold', 10)
        self.max_queries_per_minute = self.config.get('queries_per_minute', 20)
        self.max_queries_per_hour = self.config.get('queries_per_hour', 200)
        self.max_tokens_per_minute = self.config.get('tokens_per_minute', 10000)
        self.suspicious_patterns = self.config.get('suspicious_patterns', [
            r'list\s+all', r'show\s+all', r'dump', r'extract', r'download',
            r'SELECT\s+\*', r'UNION', r'OR\s+1\s*=\s*1', r"';\s*DROP",
            r'<script', r'javascript:', r'eval\s*\(', r'exec\s*\('
        ])
    
    def analyze_query_pattern(self, user_id: str, query: str, source_ip: str) -> Tuple[bool, str, Dict]:
        """
        Analyze query for suspicious patterns and rate limiting
        Returns: (is_allowed, reason, metrics)
        """
        current_time = datetime.now()
        metrics = {
            'timestamp': current_time.isoformat(),
            'user_id': user_id,
            'source_ip': source_ip,
            'query_length': len(query),
            'suspicious_patterns_found': [],
            'rate_limit_status': 'ok'
        }
        
        # Check for suspicious patterns
        suspicious_found = self._check_suspicious_patterns(query)
        if suspicious_found:
            metrics['suspicious_patterns_found'] = suspicious_found
            self.pattern_violations[user_id] += 1
            
            logger.warning(f"Suspicious patterns detected for user {user_id}: {suspicious_found}")
            
            try:
                self.metrics_store.increment_violation(user_id, 'suspicious_pattern')
            except Exception as e:
                logger.warning(f"Failed to record violation: {e}")
            
            if self.pattern_violations[user_id] >= 3:
                return False, "Multiple suspicious pattern violations detected", metrics
        
        # Check rate limits
        rate_limit_ok, rate_reason = self._check_rate_limits(user_id, current_time)
        if not rate_limit_ok:
            metrics['rate_limit_status'] = 'exceeded'
            return False, rate_reason, metrics
        
        # Check for bulk extraction patterns
        bulk_extraction_detected = self._detect_bulk_extraction(user_id, query, current_time)
        if bulk_extraction_detected:
            metrics['bulk_extraction_detected'] = True
            return False, "Bulk extraction pattern detected", metrics
        
        # Record successful query
        self._record_query(user_id, current_time)
        
        # Store in metrics store
        try:
            self.metrics_store.record_query(user_id, metrics)
        except Exception as e:
            logger.warning(f"Failed to store metrics: {e}")
        
        return True, "Query approved", metrics
    
    def _check_suspicious_patterns(self, query: str) -> List[str]:
        """Check query against suspicious patterns"""
        found_patterns = []
        query_lower = query.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _check_rate_limits(self, user_id: str, current_time: datetime) -> Tuple[bool, str]:
        """Check if user exceeds rate limits"""
        
        # Try metrics store first for cross-instance rate limiting
        try:
            queries_last_minute = self.metrics_store.get_query_count(user_id, 1)
            queries_last_hour = self.metrics_store.get_query_count(user_id, 60)
            
            if queries_last_minute >= self.max_queries_per_minute:
                return False, f"Rate limit exceeded: {queries_last_minute} queries in last minute"
            
            if queries_last_hour >= self.max_queries_per_hour:
                return False, f"Rate limit exceeded: {queries_last_hour} queries in last hour"
            
            return True, "Rate limit OK"
        except Exception as e:
            logger.warning(f"Metrics store rate limit check failed, using in-memory: {e}")
        
        # Fallback to in-memory rate limiting
        self._cleanup_old_entries(user_id, current_time)
        
        minute_ago = current_time - timedelta(minutes=1)
        recent_queries = [t for t in self.query_history[user_id] if t > minute_ago]
        
        if len(recent_queries) >= self.max_queries_per_minute:
            return False, f"Rate limit exceeded: {len(recent_queries)} queries in last minute"
        
        hour_ago = current_time - timedelta(hours=1)
        hourly_queries = [t for t in self.query_history[user_id] if t > hour_ago]
        
        if len(hourly_queries) >= self.max_queries_per_hour:
            return False, f"Rate limit exceeded: {len(hourly_queries)} queries in last hour"
        
        return True, "Rate limit OK"
    
    def _detect_bulk_extraction(self, user_id: str, query: str, current_time: datetime) -> bool:
        """Detect potential bulk extraction attempts"""
        
        # Check for rapid sequential queries
        minute_ago = current_time - timedelta(minutes=1)
        recent_queries = [t for t in self.query_history[user_id] if t > minute_ago]
        
        if len(recent_queries) >= self.bulk_threshold:
            logger.warning(f"Bulk extraction detected: {len(recent_queries)} queries in 1 minute for user {user_id}")
            return True
        
        # Check for extraction-related keywords
        extraction_keywords = ['all', 'list', 'dump', 'export', 'download', 'extract']
        query_words = query.lower().split()
        
        if any(keyword in query_words for keyword in extraction_keywords):
            # If extraction keywords found, apply stricter rate limiting
            if len(recent_queries) >= 3:  # Lower threshold for extraction queries
                return True
        
        return False
    
    def _record_query(self, user_id: str, timestamp: datetime):
        """Record a successful query"""
        self.query_history[user_id].append(timestamp)
        
        # Keep only last 1000 queries per user to prevent memory issues
        if len(self.query_history[user_id]) > 1000:
            self.query_history[user_id].popleft()
    
    def _cleanup_old_entries(self, user_id: str, current_time: datetime):
        """Remove entries older than 24 hours"""
        cutoff_time = current_time - timedelta(hours=24)
        
        # Clean query history
        while (self.query_history[user_id] and 
               self.query_history[user_id][0] < cutoff_time):
            self.query_history[user_id].popleft()
        
        # Clean token usage
        while (self.token_usage[user_id] and 
               self.token_usage[user_id][0][0] < cutoff_time):
            self.token_usage[user_id].popleft()
    
    def record_token_usage(self, user_id: str, tokens_used: int):
        """Record token usage for monitoring"""
        current_time = datetime.now()
        self.token_usage[user_id].append((current_time, tokens_used))
        
        # Check token rate limits
        minute_ago = current_time - timedelta(minutes=1)
        recent_tokens = sum(tokens for timestamp, tokens in self.token_usage[user_id] 
                          if timestamp > minute_ago)
        
        if recent_tokens > self.max_tokens_per_minute:
            logger.warning(f"Token rate limit exceeded for user {user_id}: {recent_tokens} tokens in last minute")
    
    def get_user_metrics(self, user_id: str) -> Dict:
        """Get current metrics for a user"""
        current_time = datetime.now()
        self._cleanup_old_entries(user_id, current_time)
        
        minute_ago = current_time - timedelta(minutes=1)
        hour_ago = current_time - timedelta(hours=1)
        
        recent_queries = [t for t in self.query_history[user_id] if t > minute_ago]
        hourly_queries = [t for t in self.query_history[user_id] if t > hour_ago]
        
        recent_tokens = sum(tokens for timestamp, tokens in self.token_usage[user_id] 
                          if timestamp > minute_ago)
        
        return {
            'queries_last_minute': len(recent_queries),
            'queries_last_hour': len(hourly_queries),
            'tokens_last_minute': recent_tokens,
            'pattern_violations': self.pattern_violations[user_id],
            'total_queries': len(self.query_history[user_id])
        }

# Global monitor instance
bedrock_monitor = None

def get_bedrock_monitor(config: Dict = None) -> BedrockQueryMonitor:
    """Get or create global Bedrock monitor instance"""
    global bedrock_monitor
    if bedrock_monitor is None:
        bedrock_monitor = BedrockQueryMonitor(config)
    return bedrock_monitor