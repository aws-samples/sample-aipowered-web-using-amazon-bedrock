"""
Metrics storage for demo/development
Extensible interface allows adding DynamoDB or other storage backends
"""

import logging
from datetime import datetime, timedelta
from typing import Dict

logger = logging.getLogger(__name__)

class MetricsStore:
    """Abstract metrics storage interface for extensibility"""
    
    def record_query(self, user_id: str, query_data: Dict):
        raise NotImplementedError
    
    def get_query_count(self, user_id: str, minutes: int) -> int:
        """Get count of queries in last N minutes for rate limiting"""
        raise NotImplementedError
    
    def increment_violation(self, user_id: str, violation_type: str):
        raise NotImplementedError


class InMemoryMetricsStore(MetricsStore):
    """In-memory metrics storage for demo/development"""
    
    def __init__(self):
        self.queries = {}
        self.violations = {}
    
    def record_query(self, user_id: str, query_data: Dict):
        if user_id not in self.queries:
            self.queries[user_id] = []
        self.queries[user_id].append({
            'timestamp': datetime.now().timestamp(),
            'query_data': query_data
        })
    
    def get_query_count(self, user_id: str, minutes: int) -> int:
        """Get count of queries in last N minutes"""
        cutoff = (datetime.now() - timedelta(minutes=minutes)).timestamp()
        return len([q for q in self.queries.get(user_id, []) if q['timestamp'] > cutoff])
    
    def increment_violation(self, user_id: str, violation_type: str):
        if user_id not in self.violations:
            self.violations[user_id] = {}
        self.violations[user_id][violation_type] = self.violations[user_id].get(violation_type, 0) + 1


def get_metrics_store() -> MetricsStore:
    """Get metrics store instance"""
    logger.info("Using in-memory metrics store (demo mode)")
    return InMemoryMetricsStore()
