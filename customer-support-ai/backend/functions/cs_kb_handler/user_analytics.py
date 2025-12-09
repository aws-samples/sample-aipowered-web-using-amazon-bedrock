"""
User Behavior Analytics for Lambda Function
Tracks query patterns, volumes, and detects anomalous behavior
"""

import json
import logging
import time
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)

class UserBehaviorAnalytics:
    """Analyze user behavior patterns and detect anomalies"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # User session tracking
        self.user_sessions = defaultdict(dict)  # user_id -> session_data
        self.query_patterns = defaultdict(list)  # user_id -> query_hashes
        self.volume_tracking = defaultdict(deque)  # user_id -> timestamps
        
        # Configuration
        self.max_queries_per_minute = self.config.get('max_queries_per_minute', 30)
        self.max_queries_per_hour = self.config.get('max_queries_per_hour', 300)
        self.max_daily_queries = self.config.get('max_daily_queries', 1000)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.8)
        
    def analyze_user_behavior(self, user_id: str, query: str, source_ip: str, 
                            user_agent: str, session_id: str = None) -> Tuple[bool, str, Dict]:
        """
        Analyze user behavior and detect anomalies
        Returns: (is_allowed, reason, analytics_data)
        """
        current_time = datetime.now()
        
        # Initialize user session if not exists
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {
                'first_seen': current_time,
                'last_activity': current_time,
                'total_queries': 0,
                'unique_ips': set(),
                'user_agents': set(),
                'query_diversity': 0,
                'suspicious_score': 0.0
            }
        
        session = self.user_sessions[user_id]
        
        # Update session data
        session['last_activity'] = current_time
        session['total_queries'] += 1
        session['unique_ips'].add(source_ip)
        session['user_agents'].add(user_agent)
        
        # Check volume limits
        volume_ok, volume_reason = self._check_volume_limits(user_id, current_time)
        if not volume_ok:
            return False, volume_reason, self._get_analytics_data(user_id)
        
        # Analyze query patterns
        pattern_score = self._analyze_query_patterns(user_id, query)
        
        # Calculate behavioral anomaly score
        anomaly_score = self._calculate_anomaly_score(user_id, source_ip, user_agent)
        
        # Update suspicious score
        session['suspicious_score'] = max(pattern_score, anomaly_score)
        
        # Record query
        self._record_query(user_id, query, current_time)
        
        # Check if behavior is suspicious
        if session['suspicious_score'] > self.anomaly_threshold:
            return False, f"Suspicious behavior detected (score: {session['suspicious_score']:.2f})", self._get_analytics_data(user_id)
        
        return True, "Behavior analysis passed", self._get_analytics_data(user_id)
    
    def _check_volume_limits(self, user_id: str, current_time: datetime) -> Tuple[bool, str]:
        """Check if user exceeds volume limits"""
        
        # Clean old entries
        self._cleanup_old_entries(user_id, current_time)
        
        # Check per-minute limit
        minute_ago = current_time - timedelta(minutes=1)
        recent_queries = [t for t in self.volume_tracking[user_id] if t > minute_ago]
        
        if len(recent_queries) >= self.max_queries_per_minute:
            return False, f"Query volume limit exceeded: {len(recent_queries)} queries in last minute"
        
        # Check hourly limit
        hour_ago = current_time - timedelta(hours=1)
        hourly_queries = [t for t in self.volume_tracking[user_id] if t > hour_ago]
        
        if len(hourly_queries) >= self.max_queries_per_hour:
            return False, f"Query volume limit exceeded: {len(hourly_queries)} queries in last hour"
        
        # Check daily limit
        day_ago = current_time - timedelta(days=1)
        daily_queries = [t for t in self.volume_tracking[user_id] if t > day_ago]
        
        if len(daily_queries) >= self.max_daily_queries:
            return False, f"Daily query limit exceeded: {len(daily_queries)} queries in last 24 hours"
        
        return True, "Volume limits OK"
    
    def _analyze_query_patterns(self, user_id: str, query: str) -> float:
        """Analyze query patterns for suspicious behavior"""
        
        # Create query hash for pattern analysis
        query_hash = hashlib.sha256(query.lower().strip().encode()).hexdigest()[:16]
        
        # Track query diversity
        if query_hash not in self.query_patterns[user_id]:
            self.query_patterns[user_id].append(query_hash)
            
        # Keep only last 100 queries for analysis
        if len(self.query_patterns[user_id]) > 100:
            self.query_patterns[user_id] = self.query_patterns[user_id][-100:]
        
        # Calculate pattern score
        total_queries = len(self.query_patterns[user_id])
        unique_queries = len(set(self.query_patterns[user_id]))
        
        if total_queries == 0:
            return 0.0
        
        # Low diversity indicates potential automation
        diversity_ratio = unique_queries / total_queries
        
        # Check for repetitive patterns
        recent_queries = self.query_patterns[user_id][-10:]  # Last 10 queries
        if len(recent_queries) >= 5:
            recent_unique = len(set(recent_queries))
            if recent_unique <= 2:  # Very low diversity in recent queries
                return 0.9
        
        # Score based on diversity (lower diversity = higher suspicion)
        if diversity_ratio < 0.3:
            return 0.8
        elif diversity_ratio < 0.5:
            return 0.6
        elif diversity_ratio < 0.7:
            return 0.4
        else:
            return 0.2
    
    def _calculate_anomaly_score(self, user_id: str, source_ip: str, user_agent: str) -> float:
        """Calculate behavioral anomaly score"""
        
        session = self.user_sessions[user_id]
        score = 0.0
        
        # Multiple IP addresses (potential account sharing/compromise)
        if len(session['unique_ips']) > 3:
            score += 0.3
        
        # Multiple user agents (potential automation)
        if len(session['user_agents']) > 2:
            score += 0.2
        
        # Rapid query frequency
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)
        recent_queries = [t for t in self.volume_tracking[user_id] if t > minute_ago]
        
        if len(recent_queries) > 20:  # Very high frequency
            score += 0.4
        elif len(recent_queries) > 10:
            score += 0.2
        
        # Session duration vs query count (automation indicator)
        session_duration = (current_time - session['first_seen']).total_seconds()
        if session_duration > 0:
            queries_per_second = session['total_queries'] / session_duration
            if queries_per_second > 0.5:  # More than 1 query per 2 seconds
                score += 0.3
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _record_query(self, user_id: str, query: str, timestamp: datetime):
        """Record a query for volume tracking"""
        self.volume_tracking[user_id].append(timestamp)
        
        # Keep only last 2000 queries per user
        if len(self.volume_tracking[user_id]) > 2000:
            self.volume_tracking[user_id] = deque(list(self.volume_tracking[user_id])[-1000:])
    
    def _cleanup_old_entries(self, user_id: str, current_time: datetime):
        """Remove entries older than 24 hours"""
        cutoff_time = current_time - timedelta(hours=24)
        
        # Clean volume tracking
        while (self.volume_tracking[user_id] and 
               self.volume_tracking[user_id][0] < cutoff_time):
            self.volume_tracking[user_id].popleft()
    
    def _get_analytics_data(self, user_id: str) -> Dict:
        """Get current analytics data for a user"""
        session = self.user_sessions.get(user_id, {})
        current_time = datetime.now()
        
        # Calculate recent activity
        minute_ago = current_time - timedelta(minutes=1)
        hour_ago = current_time - timedelta(hours=1)
        
        recent_queries = [t for t in self.volume_tracking[user_id] if t > minute_ago]
        hourly_queries = [t for t in self.volume_tracking[user_id] if t > hour_ago]
        
        return {
            'user_id': user_id,
            'total_queries': session.get('total_queries', 0),
            'queries_last_minute': len(recent_queries),
            'queries_last_hour': len(hourly_queries),
            'unique_ips': len(session.get('unique_ips', set())),
            'unique_user_agents': len(session.get('user_agents', set())),
            'suspicious_score': session.get('suspicious_score', 0.0),
            'query_diversity': len(set(self.query_patterns[user_id])) / max(len(self.query_patterns[user_id]), 1),
            'session_duration_minutes': (current_time - session.get('first_seen', current_time)).total_seconds() / 60
        }
    
    def get_user_risk_profile(self, user_id: str) -> Dict:
        """Get comprehensive risk profile for a user"""
        analytics = self._get_analytics_data(user_id)
        session = self.user_sessions.get(user_id, {})
        
        # Calculate risk level
        risk_score = session.get('suspicious_score', 0.0)
        
        if risk_score > 0.8:
            risk_level = "HIGH"
        elif risk_score > 0.6:
            risk_level = "MEDIUM"
        elif risk_score > 0.4:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            **analytics,
            'risk_level': risk_level,
            'risk_factors': self._identify_risk_factors(user_id),
            'recommendations': self._get_security_recommendations(risk_level)
        }
    
    def _identify_risk_factors(self, user_id: str) -> List[str]:
        """Identify specific risk factors for a user"""
        factors = []
        session = self.user_sessions.get(user_id, {})
        analytics = self._get_analytics_data(user_id)
        
        if analytics['queries_last_minute'] > 15:
            factors.append("High query frequency")
        
        if analytics['unique_ips'] > 2:
            factors.append("Multiple IP addresses")
        
        if analytics['unique_user_agents'] > 1:
            factors.append("Multiple user agents")
        
        if analytics['query_diversity'] < 0.3:
            factors.append("Low query diversity (potential automation)")
        
        if analytics['session_duration_minutes'] > 0:
            qps = analytics['total_queries'] / (analytics['session_duration_minutes'] * 60)
            if qps > 0.3:
                factors.append("Rapid query pattern")
        
        return factors
    
    def _get_security_recommendations(self, risk_level: str) -> List[str]:
        """Get security recommendations based on risk level"""
        recommendations = []
        
        if risk_level == "HIGH":
            recommendations.extend([
                "Implement additional authentication challenges",
                "Reduce rate limits for this user",
                "Monitor all queries for this session",
                "Consider temporary access restriction"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "Increase monitoring frequency",
                "Apply stricter rate limits",
                "Log all queries for review"
            ])
        elif risk_level == "LOW":
            recommendations.extend([
                "Continue standard monitoring",
                "Log query patterns"
            ])
        
        return recommendations

# Global analytics instance
user_analytics = None

def get_user_analytics(config: Dict = None) -> UserBehaviorAnalytics:
    """Get or create global user analytics instance"""
    global user_analytics
    if user_analytics is None:
        user_analytics = UserBehaviorAnalytics(config)
    return user_analytics