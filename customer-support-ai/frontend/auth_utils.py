"""
Utility functions for Streamlit frontend
Contains input validation and security headers for the Customer Support AI application
"""

import streamlit as st
import re
from typing import Tuple

class InputValidator:
    """Input validation for Streamlit frontend"""
    
    @staticmethod
    def validate_query(query: str) -> Tuple[bool, str]:
        """Validate user query input"""
        
        if not query or not query.strip():
            return False, "Query cannot be empty"
        
        if len(query) > 1000:
            return False, "Query too long (max 1000 characters)"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'(SELECT|INSERT|UPDATE|DELETE|DROP)\s+',
            r'(UNION|OR|AND)\s+\d+\s*=\s*\d+'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return False, "Invalid characters detected in query"
        
        return True, "Valid query"
    
    @staticmethod
    def sanitize_query(query: str) -> str:
        """Sanitize query input"""
        # Remove null bytes and control characters
        query = ''.join(char for char in query if ord(char) >= 32 or char in '\n\t')
        
        # Normalize whitespace
        query = ' '.join(query.split())
        
        # Limit length
        if len(query) > 1000:
            query = query[:1000]
        
        return query.strip()

class SecurityHeaders:
    """Security headers for Streamlit"""
    
    @staticmethod
    def inject_security_headers():
        """Inject security headers into Streamlit"""
        
        # Content Security Policy - strict, no external CDNs
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        # Inject headers using Streamlit's HTML component
        st.markdown(f"""
        <script>
            // Set security headers (limited in Streamlit)
            document.addEventListener('DOMContentLoaded', function() {{
                // Add security meta tags
                var meta = document.createElement('meta');
                meta.httpEquiv = 'Content-Security-Policy';
                meta.content = '{csp}';
                document.head.appendChild(meta);
                
                // Disable right-click context menu
                document.addEventListener('contextmenu', function(e) {{
                    e.preventDefault();
                }});
                
                // Disable F12 and other dev tools shortcuts
                document.addEventListener('keydown', function(e) {{
                    if (e.key === 'F12' || 
                        (e.ctrlKey && e.shiftKey && e.key === 'I') ||
                        (e.ctrlKey && e.shiftKey && e.key === 'C') ||
                        (e.ctrlKey && e.key === 'U')) {{
                        e.preventDefault();
                    }}
                }});
            }});
        </script>
        """, unsafe_allow_html=True)