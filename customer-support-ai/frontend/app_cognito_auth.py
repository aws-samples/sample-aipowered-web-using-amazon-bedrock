"""
Application-Level Cognito Authentication for Streamlit
Direct integration with AWS Cognito using boto3 SDK
"""

import streamlit as st
import boto3
import json
import hashlib
import hmac
import base64
import time
import logging
from typing import Optional, Dict, Any, Tuple
from botocore.exceptions import ClientError, NoCredentialsError
import os

logger = logging.getLogger(__name__)

class AppCognitoAuth:
    """Application-level Cognito authentication using AWS SDK"""
    
    def __init__(self):
        self.config = self._load_cognito_config()
        self.cognito_client = None
        self.session_timeout = 3600  # 1 hour
        
        if self.config:
            try:
                self.cognito_client = boto3.client(
                    'cognito-idp',
                    region_name=self.config.get('region', 'us-east-1')
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Cognito client: {e}")
    
    def _load_cognito_config(self) -> Optional[Dict[str, str]]:
        """Load Cognito configuration from environment variables or file"""
        
        # Try to load from environment variables first (CDK deployment)
        config = {
            'user_pool_id': os.getenv('COGNITO_USER_POOL_ID'),
            'client_id': os.getenv('COGNITO_CLIENT_ID'),
            'client_secret': os.getenv('COGNITO_CLIENT_SECRET'),
            'region': os.getenv('AWS_REGION', 'us-east-1')
        }
        
        # Check if we have the required environment variables
        if config['user_pool_id'] and config['client_id']:
            # For environment-based config, we'll retrieve the secret at runtime
            logger.info("Loaded Cognito config from environment variables")
            return config
        
        # Fallback to config file (for local development)
        config_file = os.path.join(os.path.dirname(__file__), 'cognito_config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    logger.info("Loaded Cognito config from file")
                    return config
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
        
        logger.warning("No Cognito configuration found in environment or file")
        return None
    
    def is_available(self) -> bool:
        """Check if Cognito authentication is available"""
        return self.config is not None and self.cognito_client is not None
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated"""
        if not self.is_available():
            return False
        
        # Check session state
        if not st.session_state.get('cognito_authenticated', False):
            return False
        
        # Check session timeout
        auth_time = st.session_state.get('cognito_auth_time', 0)
        if time.time() - auth_time > self.session_timeout:
            self.logout()
            return False
        
        # Check if tokens are still valid
        access_token = st.session_state.get('cognito_access_token')
        if access_token and not self._is_token_valid(access_token):
            self.logout()
            return False
        
        return True
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user with Cognito"""
        
        if not self.is_available():
            return False, "Cognito authentication not available"
        
        try:
            # Get client secret (from config file or retrieve from Cognito)
            client_secret = self.config.get('client_secret')
            if not client_secret:
                client_secret = self._get_client_secret()
            
            # Calculate SECRET_HASH if client has secret
            secret_hash = None
            if client_secret:
                secret_hash = self._calculate_secret_hash(username, client_secret)
            
            # Prepare authentication parameters
            auth_params = {
                'USERNAME': username,
                'PASSWORD': password
            }
            
            if secret_hash:
                auth_params['SECRET_HASH'] = secret_hash
            
            # Authenticate with Cognito
            response = self.cognito_client.admin_initiate_auth(
                UserPoolId=self.config['user_pool_id'],
                ClientId=self.config['client_id'],
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters=auth_params
            )
            
            # Handle authentication result
            if 'AuthenticationResult' in response:
                auth_result = response['AuthenticationResult']
                
                # Store tokens in session
                st.session_state.cognito_authenticated = True
                st.session_state.cognito_auth_time = time.time()
                st.session_state.cognito_access_token = auth_result['AccessToken']
                st.session_state.cognito_id_token = auth_result['IdToken']
                st.session_state.cognito_refresh_token = auth_result.get('RefreshToken')
                
                # Extract user info from ID token
                user_info = self._extract_user_info(auth_result['IdToken'])
                st.session_state.cognito_user_info = user_info
                
                # Extract user type from Cognito groups
                user_groups = user_info.get('cognito:groups', [])
                user_type = 'internal'  # Default to internal
                if 'external' in user_groups:
                    user_type = 'external'
                elif 'internal' in user_groups:
                    user_type = 'internal'
                
                # Set standard session variables
                st.session_state.authenticated = True
                st.session_state.user_id = user_info.get('cognito:username', username)
                st.session_state.user_email = user_info.get('email', f'{username}@example.com')
                st.session_state.user_type = user_type
                st.session_state.auth_method = 'cognito_app'
                st.session_state.session_start_time = time.time()
                
                # Clear chat history for new user session
                st.session_state.messages = []
                st.session_state.generated = []
                st.session_state.past = []
                st.session_state.input = ""
                
                logger.info(f"User {username} authenticated successfully")
                return True, "Authentication successful"
            
            elif 'ChallengeName' in response:
                challenge = response['ChallengeName']
                
                if challenge == 'NEW_PASSWORD_REQUIRED':
                    return False, "Password change required. Please contact administrator."
                elif challenge == 'MFA_SETUP':
                    return False, "MFA setup required. Please contact administrator."
                else:
                    return False, f"Authentication challenge required: {challenge}"
            
            else:
                return False, "Authentication failed - unexpected response"
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NotAuthorizedException':
                return False, "Invalid username or password"
            elif error_code == 'UserNotFoundException':
                return False, "User not found"
            elif error_code == 'UserNotConfirmedException':
                return False, "User account not confirmed"
            elif error_code == 'PasswordResetRequiredException':
                return False, "Password reset required"
            elif error_code == 'TooManyRequestsException':
                return False, "Too many requests. Please try again later."
            else:
                logger.error(f"Cognito authentication error: {e}")
                return False, f"Authentication error: {error_code}"
        
        except Exception as e:
            logger.error(f"Unexpected authentication error: {e}")
            return False, "Authentication service unavailable"
    
    def logout(self):
        """Logout user and clear session"""
        
        # Revoke tokens if possible
        try:
            if self.cognito_client and st.session_state.get('cognito_access_token'):
                self.cognito_client.global_sign_out(
                    AccessToken=st.session_state.cognito_access_token
                )
        except Exception as e:
            logger.warning(f"Failed to revoke tokens: {e}")
        
        # Clear Cognito session state
        cognito_keys = [
            'cognito_authenticated', 'cognito_auth_time', 'cognito_access_token',
            'cognito_id_token', 'cognito_refresh_token', 'cognito_user_info'
        ]
        
        for key in cognito_keys:
            if key in st.session_state:
                del st.session_state[key]
        
        # Clear standard session state
        standard_keys = [
            'authenticated', 'user_id', 'user_email', 'user_type', 
            'auth_method', 'session_start_time', 'messages', 'generated', 'past', 'input'
        ]
        
        for key in standard_keys:
            if key in st.session_state:
                del st.session_state[key]
    
    def render_login_form(self):
        """Render Cognito login form"""
        
        st.title("🔐 Login")
        
        if not self.is_available():
            st.error("❌ Authentication not configured")
            st.info("Please configure authentication settings")
            return False
        
        with st.form("cognito_login_form"):
            st.subheader("🔐 Authentication")
            
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            submitted = st.form_submit_button("Login")
            
            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password")
                    return False
                
                with st.spinner("Authenticating..."):
                    success, message = self.authenticate(username, password)
                
                if success:
                    st.success("✅ Authentication successful!")
                    st.rerun()
                else:
                    st.error(f"❌ {message}")
                    return False
        
        # Show demo credentials
        self._display_demo_info()
        return True
    
    def render_user_info(self):
        """Render authenticated user information"""
        
        if not self.is_authenticated():
            return
        
        user_info = st.session_state.get('cognito_user_info', {})
        
        st.success("🔐 Authenticated")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            username = st.session_state.get('user_id', 'Unknown')
            email = st.session_state.get('user_email', 'Unknown')
            st.write(f"👤 **{username}** ({email})")
            st.write(f"🏢 User Type: **{st.session_state.get('user_type', 'internal')}**")
        
        with col2:
            auth_time = st.session_state.get('cognito_auth_time', 0)
            session_duration = int(time.time() - auth_time)
            st.write(f"⏱️ Session: {session_duration//60}m {session_duration%60}s")
        
        with col3:
            if st.button("Logout", key="cognito_app_logout"):
                self.logout()
                st.success("Logged out successfully!")
                st.rerun()
    
    def _get_client_secret(self) -> Optional[str]:
        """Retrieve client secret from Cognito (when not in config file)"""
        try:
            # Try to describe the client to get the secret
            response = self.cognito_client.describe_user_pool_client(
                UserPoolId=self.config['user_pool_id'],
                ClientId=self.config['client_id']
            )
            
            client_details = response['UserPoolClient']
            return client_details.get('ClientSecret')
            
        except Exception as e:
            logger.warning(f"Could not retrieve client secret: {e}")
            return None
    
    def _calculate_secret_hash(self, username: str, client_secret: str) -> str:
        """Calculate SECRET_HASH for Cognito authentication"""
        
        client_id = self.config['client_id']
        
        message = username + client_id
        secret_hash = hmac.new(
            client_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        return base64.b64encode(secret_hash).decode()
    
    def _extract_user_info(self, id_token: str) -> Dict[str, Any]:
        """Extract user information from ID token"""
        
        try:
            # Split JWT and get payload (simplified - no signature verification)
            parts = id_token.split('.')
            if len(parts) >= 2:
                payload = parts[1]
                # Add padding if needed
                payload += '=' * (4 - len(payload) % 4)
                decoded = base64.b64decode(payload)
                user_data = json.loads(decoded)
                return user_data
        except Exception as e:
            logger.warning(f"Failed to extract user info from token: {e}")
        
        return {}
    
    def _is_token_valid(self, access_token: str) -> bool:
        """Check if access token is still valid"""
        
        try:
            # Try to get user info with the token
            self.cognito_client.get_user(AccessToken=access_token)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] in ['NotAuthorizedException', 'TokenExpiredException']:
                return False
            # Other errors might be temporary
            return True
        except Exception:
            return False
    
    def _display_demo_info(self):
        """Display demo user information"""
        
        with st.expander("Demo User Information", expanded=False):
            st.info("🔐 **Demo Credentials**")
            
            st.markdown("""
            ### Demo Users
            - **Internal User**: Access to all data sources (internal + external)
            - **External User**: Access to public data sources only
            - Check **deployment output** for usernames and passwords
            """)


class CognitoAuth:
    """Cognito-only authentication handler"""
    
    def __init__(self):
        self.cognito_auth = AppCognitoAuth()
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated via Cognito"""
        return self.cognito_auth.is_authenticated()
    
    def render_login_form(self):
        """Render Cognito login form"""
        if not self.cognito_auth.is_available():
            st.error("❌ Authentication is not configured")
            st.info("Please ensure the application is properly deployed")
            st.stop()
        
        return self.cognito_auth.render_login_form()
    
    def render_user_info(self):
        """Render user info for authenticated user"""
        if self.cognito_auth.is_authenticated():
            self.cognito_auth.render_user_info()
    
    def logout(self):
        """Logout from Cognito"""
        self.cognito_auth.logout()
    
    def render_session_info(self):
        """Render session information"""
        if self.is_authenticated():
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                user_id = st.session_state.get('user_id', 'Unknown')
                user_type = st.session_state.get('user_type', 'Unknown')
                st.write(f"👤 Logged in as: **{user_id}** ({user_type})")
            
            with col2:
                session_start = st.session_state.get('session_start_time', time.time())
                session_time = int(time.time() - session_start)
                st.write(f"⏱️ Session: {session_time//60}m {session_time%60}s")
            
            with col3:
                if st.button("Logout", key="session_logout"):
                    self.logout()
                    st.success("Logged out successfully!")
                    st.rerun()