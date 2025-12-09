"""Cognito user management"""

import boto3
import secrets
import string
from botocore.exceptions import ClientError


def generate_password() -> str:
    """Generate password that meets Cognito requirements"""
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice('!@#$%^&*')
    ]
    all_chars = string.ascii_letters + string.digits + '!@#$%^&*'
    password.extend(secrets.choice(all_chars) for _ in range(8))
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def setup_demo_users(user_pool_id: str, region: str = 'us-east-1') -> dict:
    """Set up demo users passwords"""
    print("👤 Setting up demo users...")
    
    cognito = boto3.client('cognito-idp', region_name=region)
    
    users = [
        {'username': 'internal_user', 'group': 'internal'},
        {'username': 'external_user', 'group': 'external'}
    ]
    
    credentials = {}
    
    for user in users:
        username = user['username']
        password = generate_password()
        
        try:
            cognito.admin_set_user_password(
                UserPoolId=user_pool_id,
                Username=username,
                Password=password,
                Permanent=True
            )
            
            credentials[username] = password
            print(f"✅ Password set for {username} ({user['group']} group)")
        except ClientError as e:
            print(f"⚠️  Could not set password for {username}: {e}")
    
    return credentials
