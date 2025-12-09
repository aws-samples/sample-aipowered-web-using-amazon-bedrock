"""Check deployment prerequisites"""

import boto3
import subprocess


def check_aws_credentials() -> bool:
    """Check if AWS credentials are configured"""
    try:
        boto3.client('sts').get_caller_identity()
        print("✅ AWS credentials configured")
        return True
    except Exception as e:
        print(f"❌ AWS credentials not configured: {e}")
        print("   Run: aws configure")
        return False


def check_docker() -> bool:
    """Check if Docker is installed and running"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True, check=True)
        print(f"✅ Docker installed: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker not installed")
        print("   Install Docker Desktop")
        return False


def check_all_prerequisites() -> bool:
    """Check if all prerequisites are met"""
    print("🔍 Checking prerequisites...")
    
    checks = [
        check_aws_credentials(),
        check_docker()
    ]
    
    if all(checks):
        print("✅ All prerequisites met")
        return True
    
    return False
