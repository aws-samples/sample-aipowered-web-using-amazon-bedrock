"""CDK deployment operations"""

import boto3
import subprocess
from botocore.exceptions import ClientError


def check_cdk_installed() -> bool:
    """Check if CDK is installed"""
    try:
        result = subprocess.run(['cdk', '--version'], capture_output=True, text=True, check=True)
        print(f"✅ CDK installed: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ CDK not installed")
        print("   Run: npm install -g aws-cdk")
        return False


def bootstrap_cdk() -> bool:
    """Bootstrap CDK if needed"""
    print("🚀 Bootstrapping CDK...")
    try:
        subprocess.run(['cdk', 'bootstrap'], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ CDK bootstrap failed: {e}")
        return False


def deploy_stack(stack_name: str) -> bool:
    """Deploy a single CDK stack"""
    # Validate stack name to prevent command injection
    if not stack_name.replace('-', '').replace('_', '').isalnum():
        print(f"❌ Invalid stack name: {stack_name}")
        return False
    
    print(f"📦 Deploying stack: {stack_name}")
    try:
        subprocess.run(
            ['cdk', 'deploy', stack_name, '--require-approval', 'never'],
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to deploy {stack_name}: {e}")
        return False


def deploy_all_stacks() -> bool:
    """Deploy all stacks in correct order"""
    print("📦 Deploying stacks...")
    
    stacks = [
        'CSGenAIDemo-Security',
        'CSGenAIDemo',
        'CSGenAIDemo-Monitoring'
    ]
    
    for stack in stacks:
        if not deploy_stack(stack):
            return False
    
    return True


def destroy_stack(stack_name: str) -> bool:
    """Destroy a single CDK stack"""
    # Validate stack name to prevent command injection
    if not stack_name.replace('-', '').replace('_', '').isalnum():
        print(f"❌ Invalid stack name: {stack_name}")
        return False
    
    print(f"🗑️  Destroying stack: {stack_name}")
    try:
        subprocess.run(
            ['cdk', 'destroy', stack_name, '--force'],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        print(f"⚠️  Failed to destroy {stack_name}, continuing...")
        return False


def destroy_all_stacks() -> bool:
    """Destroy all CDK stacks in reverse order"""
    print("🗑️  Destroying CDK stacks...")
    
    stacks = [
        'CSGenAIDemo-Monitoring',
        'CSGenAIDemo',
        'CSGenAIDemo-Security'
    ]
    
    for stack in stacks:
        destroy_stack(stack)
    
    return True


def get_stack_outputs(stack_name: str, region: str = 'us-east-1') -> dict:
    """Get CloudFormation stack outputs"""
    cf = boto3.client('cloudformation', region_name=region)
    
    try:
        response = cf.describe_stacks(StackName=stack_name)
        outputs = {}
        
        for stack in response['Stacks']:
            for output in stack.get('Outputs', []):
                outputs[output['OutputKey']] = output['OutputValue']
        
        return outputs
    except ClientError:
        return {}
