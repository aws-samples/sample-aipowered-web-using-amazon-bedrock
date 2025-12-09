"""AWS resource cleanup operations"""

import boto3
import shutil
from pathlib import Path
from botocore.exceptions import ClientError


def empty_s3_bucket(bucket_name: str) -> bool:
    """Empty all objects from S3 bucket"""
    try:
        s3 = boto3.resource('s3')
        bucket = s3.Bucket(bucket_name)
        
        print(f"🗑️  Emptying bucket: {bucket_name}")
        bucket.object_versions.all().delete()
        bucket.objects.all().delete()
        
        print(f"✅ Bucket {bucket_name} emptied")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"ℹ️  Bucket {bucket_name} does not exist")
            return True
        print(f"❌ Failed to empty bucket {bucket_name}: {e}")
        return False


def get_stack_buckets(stack_name: str, region: str = 'us-east-1') -> list:
    """Get all S3 buckets created by a stack"""
    try:
        cf = boto3.client('cloudformation', region_name=region)
        response = cf.describe_stack_resources(StackName=stack_name)
        
        buckets = []
        for resource in response['StackResources']:
            if resource['ResourceType'] == 'AWS::S3::Bucket':
                buckets.append(resource['PhysicalResourceId'])
        
        return buckets
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ValidationError':
            print(f"ℹ️  Stack {stack_name} does not exist")
            return []
        print(f"⚠️  Could not get buckets for stack {stack_name}: {e}")
        return []


def cleanup_ecr_images(region: str = 'us-east-1') -> bool:
    """Delete ECR repository images"""
    try:
        ecr = boto3.client('ecr', region_name=region)
        response = ecr.describe_repositories()
        
        for repo in response['repositories']:
            repo_name = repo['repositoryName']
            
            if 'csgenaidemo' in repo_name.lower():
                try:
                    images_response = ecr.list_images(repositoryName=repo_name)
                    image_ids = images_response.get('imageIds', [])
                    
                    if image_ids:
                        ecr.batch_delete_image(
                            repositoryName=repo_name,
                            imageIds=image_ids
                        )
                        print(f"✅ Deleted images from ECR repository: {repo_name}")
                except Exception as e:
                    print(f"⚠️  Could not delete images from {repo_name}: {e}")
        
        return True
    except Exception as e:
        print(f"⚠️  Error cleaning up ECR images: {e}")
        return True


def cleanup_local_files() -> bool:
    """Clean up local generated files"""
    print("🧹 Cleaning up local files...")
    
    paths_to_remove = ['cdk.out', 'certs', '.venv', '__pycache__']
    
    for path in paths_to_remove:
        try:
            p = Path(path)
            if p.is_dir():
                shutil.rmtree(p)
                print(f"✅ Removed directory: {path}")
            elif p.is_file():
                p.unlink()
                print(f"✅ Removed file: {path}")
        except Exception as e:
            print(f"⚠️  Could not remove {path}: {e}")
    
    return True
