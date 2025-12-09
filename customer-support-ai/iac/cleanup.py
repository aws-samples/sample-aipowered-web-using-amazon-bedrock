#!/usr/bin/env python3
"""
Comprehensive cleanup script for Customer Support AI
Handles cleanup of all resources including S3 buckets
"""

import sys
from deploy.aws_resources import cleanup_ecr_images, get_stack_buckets, empty_s3_bucket, cleanup_local_files
from deploy.cdk_operations import destroy_all_stacks
from deploy.certificate import delete_certificate


def confirm_cleanup() -> bool:
    """Ask user to confirm cleanup"""
    print("\n" + "=" * 60)
    print("⚠️  WARNING: This will DELETE ALL resources!")
    print("=" * 60)
    print("\nThis will:")
    print("  - Delete all CDK stacks")
    print("  - Empty and delete all S3 buckets")
    print("  - Delete ECR images")
    print("  - Delete SSL certificates")
    print("  - Clean up local files")
    print("\n⚠️  This action CANNOT be undone!")
    
    response = input("\nType 'DELETE' to confirm: ")
    return response == 'DELETE'


def main():
    """Main cleanup function"""
    print("🗑️  Customer Support AI - Comprehensive Cleanup")
    print("=" * 60)
    
    if not confirm_cleanup():
        print("\n❌ Cleanup cancelled")
        sys.exit(0)
    
    print("\n🚀 Starting cleanup process...")
    
    print("\n" + "=" * 60)
    print("Step 1: Cleaning up ECR images")
    print("=" * 60)
    cleanup_ecr_images()
    
    print("\n" + "=" * 60)
    print("Step 2: Emptying S3 buckets")
    print("=" * 60)
    stacks = ['CSGenAIDemo-Monitoring', 'CSGenAIDemo', 'CSGenAIDemo-Security']
    for stack in stacks:
        buckets = get_stack_buckets(stack)
        for bucket in buckets:
            empty_s3_bucket(bucket)
    
    print("\n" + "=" * 60)
    print("Step 3: Destroying CDK stacks")
    print("=" * 60)
    destroy_all_stacks()
    
    print("\n" + "=" * 60)
    print("Step 4: Deleting SSL certificate")
    print("=" * 60)
    delete_certificate()
    
    print("\n" + "=" * 60)
    print("Step 5: Cleaning up local files")
    print("=" * 60)
    cleanup_local_files()
    
    print("\n" + "=" * 60)
    print("✅ CLEANUP COMPLETE!")
    print("=" * 60)
    print("\nAll resources have been deleted.")
    print("\nNote: Some resources may take a few minutes to fully delete.")
    print("Check AWS Console to verify all resources are removed.")


if __name__ == "__main__":
    main()
