#!/usr/bin/env python3
"""
Comprehensive deployment script for Customer Support AI
Handles all deployment steps in the correct order
"""

import sys
from deploy.prerequisites import check_all_prerequisites
from deploy.certificate import check_and_generate_certificate
from deploy.cdk_operations import check_cdk_installed, deploy_all_stacks, get_stack_outputs
from deploy.cognito_users import setup_demo_users


def show_deployment_info(credentials: dict):
    """Show deployment information and next steps"""
    print("\n" + "=" * 60)
    print("🎉 DEPLOYMENT COMPLETE!")
    print("=" * 60)
    
    outputs = get_stack_outputs('CSGenAIDemo')
    app_url = outputs.get('ApplicationURL')
    
    if app_url:
        print(f"🌐 Application URL: {app_url}")
        print(f"👤 Demo Credentials:")
        print(f"   Internal User: internal_user / {credentials.get('internal_user', 'N/A')}")
        print(f"   External User: external_user / {credentials.get('external_user', 'N/A')}")
        print()
        print(f"🔒 Security Notes:")
        print(f"   - Using self-signed SSL certificate (browser will show warning)")
        print(f"   - Click 'Advanced' and 'Proceed' in your browser")
        print(f"   - WAF protection is active")
        print()
        print(f"📋 Next Steps:")
        print(f"   1. Visit the application URL above")
        print(f"   2. Login with demo credentials")
        print(f"   3. Test the AI assistant functionality")
        print()
        print(f"🗑️  To clean up:")
        print(f"   python3 cleanup.py")


def main():
    """Main deployment function"""
    print("🚀 Customer Support AI - Comprehensive Deployment")
    print("=" * 60)
    
    if not check_all_prerequisites():
        sys.exit(1)
    
    if not check_cdk_installed():
        sys.exit(1)
    
    if not check_and_generate_certificate():
        print("❌ SSL certificate setup failed")
        sys.exit(1)
    
    if not deploy_all_stacks():
        print("❌ Stack deployment failed")
        sys.exit(1)
    
    outputs = get_stack_outputs('CSGenAIDemo')
    user_pool_id = outputs.get('CognitoUserPoolId')
    
    credentials = {}
    if user_pool_id:
        credentials = setup_demo_users(user_pool_id)
    else:
        print("⚠️  Could not find Cognito User Pool ID")
    
    show_deployment_info(credentials)
    print("\n✅ Deployment completed successfully!")


if __name__ == "__main__":
    main()
