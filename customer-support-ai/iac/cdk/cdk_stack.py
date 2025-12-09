from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elb_v2,
    aws_elasticloadbalancingv2_actions as elb_actions,
    Duration,
    aws_lambda as _lambda,
    Fn,
    aws_logs as logs,
    RemovalPolicy,
    CfnOutput,
    aws_secretsmanager as secretsmanager,
    aws_cognito as cognito,
    aws_certificatemanager as acm,
    aws_wafv2 as wafv2,
    CfnResource
)
# CloudFront removed - using ALB directly with WAF protection

from constructs import Construct


class CdkStack(Stack):
    

    
    def _create_alb_security_group(self, vpc: ec2.Vpc, config: dict) -> ec2.SecurityGroup:
        """Create Security Group for ALB with IP restrictions matching WAF configuration"""
        
        # Get IP configuration from parameters (same logic as WAF)
        allow_all_ips = config.get('allow_all_ips', False)
        allowed_ip_ranges = config.get('allowed_ip_ranges', [])
        
        # Debug: Print configuration being used
        print(f"ALB Security Group Config: allow_all_ips={allow_all_ips}, allowed_ip_ranges={allowed_ip_ranges}")
        
        if allow_all_ips:
            # Allow all IPs when explicitly configured
            allowed_cidrs = ["0.0.0.0/0"]
        elif allowed_ip_ranges:
            # Use configured IP ranges
            allowed_cidrs = allowed_ip_ranges
        else:
            # Require explicit IP configuration - no fallback
            raise ValueError(
                "IP access must be explicitly configured. Set 'allow_all_ips: true' or provide 'allowed_ip_ranges' in parameters.json. "
                "For security, there is no default fallback to allow all IPs."
            )
        
        print(f"Creating ALB Security Group with CIDRs: {allowed_cidrs}")
        
        # Validate configuration before creating security group
        if "0.0.0.0/0" in allowed_cidrs and not allow_all_ips:
            raise ValueError(f"ERROR: 0.0.0.0/0 found in allowed_cidrs but allow_all_ips is False. Config: {config}")
        
        # Create Security Group with unique name to avoid conflicts
        alb_sg = ec2.SecurityGroup(
            self, "ALBSecurityGroupV2",  # Increment version
            vpc=vpc,
            description=f"ALB SG V2 - ONLY {', '.join(allowed_cidrs)} - NO 0.0.0.0/0",
            allow_all_outbound=False  # Restrict outbound traffic
        )
        
        # Explicitly validate we're only adding intended rules
        print(f"SECURITY CHECK: Will add {len(allowed_cidrs)} rules for CIDRs: {allowed_cidrs}")
        
        # Add inbound rules for each allowed IP range
        for i, cidr in enumerate(allowed_cidrs):
            if cidr == "0.0.0.0/0" and not allow_all_ips:
                raise ValueError(f"SECURITY VIOLATION: Attempting to add 0.0.0.0/0 rule when allow_all_ips is False")
            
            # HTTPS (443) - Only allow secure access
            alb_sg.add_ingress_rule(
                peer=ec2.Peer.ipv4(cidr),
                connection=ec2.Port.tcp(443),
                description=f"HTTPS-ONLY from {cidr} - V4"
            )
            print(f"✅ ADDED RULE {i+1}: HTTPS (443) from {cidr}")
        
        print(f"✅ SECURITY GROUP CREATED: {len(allowed_cidrs)} inbound rules added, NO additional rules should exist")
        
        # Add outbound rules to ECS tasks
        alb_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(8501),
            description="Outbound to ECS tasks on port 8501"
        )
        
        # Add outbound for health checks
        alb_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(8501),
            description="Health check to ECS tasks"
        )
        
        return alb_sg
    
    def _create_ecs_security_group(self, vpc: ec2.Vpc, alb_sg: ec2.SecurityGroup) -> ec2.SecurityGroup:
        """Create Security Group for ECS tasks with restricted access"""
        
        ecs_sg = ec2.SecurityGroup(
            self, "ECSSecurityGroup",
            vpc=vpc,
            description="Security Group for ECS Fargate tasks",
            allow_all_outbound=True  # Allow outbound for Lambda calls, etc.
        )
        
        # Allow inbound from ALB only
        ecs_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(alb_sg.security_group_id),
            connection=ec2.Port.tcp(8501),
            description="Inbound from ALB on port 8501"
        )
        
        # Allow inbound for health checks from ALB
        ecs_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(alb_sg.security_group_id),
            connection=ec2.Port.tcp(8501),
            description="Health checks from ALB"
        )
        
        return ecs_sg

    def create_cognito_auth(self, alb_dns_name: str, config: dict) -> tuple[str, str, str]:
        """Create Cognito User Pool and User Pool Client for authentication"""
        # Create User Pool
        user_pool = cognito.UserPool(
            self, "CustomerSupportUserPool",
            user_pool_name="customer-support-ai-users",
            sign_in_aliases=cognito.SignInAliases(username=True, email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Create User Pool Client using CfnUserPoolClient for explicit control
        user_pool_client = cognito.CfnUserPoolClient(
            self, "CustomerSupportUserPoolClientV3",
            user_pool_id=user_pool.user_pool_id,
            client_name="CustomerSupportAIClient",
            generate_secret=True,  # Explicitly set to True for ALB authentication
            explicit_auth_flows=[
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_USER_SRP_AUTH", 
                "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH"
            ],
            supported_identity_providers=["COGNITO"],
            callback_ur_ls=[f"https://{alb_dns_name}/oauth2/idpresponse"],
            logout_ur_ls=[f"https://{alb_dns_name}/oauth2/logout"],
            allowed_o_auth_flows=["code"],
            allowed_o_auth_scopes=["openid", "email", "profile"],
            allowed_o_auth_flows_user_pool_client=True
        )
        
        # Create User Pool Domain
        user_pool_domain = cognito.UserPoolDomain(
            self, "CustomerSupportUserPoolDomain",
            user_pool=user_pool,
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="customer-support-ai-demo"
            )
        )
        
        # Create Cognito Groups for user types
        internal_group = cognito.CfnUserPoolGroup(
            self, "InternalUsersGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="internal",
            description="Internal users with access to all data sources"
        )
        
        external_group = cognito.CfnUserPoolGroup(
            self, "ExternalUsersGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="external",
            description="External users with access to public data sources only"
        )
        
        # Create internal demo user
        internal_user = cognito.CfnUserPoolUser(
            self, "InternalDemoUser",
            user_pool_id=user_pool.user_pool_id,
            username="internal_user",
            user_attributes=[
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email",
                    value="internal@example.com"
                ),
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email_verified",
                    value="true"
                )
            ],
            message_action="SUPPRESS"
        )
        
        # Create external demo user
        external_user = cognito.CfnUserPoolUser(
            self, "ExternalDemoUser",
            user_pool_id=user_pool.user_pool_id,
            username="external_user",
            user_attributes=[
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email",
                    value="external@example.com"
                ),
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email_verified",
                    value="true"
                )
            ],
            message_action="SUPPRESS"
        )
        
        # Assign users to groups (with explicit dependencies)
        internal_attachment = cognito.CfnUserPoolUserToGroupAttachment(
            self, "InternalUserGroupAttachment",
            user_pool_id=user_pool.user_pool_id,
            group_name=internal_group.group_name,
            username=internal_user.username
        )
        internal_attachment.add_dependency(internal_user)
        internal_attachment.add_dependency(internal_group)
        
        external_attachment = cognito.CfnUserPoolUserToGroupAttachment(
            self, "ExternalUserGroupAttachment",
            user_pool_id=user_pool.user_pool_id,
            group_name=external_group.group_name,
            username=external_user.username
        )
        external_attachment.add_dependency(external_user)
        external_attachment.add_dependency(external_group)
        
        return user_pool.user_pool_id, user_pool_client.ref, user_pool_domain.domain_name
    
    def create_frontend_infra(self, config: list, lambda_function_arn: str) -> tuple[str, str, str]:
        # Create a VPC
        vpc = ec2.Vpc(
            self, "CSGenAIDemoVPC",
            max_azs=2,
        )

        # Create ECS cluster (Fargate only - no EC2 capacity needed)
        cluster = ecs.Cluster(self, "CSGenAIDemoCluster", vpc=vpc)
            
        # Build Dockerfile from local folder and push to ECR
        image = ecs.ContainerImage.from_asset('../frontend')

        task_definition = ecs.FargateTaskDefinition(
            self, 'CSGenAIDemoTaskDefinition',
            cpu=1024, memory_limit_mib=4096,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.X86_64  # or ARM64 if you're using ARM
            )
            )

        task_definition.add_to_execution_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=[
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetAuthorizationToken",
                "ecr:GetDownloadUrlForLayer",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ]
        ))
        

        
        task_definition.add_to_task_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                Fn.sub("arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/ecs/csgenai-demo-task:*")
            ],
            actions=[
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ]
        ))
        
        # Add Cognito permissions for application-level authentication
        task_definition.add_to_task_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=[
                Fn.sub("arn:aws:cognito-idp:${AWS::Region}:${AWS::AccountId}:userpool/*")
            ],
            actions=[
                "cognito-idp:AdminInitiateAuth",
                "cognito-idp:AdminGetUser",
                "cognito-idp:GetUser",
                "cognito-idp:GlobalSignOut",
                "cognito-idp:DescribeUserPoolClient",
                "cognito-idp:DescribeUserPool"
            ]
        ))
        

        
        # Add KMS permissions for secret encryption if security stack exists
        if self.security_stack:
            task_definition.add_to_task_role_policy(iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                resources=[self.security_stack.kms_key.key_arn],
                actions=[
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:DescribeKey"
                ]
            ))
        

        
        task_definition.add_to_task_role_policy(
        iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["lambda:InvokeFunction"],
        resources=[lambda_function_arn]))

        task_log_group = logs.LogGroup(
            self,
            "CSGenAIDemoLogGroup",
            log_group_name="/ecs/csgenai-demo-task",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
            encryption_key=self.security_stack.kms_key if self.security_stack else None
        )

        # Container will be defined after Cognito creation

        # Create Security Group for ALB with IP restrictions
        alb_security_group = self._create_alb_security_group(vpc, config)
        
        lb = elb_v2.ApplicationLoadBalancer(
            self, "CSGenAIDemoLoadBalancer", 
            vpc=vpc, 
            internet_facing=True,
            security_group=alb_security_group,
            drop_invalid_header_fields=True  # Security best practice
        )
        
        # CRITICAL: Remove any default security group rules that AWS might add
        # The ALB should ONLY use our custom security group with restricted IPs
        
        # Get SSL certificate ARN - required for HTTPS
        ssl_cert_arn = config.get("ssl_certificate_arn")
        if not ssl_cert_arn:
            raise ValueError(
                "SSL certificate ARN is required for HTTPS deployment. Please:\n"
                "1. Create an SSL certificate in AWS Certificate Manager (ACM)\n"
                "2. Add 'ssl_certificate_arn' to your parameters.json file\n"
                "Example: 'ssl_certificate_arn': 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012'"
            )
        
        # Create Cognito authentication (before container definition)
        user_pool_id, user_pool_client_id, user_pool_domain = self.create_cognito_auth(lb.load_balancer_dns_name, config)
        
        # Now create container with Cognito environment variables
        container = task_definition.add_container(
            "CSGenAIDemoContainer",
            image=image,
            logging=ecs.LogDriver.aws_logs(
                log_group=task_log_group,
                stream_prefix="ecs",
                mode=ecs.AwsLogDriverMode.NON_BLOCKING
            ),
            environment={
                "LLM_FUNCTION_ARN": lambda_function_arn,
                "COGNITO_USER_POOL_ID": user_pool_id,
                "COGNITO_CLIENT_ID": user_pool_client_id,  # Use newly created client
                "AWS_REGION": self.region
            })
        container.add_port_mappings(ecs.PortMapping(container_port=8501, protocol=ecs.Protocol.TCP))

        # Create Security Group for ECS tasks
        ecs_security_group = self._create_ecs_security_group(vpc, alb_security_group)
        
        fargate_service = ecs.FargateService(
            self, "CSGenAIDemoFargateService", 
            cluster=cluster, 
            task_definition=task_definition,
            security_groups=[ecs_security_group]
        )
        
        # Target group for Fargate service (create before listeners)
        target_group = elb_v2.ApplicationTargetGroup(
            self, "CSGenAIDemoTargetGroup",
            vpc=vpc,
            port=8501,
            protocol=elb_v2.ApplicationProtocol.HTTP,
            target_type=elb_v2.TargetType.IP,
            health_check=elb_v2.HealthCheck(
                enabled=True,
                path="/_stcore/health",
                healthy_http_codes="200"
            )
        )
        
        # No HTTP listener - HTTPS only for maximum security
        
        # HTTPS listener with SSL certificate
        # NOTE: CDK/CloudFormation may automatically add a 0.0.0.0/0 rule to the security group
        # when creating a listener. We need to prevent this.
        https_listener = lb.add_listener(
            "CSGenAIDemoHTTPSListener",
            port=443,
            protocol=elb_v2.ApplicationProtocol.HTTPS,
            certificates=[elb_v2.ListenerCertificate.from_arn(ssl_cert_arn)],
            open=False  # CRITICAL: Prevent automatic 0.0.0.0/0 rule creation
        )
        
        # Add Fargate service to target group
        target_group.add_target(fargate_service.load_balancer_target(
            container_name="CSGenAIDemoContainer",
            container_port=8501
        ))
        
        # Direct forward to application (no ALB authentication)
        https_listener.add_action(
            "ForwardToApp",
            action=elb_v2.ListenerAction.forward([target_group])
        )
        """fargate_service.attach_to_application_target_group(target_group)"""

        # Setup task auto-scaling
        scaling = fargate_service.auto_scale_task_count(
            max_capacity=5
        )

        scaling.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=50,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60),
        )                

        # Associate WAF with ALB
        if self.security_stack:
            wafv2.CfnWebACLAssociation(
                self, "ALBWebACLAssociation",
                resource_arn=lb.load_balancer_arn,
                web_acl_arn=self.security_stack.web_acl.attr_arn
            )
        
        # Output ALB information (primary access method)
        CfnOutput(
            self, "ApplicationURL",
            value=f"https://{lb.load_balancer_dns_name}",
            description="Primary application URL (ALB with Cognito authentication)"
        )
        
        # Output Cognito details
        CfnOutput(
            self, "CognitoUserPoolId",
            value=user_pool_id,
            description="Cognito User Pool ID for authentication"
        )
        
        CfnOutput(
            self, "CognitoUserPoolClientId",
            value=user_pool_client_id,
            description="Cognito User Pool Client ID"
        )
        
        CfnOutput(
            self, "LoadBalancerDNS",
            value=lb.load_balancer_dns_name,
            description="Application Load Balancer DNS name"
        )
        
        # Output SSL certificate ARN
        CfnOutput(
            self, "SSLCertificateArn",
            value=ssl_cert_arn,
            description="SSL Certificate ARN used for HTTPS"
        )
        
        # Output demo users info
        CfnOutput(
            self, "DemoUsersInfo",
            value="internal_user (internal group) | external_user (external group) | Passwords set via deployment script",
            description="Demo users - passwords set during deployment"
        )
        
        # Output Security Group information
        CfnOutput(
            self, "ALBSecurityGroupId",
            value=alb_security_group.security_group_id,
            description="ALB Security Group ID with IP restrictions"
        )
        
        CfnOutput(
            self, "ECSSecurityGroupId", 
            value=ecs_security_group.security_group_id,
            description="ECS Security Group ID for Fargate tasks"
        )
        
        # Output security configuration summary
        allowed_ip_ranges = config.get('allowed_ip_ranges', [])
        allow_all_ips = config.get('allow_all_ips', False)
        
        if allow_all_ips:
            security_note = "⚠️  ALB allows access from all IPs (0.0.0.0/0)"
        elif allowed_ip_ranges:
            security_note = f"🔒 ALB restricted to IP ranges: {', '.join(allowed_ip_ranges)}"
        else:
            security_note = "⚠️  ALB allows access from all IPs (default configuration)"
            
        CfnOutput(
            self, "NetworkSecurityConfiguration",
            value=security_note,
            description="Network-level security configuration for ALB"
        )

        # Return resource identifiers for monitoring
        return (
            cluster.cluster_name,
            fargate_service.service_name,
            lb.load_balancer_full_name
        )

    def create_bedrock_guardrail(self) -> str:
        """Create Bedrock guardrail using CloudFormation"""
        guardrail = CfnResource(
            self, "BedrockGuardrail",
            type="AWS::Bedrock::Guardrail",
            properties={
                "Name": "customer-support-ai-guardrail",
                "Description": "Content filtering guardrail for Customer Support AI",
                "ContentPolicyConfig": {
                    "FiltersConfig": [
                        {"Type": "SEXUAL", "InputStrength": "HIGH", "OutputStrength": "HIGH"},
                        {"Type": "VIOLENCE", "InputStrength": "HIGH", "OutputStrength": "HIGH"},
                        {"Type": "HATE", "InputStrength": "HIGH", "OutputStrength": "HIGH"},
                        {"Type": "INSULTS", "InputStrength": "HIGH", "OutputStrength": "HIGH"},
                        {"Type": "MISCONDUCT", "InputStrength": "HIGH", "OutputStrength": "HIGH"},
                        {"Type": "PROMPT_ATTACK", "InputStrength": "HIGH", "OutputStrength": "NONE"}
                    ]
                },
                "SensitiveInformationPolicyConfig": {
                    "PiiEntitiesConfig": [
                        {"Type": "EMAIL", "Action": "BLOCK"},
                        {"Type": "PHONE", "Action": "BLOCK"},
                        {"Type": "US_SOCIAL_SECURITY_NUMBER", "Action": "BLOCK"},
                        {"Type": "CREDIT_DEBIT_CARD_NUMBER", "Action": "BLOCK"}
                    ]
                },
                "BlockedInputMessaging": "I cannot process that request due to content restrictions.",
                "BlockedOutputsMessaging": "I cannot provide that information due to content restrictions."
            }
        )
        return guardrail.ref

    def create_backend_infra(self, config: list) -> tuple[str, str, str]:
        
        # Create Bedrock guardrail if enabled
        guardrail_id = ""
        if config.get("guardrail_enabled", "false").lower() == "true":
            guardrail_id = self.create_bedrock_guardrail()

        # Create IAM role for Lambda
        lambda_role = iam.Role(
            self, "cs-kb-handler-role",
            role_name="cs-kb-handler-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )

        # Add policies    
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    Fn.sub("arn:aws:logs:${AWS::Region}:${AWS::AccountId}:*")
                ]
            )
        )
        
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                    "bedrock:ApplyGuardrail"
                ],
                resources=[
                    Fn.sub("arn:aws:bedrock:${AWS::Region}::foundation-model/anthropic.claude*"),
                    Fn.sub("arn:aws:bedrock:${AWS::Region}::foundation-model/amazon.nova*"),
                    Fn.sub("arn:aws:bedrock:${AWS::Region}:${AWS::AccountId}:guardrail/*")
                    ]
            )
        )
        
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "bedrock:Retrieve",
                    "bedrock:RetrieveAndGenerate"
                ],
                resources=[
                    Fn.sub("arn:aws:bedrock:${AWS::Region}:${AWS::AccountId}:knowledge-base/*")
                ]
            )
        )
        
        # Add SSM parameter access for security configuration
        if self.security_stack:
            lambda_role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["ssm:GetParameter", "ssm:GetParameters"],
                    resources=[
                        Fn.sub("arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/customer-support-ai/security/*")
                    ]
                )
            )
        
        # Add CloudWatch metrics permission (scoped to namespace)
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "cloudwatch:namespace": "CustomerSupportAI/Security"
                    }
                }
            )
        )
                
        # Create Lambda function
        lambda_function = _lambda.Function(
            self, "cs-kb-handler",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="main.cs_kb_handler",
            code=_lambda.Code.from_asset("../backend/functions/cs_kb_handler"),
            role=lambda_role,
            function_name="cs-kb-handler",
            timeout=Duration.minutes(5),
            memory_size=1024,
            environment={
                "EXTERNAL_SOURCE_ID": str(config["external_source_id"]),
                "INTERNAL_SOURCE_ID": str(config["internal_source_id"]),
                "KNOWLEDGE_BASE_ID": str(config["knowledge_base_id"]),
                "MODEL_ID": str(config["model_id"]),
                "GUARDRAIL_ENABLED": str(config.get("guardrail_enabled", "false")),
                "GUARDRAIL_ID": str(guardrail_id if guardrail_id else config.get("guardrail_id", "")),
                "GUARDRAIL_VERSION": str(config.get("guardrail_version", "DRAFT")),
            },
            environment_encryption=self.security_stack.kms_key if self.security_stack else None
        )
        
        return lambda_role.role_arn, lambda_function.function_arn, guardrail_id

    def __init__(self, scope: Construct, construct_id: str, config: list, security_stack=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.security_stack = security_stack
   
        lambda_role_arn, lambda_function_arn, guardrail_id = self.create_backend_infra(config)
        cluster_name, service_name, alb_name = self.create_frontend_infra(config, lambda_function_arn)
        
        # Store resource identifiers for monitoring
        self.lambda_function_name = "cs-kb-handler"
        self.cluster_name = cluster_name
        self.service_name = service_name
        self.alb_name = alb_name
        
        # Output guardrail ID if created
        if guardrail_id:
            CfnOutput(
                self, "GuardrailId",
                value=guardrail_id,
                description="Bedrock Guardrail ID for content filtering"
            )

