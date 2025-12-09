from aws_cdk import (
    Stack,
    aws_wafv2 as wafv2,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
    aws_kms as kms,
    aws_iam as iam,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct
import json


class SecurityStack(Stack):
    
    def __init__(self, scope: Construct, construct_id: str, config: dict = None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.config = config or {}
        
        # Create KMS key for encryption
        self.kms_key = self._create_kms_key()
        
        # Create WAF for ALB (Regional scope only)
        self.web_acl = self._create_alb_waf()
        
        # IP management is handled directly in _create_alb_waf() via _create_ip_set()
        
        # Create security configuration
        self._create_security_config()
        
        # Create outputs
        self._create_outputs()
    
    def _create_kms_key(self) -> kms.Key:
        """Create KMS key for encryption"""
        key = kms.Key(
            self, "CustomerSupportAIKey",
            description="KMS key for Customer Support AI encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="Enable IAM User Permissions",
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AccountRootPrincipal()],
                        actions=["kms:*"],
                        resources=["*"]
                    ),
                    iam.PolicyStatement(
                        sid="Allow CloudWatch Logs",
                        effect=iam.Effect.ALLOW,
                        principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                        actions=[
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:DescribeKey"
                        ],
                        resources=["*"],
                        conditions={
                            "ArnEquals": {
                                "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"
                            }
                        }
                    )
                ]
            )
        )
        
        key.add_alias("alias/customer-support-ai")
        return key
    
    def _create_alb_waf(self) -> wafv2.CfnWebACL:
        """Create WAF Web ACL for ALB (Regional scope)"""
        
        # IP allowlist rule (highest priority)
        # Add your office/home IP ranges here
        ip_allowlist_rule = wafv2.CfnWebACL.RuleProperty(
            name="IPAllowlistRule",
            priority=0,
            statement=wafv2.CfnWebACL.StatementProperty(
                ip_set_reference_statement=wafv2.CfnWebACL.IPSetReferenceStatementProperty(
                    arn=self._create_ip_set().attr_arn
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="IPAllowlistRule"
            )
        )
        
        # Multi-layer rate limiting with CAPTCHA
        # Layer 1: Aggressive rate limit with CAPTCHA challenge
        rate_limit_captcha_rule = wafv2.CfnWebACL.RuleProperty(
            name="RateLimitCAPTCHARule",
            priority=1,
            statement=wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=100,  # 100 requests per 5 minutes per IP
                    aggregate_key_type="IP"
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(
                captcha=wafv2.CfnWebACL.CaptchaActionProperty(
                    custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                        insert_headers=[
                            wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="X-Rate-Limited",
                                value="captcha-challenge"
                            )
                        ]
                    )
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="RateLimitCAPTCHARule"
            )
        )
        
        # Layer 2: User-Agent based rate limiting
        user_agent_rate_limit_rule = wafv2.CfnWebACL.RuleProperty(
            name="UserAgentRateLimitRule",
            priority=2,
            statement=wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=200,  # 200 requests per 5 minutes per user-agent
                    aggregate_key_type="FORWARDED_IP",
                    forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                        header_name="X-Forwarded-For",
                        fallback_behavior="MATCH"
                    ),
                    scope_down_statement=wafv2.CfnWebACL.StatementProperty(
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            search_string="Mozilla",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                single_header=wafv2.CfnWebACL.SingleHeaderProperty(
                                    name="user-agent"
                                )
                            ),
                            text_transformations=[
                                wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=0,
                                    type="LOWERCASE"
                                )
                            ],
                            positional_constraint="CONTAINS"
                        )
                    )
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(
                captcha=wafv2.CfnWebACL.CaptchaActionProperty()
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="UserAgentRateLimitRule"
            )
        )
        
        # Layer 3: Session-based rate limiting (using custom header)
        session_rate_limit_rule = wafv2.CfnWebACL.RuleProperty(
            name="SessionRateLimitRule",
            priority=3,
            statement=wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=150,  # 150 requests per 5 minutes per session
                    aggregate_key_type="CUSTOM_KEYS",
                    custom_keys=[
                        wafv2.CfnWebACL.RateBasedStatementCustomKeyProperty(
                            header=wafv2.CfnWebACL.RateLimitHeaderProperty(
                                name="x-session-id",
                                text_transformations=[
                                    wafv2.CfnWebACL.TextTransformationProperty(
                                        priority=0,
                                        type="NONE"
                                    )
                                ]
                            )
                        )
                    ]
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(
                captcha=wafv2.CfnWebACL.CaptchaActionProperty()
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="SessionRateLimitRule"
            )
        )
        
        # Layer 4: Strict IP-based rate limit with block
        rate_limit_block_rule = wafv2.CfnWebACL.RuleProperty(
            name="RateLimitBlockRule",
            priority=4,
            statement=wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    limit=500,  # 500 requests per 5 minutes per IP
                    aggregate_key_type="IP"
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(block={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="RateLimitBlockRule"
            )
        )
        
        # Layer 5: Bot detection with CAPTCHA
        bot_control_rule = wafv2.CfnWebACL.RuleProperty(
            name="BotControlRule",
            priority=5,
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    vendor_name="AWS",
                    name="AWSManagedRulesBotControlRuleSet",
                    managed_rule_group_configs=[
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            aws_managed_rules_bot_control_rule_set=wafv2.CfnWebACL.AWSManagedRulesBotControlRuleSetProperty(
                                inspection_level="TARGETED"
                            )
                        )
                    ]
                )
            ),
            override_action=wafv2.CfnWebACL.OverrideActionProperty(
                none={}
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="BotControlRule"
            )
        )
        # Layer 6: Custom header validation
        custom_header_rule = wafv2.CfnWebACL.RuleProperty(
            name="CustomHeaderValidationRule",
            priority=6,
            statement=wafv2.CfnWebACL.StatementProperty(
                not_statement=wafv2.CfnWebACL.NotStatementProperty(
                    statement=wafv2.CfnWebACL.StatementProperty(
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            search_string="cs-ai-auth-2024",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                single_header=wafv2.CfnWebACL.SingleHeaderProperty(
                                    name="x-custom-auth"
                                )
                            ),
                            text_transformations=[
                                wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=0,
                                    type="NONE"
                                )
                            ],
                            positional_constraint="EXACTLY"
                        )
                    )
                )
            ),
            action=wafv2.CfnWebACL.RuleActionProperty(block={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="CustomHeaderValidationRule"
            )
        )
        
        # AWS Managed Rules - Core Rule Set
        core_rule_set = wafv2.CfnWebACL.RuleProperty(
            name="ALBAWSManagedRulesCoreRuleSet",
            priority=7,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    vendor_name="AWS",
                    name="AWSManagedRulesCommonRuleSet"
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="ALBCoreRuleSet"
            )
        )
        
        # Create Regional Web ACL for ALB with multi-layer protection
        web_acl = wafv2.CfnWebACL(
            self, "CustomerSupportAIALBWebACL",
            scope="REGIONAL",  # For ALB
            default_action=wafv2.CfnWebACL.DefaultActionProperty(block={}),  # Block by default
            rules=[ip_allowlist_rule, rate_limit_captcha_rule, user_agent_rate_limit_rule, session_rate_limit_rule, rate_limit_block_rule, bot_control_rule, custom_header_rule, core_rule_set],
            captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                    immunity_time=300  # 5 minutes immunity after solving CAPTCHA
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="CustomerSupportAIALBWebACL"
            ),
            name="CustomerSupportAI-ALB-WebACL"
        )
        return web_acl
    
    def _create_ip_set(self) -> wafv2.CfnIPSet:
        """Create IP set for allowed IP ranges"""
        # Get IP configuration from parameters
        allow_all_ips = self.config.get('allow_all_ips', False)
        allowed_ip_ranges = self.config.get('allowed_ip_ranges', [])
        
        if allow_all_ips:
            # Allow all IPs when explicitly configured
            allowed_ips = ["0.0.0.0/0"]
        elif allowed_ip_ranges:
            # Use configured IP ranges
            allowed_ips = allowed_ip_ranges
        else:
            # Require explicit IP configuration - no fallback
            raise ValueError(
                "IP access must be explicitly configured in WAF. Set 'allow_all_ips: true' or provide 'allowed_ip_ranges' in parameters.json. "
                "For security, there is no default fallback to allow all IPs."
            )
        
        ip_set = wafv2.CfnIPSet(
            self, "AllowedIPSet",
            scope="REGIONAL",
            ip_address_version="IPV4",
            addresses=allowed_ips,
            name="CustomerSupportAI-AllowedIPs",
            description="Allowed IP addresses for Customer Support AI"
        )
        return ip_set
    
    def _create_security_config(self):
        """Create security configuration parameters"""
        
        security_config = {
            "max_query_length": 1000,
            "rate_limit_per_user": 100,
            "bedrock_query_monitoring": {
                "bulk_extraction_threshold": 10,  # queries per minute
                "pattern_analysis_enabled": True,
                "suspicious_patterns": [
                    "list all", "show all", "dump", "extract", "download",
                    "SELECT *", "UNION", "OR 1=1", "'; DROP",
                    "<script", "javascript:", "eval(", "exec("
                ],
                "max_tokens_per_query": 1000,
                "max_queries_per_session": 50
            }
        }
        
        ssm.StringParameter(
            self, "SecurityConfig",
            parameter_name="/customer-support-ai/security/config",
            string_value=json.dumps(security_config),
            description="Security configuration for Customer Support AI"
        )
        
        # Bedrock monitoring configuration
        bedrock_monitoring_config = {
            "query_pattern_analysis": {
                "enabled": True,
                "bulk_extraction_detection": True,
                "rate_limiting": {
                    "queries_per_minute": 20,
                    "queries_per_hour": 200,
                    "tokens_per_minute": 10000
                },
                "alert_thresholds": {
                    "suspicious_pattern_count": 5,
                    "bulk_query_attempts": 3,
                    "rate_limit_violations": 10
                }
            }
        }
        
        ssm.StringParameter(
            self, "BedrockMonitoringConfig",
            parameter_name="/customer-support-ai/security/bedrock-monitoring",
            string_value=json.dumps(bedrock_monitoring_config),
            description="Bedrock query monitoring and pattern analysis configuration"
        )
        
        # User behavior analytics configuration
        user_analytics_config = {
            "volume_limits": {
                "max_queries_per_minute": 30,
                "max_queries_per_hour": 300,
                "max_daily_queries": 1000
            },
            "behavior_analysis": {
                "anomaly_threshold": 0.8,
                "diversity_threshold": 0.3,
                "max_unique_ips": 3,
                "max_user_agents": 2,
                "rapid_query_threshold": 20
            },
            "risk_scoring": {
                "multiple_ip_penalty": 0.3,
                "multiple_ua_penalty": 0.2,
                "high_frequency_penalty": 0.4,
                "automation_penalty": 0.3
            }
        }
        
        ssm.StringParameter(
            self, "UserAnalyticsConfig",
            parameter_name="/customer-support-ai/security/user-analytics",
            string_value=json.dumps(user_analytics_config),
            description="User behavior analytics and volume limiting configuration"
        )
        
        # Custom header authentication configuration
        custom_auth_config = {
            "header_name": "x-custom-auth",
            "header_value": "cs-ai-auth-2024",
            "validation_enabled": True,
            "description": "Custom header for additional authentication layer"
        }
        
        ssm.StringParameter(
            self, "CustomAuthConfig",
            parameter_name="/customer-support-ai/security/custom-auth",
            string_value=json.dumps(custom_auth_config),
            description="Custom header authentication configuration for ALB"
        )
        
        # Result filtering and validation configuration
        result_filter_config = {
            "filtering": {
                "max_result_length": 2000,
                "sensitive_data_patterns": [
                    "ssn", "credit_card", "email", "phone", "credentials"
                ],
                "prohibited_content_patterns": [
                    "script_tags", "javascript_urls", "event_handlers"
                ],
                "internal_content_patterns": [
                    "internal_keywords", "employee_info", "confidential_data"
                ]
            },
            "validation": {
                "min_result_length": 10,
                "max_result_length": 3000,
                "quality_threshold": 0.5,
                "context_relevance_required": True
            },
            "user_type_filtering": {
                "external_user_restrictions": True,
                "internal_content_blocking": True,
                "sensitive_data_redaction": True
            }
        }
        
        ssm.StringParameter(
            self, "ResultFilterConfig",
            parameter_name="/customer-support-ai/security/result-filter",
            string_value=json.dumps(result_filter_config),
            description="Query result filtering and validation configuration"
        )
        
        # Access control and privacy protection configuration
        access_control_config = {
            "multi_layer_access_control": {
                "user_type_validation": True,
                "query_context_isolation": True,
                "cross_user_access_detection": True,
                "data_source_authorization": True
            },
            "privacy_violation_detection": {
                "query_privacy_check": True,
                "result_privacy_check": True,
                "cross_user_leakage_check": True,
                "pii_detection_enabled": True
            },
            "data_source_access_matrix": {
                "external": ["external_source"],
                "internal": ["external_source", "internal_source"]
            },
            "monitoring": {
                "access_pattern_tracking": True,
                "privacy_violation_alerts": True,
                "cross_user_access_alerts": True
            }
        }
        
        ssm.StringParameter(
            self, "AccessControlConfig",
            parameter_name="/customer-support-ai/security/access-control",
            string_value=json.dumps(access_control_config),
            description="Multi-layer access control and privacy violation detection configuration"
        )
        

    
    def _create_outputs(self):
        """Create CloudFormation outputs"""
        CfnOutput(
            self, "WebACLArn",
            value=self.web_acl.attr_arn,
            description="WAF Web ACL ARN for ALB"
        )
        CfnOutput(
            self, "KMSKeyId",
            value=self.kms_key.key_id,
            description="KMS Key ID for encryption"
        )
        CfnOutput(
            self, "SecurityNote",
            value="WAF configured with IP restrictions. Update IP set to restrict access to specific networks.",
            description="Security configuration note"
        )
        
