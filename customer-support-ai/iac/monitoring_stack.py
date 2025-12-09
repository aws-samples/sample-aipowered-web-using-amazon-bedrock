from aws_cdk import (
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_logs as logs,
    Duration,
    CfnOutput
)
from constructs import Construct


class MonitoringStack(Stack):
    
    def __init__(self, scope: Construct, construct_id: str, 
                 lambda_function_name: str,
                 ecs_cluster_name: str,
                 ecs_service_name: str,
                 alb_name: str,
                 notification_email: str = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create SNS topic for alerts
        alert_topic = sns.Topic(
            self, "SecurityAlertTopic",
            display_name="Customer Support AI Security Alerts"
        )
        
        if notification_email:
            alert_topic.add_subscription(
                subscriptions.EmailSubscription(notification_email)
            )
        
        # Create CloudWatch Dashboard
        dashboard = cloudwatch.Dashboard(
            self, "CustomerSupportAIDashboard",
            dashboard_name="CustomerSupportAI-Monitoring"
        )
        
        # Lambda Function Monitoring
        self._create_lambda_alarms(lambda_function_name, alert_topic, dashboard)
        
        # ECS Service Monitoring
        self._create_ecs_alarms(ecs_cluster_name, ecs_service_name, alert_topic, dashboard)
        
        # ALB Monitoring
        self._create_alb_alarms(alb_name, alert_topic, dashboard)
        
        # Security-specific Monitoring
        self._create_security_alarms(lambda_function_name, alert_topic, dashboard)
        
        # Custom Application Metrics
        self._create_custom_metrics(dashboard)
        
        # Output SNS topic ARN
        CfnOutput(
            self, "AlertTopicArn",
            value=alert_topic.topic_arn,
            description="SNS Topic ARN for monitoring alerts"
        )
    
    def _create_lambda_alarms(self, function_name: str, alert_topic: sns.Topic, dashboard: cloudwatch.Dashboard):
        """Create Lambda function monitoring alarms"""
        
        # Lambda Error Rate Alarm
        lambda_error_alarm = cloudwatch.Alarm(
            self, "LambdaErrorRateAlarm",
            alarm_name="CustomerSupportAI-Lambda-ErrorRate",
            alarm_description="Lambda function error rate is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/Lambda",
                metric_name="Errors",
                dimensions_map={"FunctionName": function_name},
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=5,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        )
        lambda_error_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Lambda Duration Alarm
        lambda_duration_alarm = cloudwatch.Alarm(
            self, "LambdaDurationAlarm",
            alarm_name="CustomerSupportAI-Lambda-Duration",
            alarm_description="Lambda function duration is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/Lambda",
                metric_name="Duration",
                dimensions_map={"FunctionName": function_name},
                statistic="Average",
                period=Duration.minutes(5)
            ),
            threshold=30000,  # 30 seconds
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        lambda_duration_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Lambda Throttles Alarm
        lambda_throttle_alarm = cloudwatch.Alarm(
            self, "LambdaThrottleAlarm",
            alarm_name="CustomerSupportAI-Lambda-Throttles",
            alarm_description="Lambda function is being throttled",
            metric=cloudwatch.Metric(
                namespace="AWS/Lambda",
                metric_name="Throttles",
                dimensions_map={"FunctionName": function_name},
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        )
        lambda_throttle_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Add Lambda metrics to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Function Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Lambda",
                        metric_name="Invocations",
                        dimensions_map={"FunctionName": function_name},
                        statistic="Sum"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Lambda",
                        metric_name="Errors",
                        dimensions_map={"FunctionName": function_name},
                        statistic="Sum"
                    )
                ],
                right=[
                    cloudwatch.Metric(
                        namespace="AWS/Lambda",
                        metric_name="Duration",
                        dimensions_map={"FunctionName": function_name},
                        statistic="Average"
                    )
                ]
            )
        )
    
    def _create_ecs_alarms(self, cluster_name: str, service_name: str, alert_topic: sns.Topic, dashboard: cloudwatch.Dashboard):
        """Create ECS service monitoring alarms"""
        
        # ECS CPU Utilization Alarm
        ecs_cpu_alarm = cloudwatch.Alarm(
            self, "ECSCpuUtilizationAlarm",
            alarm_name="CustomerSupportAI-ECS-CPUUtilization",
            alarm_description="ECS service CPU utilization is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="CPUUtilization",
                dimensions_map={
                    "ServiceName": service_name,
                    "ClusterName": cluster_name
                },
                statistic="Average",
                period=Duration.minutes(5)
            ),
            threshold=80,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        ecs_cpu_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # ECS Memory Utilization Alarm
        ecs_memory_alarm = cloudwatch.Alarm(
            self, "ECSMemoryUtilizationAlarm",
            alarm_name="CustomerSupportAI-ECS-MemoryUtilization",
            alarm_description="ECS service memory utilization is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="MemoryUtilization",
                dimensions_map={
                    "ServiceName": service_name,
                    "ClusterName": cluster_name
                },
                statistic="Average",
                period=Duration.minutes(5)
            ),
            threshold=85,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        ecs_memory_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # ECS Running Task Count Alarm
        ecs_task_alarm = cloudwatch.Alarm(
            self, "ECSRunningTasksAlarm",
            alarm_name="CustomerSupportAI-ECS-RunningTasks",
            alarm_description="ECS service has no running tasks",
            metric=cloudwatch.Metric(
                namespace="AWS/ECS",
                metric_name="RunningTaskCount",
                dimensions_map={
                    "ServiceName": service_name,
                    "ClusterName": cluster_name
                },
                statistic="Average",
                period=Duration.minutes(1)
            ),
            threshold=1,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD
        )
        ecs_task_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Add ECS metrics to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="ECS Service Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/ECS",
                        metric_name="CPUUtilization",
                        dimensions_map={
                            "ServiceName": service_name,
                            "ClusterName": cluster_name
                        },
                        statistic="Average"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/ECS",
                        metric_name="MemoryUtilization",
                        dimensions_map={
                            "ServiceName": service_name,
                            "ClusterName": cluster_name
                        },
                        statistic="Average"
                    )
                ],
                right=[
                    cloudwatch.Metric(
                        namespace="AWS/ECS",
                        metric_name="RunningTaskCount",
                        dimensions_map={
                            "ServiceName": service_name,
                            "ClusterName": cluster_name
                        },
                        statistic="Average"
                    )
                ]
            )
        )
    
    def _create_alb_alarms(self, alb_name: str, alert_topic: sns.Topic, dashboard: cloudwatch.Dashboard):
        """Create Application Load Balancer monitoring alarms"""
        
        # ALB 5XX Error Rate Alarm
        alb_5xx_alarm = cloudwatch.Alarm(
            self, "ALB5XXErrorAlarm",
            alarm_name="CustomerSupportAI-ALB-5XXErrors",
            alarm_description="ALB 5XX error rate is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="HTTPCode_ELB_5XX_Count",
                dimensions_map={"LoadBalancer": alb_name},
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=10,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        alb_5xx_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # ALB Response Time Alarm
        alb_response_time_alarm = cloudwatch.Alarm(
            self, "ALBResponseTimeAlarm",
            alarm_name="CustomerSupportAI-ALB-ResponseTime",
            alarm_description="ALB response time is too high",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name="TargetResponseTime",
                dimensions_map={"LoadBalancer": alb_name},
                statistic="Average",
                period=Duration.minutes(5)
            ),
            threshold=5,  # 5 seconds
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        alb_response_time_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Add ALB metrics to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Application Load Balancer Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/ApplicationELB",
                        metric_name="RequestCount",
                        dimensions_map={"LoadBalancer": alb_name},
                        statistic="Sum"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/ApplicationELB",
                        metric_name="HTTPCode_ELB_5XX_Count",
                        dimensions_map={"LoadBalancer": alb_name},
                        statistic="Sum"
                    )
                ],
                right=[
                    cloudwatch.Metric(
                        namespace="AWS/ApplicationELB",
                        metric_name="TargetResponseTime",
                        dimensions_map={"LoadBalancer": alb_name},
                        statistic="Average"
                    )
                ]
            )
        )
    

    
    def _create_security_alarms(self, function_name: str, alert_topic: sns.Topic, dashboard: cloudwatch.Dashboard):
        """Create security-specific monitoring alarms"""
        
        # Suspicious Activity - High Error Rate
        security_error_alarm = cloudwatch.Alarm(
            self, "SecurityHighErrorRateAlarm",
            alarm_name="CustomerSupportAI-Security-HighErrorRate",
            alarm_description="Potential security attack - high error rate detected",
            metric=cloudwatch.Metric(
                namespace="AWS/Lambda",
                metric_name="Errors",
                dimensions_map={"FunctionName": function_name},
                statistic="Sum",
                period=Duration.minutes(1)
            ),
            threshold=20,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        security_error_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Create log-based metric filter for invalid user types
        invalid_user_type_filter = logs.MetricFilter(
            self, "InvalidUserTypeFilter",
            log_group=logs.LogGroup.from_log_group_name(
                self, "LambdaLogGroup",
                log_group_name=f"/aws/lambda/{function_name}"
            ),
            metric_namespace="CustomerSupportAI/Security",
            metric_name="InvalidUserTypeAttempts",
            filter_pattern=logs.FilterPattern.literal("[timestamp, request_id, level=\"ERROR\", message=\"Invalid user type*\"]"),
            metric_value="1"
        )
        
        # Alarm for invalid user type attempts
        invalid_user_alarm = cloudwatch.Alarm(
            self, "InvalidUserTypeAlarm",
            alarm_name="CustomerSupportAI-Security-InvalidUserType",
            alarm_description="Multiple invalid user type attempts detected",
            metric=cloudwatch.Metric(
                namespace="CustomerSupportAI/Security",
                metric_name="InvalidUserTypeAttempts",
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=10,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        invalid_user_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Add security metrics to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Security Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="CustomerSupportAI/Security",
                        metric_name="InvalidUserTypeAttempts",
                        statistic="Sum"
                    )
                ]
            )
        )
    
    def _create_custom_metrics(self, dashboard: cloudwatch.Dashboard):
        """Create custom application metrics dashboard widgets"""
        
        # Bedrock API metrics (if available)
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Bedrock API Metrics",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Bedrock",
                        metric_name="Invocations",
                        statistic="Sum"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Bedrock",
                        metric_name="InvocationLatency",
                        statistic="Average"
                    )
                ]
            )
        )
        
        # Custom business metrics placeholder
        dashboard.add_widgets(
            cloudwatch.SingleValueWidget(
                title="System Health Score",
                metrics=[
                    cloudwatch.MathExpression(
                        expression="100 - (lambda_errors + alb_5xx)",
                        using_metrics={
                            "lambda_errors": cloudwatch.Metric(
                                namespace="AWS/Lambda",
                                metric_name="Errors",
                                statistic="Sum"
                            ),
                            "alb_5xx": cloudwatch.Metric(
                                namespace="AWS/ApplicationELB",
                                metric_name="HTTPCode_ELB_5XX_Count",
                                statistic="Sum"
                            )
                        }
                    )
                ]
            )
        )