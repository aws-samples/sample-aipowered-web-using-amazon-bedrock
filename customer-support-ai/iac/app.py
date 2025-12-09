#!/usr/bin/env python3
import os
import json

import aws_cdk as cdk

from cdk.cdk_stack import CdkStack
from monitoring_stack import MonitoringStack
from security_stack import SecurityStack

app = cdk.App()

instance = app.node.try_get_context("environment")
if not instance: 
    raise ValueError("Missing environment in the application context.")

with open("parameters.json", "r", encoding="utf-8") as param_file:
    param_data = param_file.read()

config_all = json.loads(param_data)
config = config_all["Parameters"][instance]

# Deploy security stack first
security_stack = SecurityStack(
    app, "CSGenAIDemo-Security", 
    config=config
)

# Deploy main application stack
cdkStack = CdkStack(app, "CSGenAIDemo", config=config, security_stack=security_stack)

cdkStack.add_dependency(security_stack)

# Deploy monitoring stack
monitoring_stack = MonitoringStack(
    app, "CSGenAIDemo-Monitoring",
    lambda_function_name=cdkStack.lambda_function_name,
    ecs_cluster_name=cdkStack.cluster_name,
    ecs_service_name=cdkStack.service_name,
    alb_name=cdkStack.alb_name,
    notification_email=config.get("notification_email")
)
monitoring_stack.add_dependency(cdkStack)

app.synth()
