# Bedrock Knowledge Base CDK Project

This CDK project creates an Amazon Bedrock Knowledge Base with two data sources:
1. An S3 bucket data source for internal documents
2. A web crawler data source for external website content

## Prerequisites

- AWS CDK installed (`npm install -g aws-cdk`)
- Python 3.9 or later
- AWS credentials configured

## Setup

1. Create a virtual environment:
```
python -m venv .venv
```

2. Activate the virtual environment:
```
# On Windows
.venv\Scripts\activate.bat
# On macOS/Linux
source .venv/bin/activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Bootstrap your AWS environment (if not already done):
```
cdk bootstrap
```

## Deployment

To deploy the stack:
```
cdk deploy
```

To deploy to a specific environment:
```
cdk deploy --context env=PROD
```

## Configuration

Update the `parameters.json` file to configure your environments.

## Cleanup

To destroy the stack:
```
cdk destroy
```

Note: The S3 bucket is configured with `RemovalPolicy.RETAIN` to prevent accidental deletion of your data. You'll need to manually empty and delete the bucket if you want to remove it completely.