"""SSL Certificate generation and management"""

import json
import os
import boto3
from pathlib import Path
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta


def generate_certificate(domain_name: str, cert_dir: str) -> tuple[str, str]:
    """Generate self-signed certificate using cryptography library"""
    print(f"🔐 Generating self-signed SSL certificate for domain: {domain_name}")
    
    Path(cert_dir).mkdir(parents=True, exist_ok=True)
    
    private_key_path = os.path.join(cert_dir, "private-key.pem")
    cert_path = os.path.join(cert_dir, "certificate.pem")
    
    # Generate private key
    print("📝 Generating private key...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Generate certificate
    print("📝 Generating self-signed certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Demo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Demo"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CustomerSupportAI"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain_name),
                x509.DNSName(f"*.{domain_name}"),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Write private key
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return cert_path, private_key_path


def upload_to_acm(cert_path: str, private_key_path: str, region: str) -> str:
    """Upload certificate to AWS Certificate Manager"""
    print("☁️  Uploading certificate to AWS Certificate Manager...")
    
    with open(cert_path, 'r', encoding='utf-8') as f:
        certificate = f.read()
    
    with open(private_key_path, 'r', encoding='utf-8') as f:
        private_key = f.read()
    
    acm = boto3.client('acm', region_name=region)
    response = acm.import_certificate(
        Certificate=certificate,
        PrivateKey=private_key
    )
    
    return response['CertificateArn']


def update_parameters(cert_arn: str, params_file: str = 'parameters.json'):
    """Update parameters.json with certificate ARN"""
    print("📝 Updating parameters.json with certificate ARN...")
    
    with open(params_file, 'r', encoding='utf-8') as f:
        params = json.load(f)
    
    params['Parameters']['DEV']['ssl_certificate_arn'] = cert_arn
    
    with open(params_file, 'w', encoding='utf-8') as f:
        json.dump(params, f, indent=4)
    
    print("✅ Updated parameters.json with certificate ARN")


def check_and_generate_certificate(params_file: str = 'parameters.json', 
                                   domain_name: str = "demo.customer-support-ai.local",
                                   region: str = "us-east-1") -> bool:
    """Check if SSL certificate is configured, generate if needed"""
    print("🔐 Checking SSL certificate configuration...")
    
    with open(params_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    env_config = config.get("Parameters", {}).get("DEV", {})
    ssl_cert_arn = env_config.get("ssl_certificate_arn")
    
    if ssl_cert_arn:
        print(f"✅ SSL certificate already configured: {ssl_cert_arn}")
        return True
    
    print("⚠️  No SSL certificate configured")
    print("🔐 Generating self-signed certificate for demo...")
    
    cert_dir = "./certs"
    cert_path, private_key_path = generate_certificate(domain_name, cert_dir)
    cert_arn = upload_to_acm(cert_path, private_key_path, region)
    
    print(f"✅ Certificate uploaded successfully!")
    print(f"📋 Certificate ARN: {cert_arn}")
    
    update_parameters(cert_arn, params_file)
    return True


def delete_certificate(params_file: str = 'parameters.json', region: str = 'us-east-1') -> bool:
    """Delete SSL certificate from ACM"""
    with open(params_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    env_config = config.get("Parameters", {}).get("DEV", {})
    cert_arn = env_config.get("ssl_certificate_arn")
    
    if not cert_arn:
        print("ℹ️  No SSL certificate configured")
        return True
    
    acm = boto3.client('acm', region_name=region)
    
    try:
        response = acm.describe_certificate(CertificateArn=cert_arn)
        in_use_by = response['Certificate'].get('InUseBy', [])
        
        if in_use_by:
            print(f"⚠️  Certificate is still in use by: {in_use_by}")
            print("   Will be deleted after stack deletion")
            return True
        
        acm.delete_certificate(CertificateArn=cert_arn)
        print(f"✅ Deleted SSL certificate: {cert_arn}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("ℹ️  SSL certificate does not exist")
            return True
        print(f"⚠️  Could not delete SSL certificate: {e}")
        return True
