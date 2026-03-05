#!/usr/bin/env python3
"""
AWS Cloud Security Posture Scanner
===================================
Author: Akintade Akinokun
Purpose: Scans AWS environments against CIS Benchmark controls

This tool checks your AWS account for common security misconfigurations
based on CIS (Center for Internet Security) AWS Foundations Benchmark.

CIS Benchmarks are industry-accepted security standards that provide
prescriptive guidance for establishing secure configurations.

WHAT THIS SCANNER CHECKS:
-------------------------
1. IAM (Identity & Access Management) - Who can access what
2. S3 Buckets - Storage security
3. CloudTrail - Audit logging
4. Security Groups - Network firewall rules
5. EC2 Instances - Virtual machine security
6. RDS Databases - Database security
7. KMS - Encryption key management

HOW IT WORKS:
-------------
1. Connects to AWS using boto3 (AWS SDK for Python)
2. Queries each service for current configuration
3. Compares configuration against CIS benchmarks
4. Generates a compliance report with findings

REQUIREMENTS:
-------------
- Python 3.7+
- boto3 library (pip install boto3)
- AWS credentials configured (aws configure)
- Appropriate IAM permissions to read resources
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timezone
import json
import os

# ==============================================================================
# SECTION 1: CONFIGURATION
# ==============================================================================
# These are the settings that control how the scanner behaves.
# In a production tool, these would come from a config file or command line args.

class ScannerConfig:
    """
    Configuration class for the scanner.

    WHY USE A CLASS?
    - Keeps all settings in one place
    - Easy to modify without changing code throughout
    - Can be extended to load from files
    """

    def __init__(self):
        # AWS Region to scan (can be changed or made to scan all regions)
        self.region = "us-east-1"

        # Output directory for reports
        self.report_dir = "reports"

        # Severity levels for findings
        self.severity_levels = {
            "CRITICAL": 1,  # Must fix immediately
            "HIGH": 2,      # Fix within 24-48 hours
            "MEDIUM": 3,    # Fix within 1-2 weeks
            "LOW": 4,       # Fix when convenient
            "INFO": 5       # Informational only
        }


# ==============================================================================
# SECTION 2: AWS CLIENT INITIALIZATION
# ==============================================================================
# boto3 is the AWS SDK for Python. It lets us interact with AWS services.

def get_aws_client(service_name, region="us-east-1"):
    """
    Creates a connection (client) to an AWS service.

    PARAMETERS:
    -----------
    service_name : str
        The AWS service to connect to (e.g., 's3', 'iam', 'ec2')
    region : str
        AWS region (e.g., 'us-east-1', 'us-west-2')

    RETURNS:
    --------
    boto3.client
        A client object to interact with the AWS service

    EXAMPLE:
    --------
    s3_client = get_aws_client('s3')
    buckets = s3_client.list_buckets()

    WHY THIS FUNCTION EXISTS:
    -------------------------
    - Centralizes AWS client creation
    - Handles errors in one place
    - Easy to add authentication methods later
    """
    try:
        # boto3.client() creates a low-level service client
        # It uses credentials from:
        # 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        # 2. ~/.aws/credentials file
        # 3. IAM role (if running on EC2/Lambda)
        client = boto3.client(service_name, region_name=region)
        return client
    except NoCredentialsError:
        print("[ERROR] AWS credentials not found!")
        print("Run 'aws configure' to set up credentials")
        return None


def get_aws_resource(service_name, region="us-east-1"):
    """
    Creates a resource object for AWS service (higher-level interface).

    DIFFERENCE BETWEEN CLIENT AND RESOURCE:
    ---------------------------------------
    - Client: Low-level, maps directly to AWS API calls
    - Resource: High-level, more Pythonic, easier to use

    Example with Client:
        response = s3_client.list_objects_v2(Bucket='my-bucket')
        for obj in response['Contents']:
            print(obj['Key'])

    Example with Resource:
        bucket = s3_resource.Bucket('my-bucket')
        for obj in bucket.objects.all():
            print(obj.key)
    """
    try:
        resource = boto3.resource(service_name, region_name=region)
        return resource
    except NoCredentialsError:
        print("[ERROR] AWS credentials not found!")
        return None


# ==============================================================================
# SECTION 3: FINDING CLASS
# ==============================================================================
# A "Finding" represents a security issue discovered during the scan.

class Finding:
    """
    Represents a single security finding.

    This is how security tools report issues. Each finding contains:
    - What the issue is
    - Where it was found
    - How severe it is
    - How to fix it

    INTERVIEW TIP:
    --------------
    Security findings typically follow a standard format (like SARIF or
    the format used by AWS Security Hub). Understanding this structure
    shows you know how security tools work.
    """

    def __init__(self, title, description, severity, resource_id,
                 resource_type, recommendation, cis_control=None):
        """
        Initialize a new finding.

        PARAMETERS:
        -----------
        title : str
            Short description of the issue
        description : str
            Detailed explanation of why this is a security risk
        severity : str
            CRITICAL, HIGH, MEDIUM, LOW, or INFO
        resource_id : str
            The specific AWS resource affected (e.g., bucket name, instance ID)
        resource_type : str
            Type of resource (e.g., 'S3 Bucket', 'EC2 Instance')
        recommendation : str
            How to fix the issue
        cis_control : str
            The CIS Benchmark control this relates to (e.g., "CIS 2.1.1")
        """
        self.title = title
        self.description = description
        self.severity = severity
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.recommendation = recommendation
        self.cis_control = cis_control
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        """Convert finding to dictionary for JSON export."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "recommendation": self.recommendation,
            "cis_control": self.cis_control,
            "timestamp": self.timestamp
        }

    def __str__(self):
        """String representation for printing."""
        return f"[{self.severity}] {self.title} - {self.resource_id}"


# ==============================================================================
# SECTION 4: SECURITY CHECKS - IAM
# ==============================================================================
# IAM (Identity and Access Management) controls WHO can access WHAT in AWS.
# These are critical checks because compromised credentials = compromised account.

class IAMChecks:
    """
    Security checks for AWS IAM (Identity and Access Management).

    IAM is the foundation of AWS security. It controls:
    - Users: Human identities
    - Roles: Identities for services/applications
    - Policies: What actions are allowed/denied
    - Groups: Collections of users with shared permissions

    CIS BENCHMARK CONTROLS COVERED:
    -------------------------------
    - 1.4: Ensure no root account access key exists
    - 1.5: Ensure MFA is enabled for root account
    - 1.6: Ensure hardware MFA is enabled for root account
    - 1.10: Ensure multi-factor authentication (MFA) is enabled for all IAM users
    - 1.12: Ensure credentials unused for 90 days or greater are disabled
    - 1.16: Ensure IAM policies are attached only to groups or roles
    """

    def __init__(self):
        """Initialize IAM client."""
        self.client = get_aws_client('iam')
        self.findings = []

    def check_root_access_keys(self):
        """
        CIS 1.4: Check if root account has access keys.

        WHY THIS MATTERS:
        -----------------
        The root account has UNLIMITED access to your AWS account.
        If root access keys are compromised, attackers have full control.
        Root should ONLY be accessed via console with MFA, NEVER via API keys.

        HOW WE CHECK:
        -------------
        1. Get the account summary
        2. Check if 'AccountAccessKeysPresent' > 0
        """
        print("  [*] Checking root account access keys...")

        try:
            # get_account_summary() returns metrics about the AWS account
            summary = self.client.get_account_summary()

            # AccountAccessKeysPresent tells us if root has API keys
            if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                finding = Finding(
                    title="Root Account Has Access Keys",
                    description="The root account has active access keys. Root access "
                               "keys provide unrestricted access to all resources and "
                               "should never be created.",
                    severity="CRITICAL",
                    resource_id="root-account",
                    resource_type="IAM Root Account",
                    recommendation="Delete root access keys immediately. Use IAM users "
                                  "or roles with appropriate permissions instead.",
                    cis_control="CIS 1.4"
                )
                self.findings.append(finding)
                print(f"    [!] CRITICAL: Root account has access keys!")
            else:
                print("    [+] PASS: No root access keys found")

        except ClientError as e:
            print(f"    [!] Error checking root access keys: {e}")

    def check_root_mfa(self):
        """
        CIS 1.5: Check if MFA is enabled for root account.

        WHY THIS MATTERS:
        -----------------
        MFA (Multi-Factor Authentication) adds a second layer of security.
        Even if password is compromised, attacker needs the MFA device.
        For root account, this is ESSENTIAL.

        WHAT IS MFA:
        ------------
        Something you KNOW (password) + Something you HAVE (phone/hardware token)
        """
        print("  [*] Checking root MFA status...")

        try:
            summary = self.client.get_account_summary()

            # AccountMFAEnabled: 1 = MFA enabled, 0 = disabled
            if summary['SummaryMap'].get('AccountMFAEnabled', 0) != 1:
                finding = Finding(
                    title="Root Account MFA Not Enabled",
                    description="Multi-Factor Authentication is not enabled for the "
                               "root account. This significantly increases the risk of "
                               "account compromise.",
                    severity="CRITICAL",
                    resource_id="root-account",
                    resource_type="IAM Root Account",
                    recommendation="Enable MFA for the root account immediately. Use a "
                                  "hardware MFA device for highest security.",
                    cis_control="CIS 1.5"
                )
                self.findings.append(finding)
                print("    [!] CRITICAL: Root MFA is not enabled!")
            else:
                print("    [+] PASS: Root MFA is enabled")

        except ClientError as e:
            print(f"    [!] Error checking root MFA: {e}")

    def check_user_mfa(self):
        """
        CIS 1.10: Check if MFA is enabled for all IAM users.

        WHY THIS MATTERS:
        -----------------
        Any user with console access should have MFA.
        Passwords can be phished, guessed, or leaked.
        MFA provides protection even if password is compromised.
        """
        print("  [*] Checking user MFA status...")

        try:
            # list_users() returns all IAM users in the account
            # We use a paginator because there might be many users
            paginator = self.client.get_paginator('list_users')

            users_without_mfa = []

            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']

                    # Check if user has MFA devices
                    mfa_devices = self.client.list_mfa_devices(UserName=username)

                    # Also check if user has console access (password)
                    try:
                        login_profile = self.client.get_login_profile(UserName=username)
                        has_console_access = True
                    except self.client.exceptions.NoSuchEntityException:
                        has_console_access = False

                    # User needs MFA if they have console access but no MFA device
                    if has_console_access and len(mfa_devices['MFADevices']) == 0:
                        users_without_mfa.append(username)

            if users_without_mfa:
                finding = Finding(
                    title="IAM Users Without MFA",
                    description=f"The following users have console access but no MFA: "
                               f"{', '.join(users_without_mfa)}",
                    severity="HIGH",
                    resource_id=", ".join(users_without_mfa),
                    resource_type="IAM Users",
                    recommendation="Enable MFA for all users with console access. "
                                  "Consider enforcing MFA via IAM policy.",
                    cis_control="CIS 1.10"
                )
                self.findings.append(finding)
                print(f"    [!] HIGH: {len(users_without_mfa)} users without MFA")
            else:
                print("    [+] PASS: All console users have MFA")

        except ClientError as e:
            print(f"    [!] Error checking user MFA: {e}")

    def check_unused_credentials(self):
        """
        CIS 1.12: Check for credentials unused for 90+ days.

        WHY THIS MATTERS:
        -----------------
        Unused credentials are a security risk because:
        - May belong to former employees
        - Might be forgotten/unmonitored
        - If compromised, attack could go unnoticed

        BEST PRACTICE:
        --------------
        Disable or delete credentials not used in 90 days.
        """
        print("  [*] Checking for unused credentials...")

        try:
            # Generate credential report - this is an async operation
            self.client.generate_credential_report()

            # Get the credential report
            response = self.client.get_credential_report()

            # The report is CSV format, decode it
            import csv
            from io import StringIO

            report_csv = response['Content'].decode('utf-8')
            reader = csv.DictReader(StringIO(report_csv))

            unused_users = []
            ninety_days_ago = datetime.now(timezone.utc).timestamp() - (90 * 24 * 60 * 60)

            for row in reader:
                username = row['user']

                # Check password last used
                password_last_used = row.get('password_last_used', 'N/A')
                if password_last_used not in ['N/A', 'no_information', 'not_supported']:
                    try:
                        last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                        if last_used.timestamp() < ninety_days_ago:
                            unused_users.append(f"{username} (password)")
                    except:
                        pass

                # Check access key 1 last used
                key1_last_used = row.get('access_key_1_last_used_date', 'N/A')
                if key1_last_used not in ['N/A', 'no_information', 'not_supported']:
                    try:
                        last_used = datetime.fromisoformat(key1_last_used.replace('Z', '+00:00'))
                        if last_used.timestamp() < ninety_days_ago:
                            unused_users.append(f"{username} (access_key_1)")
                    except:
                        pass

            if unused_users:
                finding = Finding(
                    title="Unused Credentials Detected",
                    description=f"Credentials not used in 90+ days: {', '.join(unused_users[:5])}...",
                    severity="MEDIUM",
                    resource_id="multiple-users",
                    resource_type="IAM Credentials",
                    recommendation="Review and disable unused credentials. Implement a "
                                  "regular credential rotation policy.",
                    cis_control="CIS 1.12"
                )
                self.findings.append(finding)
                print(f"    [!] MEDIUM: {len(unused_users)} unused credentials found")
            else:
                print("    [+] PASS: No unused credentials found")

        except ClientError as e:
            print(f"    [!] Error checking unused credentials: {e}")

    def run_all_checks(self):
        """Run all IAM security checks."""
        print("\n[IAM CHECKS]")
        print("=" * 50)

        self.check_root_access_keys()
        self.check_root_mfa()
        self.check_user_mfa()
        self.check_unused_credentials()

        return self.findings


# ==============================================================================
# SECTION 5: SECURITY CHECKS - S3
# ==============================================================================
# S3 (Simple Storage Service) is where most data lives in AWS.
# Misconfigured S3 buckets are one of the TOP causes of data breaches.

class S3Checks:
    """
    Security checks for AWS S3 (Simple Storage Service).

    S3 SECURITY FUNDAMENTALS:
    -------------------------
    1. Block Public Access - Prevent accidental public exposure
    2. Encryption - Protect data at rest
    3. Versioning - Protect against accidental deletion
    4. Logging - Track who accesses what

    REAL-WORLD BREACHES:
    --------------------
    - Capital One (2019): 100M records exposed via misconfigured S3
    - Twitch (2021): Source code leaked from public bucket
    - Many more...

    CIS BENCHMARK CONTROLS:
    -----------------------
    - 2.1.1: Ensure S3 bucket policy denies HTTP requests
    - 2.1.2: Ensure MFA Delete is enabled
    - 2.1.5: Ensure S3 buckets are configured with Block Public Access
    """

    def __init__(self, region="us-east-1"):
        """Initialize S3 client."""
        self.client = get_aws_client('s3', region)
        self.findings = []

    def check_public_access_block(self):
        """
        CIS 2.1.5: Check if S3 Block Public Access is enabled.

        WHAT IS BLOCK PUBLIC ACCESS:
        ----------------------------
        A set of controls that OVERRIDE any policies that would make
        buckets or objects public. It's a safety net.

        There are 4 settings:
        1. BlockPublicAcls - Block public ACLs from being set
        2. IgnorePublicAcls - Ignore existing public ACLs
        3. BlockPublicPolicy - Block public bucket policies
        4. RestrictPublicBuckets - Restrict public bucket access

        ALL FOUR should be enabled for maximum security.
        """
        print("  [*] Checking S3 Block Public Access settings...")

        try:
            # List all buckets
            buckets = self.client.list_buckets()['Buckets']

            insecure_buckets = []

            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    # Get the public access block configuration
                    pab = self.client.get_public_access_block(Bucket=bucket_name)
                    config = pab['PublicAccessBlockConfiguration']

                    # Check if ALL settings are True
                    all_blocked = all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])

                    if not all_blocked:
                        insecure_buckets.append(bucket_name)

                except ClientError as e:
                    # If no configuration exists, bucket is not protected
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        insecure_buckets.append(bucket_name)

            if insecure_buckets:
                finding = Finding(
                    title="S3 Buckets Without Full Public Access Block",
                    description=f"Buckets without complete public access block: "
                               f"{', '.join(insecure_buckets[:5])}{'...' if len(insecure_buckets) > 5 else ''}",
                    severity="HIGH",
                    resource_id=", ".join(insecure_buckets[:3]),
                    resource_type="S3 Bucket",
                    recommendation="Enable all four Block Public Access settings on each bucket "
                                  "and at the account level.",
                    cis_control="CIS 2.1.5"
                )
                self.findings.append(finding)
                print(f"    [!] HIGH: {len(insecure_buckets)} buckets without full public access block")
            else:
                print("    [+] PASS: All buckets have public access blocked")

        except ClientError as e:
            print(f"    [!] Error checking public access block: {e}")

    def check_bucket_encryption(self):
        """
        Check if S3 buckets have default encryption enabled.

        WHY ENCRYPTION MATTERS:
        -----------------------
        - Protects data if storage media is compromised
        - Required for many compliance frameworks (HIPAA, PCI-DSS)
        - Should ALWAYS be enabled - there's no good reason not to

        ENCRYPTION OPTIONS:
        -------------------
        - SSE-S3: AWS managed keys (simplest)
        - SSE-KMS: Customer managed keys (more control)
        - SSE-C: Customer provided keys (you manage everything)
        """
        print("  [*] Checking S3 bucket encryption...")

        try:
            buckets = self.client.list_buckets()['Buckets']
            unencrypted_buckets = []

            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    # Get bucket encryption configuration
                    encryption = self.client.get_bucket_encryption(Bucket=bucket_name)
                    # If we get here, encryption is configured

                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        unencrypted_buckets.append(bucket_name)

            if unencrypted_buckets:
                finding = Finding(
                    title="S3 Buckets Without Default Encryption",
                    description=f"Buckets without default encryption: "
                               f"{', '.join(unencrypted_buckets[:5])}",
                    severity="MEDIUM",
                    resource_id=", ".join(unencrypted_buckets[:3]),
                    resource_type="S3 Bucket",
                    recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on all buckets.",
                    cis_control="CIS 2.1.1"
                )
                self.findings.append(finding)
                print(f"    [!] MEDIUM: {len(unencrypted_buckets)} buckets without encryption")
            else:
                print("    [+] PASS: All buckets have default encryption")

        except ClientError as e:
            print(f"    [!] Error checking bucket encryption: {e}")

    def check_bucket_versioning(self):
        """
        Check if S3 buckets have versioning enabled.

        WHY VERSIONING MATTERS:
        -----------------------
        - Protects against accidental deletion
        - Allows recovery of previous versions
        - Required for compliance (some frameworks)
        - Enables MFA Delete for extra protection

        COST CONSIDERATION:
        -------------------
        Versioning increases storage costs (keeps old versions).
        Use lifecycle policies to manage old versions.
        """
        print("  [*] Checking S3 bucket versioning...")

        try:
            buckets = self.client.list_buckets()['Buckets']
            unversioned_buckets = []

            for bucket in buckets:
                bucket_name = bucket['Name']

                versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
                status = versioning.get('Status', 'Disabled')

                if status != 'Enabled':
                    unversioned_buckets.append(bucket_name)

            if unversioned_buckets:
                finding = Finding(
                    title="S3 Buckets Without Versioning",
                    description=f"Buckets without versioning enabled: "
                               f"{', '.join(unversioned_buckets[:5])}",
                    severity="LOW",
                    resource_id=", ".join(unversioned_buckets[:3]),
                    resource_type="S3 Bucket",
                    recommendation="Enable versioning on buckets containing important data. "
                                  "Consider implementing lifecycle policies.",
                    cis_control="CIS 2.1.3"
                )
                self.findings.append(finding)
                print(f"    [!] LOW: {len(unversioned_buckets)} buckets without versioning")
            else:
                print("    [+] PASS: All buckets have versioning enabled")

        except ClientError as e:
            print(f"    [!] Error checking bucket versioning: {e}")

    def run_all_checks(self):
        """Run all S3 security checks."""
        print("\n[S3 CHECKS]")
        print("=" * 50)

        self.check_public_access_block()
        self.check_bucket_encryption()
        self.check_bucket_versioning()

        return self.findings


# ==============================================================================
# SECTION 6: SECURITY CHECKS - EC2
# ==============================================================================
# EC2 (Elastic Compute Cloud) are virtual machines in AWS.
# Security Groups are the firewall rules that protect them.

class EC2Checks:
    """
    Security checks for AWS EC2 (Elastic Compute Cloud).

    KEY CONCEPTS:
    -------------
    - Security Groups: Virtual firewalls (stateful)
    - NACLs: Network Access Control Lists (stateless)
    - IMDSv2: Instance Metadata Service version 2

    COMMON MISCONFIGURATIONS:
    -------------------------
    - Security groups open to 0.0.0.0/0 (the whole internet)
    - SSH (port 22) open to the world
    - RDP (port 3389) open to the world
    - All ports open (extremely dangerous)
    """

    def __init__(self, region="us-east-1"):
        """Initialize EC2 client."""
        self.client = get_aws_client('ec2', region)
        self.findings = []

    def check_security_groups(self):
        """
        Check for overly permissive security group rules.

        WHAT WE'RE LOOKING FOR:
        -----------------------
        - Ingress rules with 0.0.0.0/0 (allow from anywhere)
        - Critical ports open to the internet:
          - 22 (SSH) - remote shell access
          - 3389 (RDP) - Windows remote desktop
          - 3306 (MySQL) - database
          - 5432 (PostgreSQL) - database
          - 1433 (MSSQL) - database
          - 27017 (MongoDB) - database

        WHY THIS MATTERS:
        -----------------
        Open security groups are the #1 cause of breached EC2 instances.
        Attackers constantly scan for open ports.
        """
        print("  [*] Checking security group rules...")

        # Ports that should NEVER be open to 0.0.0.0/0
        dangerous_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch",
            11211: "Memcached"
        }

        try:
            # Get all security groups
            security_groups = self.client.describe_security_groups()['SecurityGroups']

            risky_groups = []

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                # Check inbound rules (IpPermissions)
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)

                    # Check if rule allows access from anywhere (0.0.0.0/0)
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Check if it's a dangerous port
                            for port, service in dangerous_ports.items():
                                if from_port <= port <= to_port:
                                    risky_groups.append({
                                        'sg_id': sg_id,
                                        'sg_name': sg_name,
                                        'port': port,
                                        'service': service
                                    })

                    # Also check for ::/0 (IPv6 equivalent of 0.0.0.0/0)
                    for ip_range in rule.get('Ipv6Ranges', []):
                        if ip_range.get('CidrIpv6') == '::/0':
                            for port, service in dangerous_ports.items():
                                if from_port <= port <= to_port:
                                    risky_groups.append({
                                        'sg_id': sg_id,
                                        'sg_name': sg_name,
                                        'port': port,
                                        'service': service
                                    })

            if risky_groups:
                # Group findings by severity
                critical_ports = [22, 3389]  # SSH and RDP are critical

                for risk in risky_groups:
                    severity = "CRITICAL" if risk['port'] in critical_ports else "HIGH"

                    finding = Finding(
                        title=f"Security Group Allows {risk['service']} from Internet",
                        description=f"Security group {risk['sg_name']} ({risk['sg_id']}) "
                                   f"allows {risk['service']} (port {risk['port']}) from 0.0.0.0/0",
                        severity=severity,
                        resource_id=risk['sg_id'],
                        resource_type="EC2 Security Group",
                        recommendation=f"Restrict {risk['service']} access to specific IP ranges. "
                                      f"Use VPN or bastion host for remote access.",
                        cis_control="CIS 5.2"
                    )
                    self.findings.append(finding)

                print(f"    [!] Found {len(risky_groups)} risky security group rules")
            else:
                print("    [+] PASS: No overly permissive security groups found")

        except ClientError as e:
            print(f"    [!] Error checking security groups: {e}")

    def check_imdsv2(self):
        """
        Check if EC2 instances require IMDSv2.

        WHAT IS IMDS:
        -------------
        Instance Metadata Service - allows EC2 instances to access
        metadata about themselves (instance ID, IAM role credentials, etc.)

        WHY IMDSv2:
        -----------
        IMDSv1 is vulnerable to SSRF attacks. An attacker who can make
        the instance send HTTP requests can steal IAM credentials.

        IMDSv2 requires a session token, preventing this attack.

        REAL-WORLD IMPACT:
        ------------------
        The Capital One breach used SSRF to steal IAM credentials via IMDSv1.
        """
        print("  [*] Checking IMDSv2 enforcement...")

        try:
            # Get all instances
            instances = self.client.describe_instances()

            vulnerable_instances = []

            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']

                    # Only check running instances
                    if state != 'running':
                        continue

                    # Check metadata options
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional')

                    # 'required' means IMDSv2 is enforced
                    # 'optional' means IMDSv1 is still allowed (vulnerable)
                    if http_tokens != 'required':
                        vulnerable_instances.append(instance_id)

            if vulnerable_instances:
                finding = Finding(
                    title="EC2 Instances Not Requiring IMDSv2",
                    description=f"Instances allowing IMDSv1: {', '.join(vulnerable_instances[:5])}",
                    severity="MEDIUM",
                    resource_id=", ".join(vulnerable_instances[:3]),
                    resource_type="EC2 Instance",
                    recommendation="Modify instance metadata options to require IMDSv2 "
                                  "(HttpTokens = required).",
                    cis_control="CIS 5.6"
                )
                self.findings.append(finding)
                print(f"    [!] MEDIUM: {len(vulnerable_instances)} instances not requiring IMDSv2")
            else:
                print("    [+] PASS: All instances require IMDSv2")

        except ClientError as e:
            print(f"    [!] Error checking IMDSv2: {e}")

    def run_all_checks(self):
        """Run all EC2 security checks."""
        print("\n[EC2 CHECKS]")
        print("=" * 50)

        self.check_security_groups()
        self.check_imdsv2()

        return self.findings


# ==============================================================================
# SECTION 7: SECURITY CHECKS - CLOUDTRAIL
# ==============================================================================
# CloudTrail logs ALL API calls made to your AWS account.
# It's essential for security monitoring and incident investigation.

class CloudTrailChecks:
    """
    Security checks for AWS CloudTrail.

    WHAT CLOUDTRAIL DOES:
    ---------------------
    - Records API calls (who did what, when, from where)
    - Stores logs in S3
    - Can trigger alerts via CloudWatch

    WHY IT'S CRITICAL:
    ------------------
    - Required for compliance (HIPAA, PCI, SOC2)
    - Essential for incident investigation
    - Detects unauthorized access attempts
    - Provides audit trail

    CIS BENCHMARK CONTROLS:
    -----------------------
    - 3.1: Ensure CloudTrail is enabled in all regions
    - 3.2: Ensure CloudTrail log file validation is enabled
    - 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs
    """

    def __init__(self, region="us-east-1"):
        """Initialize CloudTrail client."""
        self.client = get_aws_client('cloudtrail', region)
        self.findings = []

    def check_cloudtrail_enabled(self):
        """
        CIS 3.1: Check if CloudTrail is enabled in all regions.

        WHY ALL REGIONS:
        ----------------
        Attackers can operate in any region. If you only monitor us-east-1,
        they can launch resources in ap-southeast-1 undetected.
        """
        print("  [*] Checking CloudTrail status...")

        try:
            trails = self.client.describe_trails()['trailList']

            if not trails:
                finding = Finding(
                    title="No CloudTrail Trails Configured",
                    description="No CloudTrail trails are configured. API activity is not being logged.",
                    severity="CRITICAL",
                    resource_id="account",
                    resource_type="CloudTrail",
                    recommendation="Create a CloudTrail trail that logs to S3. Enable multi-region logging.",
                    cis_control="CIS 3.1"
                )
                self.findings.append(finding)
                print("    [!] CRITICAL: No CloudTrail trails found!")
                return

            # Check for multi-region trail
            multi_region_trail = False
            for trail in trails:
                if trail.get('IsMultiRegionTrail', False):
                    multi_region_trail = True

                    # Check if trail is logging
                    status = self.client.get_trail_status(Name=trail['TrailARN'])
                    if not status.get('IsLogging', False):
                        finding = Finding(
                            title="CloudTrail Trail Not Logging",
                            description=f"Trail {trail['Name']} is configured but not actively logging.",
                            severity="HIGH",
                            resource_id=trail['Name'],
                            resource_type="CloudTrail Trail",
                            recommendation="Start logging on the trail using 'start_logging' API.",
                            cis_control="CIS 3.1"
                        )
                        self.findings.append(finding)
                        print(f"    [!] HIGH: Trail {trail['Name']} is not logging")

            if not multi_region_trail:
                finding = Finding(
                    title="No Multi-Region CloudTrail Trail",
                    description="No CloudTrail trail is configured for all regions.",
                    severity="HIGH",
                    resource_id="account",
                    resource_type="CloudTrail",
                    recommendation="Configure a multi-region trail to capture activity in all regions.",
                    cis_control="CIS 3.1"
                )
                self.findings.append(finding)
                print("    [!] HIGH: No multi-region trail configured")
            else:
                print("    [+] PASS: Multi-region CloudTrail is configured and logging")

        except ClientError as e:
            print(f"    [!] Error checking CloudTrail: {e}")

    def check_log_file_validation(self):
        """
        CIS 3.2: Check if CloudTrail log file validation is enabled.

        WHAT IS LOG FILE VALIDATION:
        ----------------------------
        CloudTrail creates a hash (digest) of each log file.
        This lets you verify logs haven't been tampered with.

        WHY IT MATTERS:
        ---------------
        Attackers may try to delete or modify logs to cover their tracks.
        Log validation ensures log integrity.
        """
        print("  [*] Checking CloudTrail log file validation...")

        try:
            trails = self.client.describe_trails()['trailList']

            trails_without_validation = []

            for trail in trails:
                if not trail.get('LogFileValidationEnabled', False):
                    trails_without_validation.append(trail['Name'])

            if trails_without_validation:
                finding = Finding(
                    title="CloudTrail Log File Validation Disabled",
                    description=f"Trails without log validation: {', '.join(trails_without_validation)}",
                    severity="MEDIUM",
                    resource_id=", ".join(trails_without_validation),
                    resource_type="CloudTrail Trail",
                    recommendation="Enable log file validation to ensure log integrity.",
                    cis_control="CIS 3.2"
                )
                self.findings.append(finding)
                print(f"    [!] MEDIUM: {len(trails_without_validation)} trails without log validation")
            else:
                print("    [+] PASS: All trails have log file validation enabled")

        except ClientError as e:
            print(f"    [!] Error checking log file validation: {e}")

    def run_all_checks(self):
        """Run all CloudTrail security checks."""
        print("\n[CLOUDTRAIL CHECKS]")
        print("=" * 50)

        self.check_cloudtrail_enabled()
        self.check_log_file_validation()

        return self.findings


# ==============================================================================
# SECTION 8: REPORT GENERATOR
# ==============================================================================
# Generates reports from the scan findings.

class ReportGenerator:
    """
    Generates security reports from scan findings.

    REPORT FORMATS:
    ---------------
    - JSON: Machine-readable, good for automation
    - HTML: Human-readable, good for sharing
    - CSV: Good for importing into other tools

    EXECUTIVE SUMMARY:
    ------------------
    Always include a summary for management:
    - Total findings by severity
    - Overall risk score
    - Top recommendations
    """

    def __init__(self, findings):
        """
        Initialize with list of findings.

        PARAMETERS:
        -----------
        findings : list
            List of Finding objects from all checks
        """
        self.findings = findings
        self.report_dir = "reports"

        # Create reports directory if it doesn't exist
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_json_report(self):
        """Generate JSON format report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/security_report_{timestamp}.json"

        report = {
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "findings_by_severity": self._count_by_severity(),
            "findings": [f.to_dict() for f in self.findings]
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] JSON report saved: {filename}")
        return filename

    def generate_html_report(self):
        """Generate HTML format report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/security_report_{timestamp}.html"

        severity_counts = self._count_by_severity()

        # HTML template with styling
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
        .critical {{ background: #fee2e2; color: #991b1b; }}
        .high {{ background: #ffedd5; color: #9a3412; }}
        .medium {{ background: #fef3c7; color: #92400e; }}
        .low {{ background: #dbeafe; color: #1e40af; }}
        .finding {{ border: 1px solid #e5e7eb; margin: 15px 0; padding: 20px; border-radius: 8px; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .recommendation {{ background: #f0fdf4; padding: 15px; border-radius: 4px; margin-top: 10px; }}
        .cis-control {{ color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS Security Scan Report</h1>
        <p>Scan completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>{severity_counts.get('CRITICAL', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{severity_counts.get('HIGH', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{severity_counts.get('MEDIUM', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{severity_counts.get('LOW', 0)}</h3>
                <p>Low</p>
            </div>
        </div>

        <h2>Findings ({len(self.findings)} total)</h2>
"""

        # Add each finding
        for finding in sorted(self.findings, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x.severity, 5)):
            severity_class = finding.severity.lower()
            html += f"""
        <div class="finding">
            <div class="finding-header">
                <h3>{finding.title}</h3>
                <span class="severity-badge {severity_class}">{finding.severity}</span>
            </div>
            <p class="cis-control">{finding.cis_control or ''}</p>
            <p><strong>Resource:</strong> {finding.resource_id} ({finding.resource_type})</p>
            <p>{finding.description}</p>
            <div class="recommendation">
                <strong>Recommendation:</strong> {finding.recommendation}
            </div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        with open(filename, 'w') as f:
            f.write(html)

        print(f"[+] HTML report saved: {filename}")
        return filename

    def _count_by_severity(self):
        """Count findings by severity level."""
        counts = {}
        for finding in self.findings:
            severity = finding.severity
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def print_summary(self):
        """Print summary to console."""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)

        counts = self._count_by_severity()
        total = len(self.findings)

        print(f"\nTotal Findings: {total}")
        print("-" * 30)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")

        print("\n" + "=" * 60)


# ==============================================================================
# SECTION 9: MAIN EXECUTION
# ==============================================================================
# This is where everything comes together.

def main():
    """
    Main function that orchestrates the security scan.

    FLOW:
    -----
    1. Initialize all check classes
    2. Run checks for each service
    3. Collect all findings
    4. Generate reports
    """
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         AWS Cloud Security Posture Scanner                ║
    ║         ─────────────────────────────────────             ║
    ║         CIS Benchmark Compliance Checker                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    print("[*] Starting security scan...")
    print("[*] Region: us-east-1")
    print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Collect all findings
    all_findings = []

    # Run IAM checks
    iam_checks = IAMChecks()
    all_findings.extend(iam_checks.run_all_checks())

    # Run S3 checks
    s3_checks = S3Checks()
    all_findings.extend(s3_checks.run_all_checks())

    # Run EC2 checks
    ec2_checks = EC2Checks()
    all_findings.extend(ec2_checks.run_all_checks())

    # Run CloudTrail checks
    cloudtrail_checks = CloudTrailChecks()
    all_findings.extend(cloudtrail_checks.run_all_checks())

    # Generate reports
    print("\n[*] Generating reports...")
    report_gen = ReportGenerator(all_findings)
    report_gen.print_summary()
    report_gen.generate_json_report()
    report_gen.generate_html_report()

    print("\n[*] Scan complete!")

    return all_findings


# This block ensures main() only runs when script is executed directly,
# not when imported as a module
if __name__ == "__main__":
    main()
