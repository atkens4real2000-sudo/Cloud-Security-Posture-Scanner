import boto3
import json
import os
from datetime import datetime, timezone, timedelta

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:ACCOUNT_ID:security-scan-alerts")

def lambda_handler(event, context):
    findings = []
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    ec2 = boto3.client('ec2')
    ct = boto3.client('cloudtrail')
    rds = boto3.client('rds')
    sns = boto3.client('sns')

    # CHECK 1: Root Access Keys
    summary = iam.get_account_summary()
    if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
        findings.append({"title": "Root Has Access Keys", "severity": "CRITICAL", "cis": "1.4"})

    # CHECK 2: Root MFA
    if summary['SummaryMap'].get('AccountMFAEnabled', 0) != 1:
        findings.append({"title": "Root MFA Not Enabled", "severity": "CRITICAL", "cis": "1.5"})

    # CHECK 3: IAM Password Policy
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        if policy.get('MinimumPasswordLength', 0) < 14:
            findings.append({"title": "Weak Password Policy - Min Length < 14", "severity": "MEDIUM", "cis": "1.8"})
        if not policy.get('RequireUppercaseCharacters', False):
            findings.append({"title": "Password Policy Missing Uppercase Requirement", "severity": "MEDIUM", "cis": "1.5"})
        if not policy.get('RequireLowercaseCharacters', False):
            findings.append({"title": "Password Policy Missing Lowercase Requirement", "severity": "MEDIUM", "cis": "1.6"})
        if not policy.get('RequireNumbers', False):
            findings.append({"title": "Password Policy Missing Number Requirement", "severity": "MEDIUM", "cis": "1.7"})
        if not policy.get('RequireSymbols', False):
            findings.append({"title": "Password Policy Missing Symbol Requirement", "severity": "MEDIUM", "cis": "1.8"})
        if not policy.get('MaxPasswordAge', 0) or policy.get('MaxPasswordAge', 999) > 90:
            findings.append({"title": "Password Expiry > 90 Days", "severity": "MEDIUM", "cis": "1.10"})
    except:
        findings.append({"title": "No IAM Password Policy Set", "severity": "MEDIUM", "cis": "1.5-1.11"})

    # CHECK 4: Access Keys Older Than 90 Days
    try:
        users = iam.list_users()['Users']
        for user in users:
            keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                if key['Status'] == 'Active':
                    age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if age > 90:
                        findings.append({"title": f"Access Key > 90 Days: {user['UserName']}", "severity": "MEDIUM", "cis": "1.14"})
    except Exception as e:
        pass

    # CHECK 5: S3 Public Access Block
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        try:
            s3.get_public_access_block(Bucket=bucket['Name'])
        except:
            findings.append({"title": f"S3 {bucket['Name']} No Public Block", "severity": "HIGH", "cis": "2.1.5"})

    # CHECK 13: S3 Bucket Encryption (NEW CHECK ADDED)
    for bucket in buckets:
        try:
            s3.get_bucket_encryption(Bucket=bucket['Name'])
        except:
            findings.append({"title": f"S3 {bucket['Name']} No Default Encryption", "severity": "MEDIUM", "cis": "2.1.1"})

    # CHECK 7: Security Groups Open to Internet
    sgs = ec2.describe_security_groups()['SecurityGroups']
    dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            for ip in rule.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 0)
                    if port in dangerous_ports:
                        findings.append({"title": f"SG {sg['GroupId']} {dangerous_ports[port]} Open", "severity": "CRITICAL", "cis": "5.2"})

    # CHECK 8: Default Security Group Has Rules
    for sg in sgs:
        if sg['GroupName'] == 'default':
            if sg.get('IpPermissions') or sg.get('IpPermissionsEgress'):
                has_non_default = False
                for rule in sg.get('IpPermissions', []):
                    if rule.get('IpRanges') or rule.get('Ipv6Ranges'):
                        has_non_default = True
                if has_non_default:
                    findings.append({"title": f"Default SG {sg['GroupId']} Has Inbound Rules", "severity": "MEDIUM", "cis": "5.4"})

    # CHECK 9: EBS Encryption
    try:
        volumes = ec2.describe_volumes()['Volumes']
        for vol in volumes:
            if not vol.get('Encrypted', False):
                findings.append({"title": f"EBS {vol['VolumeId']} Not Encrypted", "severity": "MEDIUM", "cis": "2.2.1"})
    except:
        pass

    # CHECK 10: RDS Public Access
    try:
        instances = rds.describe_db_instances()['DBInstances']
        for db in instances:
            if db.get('PubliclyAccessible', False):
                findings.append({"title": f"RDS {db['DBInstanceIdentifier']} Publicly Accessible", "severity": "CRITICAL", "cis": "2.3.1"})
            if not db.get('StorageEncrypted', False):
                findings.append({"title": f"RDS {db['DBInstanceIdentifier']} Not Encrypted", "severity": "HIGH", "cis": "2.3.1"})
    except:
        pass

    # CHECK 11: VPC Flow Logs
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        vpc_with_logs = [fl['ResourceId'] for fl in flow_logs]
        for vpc in vpcs:
            if vpc['VpcId'] not in vpc_with_logs:
                findings.append({"title": f"VPC {vpc['VpcId']} No Flow Logs", "severity": "MEDIUM", "cis": "3.9"})
    except:
        pass

    # CHECK 12: CloudTrail Enabled
    trails = ct.describe_trails()['trailList']
    if not trails:
        findings.append({"title": "No CloudTrail", "severity": "CRITICAL", "cis": "3.1"})

    # BUILD REPORT
    critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high = len([f for f in findings if f['severity'] == 'HIGH'])
    medium = len([f for f in findings if f['severity'] == 'MEDIUM'])
    low = len([f for f in findings if f['severity'] == 'LOW'])

    subject = f"AWS Scan: {critical} Critical, {high} High, {medium} Medium"

    message = "AWS SECURITY SCAN REPORT\n"
    message += "=" * 40 + "\n\n"
    message += f"Time: {datetime.now(timezone.utc).isoformat()}\n"
    message += f"Total Findings: {len(findings)}\n\n"
    message += f"CRITICAL: {critical}\n"
    message += f"HIGH: {high}\n"
    message += f"MEDIUM: {medium}\n"
    message += f"LOW: {low}\n\n"
    message += "FINDINGS\n"
    message += "-" * 40 + "\n"
    for f in findings:
        message += f"[{f['severity']}] {f['title']} (CIS {f.get('cis', 'N/A')})\n"

    if not findings:
        message += "No findings - all checks passed!\n"

    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    return {"statusCode": 200, "body": json.dumps({"total": len(findings), "critical": critical, "high": high, "medium": medium, "low": low, "findings": findings})}
