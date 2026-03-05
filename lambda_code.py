import boto3
import json
import os
from datetime import datetime, timezone

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:ACCOUNT_ID:security-scan-alerts")

def lambda_handler(event, context):
    findings = []
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    ec2 = boto3.client('ec2')
    ct = boto3.client('cloudtrail')
    sns = boto3.client('sns')
    summary = iam.get_account_summary()
    if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
        findings.append({"title": "Root Has Access Keys", "severity": "CRITICAL"})
    if summary['SummaryMap'].get('AccountMFAEnabled', 0) != 1:
        findings.append({"title": "Root MFA Not Enabled", "severity": "CRITICAL"})
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        try:
            s3.get_public_access_block(Bucket=bucket['Name'])
        except:
            findings.append({"title": f"S3 {bucket['Name']} No Public Block", "severity": "HIGH"})
    sgs = ec2.describe_security_groups()['SecurityGroups']
    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            for ip in rule.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 0)
                    if port in [22, 3389, 3306, 5432]:
                        findings.append({"title": f"SG {sg['GroupId']} Port {port} Open", "severity": "CRITICAL"})
    trails = ct.describe_trails()['trailList']
    if not trails:
        findings.append({"title": "No CloudTrail", "severity": "CRITICAL"})
    critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high = len([f for f in findings if f['severity'] == 'HIGH'])
    subject = f"AWS Security Scan: {critical} Critical, {high} High"
    message = "AWS SECURITY SCAN REPORT\n"
    message += "========================\n\n"
    message += f"Time: {datetime.now(timezone.utc).isoformat()}\n"
    message += f"Total Findings: {len(findings)}\n"
    message += f"Critical: {critical}\n"
    message += f"High: {high}\n\n"
    message += "FINDINGS\n"
    message += "--------\n"
    for f in findings:
        message += f"[{f['severity']}] {f['title']}\n"
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    return {"statusCode": 200, "body": json.dumps({"total": len(findings), "findings": findings})}
