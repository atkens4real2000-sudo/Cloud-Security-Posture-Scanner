# Cloud Security Posture Scanner

An open-source tool for scanning AWS environments against CIS Benchmark security controls.

## Features

- **IAM Security Checks**
  - Root account access keys detection
  - Root MFA verification
  - User MFA enforcement
  - Unused credentials detection

- **S3 Security Checks**
  - Block Public Access verification
  - Default encryption status
  - Versioning configuration

- **EC2 Security Checks**
  - Security group analysis (open ports to 0.0.0.0/0)
  - IMDSv2 enforcement

- **CloudTrail Checks**
  - Multi-region trail verification
  - Log file validation status

- **Reporting**
  - JSON reports for automation
  - HTML reports for stakeholders
  - Console summary with severity breakdown

## CIS Benchmarks Covered

| Control | Description |
|---------|-------------|
| CIS 1.4 | Ensure no root account access key exists |
| CIS 1.5 | Ensure MFA is enabled for root account |
| CIS 1.10 | Ensure MFA is enabled for all IAM users with console access |
| CIS 1.12 | Ensure credentials unused for 90 days are disabled |
| CIS 2.1.1 | Ensure S3 bucket policy denies HTTP requests |
| CIS 2.1.5 | Ensure S3 buckets have Block Public Access enabled |
| CIS 3.1 | Ensure CloudTrail is enabled in all regions |
| CIS 3.2 | Ensure CloudTrail log file validation is enabled |
| CIS 5.2 | Ensure no security groups allow unrestricted ingress |
| CIS 5.6 | Ensure EC2 instances use IMDSv2 |

## Requirements

- Python 3.8+
- AWS account with appropriate permissions
- boto3 library

## Installation

```bash
# Clone the repository
git clone https://github.com/atkens4real2000-sudo/Cloud-Security-Posture-Scanner.git
cd Cloud-Security-Posture-Scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

## AWS Permissions Required

The scanner requires read-only access to security configurations. Use the AWS managed `SecurityAudit` policy or create a custom policy with these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:GetLoginProfile",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage

### Basic Scan

```bash
python3 aws_scanner.py
```

### Output

```
╔═══════════════════════════════════════════════════════════╗
║         AWS Cloud Security Posture Scanner                ║
╚═══════════════════════════════════════════════════════════╝

[IAM CHECKS]
==================================================
  [*] Checking root account access keys...
    [+] PASS: No root access keys found
  [*] Checking root MFA status...
    [!] CRITICAL: Root MFA is not enabled!

[S3 CHECKS]
==================================================
  [*] Checking S3 Block Public Access settings...
    [!] HIGH: 2 buckets without full public access block

...

SCAN SUMMARY
==================================================
Total Findings: 5
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 2

[+] JSON report saved: reports/security_report_20240125_093045.json
[+] HTML report saved: reports/security_report_20240125_093045.html
```

## Project Structure

```
CloudSecurityScanner/
├── aws_scanner.py          # Main scanner
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── checks/                 # Individual check modules
├── configs/                # Configuration files
├── reports/                # Generated reports (gitignored)
├── lambda_code.py          # AWS Lambda deployment version
├── lambda_code_v2.py       # Enhanced Lambda with additional checks
└── send_email.py           # Email notification module
```

## Roadmap

- [ ] Azure support (azure-identity, azure-mgmt-*)
- [ ] GCP support (google-cloud-*)
- [ ] Additional CIS controls
- [ ] Auto-remediation capabilities
- [ ] SIEM integration (Splunk, ELK)
- [ ] Slack/Teams notifications
- [ ] Terraform integration

## Contributing

Contributions welcome! Please read the contributing guidelines first.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Akintade Akinokun**
- LinkedIn: [linkedin.com/in/akintadeakins](https://linkedin.com/in/akintadeakins)
- GitHub: [github.com/atkens4real2000-sudo](https://github.com/atkens4real2000-sudo)

## Acknowledgments

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
