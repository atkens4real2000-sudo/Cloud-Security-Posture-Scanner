import smtplib
import json
import glob
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "your-email@gmail.com")
RECEIVER_EMAIL = os.environ.get("RECEIVER_EMAIL", "your-email@gmail.com")
APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "your-app-password")

def send_email():
    report_dir = os.path.join(os.path.dirname(__file__), "reports")
    json_files = glob.glob(os.path.join(report_dir, 'security_report_*.json'))
    if not json_files:
        print("No reports found")
        return
    latest = sorted(json_files)[-1]
    with open(latest) as f:
        data = json.load(f)
    total = data.get('total_findings', 0)
    severity = data.get('findings_by_severity', {})
    critical = severity.get('CRITICAL', 0)
    high = severity.get('HIGH', 0)
    medium = severity.get('MEDIUM', 0)
    low = severity.get('LOW', 0)
    subject = f"AWS Security Scan: {critical} Critical, {high} High findings"
    body = "AWS SECURITY SCAN REPORT\n"
    body += "========================\n"
    body += f"Scan Time: {data.get('scan_timestamp', 'Unknown')}\n\n"
    body += "SUMMARY\n"
    body += "-------\n"
    body += f"Total: {total}\n"
    body += f"CRITICAL: {critical}\n"
    body += f"HIGH: {high}\n"
    body += f"MEDIUM: {medium}\n"
    body += f"LOW: {low}\n\n"
    body += "FINDINGS\n"
    body += "--------\n"
    for finding in data.get('findings', []):
        body += f"[{finding['severity']}] {finding['title']}\n"
        body += f"Resource: {finding['resource_id']}\n"
        body += f"Fix: {finding['recommendation']}\n\n"
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Email sent at {datetime.now()}")
    except Exception as e:
        print(f"Email failed: {e}")

if __name__ == "__main__":
    send_email()
