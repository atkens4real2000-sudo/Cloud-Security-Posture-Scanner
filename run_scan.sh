#!/bin/bash
cd "$(dirname "$0")"
python3 aws_scanner.py
python3 send_email.py
echo "Scan completed at: $(date)" >> scan.log
