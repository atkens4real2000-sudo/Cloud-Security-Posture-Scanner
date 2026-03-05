#!/bin/bash                                                                                                                            
  cd /Users/akintadeakins/Desktop/Resume/CloudSecurityScanner                                                                            
  /Users/akintadeakins/Desktop/Resume/CloudSecurityScanner/venv/bin/python3 aws_scanner.py                                               
  /Users/akintadeakins/Desktop/Resume/CloudSecurityScanner/venv/bin/python3 send_email.py                                                
  echo "Scan completed at: $(date)" >> scan.log
