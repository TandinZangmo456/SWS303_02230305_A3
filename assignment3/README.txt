========================================
ASSIGNMENT 3 SUBMISSION PACKAGE
========================================

Student: Tandin Zangmo
Module: SWS303
Date: November 7, 2025

FILES INCLUDED:

1. Assignment3_Report.md          - Main report document (6 pages)
2. dns_tunnel.pcap                - DNS exfiltration traffic capture (4.9KB)
3. ssh_capture.pcap               - SSH tunneling traffic capture (504 bytes)
4. http_exfil.pcap                - HTTP/HTTPS exfiltration capture (144KB)
5. suricata_custom_rules.rules    - Custom IDS rules (3.6KB, 12 rules)
6. ssh_logs.txt                   - SSH authentication logs
7. README.txt                     - This file

QUICK START:
To view PCAPs:
  wireshark dns_tunnel.pcap
  wireshark http_exfil.pcap
  wireshark ssh_capture.pcap

To test IDS rules:
  suricata -r dns_tunnel.pcap -l ./output/ -c /etc/suricata/suricata.yaml

To read report:
  cat Assignment3_Report.md
  (or open in any markdown viewer)

SUMMARY:
All 3 tasks completed (DNS, SSH, HTTP exfiltration)
12 custom IDS rules created and documented
All traffic captured in PCAPs
Comprehensive 6-page report with analysis
Mitigation recommendations provided

Lab Environment:
- Victim: Ubuntu 10.2.38.187
- Attacker: Kali 10.2.38.82
- IDS: Suricata with custom rules
- Firewall: iptables (restrictive configuration)
