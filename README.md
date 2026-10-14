# SOC Analyst Lab Write-ups

Security+ certified, working toward a SOC analyst role. This repo collects hands-on investigation write-ups from blue-team labs: alert triage, email and log analysis, detection engineering, and incident reporting.

Each write-up walks through a realistic scenario the way an analyst would handle it, from first look to verdict and recommended response.

## Write-ups

| # | Room | Focus |
|---|---|---|
| 01 | [The Greenholt Phish](01-greenholt-phish/) | Phishing email triage: header analysis, SPF/DMARC spoofing check, malicious attachment analysis |
| 02 | [Snapped Phish-ing Line](02-snapped-phishing-line/) | Credential-harvesting campaign: HTML redirector, fake M365 login, exposed phishing kit and exfil mailbox |
| 03 | [Summit](03-summit/) | Detection engineering: hash, firewall, DNS, and Sigma rules escalating up the Pyramid of Pain |

## Skills demonstrated

- Email header and authentication analysis (SPF, DMARC, Reply-To and envelope-from inspection)
- Phishing triage and indicator of compromise (IOC) extraction
- Safe handling of malicious files and attachments: isolation, hashing, and reputation lookup
- Phishing infrastructure and kit analysis: open directories, credential logs, exfiltration addresses
- Detection engineering across the Pyramid of Pain: hash blocklists, egress firewall rules, DNS filtering, and Sigma rules
- Behavioral detection from logs: registry tampering, C2 beaconing, and host discovery commands
- Mapping findings to MITRE ATT&CK tactics and techniques
- Writing incident reports with containment and response recommendations

## Tools

Thunderbird, MXToolbox, VirusTotal, ipinfo, CyberChef, Sigma, Sysmon, Linux command line, TryHackMe

## Other hands-on training

Completed 15+ guided labs through the Google Cybersecurity Certificate, covering the Linux command line, SQL queries, Wireshark and tcpdump packet analysis, Suricata IDS alerts and rules, and hashing and encryption.

## About me

**William Dana III**, Charlotte, NC (open to remote)
CompTIA Security+ (SY0-701) | Google Cybersecurity Certificate

[LinkedIn](https://www.linkedin.com/in/william-dana-iii-083278360)
