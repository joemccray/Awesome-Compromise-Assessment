# Awesome Compromise Assessment

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A curated list of tools, resources, and best practices for performing thorough and effective compromise assessments. This list is designed for cybersecurity professionals, SOC analysts, incident response teams, and more.

---

## Table of Contents

1. [Introduction](#introduction)
2. [How to Perform a Compromise Assessment](#how-to-perform-a-compromise-assessment)
3. [Key Tools & Software](#key-tools--software)
4. [Forensic Analysis Tools](#forensic-analysis-tools)
5. [Log Analysis Tools](#log-analysis-tools)
6. [Network Monitoring & Security Tools](#network-monitoring--security-tools)
7. [Incident Response & Threat Intelligence](#incident-response--threat-intelligence)
8. [Guidelines & Best Practices](#guidelines--best-practices)
9. [Case Studies & Reports](#case-studies--reports)
10. [Training & Educational Resources](#training--educational-resources)
11. [Compliance & Regulatory Frameworks](#compliance--regulatory-frameworks)
12. [Open-Source Threat Intelligence](#open-source-threat-intelligence)
13. [Community & Discussion Forums](#community--discussion-forums)
14. [Cheat Sheets](#cheat-sheets)
15. [Best Blog Posts](#best-blog-posts)
16. [SentryCA - Compromise Assessment Platform](#sentryca-compromise-assessment-platform)
17. [Contributing](#contributing)

---

## Introduction

**Compromise Assessment** is a systematic process used to detect Indicators of Compromise (IoCs) within systems, networks, and endpoints. This helps organizations determine if they have been breached and how extensive the damage is.

This repository provides valuable tools and resources for:
- **Cybersecurity Consultants**: Providing detailed assessments for clients.
- **SOC Analysts**: Real-time monitoring and incident response.
- **Incident Response Leads**: Coordinating team responses and automating containment.
- **Network Administrators**: Ensuring network security and performance.
- **Digital Forensics Investigators**: Collecting and analyzing digital evidence after an attack.
- **Compliance Managers**: Ensuring regulatory compliance and reporting.

---

## How to Perform a Compromise Assessment

Here is a step-by-step guide to performing a compromise assessment, using various tools and methodologies tailored to your organization's needs:

### 1. **Define the Scope and Objectives**
   - Understand the systems and data involved.
   - Set clear goals for detection and remediation.

   **Relevant Links:**
   - [SANS - Incident Response Playbook](https://www.sans.org/white-papers/36302)
   - [CISA - Incident Response Guidance](https://www.cisa.gov/incident-response-playbook)
   - [NIST - Security Log Management Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92.pdf)

### 2. **Gather Logs, Endpoint Data, and Network Traffic**
   - Collect relevant logs, endpoint activity data, and network traffic to detect potential compromises.

   **Relevant Links:**
   - [Sysmon for Windows Logging](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
   - [Wireshark for Network Traffic Analysis](https://www.wireshark.org/)
   - [Velociraptor for Endpoint Data Collection](https://www.velocidex.com/)
   - [Suricata for Network IDS](https://suricata.io/)

### 3. **Investigate Indicators of Compromise (IoCs)**
   - Analyze collected data to find potential IoCs using threat intelligence.

   **Relevant Links:**
   - [AlienVault Open Threat Exchange](https://otx.alienvault.com/)
   - [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
   - [YARA for IoC Scanning](https://virustotal.github.io/yara/)

### 4. **Analyze Suspicious Activity**
   - Investigate abnormal activities such as unauthorized logins or file changes.

   **Relevant Links:**
   - [Redline Endpoint Analysis](https://www.mandiant.com/resources/redline)
   - [Autopsy Digital Forensics Tool](https://www.sleuthkit.org/autopsy/)
   - [Osquery for Endpoint Visibility](https://osquery.io/)

### 5. **Mitigate and Contain**
   - Isolate compromised systems to stop the spread of attacks.

   **Relevant Links:**
   - [Zeek Network Monitoring](https://zeek.org/)
   - [Binalyze AIR for Remote Forensics](https://www.binalyze.com/air/compromise-assessment/)
   - [Nextron Systems Thor Cloud](https://www.nextron-systems.com/thor-cloud/)

### 6. **Generate Reports**
   - Document findings, mitigation strategies, and evidence for legal and compliance purposes.

   **Relevant Links:**
   - [NIST Incident Response Template](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-115.pdf)
   - [Splunk Reporting Features](https://www.splunk.com/en_us/software/splunk-security.html)

---

## Key Tools & Software

Here is a list of essential tools for conducting compromise assessments:

1. **[Velociraptor Endpoint Forensics](https://www.velocidex.com/)** - Endpoint monitoring and forensics collection tool.
2. **[Wazuh](https://wazuh.com/)** - An open-source security monitoring platform that provides threat detection, integrity monitoring, and incident response.
3. **[Osquery](https://osquery.io/)** - An open-source tool for querying system data in real time to monitor and secure endpoints.
4. **[Binalyze AIR](https://www.binalyze.com/air/compromise-assessment/)** - A real-time forensic analysis platform for quick detection and response.
5. **[Nextron Systems Thor Cloud](https://www.nextron-systems.com/thor-cloud/)** - Cloud-based IoC scanning platform for endpoint threat detection.
6. **[Nessus](https://www.tenable.com/products/nessus)** - One of the most widely used vulnerability scanners for identifying potential weaknesses in systems.
7. **[SentryCA](https://rishisec.com/sentryca/)** is RishiSec's flagship platform for compromise assessment, providing real-time IoC detection, customizable reporting, and advanced scanning for SOC analysts, incident responders, and cybersecurity consultants.


---

## Forensic Analysis Tools

1. **[Autopsy](https://www.sleuthkit.org/autopsy/)**
2. **[Volatility Memory Forensics](https://www.volatilityfoundation.org/)**
3. **[Belkasoft Evidence Center](https://belkasoft.com/ec)**
4. **[X-Ways Forensics](https://www.x-ways.net/forensics/)**
5. **[Magnet AXIOM](https://www.magnetforensics.com/products/axiom/)**

---

## Log Analysis Tools

1. **[Graylog](https://www.graylog.org/)**
2. **[Splunk](https://www.splunk.com/)**
3. **[ELK Stack (Elasticsearch, Logstash, Kibana)](https://www.elastic.co/)**

---

## Network Monitoring & Security Tools

1. **[Suricata](https://suricata.io/)**
2. **[Wireshark](https://www.wireshark.org/)**
3. **[Zeek (formerly Bro)](https://zeek.org/)**
4. **[Tshark Command Line Tool](https://www.wireshark.org/docs/man-pages/tshark.html)**

---

## Incident Response & Threat Intelligence

1. **[AlienVault OTX](https://otx.alienvault.com/)**
2. **[MISP Threat Sharing](https://www.misp-project.org/)**
3. **[CIRCL Threat Intelligence Platform](https://www.circl.lu/services/misp-malware-information-sharing-platform/)**

---

## Guidelines & Best Practices

1. **[SANS Best Practices for Compromise Assessment](https://www.sans.org/white-papers/36607/)**
2. **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)**

---

## Case Studies & Reports

1. **[SolarWinds Cyberattack Report](https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software-0)**
2. **[Equifax Data Breach Case Study](https://www.ftc.gov/enforcement/cases-proceedings/refunds/equifax-data-breach-settlement)**
3. **[Target Data Breach Analysis](https://www.bankinfosecurity.com/target-data-breach-2013-how-attack-happened-a-7504)**

---

## Training & Educational Resources

1. **[SANS Digital Forensics Training](https://www.sans.org/cyber-security-courses/forensics/)**
2. **[MITRE ATT&CK Framework Training](https://attack.mitre.org/resources/training/)**
3. **[Pluralsight Cybersecurity Courses](https://www.pluralsight.com/paths/cybersecurity-foundations)**

---

## Compliance & Regulatory Frameworks

1. **[GDPR Compliance](https://gdpr.eu/)**
2. **[HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)**
3. **[PCI DSS Compliance](https://www.pcisecuritystandards.org/)**

---

## Open-Source Threat Intelligence

1. **[VirusTotal](https://www.virustotal.com/)**
2. **[MISP](https://www.misp-project.org/)**
3. **[Abuse.ch Botnet Tracker](https://abuse.ch/)**

---

## Community & Discussion Forums

1. **[Forensic Focus Forums](https://www.forensicfocus.com/)**
2. **[Reddit r/cybersecurity](https://www.reddit.com/r/cybersecurity/)**
3. **[Security StackExchange](https://security.stackexchange.com/)**

---

## Cheat Sheets

1. **[Incident Response Cheat Sheet](https://rishisec.com/resources/cheat-sheets/incident-response-cheat-sheet/)**
2. **[Compromise Assessment Cheat Sheet](https://rishisec.com/resources/cheat-sheets/compromise-assessment-cheat-sheet/)**
3. **[Network Forensics Cheat Sheet](https://rishisec.com/resources/cheat-sheets/network-forensics-cheat-sheet/)**

---

## Best Blog Posts

1. **[How to Perform a Thorough Compromise Assessment](https://rishisec.com/blog/how-to-perform-a-thorough-compromise-assessment/)**
2. **[Real-Time Monitoring During Incident Response](https://rishisec.com/blog/real-time-monitoring-during-incident-response/)**
3. **[How Network Forensics Enhances Compromise Detection](https://rishisec.com/blog/how-network-forensics-enhances-compromise-detection/)**

---

## Contributing

We welcome contributions! If you have tools, resources, or insights that can enhance this repository, please submit a pull request or open an issue.

For guidelines, refer to the [Contributing.md](./CONTRIBUTING.md).

---

