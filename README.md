# Threat Intelligence and Network Security — Python Practicals Lab

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Standard Library](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-brightgreen.svg)](#requirements)
[![Topic](https://img.shields.io/badge/Security-Threat%20Intelligence%20%26%20Network%20Security-red.svg)](#overview)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

A complete laboratory portfolio containing 10 Python cybersecurity practicals for **Threat Intelligence and Network Security (TINS)**. Each practical is an independent, beginner-friendly, well-commented script utilizing Python's built-in standard library.

The repository includes complete source code, realistic sample inputs, verified execution outputs, terminal screenshots, and viva preparation notes.

---

## Lab Practical Index

| Practical | Python Script | Core Topic | Screenshot |
|:---:|:---|:---|:---:|
| **01** | [`practical_01_threat_intelligence_classifier.py`](practical_01_threat_intelligence_classifier.py) | CTI Domain Classification (Banking, Healthcare, E-Commerce, Network) | [View Screenshot](screenshots/practical_01_output.png) |
| **02** | [`practical_02_port_scanner.py`](practical_02_port_scanner.py) | Socket TCP Port Scanner with Authorized Lab Guardrails | [View Screenshot](screenshots/practical_02_output.png) |
| **03** | [`practical_03_security_policy_checker.py`](practical_03_security_policy_checker.py) | Information Security Policy Compliance Auditor (ISO 27001 / NIST) | [View Screenshot](screenshots/practical_03_output.png) |
| **04** | [`practical_04_vpn_confidentiality_demo.py`](practical_04_vpn_confidentiality_demo.py) | VPN Confidentiality & Symmetric Stream Cipher Simulation | [View Screenshot](screenshots/practical_04_output.png) |
| **05** | [`practical_05_intelligence_report_classifier.py`](practical_05_intelligence_report_classifier.py) | Strategic, Tactical, and Operational CTI Report Categorization | [View Screenshot](screenshots/practical_05_output.png) |
| **06** | [`practical_06_phishing_url_detector.py`](practical_06_phishing_url_detector.py) | Multi-Factor Heuristic Phishing URL Risk Scoring | [View Screenshot](screenshots/practical_06_output.png) |
| **07** | [`practical_07_elk_stack_simulator.py`](practical_07_elk_stack_simulator.py) | Logstash Parsing, Elasticsearch Indexing, Kibana Metrics | [View Screenshot](screenshots/practical_07_output.png) |
| **08** | [`practical_08_network_segmentation.py`](practical_08_network_segmentation.py) | Multi-VLAN Micro-segmentation & Lateral Movement Blocking | [View Screenshot](screenshots/practical_08_output.png) |
| **09** | [`practical_09_threat_intelligence_lifecycle.py`](practical_09_threat_intelligence_lifecycle.py) | 6-Stage Threat Intelligence Lifecycle Mapper | [View Screenshot](screenshots/practical_09_output.png) |
| **10** | [`practical_10_stateful_firewall.py`](practical_10_stateful_firewall.py) | Layer-4 Stateful Packet Inspection (SPI) Firewall Tracker | [View Screenshot](screenshots/practical_10_output.png) |

---

## Detailed Assignment Documentation

Full laboratory writeups with aim, source code, input/output logs, and embedded output screenshots are provided in:
- [**`CYBERSECURITY_PYTHON_PRACTICALS.md`**](CYBERSECURITY_PYTHON_PRACTICALS.md)

---

## System Requirements

- **Operating System:** Windows, Linux, or macOS
- **Python Version:** Python 3.8+ (tested on Python 3.10.0)
- **Dependencies for Practicals:** **Zero external dependencies**. All 10 practicals rely exclusively on Python standard modules (`socket`, `re`, `ipaddress`, `hashlib`, `sys`, `time`, `collections`, `urllib.parse`).
- **Dependencies for Screenshot Generator (`capture_terminal_runs.py`):** `Pillow` (PIL) for terminal screenshot rendering.

---

## How to Run Each Practical

Clone the repository and run any script directly in your terminal:

```bash
# Clone the repository
git clone https://github.com/vara12126/Threat-intelligence-and-Network-security-9303.git
cd Threat-intelligence-and-Network-security-9303

# Practical 01: Threat Intelligence Domain Classifier
python practical_01_threat_intelligence_classifier.py

# Practical 02: Safe TCP Port Scanner
python practical_02_port_scanner.py

# Practical 03: Security Policy Compliance Checker
python practical_03_security_policy_checker.py

# Practical 04: VPN Confidentiality Demo
python practical_04_vpn_confidentiality_demo.py

# Practical 05: CTI Report Classifier
python practical_05_intelligence_report_classifier.py

# Practical 06: Heuristic Phishing URL Detector
python practical_06_phishing_url_detector.py

# Practical 07: ELK Stack Architecture Simulator
python practical_07_elk_stack_simulator.py

# Practical 08: Network Segmentation Simulator
python practical_08_network_segmentation.py

# Practical 09: Threat Intelligence Lifecycle Classifier
python practical_09_threat_intelligence_lifecycle.py

# Practical 10: Stateful Inspection Firewall Simulator
python practical_10_stateful_firewall.py
```

All programs feature **interactive prompts with intelligent defaults**: press `Enter` at any prompt to execute the pre-configured academic test scenario.

---

## Screenshot Generation

All screenshots in the `screenshots/` directory reflect real execution outputs produced by the Python scripts:

```bash
# Re-run all practicals and generate terminal screenshots
python capture_terminal_runs.py
```

The screenshots are saved as:
- `screenshots/practical_01_output.png`
- `screenshots/practical_02_output.png`
- `screenshots/practical_03_output.png`
- `screenshots/practical_04_output.png`
- `screenshots/practical_05_output.png`
- `screenshots/practical_06_output.png`
- `screenshots/practical_07_output.png`
- `screenshots/practical_08_output.png`
- `screenshots/practical_09_output.png`
- `screenshots/practical_10_output.png`

---

## Viva & Examination Cheatsheet

### 1. What are the three levels of Cyber Threat Intelligence (CTI)?
- **Strategic:** High-level trends, geopolitical risk, and financial impact for executive leadership (CISO, Board).
- **Tactical:** How adversaries operate — Tactics, Techniques, and Procedures (TTPs), MITRE ATT&CK mapping for security engineers.
- **Operational:** Immediate technical indicators (IOCs: malicious IPs, file hashes, URLs) for SOC analysts and incident responders.

### 2. How does a Stateful Firewall differ from a Stateless Firewall?
- **Stateless Firewall:** Examines each packet in isolation against static ACLs. Does not remember past packets. Requires opening permanent ports in both directions.
- **Stateful Firewall:** Tracks active connection sessions (5-tuple: source IP, source port, destination IP, destination port, protocol) in a dynamic state table. Automatically permits return traffic matching an outbound session and drops unsolicited inbound packets.

### 3. What is Lateral Movement and how does Network Segmentation prevent it?
- **Lateral Movement:** An adversary compromises an initial lower-privilege host (e.g., guest Wi-Fi or workstation) and pivots internally across the network toward critical assets (e.g., database).
- **Segmentation:** Dividing the network into isolated security zones (VLANs / subnets) with strict firewalls/ACLs between them ensures compromised nodes cannot directly reach crown-jewel databases.

### 4. What are the 6 stages of the Threat Intelligence Lifecycle?
1. **Direction:** Defining requirements, scope, and Priority Intelligence Requirements (PIRs).
2. **Collection:** Gathering raw threat telemetry from feeds, OSINT, logs, and dark web.
3. **Processing:** Normalizing, translating, deduplicating, and converting data into structured formats (STIX/TAXII).
4. **Analysis:** Correlating indicators, adversary attribution, and assessing capabilities.
5. **Dissemination:** Publishing actionable reports and pushing IOCs to SIEM/firewalls.
6. **Feedback:** Evaluating report utility, measuring ROI, and updating PIRs.

---

## Repository Structure

```text
Threat-intelligence-and-Network-security-9303/
├── CYBERSECURITY_PYTHON_PRACTICALS.md           # Comprehensive lab manual & reports
├── README.md                                    # Project overview and instructions
├── capture_terminal_runs.py                     # Execution & screenshot generation script
├── practical_01_threat_intelligence_classifier.py
├── practical_02_port_scanner.py
├── practical_03_security_policy_checker.py
├── practical_04_vpn_confidentiality_demo.py
├── practical_05_intelligence_report_classifier.py
├── practical_06_phishing_url_detector.py
├── practical_07_elk_stack_simulator.py
├── practical_08_network_segmentation.py
├── practical_09_threat_intelligence_lifecycle.py
├── practical_10_stateful_firewall.py
└── screenshots/
    ├── practical_01_output.png
    ├── practical_02_output.png
    ├── practical_03_output.png
    ├── practical_04_output.png
    ├── practical_05_output.png
    ├── practical_06_output.png
    ├── practical_07_output.png
    ├── practical_08_output.png
    ├── practical_09_output.png
    └── practical_10_output.png
```

---
*Created for Threat Intelligence and Network Security academic practical submissions.*
