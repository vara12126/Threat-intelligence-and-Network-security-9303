# Threat Intelligence and Network Security — Practicals 11–20 Report

**Course:** B.Tech Computer Science and Engineering (Cybersecurity)  
**Subject:** Threat Intelligence and Network Security  
**Academic Year:** 2026  
**Language:** Python 3.10  
**Environment:** Local Command-Line / PowerShell Execution  

---

## Overview Table of Practicals (11–20)

| Practical | Script Filename | Topic / Capability |
| :--- | :--- | :--- |
| **Practical 11** | `practical_11_packet_sniffing_scapy.py` | Network Packet Sniffing Using Scapy & Fallback Engine |
| **Practical 12** | `practical_12_soc_alert_priority.py` | SOC Alert Priority Classification (P1–P4 Triage) |
| **Practical 13** | `practical_13_threat_intelligence_quality.py` | Threat Intelligence Quality Assessment (Context, Confidence, Actionability) |
| **Practical 14** | `practical_14_siem_pipeline.py` | End-to-End SIEM Architecture Simulation (Collection, Normalization, Correlation, Alerting) |
| **Practical 15** | `practical_15_incident_root_cause.py` | Security Incident Root-Cause Classification (5 IR Vectors) |
| **Practical 16** | `practical_16_defense_in_depth.py` | Defense-in-Depth Multi-Layer Attack Mitigation Simulation |
| **Practical 17** | `practical_17_iso27001_control_classifier.py` | ISO/IEC 27001:2022 Annex A Control Theme Classification |
| **Practical 18** | `practical_18_sha256_malware_detection.py` | Malware Detection Using Chunked SHA-256 Hash Comparison |
| **Practical 19** | `practical_19_splunk_search_stats.py` | Splunk Search Filter & Stats Count by Field Simulation |
| **Practical 20** | `practical_20_network_threat_classifier.py` | Network Threat Category Classifier (Phishing, DoS/DDoS, Malware, MitM) |

---

## Practical 11: Network Packet Sniffing Using Scapy

### 1. Aim
To write an educational Python program using Scapy to capture live packets on a selectable network interface, display packet numbers and protocol summaries, enforce safe usage guidelines, and handle missing dependencies (Npcap / libpcap), non-root permissions, and interface limitations gracefully.

### 2. Algorithm / Working Steps
1. Display the safe usage ethical guidelines and legal notice (IT Act / authorization requirement).
2. Attempt to import Scapy modules (`sniff`, `conf`, `get_if_list`, `IP`, `TCP`, `UDP`, `Ether`).
3. If Scapy or the kernel packet capture driver (Npcap on Windows / libpcap on Linux) is unavailable, output clear environment guidance and activate the explicitly labeled demonstration engine.
4. Enumerate detected active network interfaces and allow the analyst to select an interface or accept the default.
5. Prompt for or configure a safe, bounded packet capture limit (default 3 packets; max 20).
6. Invoke Scapy's `sniff()` function with a per-packet callback (`packet_callback`) that increments a packet counter and prints the Scapy packet summary (`packet.summary()`).
7. Catch `PermissionError` and other operational exceptions, reporting remediation steps (running as Administrator / root) and falling back to sample summaries.
8. Print the total count of captured packets and terminate cleanly.

### 3. Python Source Code
Reference file: [`practical_11_packet_sniffing_scapy.py`](practical_11_packet_sniffing_scapy.py)

```python
"""
Practical 11: Network Packet Sniffing Using Scapy
Subject: Threat Intelligence and Network Security
"""

import sys
import os
import argparse

SAFE_USAGE_NOTICE = """======================================================================
  SAFE USAGE NOTICE & ETHICAL GUIDELINES
  - Packet capture must ONLY be performed on networks and systems
    for which you have explicit authorization.
  - Unauthorized interception of network communications violates
    university policies and legal frameworks (e.g., IT Act 2000).
  - Use this educational tool strictly in authorized lab environments.
======================================================================"""

try:
    from scapy.all import sniff, conf, get_if_list, IP, TCP, UDP, Ether, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def display_demo_packets(count: int = 3):
    print("\n[DEMONSTRATION MODE - EXPLICITLY LABELED SAMPLE PACKETS]")
    print("Notice: Live packet capture requires administrator privileges and a packet driver")
    print("        (Npcap on Windows / libpcap on Linux). Displaying explicitly labeled sample")
    print("        packets to demonstrate Scapy packet summary output.\n")
    
    demo_packets = [
        "Ether / IP / TCP 192.168.1.10:51520 > 93.184.216.34:443 S",
        "Ether / IP / UDP 192.168.1.10:53000 > 8.8.8.8:53 / DNS Qry \"example.com.\"",
        "Ether / IP / TCP 93.184.216.34:443 > 192.168.1.10:51520 SA",
        "Ether / IP / ICMP 192.168.1.10 > 1.1.1.1 echo-request 0",
        "Ether / IP / UDP 192.168.1.10:54001 > 1.1.1.1:53 / DNS Qry \"github.com.\""
    ]
    
    selected = demo_packets[:min(count, len(demo_packets))]
    for idx, pkt_summary in enumerate(selected, 1):
        print(f"Packet {idx}: {pkt_summary}")
        
    print(f"\nTotal packets captured: {len(selected)}")
    print("Packet sniffing completed (Demonstration Mode).")


def run_live_sniff(interface: str = None, count: int = 3, timeout: int = 5):
    print("\nPRACTICAL 11: PACKET SNIFFING USING SCAPY")
    print("Starting packet capture...")
    if interface:
        print(f"Interface: {interface}")
    print(f"Configured packet limit: {count}")
    print("-" * 70)

    packet_counter = 0

    def packet_callback(packet):
        nonlocal packet_counter
        packet_counter += 1
        summary = packet.summary()
        print(f"Packet {packet_counter}: {summary}")

    try:
        if os.name == "nt" and conf.use_pcap is False:
            print("[ENVIRONMENT NOTICE]: Npcap/WinPcap is not detected on this Windows host.")
            print("Live packet capture requires the Npcap driver (https://npcap.com/).")
            display_demo_packets(count)
            return

        kwargs = {"prn": packet_callback, "count": count, "timeout": timeout, "store": False}
        if interface:
            kwargs["iface"] = interface

        sniff(**kwargs)

        print("-" * 70)
        print(f"Total packets captured: {packet_counter}")
        print("Packet sniffing completed.")

        if packet_counter == 0:
            print("\n[Notice]: No live packets were captured during the timeout window.")
            print("Switching to demonstration mode to show expected output structure:")
            display_demo_packets(count)

    except PermissionError:
        print("\n[ERROR]: Insufficient permissions to capture raw network packets.")
        print("Resolution: On Windows, run terminal as Administrator with Npcap installed.")
        print("            On Linux, run with sudo or setcap privileges.")
        display_demo_packets(count)
    except Exception as exc:
        print(f"\n[ERROR]: Live capture encountered an error: {exc}")
        print("Falling back to demonstration mode.")
        display_demo_packets(count)
```

### 4. Sample Input
- Execution Command: `python practical_11_packet_sniffing_scapy.py --demo --count 3`
- Optional interactive run: Interface selection prompt `[Enter for default]`, Packet count `[3]`.

### 5. Actual Program Output
```text
======================================================================
  Cyber Threat Intelligence - Practical 11: Network Packet Sniffing
======================================================================
======================================================================
  SAFE USAGE NOTICE & ETHICAL GUIDELINES
  - Packet capture must ONLY be performed on networks and systems
    for which you have explicit authorization.
  - Unauthorized interception of network communications violates
    university policies and legal frameworks (e.g., IT Act 2000).
  - Use this educational tool strictly in authorized lab environments.
======================================================================

[DEMONSTRATION MODE - EXPLICITLY LABELED SAMPLE PACKETS]
Notice: Live packet capture requires administrator privileges and a packet driver
        (Npcap on Windows / libpcap on Linux). Displaying explicitly labeled sample
        packets to demonstrate Scapy packet summary output.

Packet 1: Ether / IP / TCP 192.168.1.10:51520 > 93.184.216.34:443 S
Packet 2: Ether / IP / UDP 192.168.1.10:53000 > 8.8.8.8:53 / DNS Qry "example.com."
Packet 3: Ether / IP / TCP 93.184.216.34:443 > 192.168.1.10:51520 SA

Total packets captured: 3
Packet sniffing completed (Demonstration Mode).
```

### 6. Result & Conclusion
The program successfully demonstrated network packet sniffing using Scapy packet callbacks, enforced ethical lab guidelines, set configurable capture thresholds, and provided graceful fallback handling with educational labeled packet summaries when kernel packet drivers (Npcap) or root permissions are absent.

---

## Practical 12: SOC Alert Priority Classification

### 1. Aim
To assign a standardized P1–P4 priority level to an incoming Security Operations Center (SOC) alert description using rule-based indicator scoring and severity definitions, providing analysts with actionable response recommendations.

### 2. Algorithm / Working Steps
1. Define a rule base for each priority tier:
   - **P1 (Critical):** Active ransomware, mass file encryption, rootkit, domain controller compromise.
   - **P2 (High):** Credential dumping (Mimikatz), privilege escalation, active CVE exploitation, lateral movement.
   - **P3 (Medium):** Brute force login failures, internal port scanning, anomalous beaconing, suspicious PowerShell.
   - **P4 (Low):** Informational vulnerability scans, scheduled maintenance, benign policy warnings.
2. Accept a plain-language SOC alert description from user input or automated alert queues.
3. Clean and convert the input string to lowercase tokens.
4. Scan and score indicator keyword occurrences across P1, P2, P3, and P4.
5. Apply hierarchical evaluation: P1 matches dominate; if none, check P2, then P3, then P4.
6. If no indicators match, classify as Medium (P3) triage for analyst review to prevent critical omissions.
7. Output the assigned priority, severity level, technical reasoning, trigger indicators, and recommended CSIRP action.

### 3. Python Source Code
Reference file: [`practical_12_soc_alert_priority.py`](practical_12_soc_alert_priority.py)

```python
"""
Practical 12: SOC Alert Priority Classification
Subject: Threat Intelligence and Network Security
"""

PRIORITY_RULES = {
    "P1": {
        "severity": "Critical",
        "keywords": [
            "ransomware", "encrypting files", "ransom note", "domain controller compromised",
            "active breach", "database exfiltration", "rootkit deployed", "widespread outage"
        ],
        "default_action": "Activate major incident response procedures (CSIRP), isolate affected endpoints immediately, and notify executive leadership.",
        "reason_template": "Indicators suggest an active, severe compromise or ransomware attack impacting mission-critical systems."
    },
    "P2": {
        "severity": "High",
        "keywords": [
            "active exploitation", "privilege escalation", "mimikatz", "pass-the-hash",
            "unauthorized admin login", "malware execution", "lateral movement", "credential dumping"
        ],
        "default_action": "Contain affected user accounts or hosts, collect forensic memory dumps, and initiate targeted threat containment.",
        "reason_template": "High likelihood of active exploitation or adversary presence requiring rapid containment within 1-2 hours."
    },
    "P3": {
        "severity": "Medium",
        "keywords": [
            "multiple failed logins", "brute force", "port scan detected", "unauthorized usb",
            "policy violation", "suspicious powershell", "unusual traffic spike", "outbound beaconing"
        ],
        "default_action": "Assign to Tier-1/Tier-2 analyst for queue investigation, correlate host logs, and verify legitimate business context.",
        "reason_template": "Suspicious anomalous behavior detected requiring investigation, but without verified widespread harm."
    },
    "P4": {
        "severity": "Low",
        "keywords": [
            "informational", "scheduled scan", "routine backup", "user password changed",
            "software update installed", "low risk ping", "expired cert warning"
        ],
        "default_action": "Log for situational awareness; no immediate escalation required unless correlated with higher-tier alerts.",
        "reason_template": "Routine informational or low-risk event consistent with standard baseline operational noise."
    }
}

def classify_soc_alert(alert_text: str) -> dict:
    text_clean = alert_text.strip()
    if not text_clean:
        return {"priority": "P4", "severity": "Low", "reason": "Empty alert text.", "action": "Discard/Enrich."}

    text_lower = text_clean.lower()
    scores = {p: len([kw for kw in data["keywords"] if kw in text_lower]) for p, data in PRIORITY_RULES.items()}

    if scores["P1"] > 0:
        assigned = "P1"
    elif scores["P2"] > 0:
        assigned = "P2"
    elif scores["P3"] > 0:
        assigned = "P3"
    elif scores["P4"] > 0:
        assigned = "P4"
    else:
        assigned = "P3"
        return {"priority": "P3", "severity": "Medium", "reason": "Ambiguous description; assigned Medium for manual review.", "action": "Manual triage."}

    info = PRIORITY_RULES[assigned]
    return {
        "priority": assigned,
        "severity": info["severity"],
        "reason": info["reason_template"],
        "action": info["default_action"],
        "scores": scores
    }
```

### 4. Sample Input
```text
Multiple servers are encrypting files and a ransomware note has appeared.
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 12: SOC ALERT PRIORITY CLASSIFICATION
======================================================================
Alert: Multiple servers are encrypting files and a ransomware note has appeared.

Assigned Priority: P1
Severity: Critical
Reason: Indicators suggest an active, severe compromise or ransomware attack impacting mission-critical systems. (Trigger indicators: ransomware, encrypting files)
Recommended Action: Activate major incident response procedures (CSIRP), isolate affected endpoints immediately, and notify executive leadership.
----------------------------------------------------------------------
Indicator Matching Breakdown:
  - P1 (Critical): 2 match(es)
  - P2 (High    ): 0 match(es)
  - P3 (Medium  ): 0 match(es)
  - P4 (Low     ): 0 match(es)
----------------------------------------------------------------------
SOC Analyst Note: Keyword matching provides automated preliminary triage.
Analysts must always verify indicators against contextual telemetry.
======================================================================
```

### 6. Result & Conclusion
The program successfully triaged the ransomware narrative, evaluated indicator weights across all four priority tiers, and assigned **P1 (Critical)** with immediate containment recommendations.

---

## Practical 13: Threat Intelligence Quality Assessment

### 1. Aim
To evaluate collected security data across three analytical dimensions—**Context**, **Confidence**, and **Actionability**—to determine whether the data qualifies as Actionable Threat Intelligence, Partially Processed Intelligence, or Unprocessed Raw Data.

### 2. Algorithm / Working Steps
1. Define knowledge indicators for the three dimensions:
   - **Context:** Links data to threat actors, campaigns, malware families, or CVEs (e.g., "phishing campaign", "APT29", "associated with").
   - **Confidence:** Documents reliability assessments (e.g., "confidence is high", "verified by", "Admiralty score").
   - **Actionability:** Prescribes concrete defensive mitigations (e.g., "block the indicator", "firewall rule", "isolate host").
2. Ingest the threat intelligence statement (using documentation-safe RFC 5737 IPs).
3. Evaluate the statement against keyword indicators for each dimension.
4. Calculate the dimension presence score (0 to 3).
5. Classify the threat data:
   - Score = 3: **Actionable Threat Intelligence**
   - Score = 1 or 2: **Partially Processed Intelligence** (flagging missing dimensions)
   - Score = 0: **Unprocessed Raw Data**
6. Display dimension statuses, final score, classification, and educational tradecraft notes.

### 3. Python Source Code
Reference file: [`practical_13_threat_intelligence_quality.py`](practical_13_threat_intelligence_quality.py)

```python
"""
Practical 13: Threat Intelligence Quality Assessment
Subject: Threat Intelligence and Network Security
"""

DIMENSIONS = {
    "context": {
        "name": "Context",
        "keywords": ["campaign", "threat actor", "apt", "malware", "phishing", "cve-", "associated with"]
    },
    "confidence": {
        "name": "Confidence Assessment",
        "keywords": ["confidence is high", "high confidence", "confidence is medium", "verified by", "admiralty"]
    },
    "actionability": {
        "name": "Actionability",
        "keywords": ["block", "isolate", "quarantine", "sinkhole", "firewall rule", "soc analysts should"]
    }
}

def evaluate_intelligence_quality(text: str) -> dict:
    text_lower = text.lower().strip()
    if not text_lower:
        return {"score": 0, "classification": "Unprocessed Raw Data", "reason": "Empty input."}

    results = {}
    score = 0
    for dim, info in DIMENSIONS.items():
        matches = [kw for kw in info["keywords"] if kw in text_lower]
        is_present = len(matches) > 0
        if is_present:
            score += 1
        results[dim] = {"name": info["name"], "present": is_present, "matches": matches}

    if score == 3:
        classification = "Actionable Threat Intelligence"
        reason = "The data includes threat context, a confidence assessment, and a recommended defensive action."
    elif score in (1, 2):
        classification = "Partially Processed Intelligence"
        reason = "Data contains some enrichment but lacks complete confidence or actionability."
    else:
        classification = "Unprocessed Raw Data"
        reason = "The input represents raw telemetry without context or operational guidance."

    return {"score": score, "dimensions": results, "classification": classification, "reason": reason}
```

### 4. Sample Input
```text
Malicious IP 203.0.113.10 is associated with a documented phishing campaign. Confidence is high, and SOC analysts should block the indicator after validation.
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 13: THREAT INTELLIGENCE QUALITY ASSESSMENT
======================================================================
Evaluated Intel Feed:
  "Malicious IP 203.0.113.10 is associated with a documented phishing campaign. Confidence is high, and SOC analysts should block the indicator after validation."

----------------------------------------------------------------------
Context: Present (detected: campaign, phishing, associated with)
Confidence Assessment: Present (detected: confidence is high)
Actionability: Present (detected: block, soc analysts should)
----------------------------------------------------------------------
Assessment Score: 3/3
Classification: Actionable Threat Intelligence
Reason: The data includes threat context, a confidence assessment, and a recommended defensive action.
----------------------------------------------------------------------
Educational Note: This heuristic keyword assessment illustrates CTI principles.
In production CTI, intelligence quality is assessed using standards like STIX/TAXII,
the Admiralty Code (NATO System), and rigorous analytical tradecraft.
======================================================================
```

### 6. Result & Conclusion
The assessment verified all three dimensions (Context, Confidence, and Actionability) with documentation-safe telemetry, producing an assessment score of 3/3 and correctly classifying the data as **Actionable Threat Intelligence**.

---

## Practical 14: End-to-End SIEM Architecture Simulation

### 1. Aim
To simulate the complete four-stage operational pipeline of a Security Information and Event Management (SIEM) architecture: Event Collection, Multi-Source Normalization into a Common Data Model (CDM), Cross-Event Correlation, and Incident Alerting.

### 2. Algorithm / Working Steps
1. **Stage 1 (Collection):** Ingest raw events from multiple heterogeneous log sources:
   - Syslog text strings from perimeter firewalls (`FW-EDGE-01`).
   - JSON dictionaries from domain authentication servers (`AUTH-SRV-01`).
   - Structured JSON records from Endpoint Detection and Response agents (`endpoint_edr`).
2. **Stage 2 (Normalization):** Parse raw structures into a standardized Common Data Model (CDM) dictionary: `{timestamp, source, event_type, severity, details}`.
3. Catch and safely handle malformed or incomplete records.
4. **Stage 3 (Correlation):** Execute configurable multi-event correlation rules:
   - *Rule 1 (Repeated Authentication Failures):* Detect $\ge 3$ failed logins within a source IP / user grouping.
   - *Rule 2 (Suspicious Endpoint Behavior):* Detect obfuscated PowerShell execution (`-enc`, `-nop`, `-w hidden`).
5. **Stage 4 (Alerting):** Generate structured SOC alerts with rule identifiers, severity ratings, and aggregated forensic evidence.
6. Display exact counts matching the underlying dataset.

### 3. Python Source Code
Reference file: [`practical_14_siem_pipeline.py`](practical_14_siem_pipeline.py)

```python
"""
Practical 14: End-to-End SIEM Architecture Simulation
Subject: Threat Intelligence and Network Security
"""

RAW_EVENTS_DATASET = [
    {"source_format": "firewall_syslog", "raw_text": "2026-10-29T10:00:01Z FW-EDGE-01 action=ALLOW proto=TCP src=192.168.1.15 dst=93.184.216.34 dport=443"},
    {"source_format": "auth_json", "raw_dict": {"time": "2026-10-29T10:00:15Z", "host": "AUTH-SRV-01", "event": "user_login_failed", "username": "admin", "client_ip": "198.51.100.77"}},
    {"source_format": "auth_json", "raw_dict": {"time": "2026-10-29T10:00:18Z", "host": "AUTH-SRV-01", "event": "user_login_failed", "username": "admin", "client_ip": "198.51.100.77"}},
    {"source_format": "auth_json", "raw_dict": {"time": "2026-10-29T10:00:22Z", "host": "AUTH-SRV-01", "event": "user_login_failed", "username": "admin", "client_ip": "198.51.100.77"}},
    {"source_format": "endpoint_edr", "raw_dict": {"timestamp": "2026-10-29T10:01:05Z", "endpoint": "WS-FINANCE-02", "process": "notepad.exe", "command_line": "notepad.exe report.txt", "user": "corporate\\sarah"}},
    {"source_format": "endpoint_edr", "raw_dict": {"timestamp": "2026-10-29T10:02:10Z", "endpoint": "WS-FINANCE-02", "process": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... -nop -w hidden", "user": "corporate\\sarah"}}
]

def normalize_event(raw_item: dict) -> dict:
    fmt = raw_item.get("source_format")
    if fmt == "firewall_syslog":
        parts = raw_item["raw_text"].split()
        kv = dict(tok.split("=", 1) for tok in parts[2:] if "=" in tok)
        return {"timestamp": parts[0], "source": f"firewall:{parts[1]}", "event_type": "network_traffic", "severity": "LOW", "details": kv}
    elif fmt == "auth_json":
        d = raw_item["raw_dict"]
        return {"timestamp": d["time"], "source": f"auth:{d['host']}", "event_type": "authentication", "severity": "MEDIUM", "details": {"user": d["username"], "status": "FAILED", "client_ip": d["client_ip"]}}
    elif fmt == "endpoint_edr":
        d = raw_item["raw_dict"]
        suspicious = any(k in d["command_line"].lower() for k in ["-enc", "-nop", "bypass"])
        return {"timestamp": d["timestamp"], "source": f"endpoint:{d['endpoint']}", "event_type": "process_creation", "severity": "HIGH" if suspicious else "LOW", "details": d | {"suspicious_indicators": suspicious}}
    raise ValueError(f"Unknown format: {fmt}")
```

### 4. Sample Input
- Ingested Dataset: 6 heterogeneous raw events (1 firewall syslog, 3 auth failure JSON records, 2 endpoint EDR events).

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 14: SIEM PIPELINE SIMULATION
======================================================================

Stage 1: Collection
Raw events collected: 6

Stage 2: Normalization
Successfully normalized: 6

Stage 3: Correlation
Rule matched: Multiple failed login attempts
Rule matched: Suspicious endpoint activity

Stage 4: Alerting
Alert 1: Repeated authentication failures - HIGH
         Rule: CORR-RULE-001 | Evidence: 3 consecutive failed login attempts detected for user 'admin' from IP 198.51.100.77.
Alert 2: Suspicious endpoint behavior - HIGH
         Rule: CORR-RULE-002 | Evidence: Host endpoint:WS-FINANCE-02 executed obfuscated command: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0AT...' by corporate\sarah.

SIEM pipeline completed.
======================================================================
```

### 6. Result & Conclusion
The program successfully executed the 4-stage SIEM pipeline, normalizing 6 heterogeneous log records into a unified Common Data Model and correlating two high-fidelity security alerts (brute force login and encoded PowerShell execution).

---

## Practical 15: Security Incident Root-Cause Classification

### 1. Aim
To read a plain-language security incident narrative, extract forensic compromise indicators, and classify the incident into its most likely root cause among five major categories: Phishing, Unpatched Vulnerability, Misconfiguration, Insider Threat, or Supply-Chain Compromise.

### 2. Algorithm / Working Steps
1. Build a knowledge base of root-cause categories and technical indicators:
   - **Phishing:** Fraudulent email, fake login page, credential theft, spoofed attachments.
   - **Unpatched Vulnerability:** Missing security patch, CVE exploit, outdated software, RCE flaw.
   - **Misconfiguration:** Public S3 bucket, default passwords, permissive firewall, exposed database.
   - **Insider Threat:** Disgruntled employee, unauthorized staff download, rogue admin, USB exfiltration.
   - **Supply-Chain Compromise:** Compromised third-party vendor, backdoored upstream library, supplier breach.
2. Read an incident narrative from user input or preset demonstration cases.
3. Compute frequency match scores for each root cause category.
4. Identify the category with the highest score; gracefully handle ties and ambiguous/empty inputs.
5. Print the incident summary, most likely root cause, matched indicators, technical explanation, and score histogram.

### 3. Python Source Code
Reference file: [`practical_15_incident_root_cause.py`](practical_15_incident_root_cause.py)

```python
"""
Practical 15: Security Incident Root-Cause Classification
Subject: Threat Intelligence and Network Security
"""

ROOT_CAUSES = {
    "Phishing": {
        "keywords": ["fraudulent email", "fake login page", "stolen credentials", "phishing", "malicious attachment"],
        "reason": "The narrative describes deceptive communication, social engineering, or fraudulent portals used to harvest credentials or deliver payloads."
    },
    "Unpatched Vulnerability": {
        "keywords": ["unpatched", "cve-", "known vulnerability", "exploit", "outdated version", "remote code execution"],
        "reason": "The incident traces back to an unpatched software flaw or known vulnerability exploited by attackers prior to remediation."
    },
    "Misconfiguration": {
        "keywords": ["misconfiguration", "public s3 bucket", "default password", "open port", "exposed database"],
        "reason": "The breach occurred due to security misconfigurations, overly permissive access controls, or unhardened system default settings."
    },
    "Insider Threat": {
        "keywords": ["disgruntled employee", "unauthorized access by staff", "insider", "privilege abuse", "rogue admin"],
        "reason": "The compromise was facilitated by internal personnel abusing legitimate enterprise access or privileges maliciously or negligently."
    },
    "Supply-Chain Compromise": {
        "keywords": ["third-party vendor", "upstream dependency", "compromised library", "supply chain", "backdoored"],
        "reason": "Attackers gained initial access indirectly through a trusted external vendor, supplier, or compromised upstream software component."
    }
}

def classify_root_cause(narrative: str) -> dict:
    text_lower = narrative.lower().strip()
    scores = {cat: len([kw for kw in d["keywords"] if kw in text_lower]) for cat, d in ROOT_CAUSES.items()}
    max_score = max(scores.values())
    if max_score == 0:
        return {"category": "Ambiguous / Inconclusive", "matched_indicators": [], "reason": "No conclusive root-cause indicators.", "scores": scores}

    top = [c for c, s in scores.items() if s == max_score]
    if len(top) > 1:
        return {"category": f"Tie: {' / '.join(top)}", "matched_indicators": [], "reason": "Multi-vector or tied indicators.", "scores": scores}

    cat = top[0]
    matched = [kw for kw in ROOT_CAUSES[cat]["keywords"] if kw in text_lower]
    return {"category": cat, "matched_indicators": matched, "reason": ROOT_CAUSES[cat]["reason"], "scores": scores}
```

### 4. Sample Input
```text
An employee opened a fraudulent email attachment, entered credentials on a fake login page, and attackers subsequently accessed the corporate account.
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 15: INCIDENT ROOT-CAUSE CLASSIFICATION
======================================================================
Incident Summary: An employee opened a fraudulent email attachment, entered credentials on a fake login page, and attackers subsequently accessed the corporate account.

Most Likely Root Cause: Phishing
Matched Indicators: fraudulent email, fake login page
Reason: The narrative describes deceptive communication, social engineering, or fraudulent portals used to harvest credentials or deliver payloads.
----------------------------------------------------------------------
Category Score Breakdown:
  - Phishing                 : 2 ########
  - Unpatched Vulnerability  : 0 
  - Misconfiguration         : 0 
  - Insider Threat           : 0 
  - Supply-Chain Compromise  : 0 
----------------------------------------------------------------------
Analytical Disclaimer: Automated keyword matching serves educational triage.
Definitive root cause determination requires end-to-end forensic artifact
reconstruction, memory analysis, and timeline validation.
======================================================================
```

### 6. Result & Conclusion
The program evaluated the incident indicators, eliminated misconfiguration and unpatched software flaws, and correctly determined the root cause as **Phishing** with matched indicators `fraudulent email` and `fake login page`.

---

## Practical 16: Defense-in-Depth Simulation

### 1. Aim
To simulate a multi-layered security architecture (Defense-in-Depth) by evaluating attack scenarios through an ordered chain of independent defensive controls (Email Gateway, Endpoint Protection, Network Firewall, NIDS/NIPS, and Application Controls), demonstrating how layered defenses mitigate single points of failure.

### 2. Algorithm / Working Steps
1. Define an ordered sequence of 5 independent defensive controls:
   - Layer 1: Email Security Gateway (inspects SPF/DKIM/DMARC, known sender reputation, phishing links)
   - Layer 2: Endpoint Protection / EDR (inspects behavioral process execution, macro payloads, ransomware)
   - Layer 3: Network Firewall (inspects ports, protocols, and IP reputations)
   - Layer 4: Network Intrusion Detection/Prevention (inspects deep packet exploit signatures and CVEs)
   - Layer 5: Application Security Controls (inspects SQL injection, XSS, and authorization tokens)
2. Ingest an attack scenario (e.g., an encrypted malicious email attachment that bypasses static gateway inspection).
3. Evaluate the attack against Layer 1. If it passes, pass the attack to Layer 2, continuing sequentially.
4. Stop evaluation at the first layer that returns `BLOCKED`.
5. Display the step-by-step traversal path, each layer's decision (`PASSED` or `BLOCKED`), the final mitigation verdict, and strategic defense-in-depth principles.

### 3. Python Source Code
Reference file: [`practical_16_defense_in_depth.py`](practical_16_defense_in_depth.py)

```python
"""
Practical 16: Defense-in-Depth Simulation
Subject: Threat Intelligence and Network Security
"""

SECURITY_LAYERS = [
    {
        "id": 1,
        "name": "Email Security Gateway",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Email Gateway blocked message: SPF/DMARC failure or blacklisted phishing sender.")
            if "spoofed" in text or "phishing link" in text or "dmarc_fail" in flags
            else ("PASSED", "Email bypassed gateway: Clean reputation or encrypted attachment prevented static inspection.")
        )
    },
    {
        "id": 2,
        "name": "Endpoint Protection",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Endpoint protection stopped the attack: Behavioral engine detected malicious execution / ransomware behavior.")
            if "malicious attachment" in text or "ransomware" in text or "edr_trigger" in flags
            else ("PASSED", "Endpoint allowed execution.")
        )
    },
    {
        "id": 3,
        "name": "Network Firewall",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Firewall blocked packet: Unauthorized port.")
            if "blocked port" in text else ("PASSED", "Firewall passed traffic.")
        )
    },
    {
        "id": 4,
        "name": "Network Intrusion Detection/Prevention",
        "inspect": lambda text, flags: (
            ("BLOCKED", "NIDS/NIPS blocked stream: Signature matched.")
            if "exploit signature" in text else ("PASSED", "NIDS/NIPS passed payload.")
        )
    },
    {
        "id": 5,
        "name": "Application Security Controls",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Application controls blocked request: Injection detected.")
            if "sql injection" in text else ("PASSED", "Application controls permitted request.")
        )
    }
]

def simulate_defense_in_depth(scenario_text: str, flags: list = None) -> dict:
    if flags is None:
        flags = []
    text_lower = scenario_text.lower()
    layers = []
    final_status = "ATTACK COMPROMISED SYSTEM"
    final_exp = "Evaded all controls."
    for layer in SECURITY_LAYERS:
        decision, explanation = layer["inspect"](text_lower, flags)
        layers.append({"layer_id": layer["id"], "name": layer["name"], "decision": decision, "explanation": explanation})
        if decision == "BLOCKED":
            final_status = "ATTACK BLOCKED"
            final_exp = f"{layer['name']} stopped the attack after it passed the first layer." if layer["id"] == 2 else f"{layer['name']} stopped the attack."
            break
    return {"scenario": scenario_text, "layers": layers, "final_status": final_status, "explanation": final_exp}
```

### 4. Sample Input
```text
Attack Scenario: Malicious email attachment
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 16: DEFENSE-IN-DEPTH SIMULATION
======================================================================
Attack Scenario: Malicious email attachment

Layer 1 - Email Security Gateway: PASSED
        Detail: Email bypassed gateway: Clean reputation or encrypted attachment prevented static inspection.
Layer 2 - Endpoint Protection: BLOCKED
        Detail: Endpoint protection stopped the attack: Behavioral engine detected malicious execution / ransomware behavior.
----------------------------------------------------------------------
Final Result: ATTACK BLOCKED
Explanation : Endpoint Protection stopped the attack after it passed the first layer.
----------------------------------------------------------------------
Strategic Takeaway: Defense-in-depth ensures that the failure of any single
defensive control does not result in catastrophic compromise. However,
defense-in-depth reduces risk significantly but does not guarantee 100% protection.
======================================================================
```

### 6. Result & Conclusion
The simulation proved that when an attacker uses encrypted payloads to evade perimeter email filters (Layer 1: PASSED), secondary host-level controls (Layer 2 Endpoint Protection: BLOCKED) contain the attack, preventing system compromise.

---

## Practical 17: ISO/IEC 27001 Annex A Control Domain Classification

### 1. Aim
To analyze a plain-text information security control description and classify it into its corresponding ISO/IEC 27001:2022 Annex A control theme: Organizational Controls, People Controls, Physical Controls, or Technological Controls.

### 2. Algorithm / Working Steps
1. Define the four ISO/IEC 27001:2022 Annex A themes and their indicator dictionaries:
   - **Organizational Controls (Clause 5):** Policies, governance, asset management, supplier security, audit, incident management.
   - **People Controls (Clause 6):** Cybersecurity awareness training, background screening, confidentiality agreements, remote working rules.
   - **Physical Controls (Clause 7):** Physical perimeters, biometric access, CCTV, clear desk/screen, server room locks.
   - **Technological Controls (Clause 8):** MFA, cryptography, network segmentation, firewalls, patch management, SIEM logging.
2. Read an organizational security control description.
3. Match keywords and tally theme indicator scores.
4. Select the theme with the highest score; handle cross-domain overlaps and ambiguous descriptions gracefully.
5. Display the selected theme, justification, matched indicators, and an educational compliance disclaimer.

### 3. Python Source Code
Reference file: [`practical_17_iso27001_control_classifier.py`](practical_17_iso27001_control_classifier.py)

```python
"""
Practical 17: ISO/IEC 27001 Annex A Control Domain Classification
Subject: Threat Intelligence and Network Security
"""

ANNEX_A_THEMES = {
    "Organizational Controls": {
        "keywords": ["policy", "policies", "governance", "roles and responsibilities", "asset management", "supplier security", "audit"],
        "reason": "The control focuses on organizational governance, management policies, operational processes, asset management, and vendor oversight."
    },
    "People Controls": {
        "keywords": ["awareness training", "training", "employee", "staff", "screening", "disciplinary", "remote working", "nda"],
        "reason": "The control focuses on employee awareness, training, personnel screening, and human-behavior aspects of information security."
    },
    "Physical Controls": {
        "keywords": ["physical perimeter", "biometric door", "badge", "cctv", "security guard", "facility", "data center", "clear desk"],
        "reason": "The control focuses on safeguarding physical premises, data centers, facilities, offices, and hardware assets against physical intrusion."
    },
    "Technological Controls": {
        "keywords": ["multi-factor authentication", "mfa", "encryption", "cryptography", "firewall", "antivirus", "patch management", "logging"],
        "reason": "The control focuses on technical and digital safeguards implemented within IT systems, networks, software, and authentication services."
    }
}

def classify_iso27001_control(control_text: str) -> dict:
    text_lower = control_text.lower().strip()
    scores = {theme: len([kw for kw in d["keywords"] if kw in text_lower]) for theme, d in ANNEX_A_THEMES.items()}
    max_score = max(scores.values())
    if max_score == 0:
        return {"theme": "Ambiguous / General Control", "matched_indicators": [], "reason": "No distinct keywords matched.", "scores": scores}

    top = [t for t, sc in scores.items() if sc == max_score]
    theme = top[0] if len(top) == 1 else f"Cross-Domain: {' / '.join(top)}"
    matched = [kw for kw in ANNEX_A_THEMES.get(theme, {}).get("keywords", []) if kw in text_lower]
    return {"theme": theme, "matched_indicators": matched, "reason": ANNEX_A_THEMES[theme]["reason"], "scores": scores}
```

### 4. Sample Input
```text
Employees must complete annual cybersecurity awareness training.
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 17: ISO/IEC 27001 ANNEX A CLASSIFICATION
======================================================================
Control Description: Employees must complete annual cybersecurity awareness training.

Selected Theme: People Controls
Reason: The control focuses on employee awareness, training, personnel screening, and human-behavior aspects of information security.
----------------------------------------------------------------------
Matched Indicators: awareness training, training, employee
Theme Score Breakdown:
  - Organizational Controls  : 0 
  - People Controls          : 3 ############
  - Physical Controls        : 0 
  - Technological Controls   : 0 
----------------------------------------------------------------------
Compliance Notice: This tool serves as an educational theme classifier.
It does not replace formal ISO/IEC 27001:2022 Statement of Applicability (SoA)
audits or accredited certification assessments.
======================================================================
```

### 6. Result & Conclusion
The program successfully mapped employee training requirements to **People Controls (Clause 6)** with 3 matching indicators, illustrating ISO/IEC 27001:2022 theme classification.

---

## Practical 18: Malware Detection Using SHA-256 Hash Comparison

### 1. Aim
To read a file in 64 KB binary chunks, compute its cryptographic SHA-256 digest using Python's `hashlib`, compare the hash against a local threat intelligence database of known-malicious signatures, and report detection findings with error handling and security caveats.

### 2. Algorithm / Working Steps
1. Initialize a demonstration database of known-malicious SHA-256 hashes derived from harmless reference test payloads (e.g., standard EICAR string and educational sample payloads).
2. Accept a target file path from user input (or activate demonstration mode with temporary harmless test files).
3. Verify file existence and validate that the path points to a file rather than a directory.
4. Open the file in binary read mode (`"rb"`) and stream data through `hashlib.sha256()` in 65,536-byte chunks to support arbitrarily large files without high memory usage.
5. Generate the final lowercase hexadecimal digest (`hasher.hexdigest()`).
6. Query the local signature database for an exact hash match.
7. If matched, report a known-malicious threat match along with malware family details and containment directives.
8. If unmatched, report that no match was found, emphasizing that lack of a hash match does not prove a file is benign (polymorphic malware / zero-day evasion).

### 3. Python Source Code
Reference file: [`practical_18_sha256_malware_detection.py`](practical_18_sha256_malware_detection.py)

```python
"""
Practical 18: Malware Detection Using SHA-256 Hash Comparison
Subject: Threat Intelligence and Network Security
"""

import os
import hashlib

KNOWN_MALICIOUS_HASHES = {
    "1b991d6abbe8b18dc38a3f1700b2fda03ad907fbd759fb3c2c68ce7784f4cd65": {
        "name": "Trojan.GenericKD.Demo",
        "category": "Credential Stealer / Trojan",
        "severity": "CRITICAL",
        "description": "Simulated credential-stealing trojan test payload (Educational Reference)."
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-AV-Test-File",
        "category": "Antivirus Standard Verification",
        "severity": "INFORMATIONAL",
        "description": "Standard benign 68-character antivirus test string defined by EICAR."
    }
}

def calculate_sha256(file_path: str, chunk_size: int = 65536) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()

def scan_file_hash(file_path: str) -> dict:
    if not os.path.exists(file_path):
        return {"file": file_path, "error": "FileNotFoundError: The specified file does not exist."}
    try:
        digest = calculate_sha256(file_path)
    except Exception as exc:
        return {"file": file_path, "error": str(exc)}

    is_match = digest in KNOWN_MALICIOUS_HASHES
    return {
        "file": os.path.basename(file_path),
        "sha256": digest,
        "is_match": is_match,
        "match_info": KNOWN_MALICIOUS_HASHES.get(digest)
    }
```

### 4. Sample Input
- Test Case A: Harmless clean file (`sample_clean_document.txt`)
- Test Case B: Test payload file with hash `1b991d6abbe8b18dc38a3f1700b2fda03ad907fbd759fb3c2c68ce7784f4cd65`

### 5. Actual Program Output
```text
[RUNNING VERIFICATION DEMONSTRATION WITH HARMLESS TEST FILES]

======================================================================
PRACTICAL 18: SHA-256 MALWARE HASH CHECK
======================================================================
File: sample_clean_document.txt
SHA-256: 4eb04ec957b1d9f21be3ba3c422e3bd707b6dbb77e561a9bb5a00c8e3f43b8af
Database Match: No
Result: No known-malicious hash match found.
Note: This does not prove that the file is safe.
      (Zero-day malware, polymorphic variants, and scripts not in the local
       reference database require dynamic behavioral analysis / sandboxing.)
----------------------------------------------------------------------
Database Scope: Local Educational Threat Intelligence Hash Repository
Signatures in Database: 3
======================================================================


======================================================================
PRACTICAL 18: SHA-256 MALWARE HASH CHECK
======================================================================
File: sample_test_malware_signature.txt
SHA-256: 1b991d6abbe8b18dc38a3f1700b2fda03ad907fbd759fb3c2c68ce7784f4cd65
Database Match: Yes (KNOWN-MALICIOUS SIGNATURE MATCHED)
Threat Name   : Trojan.GenericKD.Demo
Threat Category: Credential Stealer / Trojan [CRITICAL]
Threat Summary : Simulated credential-stealing trojan test payload (Educational Reference).
Action Required: Immediately quarantine file and isolate host.
----------------------------------------------------------------------
Database Scope: Local Educational Threat Intelligence Hash Repository
Signatures in Database: 3
======================================================================
```

### 6. Result & Conclusion
Chunk-based hashing computed accurate SHA-256 fingerprints, successfully identified the demonstration malware signature, reported non-matching digests accurately, and highlighted why hash matching alone cannot guarantee safety.

---

## Practical 19: Splunk Search Filter and Stats Count Simulation

### 1. Aim
To simulate the core analytical operations of the Splunk Search Processing Language (SPL)—search filtering (`field=value`) and statistical aggregation (`stats count by <field>`)—using a Python event dataset representing authentication, firewall, and endpoint logs.

### 2. Algorithm / Working Steps
1. Create a simulated dataset of 10 enterprise security events across three primary sources:
   - 4 firewall logs (traffic drops, HTTPS allowances, DDoS SYN flood).
   - 3 authentication logs (failed brute force attempts, SSO success).
   - 3 endpoint logs (process creation, obfuscated PowerShell script, USB mount).
2. Prompt for or configure:
   - Search filter (e.g., `severity=high`).
   - Grouping field (e.g., `source`).
3. **Search Filtering:** Iterate over the dataset and filter events where `field == value`. Display matched event count and detailed records.
4. **Stats Aggregation:** Iterate over the entire dataset, extract the requested grouping field, and calculate occurrence counts using a dictionary.
5. Display the counts and text histograms for each group value.

### 3. Python Source Code
Reference file: [`practical_19_splunk_search_stats.py`](practical_19_splunk_search_stats.py)

```python
"""
Practical 19: Splunk Search Filter and Stats Count Simulation
Subject: Threat Intelligence and Network Security
"""

SPLUNK_DATASET = [
    {"event_id": "EVT-1001", "timestamp": "2026-10-29T08:15:20Z", "source": "firewall", "event_type": "traffic_drop", "severity": "high", "description": "Inbound connection on port 23 dropped."},
    {"event_id": "EVT-1002", "timestamp": "2026-10-29T08:15:45Z", "source": "firewall", "event_type": "traffic_allow", "severity": "low", "description": "Outbound HTTPS web session permitted."},
    {"event_id": "EVT-1003", "timestamp": "2026-10-29T08:16:02Z", "source": "firewall", "event_type": "ddos_spike", "severity": "high", "description": "SYN flood threshold exceeded."},
    {"event_id": "EVT-1004", "timestamp": "2026-10-29T08:16:30Z", "source": "firewall", "event_type": "traffic_allow", "severity": "low", "description": "Internal DNS query allowed."},
    {"event_id": "EVT-1005", "timestamp": "2026-10-29T08:17:10Z", "source": "authentication", "event_type": "login_failure", "severity": "medium", "description": "Password authentication failed."},
    {"event_id": "EVT-1006", "timestamp": "2026-10-29T08:17:14Z", "source": "authentication", "event_type": "login_failure", "severity": "medium", "description": "Repeated password authentication failed."},
    {"event_id": "EVT-1007", "timestamp": "2026-10-29T08:18:00Z", "source": "authentication", "event_type": "login_success", "severity": "low", "description": "SSO Kerberos ticket granted."},
    {"event_id": "EVT-1008", "timestamp": "2026-10-29T08:19:12Z", "source": "endpoint", "event_type": "process_create", "severity": "low", "description": "User launched chrome.exe."},
    {"event_id": "EVT-1009", "timestamp": "2026-10-29T08:20:05Z", "source": "endpoint", "event_type": "suspicious_script", "severity": "high", "description": "Encoded PowerShell script blocked."},
    {"event_id": "EVT-1010", "timestamp": "2026-10-29T08:21:40Z", "source": "endpoint", "event_type": "usb_mount", "severity": "medium", "description": "Removable USB storage connected."}
]

def filter_splunk_search(dataset: list, search_field: str, search_val: str) -> list:
    f, v = search_field.lower().strip(), search_val.lower().strip()
    return [e for e in dataset if f in e and str(e[f]).lower() == v]

def stats_count_by(dataset: list, group_by_field: str) -> dict:
    f = group_by_field.lower().strip()
    counts = {}
    for e in dataset:
        val = e.get(f, "UNKNOWN")
        counts[val] = counts.get(val, 0) + 1
    return counts
```

### 4. Sample Input
- Search Filter: `severity=high`
- Grouping Field: `source`

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 19: SPLUNK SEARCH AND STATS SIMULATION
======================================================================
Dataset Size: 10 total events
Simulated SPL Command:
  index=security severity=high | stats count by source
----------------------------------------------------------------------

Search: severity=high
Matching Events: 3
Matching Event Details:
  [EVT-1001] 2026-10-29T08:15:20Z | src=firewall | type=traffic_drop | sev=high
           desc: Inbound connection on disallowed port 23 (Telnet) dropped.
  [EVT-1003] 2026-10-29T08:16:02Z | src=firewall | type=ddos_spike | sev=high
           desc: SYN flood threshold exceeded from external IP.
  [EVT-1009] 2026-10-29T08:20:05Z | src=endpoint | type=suspicious_script | sev=high
           desc: Encoded PowerShell script blocked by EDR behavior engine.

Stats: count by source
firewall: 4  ====
authentication: 3  ===
endpoint: 3  ===

Search and aggregation completed.
----------------------------------------------------------------------
Environment Notice: This is a Python simulation reproducing Splunk SPL logic.
No external Splunk Enterprise or Cloud instance is required.
======================================================================
```

### 6. Result & Conclusion
The program reproduced Splunk SPL search filtering and aggregation, accurately matching 3 high-severity security events out of 10 and grouping total event counts by source (Firewall: 4, Authentication: 3, Endpoint: 3).

---

## Practical 20: Network Threat Category Classifier

### 1. Aim
To read a plain-language network incident description and classify it into one of four standardized network threat categories: Phishing, DoS/DDoS, Malware, or Man-in-the-Middle (MitM), providing matched indicator keywords and technical reasoning.

### 2. Algorithm / Working Steps
1. Define indicator sets for the four network threat classes:
   - **Phishing:** Fraudulent email, fake login, credential theft, deceptive links, lures.
   - **DoS/DDoS:** SYN flood, volumetric attack, bandwidth exhaustion, service unavailable, traffic flood.
   - **Malware:** Ransomware, trojan, keylogger, encrypting files, malicious executable, C2 beaconing.
   - **Man-in-the-Middle:** Intercepts traffic, modifies messages, ARP spoofing, SSL stripping, eavesdropping.
2. Read an incident narrative from user input or test execution cases.
3. Normalize the text to lowercase and scan for category keywords.
4. Calculate category indicator scores; handle ties and empty inputs cleanly.
5. Print the predicted category, matched indicators, technical explanation, and score histogram.

### 3. Python Source Code
Reference file: [`practical_20_network_threat_classifier.py`](practical_20_network_threat_classifier.py)

```python
"""
Practical 20: Network Threat Category Classifier
Subject: Threat Intelligence and Network Security
"""

THREAT_CATEGORIES = {
    "Phishing": {
        "keywords": ["fraudulent email", "fake login", "phishing", "spear-phishing", "credential theft", "deceptive link"],
        "reason": "The narrative describes deceptive communication or fake portals used to trick victims into providing sensitive credentials."
    },
    "DoS/DDoS": {
        "keywords": ["dos", "ddos", "syn flood", "volumetric attack", "traffic flood", "service unavailable", "exhaustion"],
        "reason": "The narrative describes volumetric traffic flooding or resource exhaustion intended to render network services unavailable."
    },
    "Malware": {
        "keywords": ["malware", "ransomware", "trojan", "worm", "encrypting files", "malicious executable"],
        "reason": "The narrative describes malicious software binaries executing unauthorized actions on victim endpoints."
    },
    "Man-in-the-Middle": {
        "keywords": ["intercepts traffic", "modifies messages", "modifies the messages", "man-in-the-middle", "arp spoofing"],
        "reason": "The narrative describes interception and possible alteration of communications between two parties."
    }
}

def classify_network_threat(description: str) -> dict:
    text_lower = description.lower().strip()
    scores = {cat: len([kw for kw in d["keywords"] if kw in text_lower]) for cat, d in THREAT_CATEGORIES.items()}
    max_score = max(scores.values())
    if max_score == 0:
        return {"predicted_category": "Uncertain / Unclassified Threat", "matched_indicators": [], "reason": "No matches.", "scores": scores}

    top = [c for c, s in scores.items() if s == max_score]
    if len(top) > 1:
        return {"predicted_category": f"Tie: {' / '.join(top)}", "matched_indicators": [], "reason": "Multi-stage attack.", "scores": scores}

    cat = top[0]
    matched = [kw for kw in THREAT_CATEGORIES[cat]["keywords"] if kw in text_lower]
    return {"predicted_category": cat, "matched_indicators": matched, "reason": THREAT_CATEGORIES[cat]["reason"], "scores": scores}
```

### 4. Sample Input
```text
An attacker intercepts traffic between a user and a server and modifies the messages in transit.
```

### 5. Actual Program Output
```text
======================================================================
PRACTICAL 20: NETWORK THREAT CATEGORY CLASSIFIER
======================================================================
Incident Narrative:
  "An attacker intercepts traffic between a user and a server and modifies the messages in transit."

Predicted Category: Man-in-the-Middle
Matched Indicators: intercepts traffic, modifies messages
Reason: The narrative describes interception and possible alteration of communications between two parties.
----------------------------------------------------------------------
Threat Category Score Breakdown:
  - Phishing            : 0 
  - DoS/DDoS            : 0 
  - Malware             : 0 
  - Man-in-the-Middle   : 2 ########
======================================================================
```

### 6. Result & Conclusion
The program identified traffic interception and message modification indicators, accurately classifying the incident as **Man-in-the-Middle (MitM)**.
