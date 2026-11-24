# Threat Intelligence and Network Security Practicals

This repository contains executable Python implementations for undergraduate cybersecurity lab practicals covering **Threat Intelligence and Network Security**.

All programs are written in beginner-friendly Python 3.10, featuring structured comments, sample inputs, meaningful console outputs, error handling, and cybersecurity guardrails.

---

## Repository Contents

### Practical 01–10 (Part 1)
Documented in detail in [`CYBERSECURITY_PYTHON_PRACTICALS.md`](CYBERSECURITY_PYTHON_PRACTICALS.md):
- `practical_01_threat_intelligence_classifier.py` — Threat Intelligence Domain Classifier
- `practical_02_port_scanner.py` — TCP Port Scanner with Lab Safety Guardrails
- `practical_03_security_policy_checker.py` — Information Security Policy Governance Checker
- `practical_04_vpn_confidentiality_demo.py` — VPN Confidentiality & Symmetric Stream Cipher Demo
- `practical_05_intelligence_report_classifier.py` — Threat Intelligence Report Classifier (Strategic/Tactical/Operational)
- `practical_06_phishing_url_detector.py` — Heuristic Phishing URL Risk Detector
- `practical_07_elk_stack_simulator.py` — ELK Stack Architecture Simulator (Logstash, Elasticsearch, Kibana)
- `practical_08_network_segmentation.py` — Network Segmentation & Lateral Movement Prevention
- `practical_09_threat_intelligence_lifecycle.py` — Threat Intelligence Lifecycle Stage Classifier
- `practical_10_stateful_firewall.py` — Stateful Packet Inspection (SPI) Firewall Simulator

### Practical 11–20 (Part 2)
Documented in detail in [`CYBERSECURITY_PRACTICALS_11_20.md`](CYBERSECURITY_PRACTICALS_11_20.md):
- `practical_11_packet_sniffing_scapy.py` — Network Packet Sniffing Using Scapy & Fallback Engine
- `practical_12_soc_alert_priority.py` — SOC Alert Priority Classification (P1–P4 Triage)
- `practical_13_threat_intelligence_quality.py` — Threat Intelligence Quality Assessment (Context, Confidence, Actionability)
- `practical_14_siem_pipeline.py` — End-to-End SIEM Architecture Simulation (Collection, Normalization, Correlation, Alerting)
- `practical_15_incident_root_cause.py` — Security Incident Root-Cause Classification (5 IR Categories)
- `practical_16_defense_in_depth.py` — Defense-in-Depth Multi-Layer Attack Mitigation Simulation
- `practical_17_iso27001_control_classifier.py` — ISO/IEC 27001:2022 Annex A Control Theme Classification
- `practical_18_sha256_malware_detection.py` — Malware Detection Using Chunked SHA-256 Hash Comparison
- `practical_19_splunk_search_stats.py` — Splunk Search Filter & Stats Count by Field Simulation
- `practical_20_network_threat_classifier.py` — Network Threat Category Classifier (Phishing, DoS/DDoS, Malware, MitM)

### Practical 21–40 (Part 3)
- `practical_21_post_incident_improvement_tags.py` (`EXP21.py`) — Post-Incident Report Improvement Tags (5 Focus Areas)
- `practical_22_brute_force_login_detector.py` (`EXP22.py`) — Authentication Brute-Force Login Detection
- `practical_23_ips_whitelist.py` (`EXP23.py`) — Signature-Based IPS with Whitelist Filtering & False-Positive Reduction
- `practical_24_security_baseline_compliance.py` (`EXP24.py`) — Security Baseline Configuration Audit & Compliance Checker
- `practical_25_chain_of_custody_verification.py` (`EXP25.py`) — Digital Forensics Chain of Custody & Hash Verification
- `practical_26_malware_analysis_simulation.py` (`EXP26.py`) — Malware Static (SHA-256, APIs) & Dynamic Behavioral Analysis
- `practical_27_context_aware_ids.py` (`EXP27.py`) — Context-Aware Signature-Based IDS (Protocol Context & Pattern Match)
- `practical_28_dos_detection_web_logs.py` (`EXP28.py`) — Denial-of-Service (DoS) Rate-Limit Flood Detection from Web Logs
- `practical_29_incident_containment_recommendation.py` (`EXP29.py`) — Incident Containment Strategy Decision Engine
- `practical_30_siem_cross_source_correlation.py` (`EXP30.py`) — Multi-Source SIEM Log Correlation (Firewall + VPN + Windows)
- `practical_31_firewall_rule_engine.py` (`EXP31.py`) — Packet-Filtering Firewall Rule Engine with Default-Deny
- `practical_32_cia_triad_violation_detector.py` (`EXP32.py`) — CIA Triad Security Property Violation Analyzer
- `practical_33_incident_response_lifecycle.py` (`EXP33.py`) — NIST SP 800-61 Incident Response Lifecycle Phase Classifier
- `practical_34_threat_hunting_styles.py` (`EXP34.py`) — Threat Hunting Methodologies (Hypothesis, Intel, Analytics)
- `practical_35_least_privilege_access_audit.py` (`EXP35.py`) — Principle of Least Privilege Access Audit & Permission Creep
- `practical_36_compliance_standard_classifier.py` (`EXP36.py`) — Regulatory Compliance Standard Classifier (PCI-DSS, HIPAA, GDPR, SOX)
- `practical_37_continuous_security_monitoring.py` (`EXP37.py`) — Continuous Security Monitoring & Baseline Anomaly Detection
- `practical_38_qualitative_risk_assessment.py` (`EXP38.py`) — Qualitative Threat Risk Assessment Engine (Likelihood x Impact)
- `practical_39_threat_intelligence_platform.py` (`EXP39.py`) — Threat Intelligence Platform (TIP) Pipeline Simulation
- `practical_40_security_tool_recommender.py` (`EXP40.py`) — Cybersecurity Tool Recommendation Engine

---

## Prerequisites and Execution

All programs run using Python standard libraries (except Practical 11 which utilizes `scapy` with an automatic demonstration fallback when packet drivers are not present).

```bash
# Clone the repository
git clone https://github.com/vara12126/Threat-intelligence-and-Network-security-9303.git
cd Threat-intelligence-and-Network-security-9303

# Run any practical directly
python practical_11_packet_sniffing_scapy.py --demo
python practical_12_soc_alert_priority.py
python practical_13_threat_intelligence_quality.py
python practical_14_siem_pipeline.py
python practical_15_incident_root_cause.py
python practical_16_defense_in_depth.py
python practical_17_iso27001_control_classifier.py
python practical_18_sha256_malware_detection.py
python practical_19_splunk_search_stats.py
python practical_20_network_threat_classifier.py
python practical_21_post_incident_improvement_tags.py
python practical_22_brute_force_login_detector.py
...
```

---

## Ethical and Safe Usage Notice
These programs are developed strictly for educational cybersecurity laboratory instruction. Packet capture, port scanning, and security assessment tools must only be executed on authorized networks and owned lab infrastructure.
