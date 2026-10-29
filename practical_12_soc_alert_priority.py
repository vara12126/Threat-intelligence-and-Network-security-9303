"""
Practical 12: SOC Alert Priority Classification
Subject: Threat Intelligence and Network Security

Aim:
    To analyze an incoming Security Operations Center (SOC) alert description,
    evaluate severity indicators using rule-based scoring, and assign a priority
    level from P1 (Critical) to P4 (Low) with actionable recommendations.

Description:
    Security Operations Centers (SOCs) receive hundreds or thousands of security alerts
    daily. Triage classification is essential to ensure critical incidents—such as
    ransomware outbreaks or active data breaches—are escalated immediately, while lower-priority
    informational notices are queued for routine review.
    
Priority Definitions:
    - P1 (Critical): Confirmed active compromise, ransomware execution, widespread
                     critical-system impact, or active data exfiltration.
    - P2 (High): Likely compromise, active exploitation, unauthorized administrative access,
                 or critical service degradation.
    - P3 (Medium): Suspicious activity requiring investigation (e.g., repeated login failures,
                   anomalous outbound beaconing) without confirmed severe impact.
    - P4 (Low): Informational events, routine policy violations, or low-risk scanner noise.
"""

import sys
import re

# Rule-based indicator dictionary with associated severity levels and weights
PRIORITY_RULES = {
    "P1": {
        "severity": "Critical",
        "keywords": [
            "ransomware", "encrypting files", "ransom note", "domain controller compromised",
            "active breach", "database exfiltration", "rootkit deployed", "widespread outage",
            "c2 established on prod", "mass encryption", "critical infrastructure down"
        ],
        "default_action": "Activate major incident response procedures (CSIRP), isolate affected endpoints immediately, and notify executive leadership.",
        "reason_template": "Indicators suggest an active, severe compromise or ransomware attack impacting mission-critical systems."
    },
    "P2": {
        "severity": "High",
        "keywords": [
            "active exploitation", "privilege escalation", "mimikatz", "pass-the-hash",
            "unauthorized admin login", "malware execution", "lateral movement",
            "credential dumping", "cve exploitation", "trojan detected", "data staging"
        ],
        "default_action": "Contain affected user accounts or hosts, collect forensic memory dumps, and initiate targeted threat containment.",
        "reason_template": "High likelihood of active exploitation or adversary presence requiring rapid containment within 1-2 hours."
    },
    "P3": {
        "severity": "Medium",
        "keywords": [
            "multiple failed logins", "brute force", "port scan detected", "unauthorized usb",
            "policy violation", "suspicious powershell", "unusual traffic spike",
            "outbound beaconing", "unknown external connection", "dns tunneling attempt"
        ],
        "default_action": "Assign to Tier-1/Tier-2 analyst for queue investigation, correlate host logs, and verify legitimate business context.",
        "reason_template": "Suspicious anomalous behavior detected requiring investigation, but without verified widespread harm."
    },
    "P4": {
        "severity": "Low",
        "keywords": [
            "informational", "scheduled scan", "routine backup", "user password changed",
            "software update installed", "low risk ping", "expired cert warning",
            "ad-hoc nmap test", "benign crawler", "test notification"
        ],
        "default_action": "Log for situational awareness; no immediate escalation required unless correlated with higher-tier alerts.",
        "reason_template": "Routine informational or low-risk event consistent with standard baseline operational noise."
    }
}


def classify_soc_alert(alert_text: str) -> dict:
    """
    Classifies a plain-text SOC alert into P1-P4 priority using keyword-based scoring,
    contextual rules, and provides recommended triage actions.
    """
    text_clean = alert_text.strip()
    if not text_clean:
        return {
            "priority": "P4",
            "severity": "Low",
            "reason": "Empty alert text provided. Defaulting to lowest priority queue for re-evaluation.",
            "action": "Request alert enrichment or discard as unformatted telemetry.",
            "matched_keywords": [],
            "scores": {k: 0 for k in PRIORITY_RULES}
        }

    text_lower = text_clean.lower()
    scores = {}
    matched = {}

    for p_level, data in PRIORITY_RULES.items():
        found = [kw for kw in data["keywords"] if kw in text_lower]
        scores[p_level] = len(found)
        matched[p_level] = found

    # Evaluate hierarchy: If P1 keywords are matched, P1 dominates.
    # Otherwise check P2, then P3, then P4.
    if scores["P1"] > 0:
        assigned = "P1"
    elif scores["P2"] > 0:
        assigned = "P2"
    elif scores["P3"] > 0:
        assigned = "P3"
    elif scores["P4"] > 0:
        assigned = "P4"
    else:
        # Ambiguous / General description without specific trigger words
        assigned = "P3"
        return {
            "priority": assigned,
            "severity": PRIORITY_RULES[assigned]["severity"],
            "reason": "Alert description is ambiguous with no definitive keyword matches; assigned Medium priority for manual analyst review.",
            "action": "Assign to SOC analyst for initial triage and log enrichment.",
            "matched_keywords": [],
            "scores": scores
        }

    info = PRIORITY_RULES[assigned]
    reason = info["reason_template"]
    action = info["default_action"]

    # Refine reason with specific matches
    if matched[assigned]:
        reason += f" (Trigger indicators: {', '.join(matched[assigned])})"

    return {
        "priority": assigned,
        "severity": info["severity"],
        "reason": reason,
        "action": action,
        "matched_keywords": matched[assigned],
        "scores": scores
    }


def display_alert_report(alert: str, result: dict):
    """Prints formatted SOC alert classification report."""
    print("\n" + "=" * 70)
    print("PRACTICAL 12: SOC ALERT PRIORITY CLASSIFICATION")
    print("=" * 70)
    print(f"Alert: {alert.strip()}\n")
    print(f"Assigned Priority: {result['priority']}")
    print(f"Severity: {result['severity']}")
    print(f"Reason: {result['reason']}")
    print(f"Recommended Action: {result['action']}")
    print("-" * 70)
    print("Indicator Matching Breakdown:")
    for p, score in result["scores"].items():
        print(f"  - {p} ({PRIORITY_RULES[p]['severity']:<8}): {score} match(es)")
    print("-" * 70)
    print("SOC Analyst Note: Keyword matching provides automated preliminary triage.")
    print("Analysts must always verify indicators against contextual telemetry.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  SOC Alert Priority Classification (P1 - P4)")
    print("======================================================================")
    print("Sample Alerts for Demonstration:")
    print("  [1] Multiple servers are encrypting files and a ransomware note has appeared.")
    print("  [2] Mimikatz credential dumping tool executed on domain member workstation.")
    print("  [3] Multiple failed logins followed by port scan detected from internal subnet.")
    print("  [4] Scheduled vulnerability scan completed with informational findings.")
    print("-" * 70)

    try:
        user_input = input("Enter SOC alert description (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if not user_input:
        user_input = "Multiple servers are encrypting files and a ransomware note has appeared."
        print(f"[Using Default Alert]:\n{user_input}")

    result = classify_soc_alert(user_input)
    display_alert_report(user_input, result)


if __name__ == "__main__":
    main()
