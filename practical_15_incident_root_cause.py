"""
Practical 15: Security Incident Root-Cause Classification
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a plain-language security incident narrative, identify root-cause
    indicators, and classify the incident into one of five primary root-cause categories:
    1. Phishing
    2. Unpatched Vulnerability
    3. Misconfiguration
    4. Insider Threat
    5. Supply-Chain Compromise

Description:
    After security containment, Incident Response (IR) teams perform Root Cause Analysis
    (RCA) to determine the initial vector of compromise. Identifying the root cause ensures
    remediation actions (such as patching, policy updates, or access revocation) prevent
    recurrence. This program uses indicator extraction and heuristic scoring to categorize
    incident narratives.
"""

import sys
import re

# Comprehensive root-cause categories, keywords, and reasoning templates
ROOT_CAUSES = {
    "Phishing": {
        "keywords": [
            "fraudulent email", "fake login page", "stolen credentials", "phishing",
            "malicious attachment", "spear-phishing", "credential harvesting", "spoofed email",
            "opened an attachment", "clicked a link", "social engineering", "impersonation email"
        ],
        "reason": "The narrative describes deceptive communication, social engineering, or fraudulent portals used to harvest credentials or deliver payloads."
    },
    "Unpatched Vulnerability": {
        "keywords": [
            "unpatched", "cve-", "known vulnerability", "exploit", "outdated version",
            "security update missing", "remote code execution", "rce", "buffer overflow",
            "zero-day", "legacy software", "patch not applied"
        ],
        "reason": "The incident traces back to an unpatched software flaw or known vulnerability exploited by attackers prior to remediation."
    },
    "Misconfiguration": {
        "keywords": [
            "misconfiguration", "public s3 bucket", "default password", "open port",
            "permissive firewall rule", "unauthenticated access", "directory traversal",
            "exposed database", "debug mode enabled", "weak permissions", "publicly accessible"
        ],
        "reason": "The breach occurred due to security misconfigurations, overly permissive access controls, or unhardened system default settings."
    },
    "Insider Threat": {
        "keywords": [
            "disgruntled employee", "unauthorized access by staff", "insider", "exfiltration by employee",
            "privilege abuse", "former employee token", "internal sabotage", "rogue admin",
            "copying sensitive files to personal usb", "unauthorized internal download"
        ],
        "reason": "The compromise was facilitated by internal personnel abusing legitimate enterprise access or privileges maliciously or negligently."
    },
    "Supply-Chain Compromise": {
        "keywords": [
            "third-party vendor", "upstream dependency", "compromised library", "supply chain",
            "solarwinds-style", "npm package backdoored", "trusted partner breach",
            "malicious code in software update", "contractor breach", "sub-processor leak"
        ],
        "reason": "Attackers gained initial access indirectly through a trusted external vendor, supplier, or compromised upstream software component."
    }
}


def classify_root_cause(narrative: str) -> dict:
    """
    Evaluates incident narrative text against root-cause indicators.
    Returns matched category, indicators, reasoning, and full score breakdown.
    Handles ties and ambiguous narratives cleanly.
    """
    clean_text = narrative.strip()
    if not clean_text:
        return {
            "category": "Undetermined / Empty Input",
            "matched_indicators": [],
            "reason": "No incident narrative was provided for evaluation.",
            "scores": {k: 0 for k in ROOT_CAUSES},
            "is_tie": False
        }

    text_lower = clean_text.lower()
    scores = {}
    matched = {}

    for cat, data in ROOT_CAUSES.items():
        found = [kw for kw in data["keywords"] if kw in text_lower]
        scores[cat] = len(found)
        matched[cat] = found

    max_score = max(scores.values())
    if max_score == 0:
        return {
            "category": "Ambiguous / Inconclusive",
            "matched_indicators": [],
            "reason": "The narrative does not contain sufficient specific root-cause indicators. Detailed digital forensics is recommended.",
            "scores": scores,
            "is_tie": False
        }

    top_categories = [cat for cat, s in scores.items() if s == max_score]
    is_tie = len(top_categories) > 1

    if is_tie:
        primary_category = f"Tie: {' / '.join(top_categories)}"
        all_matched = []
        for cat in top_categories:
            all_matched.extend(matched[cat])
        reason = f"Multiple root causes tied with equal indicator strength ({max_score} matches each). Multi-vector incident or forensic ambiguity."
    else:
        primary_category = top_categories[0]
        all_matched = matched[primary_category]
        reason = ROOT_CAUSES[primary_category]["reason"]

    return {
        "category": primary_category,
        "matched_indicators": all_matched,
        "reason": reason,
        "scores": scores,
        "is_tie": is_tie
    }


def display_root_cause_report(narrative: str, result: dict):
    """Displays formatted incident root-cause report."""
    print("\n" + "=" * 70)
    print("PRACTICAL 15: INCIDENT ROOT-CAUSE CLASSIFICATION")
    print("=" * 70)
    print(f"Incident Summary: {narrative.strip()}\n")
    print(f"Most Likely Root Cause: {result['category']}")
    indicators_str = ", ".join(result["matched_indicators"]) if result["matched_indicators"] else "None detected"
    print(f"Matched Indicators: {indicators_str}")
    print(f"Reason: {result['reason']}")
    print("-" * 70)
    print("Category Score Breakdown:")
    for cat, score in result["scores"].items():
        bar = "#" * (score * 4)
        print(f"  - {cat:<25}: {score} {bar}")
    print("-" * 70)
    print("Analytical Disclaimer: Automated keyword matching serves educational triage.")
    print("Definitive root cause determination requires end-to-end forensic artifact")
    print("reconstruction, memory analysis, and timeline validation.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Practical 15: Security Incident Root-Cause Classifier")
    print("======================================================================")
    print("Sample Incident Narratives:")
    print("  [1] An employee opened a fraudulent email attachment, entered credentials")
    print("      on a fake login page, and attackers subsequently accessed the corporate account.")
    print("  [2] Threat actors exploited an unpatched CVE-2023 remote code execution flaw")
    print("      in an outdated web server.")
    print("  [3] Customer PII was leaked online after an internal cloud storage misconfiguration")
    print("      left an S3 bucket publicly accessible with default permissions.")
    print("  [4] A rogue system administrator downloaded financial databases to a personal")
    print("      USB drive prior to tendering resignation.")
    print("  [5] Attackers compromised a third-party vendor update server, injecting backdoored")
    print("      code into a trusted management utility.")
    print("-" * 70)

    try:
        user_input = input("Enter incident narrative (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if not user_input:
        user_input = (
            "An employee opened a fraudulent email attachment, entered credentials on a fake "
            "login page, and attackers subsequently accessed the corporate account."
        )
        print(f"[Using Default Narrative]:\n{user_input}")

    result = classify_root_cause(user_input)
    display_root_cause_report(user_input, result)


if __name__ == "__main__":
    main()
