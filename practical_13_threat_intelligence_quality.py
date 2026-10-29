"""
Practical 13: Threat Intelligence Quality Assessment
Subject: Threat Intelligence and Network Security

Aim:
    To evaluate whether incoming threat data qualifies as actionable threat intelligence
    or remains unprocessed raw telemetry by assessing three core dimensions:
    Context, Confidence, and Actionability.

Description:
    Raw data (such as standalone IP addresses or hashes without context) does not
    constitute threat intelligence. Threat intelligence emerges only when data is
    enriched with threat context (who/what/how), verified with a confidence level
    (reliability of source/fidelity), and provides actionable defensive directives
    (e.g., blocking, hunting, patching).
    
    Dimensions Assessed:
    1. Context: Association with a threat actor, campaign, malware family, or CVE.
    2. Confidence: Documented reliability level (e.g., high, medium, Admiralty scale).
    3. Actionability: Concrete defensive recommendations (e.g., block, sinkhole, isolate).
"""

import sys
import re

# Keyword indicator patterns for each intelligence dimension
DIMENSIONS = {
    "context": {
        "name": "Context",
        "keywords": [
            "campaign", "threat actor", "apt", "malware", "phishing", "cve-",
            "ransomware", "trojan", "associated with", "targeting", "ttps",
            "technique", "adversary", "botnet", "infrastructure", "exploit"
        ],
        "description": "Associates data with known threats, campaigns, malware, or tactics."
    },
    "confidence": {
        "name": "Confidence Assessment",
        "keywords": [
            "confidence is high", "confidence is medium", "confidence is low",
            "high confidence", "medium confidence", "low confidence",
            "confidence score", "verified by", "validated", "admiralty",
            "reliability", "fidelity", "corroborated", "confirmed"
        ],
        "description": "Quantifies or qualifies the trust, source fidelity, or verification status."
    },
    "actionability": {
        "name": "Actionability",
        "keywords": [
            "block", "isolate", "quarantine", "sinkhole", "firewall rule",
            "update signature", "patch", "hunt for", "revoke", "deny",
            "soc analysts should", "defensive action", "siem detection", "mitigate"
        ],
        "description": "Enables defensive teams to take proactive or reactive mitigation steps."
    }
}


def evaluate_intelligence_quality(text: str) -> dict:
    """
    Evaluates threat intelligence data against Context, Confidence, and Actionability.
    Returns scores, dimension presence flags, matched phrases, and classification.
    """
    clean_text = text.strip()
    if not clean_text:
        return {
            "score": 0,
            "dimensions": {dim: {"present": False, "matches": []} for dim in DIMENSIONS},
            "classification": "Unprocessed Raw Data",
            "reason": "No threat data was provided to evaluate."
        }

    text_lower = clean_text.lower()
    dim_results = {}
    total_score = 0

    for dim_key, dim_info in DIMENSIONS.items():
        matched = [kw for kw in dim_info["keywords"] if kw in text_lower]
        is_present = len(matched) > 0
        if is_present:
            total_score += 1
        dim_results[dim_key] = {
            "name": dim_info["name"],
            "present": is_present,
            "matches": matched
        }

    # Classify based on score
    if total_score == 3:
        classification = "Actionable Threat Intelligence"
        reason = "The data includes threat context, a confidence assessment, and a recommended defensive action."
    elif total_score in (1, 2):
        classification = "Partially Processed Intelligence"
        present_dims = [info["name"] for info in dim_results.values() if info["present"]]
        missing_dims = [info["name"] for info in dim_results.values() if not info["present"]]
        reason = f"Present: {', '.join(present_dims)}. Missing: {', '.join(missing_dims)}. Further enrichment required before operational deployment."
    else:
        classification = "Unprocessed Raw Data"
        reason = "The input represents raw telemetry without threat context, confidence metrics, or operational actionability."

    return {
        "score": total_score,
        "dimensions": dim_results,
        "classification": classification,
        "reason": reason
    }


def display_assessment(text: str, result: dict):
    """Prints the threat intelligence quality assessment in required standard format."""
    print("\n" + "=" * 70)
    print("PRACTICAL 13: THREAT INTELLIGENCE QUALITY ASSESSMENT")
    print("=" * 70)
    print(f"Evaluated Intel Feed:\n  \"{text.strip()}\"\n")
    print("-" * 70)

    for dim_key, data in result["dimensions"].items():
        status = "Present" if data["present"] else "Missing"
        matches = f" (detected: {', '.join(data['matches'])})" if data["matches"] else ""
        print(f"{data['name']}: {status}{matches}")

    print("-" * 70)
    print(f"Assessment Score: {result['score']}/3")
    print(f"Classification: {result['classification']}")
    print(f"Reason: {result['reason']}")
    print("-" * 70)
    print("Educational Note: This heuristic keyword assessment illustrates CTI principles.")
    print("In production CTI, intelligence quality is assessed using standards like STIX/TAXII,")
    print("the Admiralty Code (NATO System), and rigorous analytical tradecraft.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Practical 13: Threat Intelligence Quality Assessment")
    print("======================================================================")
    print("Sample Intelligence Statements:")
    print("  [1] Malicious IP 203.0.113.10 is associated with a documented phishing campaign.")
    print("      Confidence is high, and SOC analysts should block the indicator after validation.")
    print("  [2] Observed inbound connection attempt from 198.51.100.45.")
    print("  [3] Cobalt Strike C2 server discovered at 192.0.2.80; high confidence from CERT.")
    print("-" * 70)

    try:
        user_input = input("Enter threat intelligence statement (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if not user_input:
        user_input = (
            "Malicious IP 203.0.113.10 is associated with a documented phishing campaign. "
            "Confidence is high, and SOC analysts should block the indicator after validation."
        )
        print(f"[Using Default Intelligence Statement]:\n{user_input}")

    result = evaluate_intelligence_quality(user_input)
    display_assessment(user_input, result)


if __name__ == "__main__":
    main()
