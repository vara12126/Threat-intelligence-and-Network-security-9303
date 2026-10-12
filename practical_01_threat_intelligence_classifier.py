"""
Practical 01: Threat Intelligence Domain Classifier
Subject: Threat Intelligence and Network Security

Aim:
    To read a short business scenario, analyze threat patterns, and classify
    it into the appropriate Cyber Threat Intelligence (CTI) application area:
    1. Banking Fraud Prevention
    2. Healthcare Data Protection
    3. E-Commerce Fraud Prevention
    4. Network Security Monitoring

Description:
    Threat intelligence must be contextualized to specific industry verticals.
    This program analyzes business scenarios using domain-specific threat indicators,
    calculates relevance scores, and explains the rationale behind the classification.
"""

import sys

# Knowledge base of domain keywords and context indicators
DOMAINS = {
    "Banking Fraud Prevention": {
        "keywords": [
            "bank", "banking", "account", "credit card", "atm", "swift",
            "wire transfer", "unauthorized transaction", "financial", "trojan",
            "credential stuffing", "fraud", "balance", "fund", "money"
        ],
        "description": "Protects financial institutions, customer assets, and transaction integrity."
    },
    "Healthcare Data Protection": {
        "keywords": [
            "hospital", "healthcare", "patient", "ehr", "electronic health record",
            "medical", "phi", "hipaa", "clinic", "doctor", "health", "prescription",
            "diagnostic", "ransomware on icu", "ambulance"
        ],
        "description": "Safeguards sensitive Patient Health Information (PHI) and critical medical devices."
    },
    "E-Commerce Fraud Prevention": {
        "keywords": [
            "ecommerce", "e-commerce", "shopping", "cart", "checkout", "store",
            "retail", "merchant", "chargeback", "inventory", "fake review",
            "order", "payment gateway", "discount abuse", "promo"
        ],
        "description": "Defends online marketplaces against bot orders, payment abuse, and chargeback scams."
    },
    "Network Security Monitoring": {
        "keywords": [
            "network", "firewall", "ids", "ips", "traffic", "ddos", "packet",
            "port scan", "lateral movement", "c2", "command and control", "dns",
            "bandwidth", "unauthorized ssh", "router", "switch", "soc"
        ],
        "description": "Monitors internal and perimeter enterprise networks for anomalous activities."
    }
}


def classify_scenario(scenario_text: str):
    """
    Analyzes the input business scenario against domain-specific indicators
    and determines the primary threat intelligence area with detailed justification.
    """
    text_lower = scenario_text.lower()
    scores = {}
    matched_keywords = {}

    for domain, info in DOMAINS.items():
        matched = [kw for kw in info["keywords"] if kw in text_lower]
        scores[domain] = len(matched)
        matched_keywords[domain] = matched

    # Find domain with highest score
    sorted_domains = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_domain, best_score = sorted_domains[0]

    return {
        "best_domain": best_domain if best_score > 0 else "Unclassified / General Cyber Threat",
        "best_score": best_score,
        "matched_keywords": matched_keywords.get(best_domain, []),
        "all_scores": scores,
        "description": DOMAINS.get(best_domain, {}).get("description", "No specific domain matched.")
    }


def display_results(scenario: str, result: dict):
    """Displays formatted classification results and reasoning."""
    print("\n" + "=" * 70)
    print("        THREAT INTELLIGENCE DOMAIN CLASSIFIER RESULT")
    print("=" * 70)
    print(f"Scenario Input:\n  \"{scenario.strip()}\"")
    print("-" * 70)
    print(f"Identified Area : {result['best_domain']}")
    print(f"Relevance Score : {result['best_score']} indicator match(es)")
    if result["matched_keywords"]:
        print(f"Matched Keywords: {', '.join(result['matched_keywords'])}")
    print(f"Scope & Purpose : {result['description']}")
    print("-" * 70)
    print("Domain Score Breakdown:")
    for domain, score in result["all_scores"].items():
        bar = "#" * (score * 3)
        print(f"  - {domain:<30}: {score:>2} {bar}")
    print("-" * 70)
    print("Classification Reason:")
    if result["best_score"] > 0:
        print(f"  The scenario exhibits indicators typical of '{result['best_domain']}'.")
        print(f"  Detected indicators ({', '.join(result['matched_keywords'])}) signify threats")
        print("  targeting industry-specific assets and regulatory obligations.")
    else:
        print("  Insufficient specific keywords detected. Recommend broader threat telemetry analysis.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Cyber Threat Intelligence - Practical 01: Scenario Classifier")
    print("======================================================================")
    print("Sample Scenarios:")
    print("  [1] Multiple customer accounts report unauthorized wire transfers and")
    print("      abnormal balance deductions after suspected credential stuffing attacks.")
    print("  [2] A regional hospital's Electronic Health Record (EHR) database is")
    print("      locked by ransomware, disrupting patient treatment and ICU telemetry.")
    print("  [3] Flash-sale orders were manipulated using checkout bots and stolen credit")
    print("      cards, causing heavy chargebacks on our online retail store.")
    print("  [4] SOC analysts detected SYN flood traffic and anomalous lateral movement")
    print("      over internal port 445 targeting core router switches.")
    print("-" * 70)

    try:
        user_input = input("Enter a business scenario (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if not user_input:
        user_input = (
            "A regional hospital's Electronic Health Record (EHR) database is locked by "
            "ransomware, disrupting patient treatment, clinic appointments, and ICU telemetry."
        )
        print(f"\n[Using Default Scenario]:\n{user_input}")

    result = classify_scenario(user_input)
    display_results(user_input, result)


if __name__ == "__main__":
    main()
