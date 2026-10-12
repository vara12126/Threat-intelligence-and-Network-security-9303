"""
Practical 05: Cyber Threat Intelligence (CTI) Report Classifier
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a threat intelligence report summary and intended audience,
    classify it into one of the three foundational CTI tiers:
      1. Strategic Intelligence (Executive & Board-level decisions)
      2. Tactical Intelligence (TTPs, MITRE ATT&CK, Security Architects)
      3. Operational Intelligence (Day-to-day SOC, Incident Responders, IoCs)
    and provide granular scoring metrics and classification justification.
"""

import sys

# Knowledge base defining the 3 Threat Intelligence tiers
TIERS = {
    "Strategic Intelligence": {
        "audience": ["ciso", "board", "executive", "cio", "vp", "stakeholder", "director", "management"],
        "keywords": [
            "geopolitical", "trend", "budget", "financial loss", "reputation",
            "compliance", "nation-state threat", "annual forecast", "risk appetite",
            "cyber warfare", "supply chain posture", "long-term", "governance", "investment"
        ],
        "description": "High-level analysis of business risks, threat actor intent, and macro-trends for executive decision-makers."
    },
    "Tactical Intelligence": {
        "audience": ["architect", "security engineer", "threat hunter", "soc lead", "designer"],
        "keywords": [
            "ttp", "tactics", "techniques", "mitre", "att&ck", "adversary methodology",
            "persistence", "privilege escalation", "lateral movement", "spear-phishing",
            "kill chain", "attack vector", "defense evasion", "detection rules", "sigma"
        ],
        "description": "Explains HOW threat actors operate (Tactics, Techniques & Procedures) to design effective security architectures."
    },
    "Operational Intelligence": {
        "audience": ["soc analyst", "incident responder", "tier 1", "tier 2", "cert", "csirt"],
        "keywords": [
            "ioc", "hash", "md5", "sha256", "ip address", "malicious domain", "cve",
            "exploit", "c2 server", "incoming alert", "siem rule", "payload",
            "active campaign", "quarantine", "firewall blocklist", "phishing url", "snort"
        ],
        "description": "Actionable technical telemetry (Indicators of Compromise & active attacks) for real-time detection and containment."
    }
}


def classify_intelligence_report(report_text: str, audience_input: str) -> dict:
    """Calculates weighted scores across Strategic, Tactical, and Operational tiers."""
    combined_text = f"{report_text} {audience_input}".lower()
    scores = {}
    matched_data = {}

    for tier, data in TIERS.items():
        # Audience matches carry higher weight (3 points each)
        aud_hits = [aud for aud in data["audience"] if aud in audience_input.lower()]
        kw_hits = [kw for kw in data["keywords"] if kw in report_text.lower()]

        total_score = (len(aud_hits) * 3) + (len(kw_hits) * 2)
        scores[tier] = total_score
        matched_data[tier] = {
            "audience_matches": aud_hits,
            "keyword_matches": kw_hits,
            "score": total_score
        }

    # Determine highest-ranking tier
    sorted_tiers = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    winner_tier, highest_score = sorted_tiers[0]

    return {
        "best_tier": winner_tier if highest_score > 0 else "Unclassified / General Report",
        "best_score": highest_score,
        "details": matched_data,
        "description": TIERS.get(winner_tier, {}).get("description", "No specific tier matched.")
    }


def display_classification(report_text: str, audience: str, result: dict):
    """Formats and prints the report classification results and reasoning."""
    print("\n" + "=" * 75)
    print("      CYBER THREAT INTELLIGENCE (CTI) REPORT CLASSIFICATION")
    print("=" * 75)
    print(f"Report Summary   : \"{report_text.strip()}\"")
    print(f"Intended Audience: \"{audience.strip()}\"")
    print("-" * 75)
    print(f"Primary Classification : {result['best_tier']}")
    print(f"Total Weighted Score   : {result['best_score']} point(s)")
    print(f"Tier Definition        : {result['description']}")
    print("-" * 75)
    print("Scoring Breakdown:")
    for tier, info in result["details"].items():
        bar = "=" * (info["score"] * 2)
        print(f"  * {tier:<25}: {info['score']:>2} pts {bar}")
        if info["audience_matches"]:
            print(f"    - Audience Matches : {', '.join(info['audience_matches'])}")
        if info["keyword_matches"]:
            print(f"    - Technical Clues  : {', '.join(info['keyword_matches'])}")

    print("-" * 75)
    print("Classification Reason:")
    best = result["best_tier"]
    if result["best_score"] > 0:
        win_info = result["details"][best]
        print(f"  The document strongly aligns with '{best}' because:")
        if win_info["audience_matches"]:
            print(f"  1. Audience alignment with {', '.join(win_info['audience_matches'])}.")
        if win_info["keyword_matches"]:
            print(f"  2. Focus on indicators/themes: {', '.join(win_info['keyword_matches'])}.")
    else:
        print("  Insufficient specific keywords detected. Please provide more context.")
    print("=" * 75 + "\n")


SAMPLE_REPORTS = [
    {
        "text": "Analysis of APT29 TTPs utilizing DLL sideloading and credential dumping for lateral movement across Windows domains (MITRE ATT&CK T1574.002).",
        "audience": "Security Architects, Threat Hunting Leads, and Defense Engineers",
        "expected": "Tactical Intelligence"
    },
    {
        "text": "Executive assessment of 2026 nation-state cyber warfare threats against critical energy grids and estimated fiscal impact on annual corporate revenue.",
        "audience": "Board of Directors, CISO, and Executive Leadership",
        "expected": "Strategic Intelligence"
    },
    {
        "text": "Immediate blocking indicators: SHA256 hashes of malicious loader dropped by phishing email, active C2 IP addresses 198.51.100.45, and related CVE-2026-1189 exploits.",
        "audience": "SOC Tier 1 & 2 Analysts and Incident Response Handlers",
        "expected": "Operational Intelligence"
    }
]


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 05: Intelligence Report Classifier")
    print("======================================================================")
    print("Select a sample case or enter custom:")
    for i, s in enumerate(SAMPLE_REPORTS, 1):
        print(f"  [{i}] Expected: {s['expected']}")
        print(f"      Text: {s['text'][:65]}...")
    print("  [4] Enter custom report and audience")
    print("-" * 70)

    try:
        choice = input("Enter option (1-4, default 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if choice in ["1", "2", "3"]:
        selected = SAMPLE_REPORTS[int(choice) - 1]
        report_text = selected["text"]
        audience = selected["audience"]
    elif choice == "4":
        report_text = input("Enter report description: ").strip()
        audience = input("Enter intended audience: ").strip()
    else:
        report_text = SAMPLE_REPORTS[0]["text"]
        audience = SAMPLE_REPORTS[0]["audience"]

    result = classify_intelligence_report(report_text, audience)
    display_classification(report_text, audience, result)


if __name__ == "__main__":
    main()
