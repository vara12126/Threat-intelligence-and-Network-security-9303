"""
Practical 20: Network Threat Category Classifier
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a plain-language network incident description and classify it into
    one of four core network threat categories:
    1. Phishing
    2. DoS/DDoS
    3. Malware
    4. Man-in-the-Middle (MitM)

Description:
    Network security analysts regularly analyze incident summaries from tickets,
    user reports, and firewall alerts. Categorizing incidents into standardized threat
    taxonomies accelerates triage, ensures appropriate playbooks are executed, and
    maintains structured threat metrics.
"""

import sys

# Four core network threat categories, their indicator keywords, and reasoning
THREAT_CATEGORIES = {
    "Phishing": {
        "keywords": [
            "fraudulent email", "fake login", "phishing", "spear-phishing",
            "credential theft", "spoofed domain", "deceptive link", "lure",
            "impersonation", "fake invoice", "harvest credentials", "urgent email"
        ],
        "reason": "The narrative describes deceptive communication or fake portals used to trick victims into providing sensitive credentials or information."
    },
    "DoS/DDoS": {
        "keywords": [
            "dos", "ddos", "syn flood", "volumetric attack", "traffic flood",
            "service unavailable", "exhaustion", "denial of service", "packet flood",
            "amplification attack", "overwhelmed server", "bandwidth exhaustion"
        ],
        "reason": "The narrative describes volumetric traffic flooding or resource exhaustion intended to render network services unavailable to legitimate users."
    },
    "Malware": {
        "keywords": [
            "malware", "ransomware", "trojan", "worm", "keylogger", "spyware",
            "backdoor", "payload", "encrypting files", "malicious executable",
            "c2 beaconing", "infected host", "rootkit", "botnet client"
        ],
        "reason": "The narrative describes malicious software binaries or scripts executing unauthorized actions on victim endpoints or networks."
    },
    "Man-in-the-Middle": {
        "keywords": [
            "intercepts traffic", "modifies messages", "modifies the messages", "man-in-the-middle", "mitm",
            "arp spoofing", "dns spoofing", "ssl stripping", "eavesdropping",
            "session hijacking", "tampered in transit", "packet injection",
            "relaying messages between", "rogue access point"
        ],
        "reason": "The narrative describes interception and possible alteration of communications between two parties."
    }
}

# Standard test cases covering all 4 categories for verification
TEST_CASES = [
    {
        "category": "Man-in-the-Middle",
        "text": "An attacker intercepts traffic between a user and a server and modifies the messages in transit using ARP spoofing."
    },
    {
        "category": "Phishing",
        "text": "Employees received a fraudulent email containing a deceptive link to a fake login portal designed for credential theft."
    },
    {
        "category": "DoS/DDoS",
        "text": "A massive SYN flood volumetric attack overwhelmed the web server, causing severe bandwidth exhaustion and service unavailable errors."
    },
    {
        "category": "Malware",
        "text": "An endpoint host was infected with ransomware that executed a malicious executable payload and began encrypting files."
    }
]


def classify_network_threat(description: str) -> dict:
    """
    Evaluates incident description against network threat indicators.
    Returns predicted category, matched indicators, reasoning, and scores.
    Handles ties, empty inputs, and uncertain descriptions cleanly.
    """
    clean_text = description.strip()
    if not clean_text:
        return {
            "predicted_category": "Undetermined / Empty Input",
            "matched_indicators": [],
            "reason": "No incident description was provided.",
            "scores": {k: 0 for k in THREAT_CATEGORIES},
            "is_tie": False
        }

    text_lower = clean_text.lower()
    scores = {}
    matched = {}

    for cat, data in THREAT_CATEGORIES.items():
        found = []
        for kw in data["keywords"]:
            if kw in text_lower:
                display_kw = "modifies messages" if kw == "modifies the messages" else kw
                if display_kw not in found:
                    found.append(display_kw)
        scores[cat] = len(found)
        matched[cat] = found

    max_score = max(scores.values())
    if max_score == 0:
        return {
            "predicted_category": "Uncertain / Unclassified Threat",
            "matched_indicators": [],
            "reason": "The description does not contain distinct indicator keywords. Recommend deeper packet capture and endpoint telemetry.",
            "scores": scores,
            "is_tie": False
        }

    top_categories = [cat for cat, s in scores.items() if s == max_score]
    is_tie = len(top_categories) > 1

    if is_tie:
        predicted = f"Tie: {' / '.join(top_categories)}"
        all_matched = []
        for cat in top_categories:
            all_matched.extend(matched[cat])
        reason = f"Indicators matched multiple threat categories with equal frequency ({', '.join(top_categories)}). Multi-stage or hybrid threat vector."
    else:
        predicted = top_categories[0]
        all_matched = matched[predicted]
        reason = THREAT_CATEGORIES[predicted]["reason"]

    return {
        "predicted_category": predicted,
        "matched_indicators": all_matched,
        "reason": reason,
        "scores": scores,
        "is_tie": is_tie
    }


def display_classification(description: str, result: dict):
    """Prints formatted network threat category classification."""
    print("\n" + "=" * 70)
    print("PRACTICAL 20: NETWORK THREAT CATEGORY CLASSIFIER")
    print("=" * 70)
    print(f"Incident Narrative:\n  \"{description.strip()}\"\n")
    print(f"Predicted Category: {result['predicted_category']}")
    indicators = ", ".join(result["matched_indicators"]) if result["matched_indicators"] else "None detected"
    print(f"Matched Indicators: {indicators}")
    print(f"Reason: {result['reason']}")
    print("-" * 70)
    print("Threat Category Score Breakdown:")
    for cat, score in result["scores"].items():
        bar = "#" * (score * 4)
        print(f"  - {cat:<20}: {score} {bar}")
    print("=" * 70 + "\n")


def run_all_test_cases():
    """Runs through predefined test cases covering all four network threat categories."""
    print("\n[RUNNING ALL VERIFICATION TEST CASES ACROSS 4 THREAT CATEGORIES]")
    for idx, tc in enumerate(TEST_CASES, 1):
        print(f"\n--- Test Case {idx}: Target Category '{tc['category']}' ---")
        res = classify_network_threat(tc["text"])
        display_classification(tc["text"], res)


def main():
    print("======================================================================")
    print("  Practical 20: Network Threat Category Classifier")
    print("======================================================================")
    print("Categories: Phishing | DoS/DDoS | Malware | Man-in-the-Middle")
    print("Sample Scenario:")
    print("  \"An attacker intercepts traffic between a user and a server and modifies the messages in transit.\"")
    print("-" * 70)

    try:
        user_input = input("Enter incident description (or press Enter for default, or 'test' for all): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if user_input.lower() == "test":
        run_all_test_cases()
        return

    if not user_input:
        user_input = "An attacker intercepts traffic between a user and a server and modifies the messages in transit."
        print(f"[Using Default Incident Description]:\n{user_input}")

    res = classify_network_threat(user_input)
    display_classification(user_input, res)


if __name__ == "__main__":
    main()
