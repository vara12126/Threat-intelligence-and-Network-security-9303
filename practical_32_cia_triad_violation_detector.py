"""
Practical 32: CIA Triad Security Violation Detection
Subject: Threat Intelligence and Network Security

Aim:
    To analyze security incident properties and classify violations against
    the core CIA Triad: Confidentiality, Integrity, and Availability.
"""

def evaluate_cia_violation(scenario_text):
    categories = {
        "Confidentiality": {
            "keywords": ["leak", "exfiltrat", "dump", "unauthorized access", "eavesdrop", "disclosure", "stolen", "sniff"],
            "impact": "Loss of sensitive data secrecy / unauthorized disclosure"
        },
        "Integrity": {
            "keywords": ["tamper", "alter", "deface", "modify", "corrupt", "unauthorized change", "forge", "checksum error"],
            "impact": "Unauthorized modification or loss of data trustworthiness"
        },
        "Availability": {
            "keywords": ["ddos", "dos", "flood", "outage", "downtime", "ransomware", "encrypt", "unreachable", "crash"],
            "impact": "Authorized users prevented from accessing system resources"
        }
    }

    text_lower = scenario_text.lower()
    violations = []

    for pillar, data in categories.items():
        matched = [kw for kw in data["keywords"] if kw in text_lower]
        if matched:
            violations.append((pillar, data["impact"], matched))

    return violations


def main():
    print("=" * 72)
    print("  Practical 32: CIA Triad Security Property Violation Analyzer")
    print("=" * 72)

    scenarios = [
        "A malicious actor conducted SQL injection and dumped 50,000 plaintext user credit card records.",
        "An insider modified database audit records and forged financial transaction balances.",
        "A high-volume SYN flood overwhelmed public web servers causing 6 hours of continuous outage.",
        "Ransomware infected file storage servers, encrypting customer data and exfiltrating legal files."
    ]

    for idx, sc in enumerate(scenarios, 1):
        print(f"\n[SCENARIO #{idx}]")
        print(f"Incident: {sc}")
        violations = evaluate_cia_violation(sc)
        print("CIA Violations Detected:")
        for pillar, impact, matched in violations:
            print(f"  -> [{pillar.upper()}] : {impact}")
            print(f"     Matched Triggers: {', '.join(matched)}")
        print("-" * 72)


if __name__ == "__main__":
    main()
