"""
Practical 36: Cybersecurity Regulatory Compliance Classifier
Subject: Threat Intelligence and Network Security

Aim:
    To classify organizational data processing descriptions into standard
    regulatory frameworks: PCI-DSS, HIPAA, GDPR, or SOX.
"""

def classify_compliance(description):
    frameworks = {
        "PCI-DSS (Payment Card Industry)": {
            "keywords": ["credit card", "debit card", "cvv", "cardholder", "pan", "payment gateway", "pos terminal"],
            "reason": "Regulates storage, processing, and transmission of cardholder payment information."
        },
        "HIPAA (Healthcare Portability)": {
            "keywords": ["patient", "medical records", "ehr", "health information", "phi", "doctor", "clinic", "hospital"],
            "reason": "Protects sensitive Protected Health Information (PHI) and clinical privacy."
        },
        "GDPR (General Data Protection)": {
            "keywords": ["european union", "eu citizen", "personal data", "right to be forgotten", "consent", "cookie tracking"],
            "reason": "Mandates data privacy, subject consent, and sovereignty for individuals in the EU."
        },
        "SOX (Sarbanes-Oxley Act)": {
            "keywords": ["financial statement", "accounting", "balance sheet", "internal audit", "public company", "quarterly earnings"],
            "reason": "Enforces corporate financial record integrity, transparency, and fraud controls."
        }
    }

    desc_lower = description.lower()
    for standard, data in frameworks.items():
        if any(kw in desc_lower for kw in data["keywords"]):
            return standard, data["reason"]

    return "General Cybersecurity Baseline", "Standard ISO/NIST organizational cyber hygiene controls."


def main():
    print("=" * 74)
    print("  Practical 36: Regulatory Compliance Standard Classifier")
    print("=" * 74)

    descriptions = [
        "Processing customer Visa and Mastercard cardholder numbers, expiration dates, and 3-digit CVV codes.",
        "Storing patient electronic health records, diagnosis histories, and prescription data on a clinic portal.",
        "Collecting cookie telemetry and email addresses belonging to European Union web platform visitors.",
        "Maintaining internal ledger controls and quarterly financial reports for SEC public auditor inspection."
    ]

    for idx, desc in enumerate(descriptions, 1):
        standard, reason = classify_compliance(desc)
        print(f"\n[SYSTEM PROFILE #{idx}]")
        print(f"Data Scope: {desc}")
        print(f"Standard  : {standard}")
        print(f"Mandate   : {reason}")
        print("-" * 74)


if __name__ == "__main__":
    main()
