"""
Practical 17: ISO/IEC 27001 Annex A Control Domain Classification
Subject: Threat Intelligence and Network Security

Aim:
    To read a plain-text security control description and classify it into its
    most relevant ISO/IEC 27001:2022 Annex A control theme:
    1. Organizational Controls (Clause 5)
    2. People Controls (Clause 6)
    3. Physical Controls (Clause 7)
    4. Technological Controls (Clause 8)

Description:
    ISO/IEC 27001:2022 reorganized information security controls into four comprehensive
    themes. Classifying controls into their correct theme helps organizations establish
    an Information Security Management System (ISMS), map governance responsibilities,
    and fulfill compliance auditing requirements.
"""

import sys

# Four ISO/IEC 27001:2022 Annex A Themes and their domain keywords
ANNEX_A_THEMES = {
    "Organizational Controls": {
        "keywords": [
            "policy", "policies", "governance", "roles and responsibilities",
            "threat intelligence", "asset management", "inventory", "supplier security",
            "vendor contract", "incident management", "business continuity", "disaster recovery",
            "compliance", "audit", "legal requirements", "acceptable use", "risk assessment"
        ],
        "reason": "The control focuses on organizational governance, management policies, operational processes, asset management, and vendor oversight."
    },
    "People Controls": {
        "keywords": [
            "awareness training", "training", "employee", "staff", "screening",
            "background check", "disciplinary", "remote working", "teleworking",
            "confidentiality agreement", "nda", "terms of employment", "personnel",
            "user education", "human resources", "termination of employment"
        ],
        "reason": "The control focuses on employee awareness, training, personnel screening, and human-behavior aspects of information security."
    },
    "Physical Controls": {
        "keywords": [
            "physical perimeter", "biometric door", "badge", "cctv", "security guard",
            "facility", "data center", "clear desk", "clear screen", "secure disposal",
            "shredding", "cabling security", "equipment protection", "fire suppression",
            "surveillance", "locks", "physical access"
        ],
        "reason": "The control focuses on safeguarding physical premises, data centers, facilities, offices, and hardware assets against physical intrusion."
    },
    "Technological Controls": {
        "keywords": [
            "multi-factor authentication", "mfa", "encryption", "cryptography",
            "firewall", "antivirus", "malware protection", "access control", "privilege",
            "backup", "patch management", "logging", "siem", "network segmentation",
            "vulnerability scanning", "secure coding", "penetration testing", "vpn"
        ],
        "reason": "The control focuses on technical and digital safeguards implemented within IT systems, networks, software, and authentication services."
    }
}


def classify_iso27001_control(control_text: str) -> dict:
    """
    Evaluates a security control description against ISO/IEC 27001:2022 Annex A themes.
    Returns matched theme, detected indicators, reasoning, and full score breakdown.
    """
    clean_text = control_text.strip()
    if not clean_text:
        return {
            "theme": "Unclassified / Empty Description",
            "matched_indicators": [],
            "reason": "No control description was provided.",
            "scores": {k: 0 for k in ANNEX_A_THEMES}
        }

    text_lower = clean_text.lower()
    scores = {}
    matched = {}

    for theme, data in ANNEX_A_THEMES.items():
        found = [kw for kw in data["keywords"] if kw in text_lower]
        scores[theme] = len(found)
        matched[theme] = found

    # Determine highest matching theme
    max_score = max(scores.values())
    if max_score == 0:
        return {
            "theme": "Ambiguous / General Control",
            "matched_indicators": [],
            "reason": "The control description does not contain distinct thematic keywords. Manual ISMS mapping is recommended.",
            "scores": scores
        }

    top_themes = [theme for theme, sc in scores.items() if sc == max_score]
    if len(top_themes) > 1:
        selected_theme = f"Cross-Domain: {' / '.join(top_themes)}"
        all_indicators = []
        for t in top_themes:
            all_indicators.extend(matched[t])
        reason = f"The control spans multiple ISO/IEC 27001 themes ({', '.join(top_themes)}) with equal indicator relevance."
    else:
        selected_theme = top_themes[0]
        all_indicators = matched[selected_theme]
        reason = ANNEX_A_THEMES[selected_theme]["reason"]

    return {
        "theme": selected_theme,
        "matched_indicators": all_indicators,
        "reason": reason,
        "scores": scores
    }


def display_classification_report(control_text: str, result: dict):
    """Displays formatted ISO/IEC 27001 classification output."""
    print("\n" + "=" * 70)
    print("PRACTICAL 17: ISO/IEC 27001 ANNEX A CLASSIFICATION")
    print("=" * 70)
    print(f"Control Description: {control_text.strip()}\n")
    print(f"Selected Theme: {result['theme']}")
    print(f"Reason: {result['reason']}")
    print("-" * 70)
    if result["matched_indicators"]:
        print(f"Matched Indicators: {', '.join(result['matched_indicators'])}")
    print("Theme Score Breakdown:")
    for theme, score in result["scores"].items():
        bar = "#" * (score * 4)
        print(f"  - {theme:<25}: {score} {bar}")
    print("-" * 70)
    print("Compliance Notice: This tool serves as an educational theme classifier.")
    print("It does not replace formal ISO/IEC 27001:2022 Statement of Applicability (SoA)")
    print("audits or accredited certification assessments.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Practical 17: ISO/IEC 27001:2022 Annex A Control Theme Classifier")
    print("======================================================================")
    print("Sample Control Descriptions:")
    print("  [1] Employees must complete annual cybersecurity awareness training.")
    print("  [2] Access to server rooms requires biometric door scan and badge logging.")
    print("  [3] Multi-factor authentication and data encryption must be enforced.")
    print("  [4] Information security policies and vendor contracts must be reviewed annually.")
    print("-" * 70)

    try:
        user_input = input("Enter security control description (or press Enter for default): ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = ""

    if not user_input:
        user_input = "Employees must complete annual cybersecurity awareness training."
        print(f"[Using Default Control Description]:\n{user_input}")

    result = classify_iso27001_control(user_input)
    display_classification_report(user_input, result)


if __name__ == "__main__":
    main()
