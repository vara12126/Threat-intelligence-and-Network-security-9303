"""
Practical 38: Qualitative Cybersecurity Risk Assessment
Subject: Threat Intelligence and Network Security

Aim:
    To evaluate threat scenarios using a qualitative 5x5 matrix
    (Risk Score = Likelihood x Impact) and classify risk severity.
"""

def calculate_risk(likelihood, impact):
    # Ratings 1 to 5
    score = likelihood * impact
    
    if score >= 16:
        level = "CRITICAL (Immediate Mitigation)"
    elif score >= 10:
        level = "HIGH (Priority Remediation)"
    elif score >= 5:
        level = "MEDIUM (Monitored Control)"
    else:
        level = "LOW (Acceptable Risk)"

    return score, level


def main():
    print("=" * 74)
    print("  Practical 38: Qualitative Threat Risk Assessment Engine")
    print("=" * 74)

    scenarios = [
        {"threat": "Zero-day RCE on Internet-Facing Web Portal",    "likelihood": 4, "impact": 5},
        {"threat": "Employee clicking simulated phishing email",     "likelihood": 4, "impact": 2},
        {"threat": "Unencrypted backup drive stolen from premises",   "likelihood": 2, "impact": 5},
        {"threat": "Minor DDoS attempt mitigated by CDN",            "likelihood": 3, "impact": 2},
        {"threat": "Accidental deletion of non-critical test repo",  "likelihood": 1, "impact": 1}
    ]

    print(f"\n{'Threat Scenario':<44} | {'L':<2} | {'I':<2} | {'Score':<5} | {'Risk Level'}")
    print("-" * 74)
    for s in scenarios:
        score, level = calculate_risk(s["likelihood"], s["impact"])
        print(f"{s['threat'][:43]:<44} | {s['likelihood']:<2} | {s['impact']:<2} | {score:<5} | {level}")
    print("=" * 74)
    print("\nRating Scale: Likelihood [1-5] x Impact [1-5] = Score [1-25]")


if __name__ == "__main__":
    main()
