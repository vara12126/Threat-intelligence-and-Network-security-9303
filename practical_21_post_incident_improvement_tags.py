"""
Practical 21: Post-Incident Report Improvement Tags
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a post-incident security report and automatically tag improvement
    areas: Patch Management, Security Awareness, Monitoring, Backup Strategy,
    and Access Control.
"""

def analyze_post_incident_report(report_text):
    categories = {
        "Patch Management": ["patch", "vulnerability", "cve", "outdated", "update", "unpatched"],
        "Security Awareness": ["phishing", "training", "employee", "awareness", "clicked", "social engineering"],
        "Monitoring & Detection": ["detection", "siem", "log", "delayed", "visibility", "alert", "sensor"],
        "Backup Strategy": ["backup", "restore", "recovery", "ransomware", "data loss", "snapshot"],
        "Access Control": ["privilege", "mfa", "credential", "admin", "unauthorized", "least privilege"]
    }

    report_lower = report_text.lower()
    detected_tags = {}

    for category, keywords in categories.items():
        matched_words = [kw for kw in keywords if kw in report_lower]
        if matched_words:
            detected_tags[category] = matched_words

    return detected_tags


def main():
    print("=" * 65)
    print("  Practical 21: Post-Incident Report Improvement Tagging")
    print("=" * 65)

    sample_report = (
        "Incident Summary: An employee clicked on a phishing link which exploited "
        "an unpatched Windows vulnerability. Detection was delayed by 36 hours due to "
        "insufficient log monitoring on the internal subnet. Restoration was slowed "
        "because the backup strategy lacked offline immutable snapshots. The compromised "
        "account held excessive admin privileges without MFA enforcement."
    )

    print("\n[POST-INCIDENT REPORT EXCERPT]")
    print(sample_report)

    tags = analyze_post_incident_report(sample_report)

    print("\n" + "-" * 65)
    print(f"{'Improvement Area':<25} | {'Matched Indicators'}")
    print("-" * 65)
    for tag, words in tags.items():
        print(f"{tag:<25} | {', '.join(words)}")
    print("-" * 65)
    print(f"\nTotal Improvement Focus Areas Identified: {len(tags)}")


if __name__ == "__main__":
    main()
