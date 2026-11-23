# LAB 21: Post-Incident Improvement Tagger
# Aim: Identify improvement areas mentioned in a report.

report = input("Enter post-incident report text: ").lower()
areas = {
    "Patch management": ["patch", "update", "vulnerability"],
    "Security awareness": ["awareness", "training", "phishing exercise"],
    "Monitoring": ["monitoring", "logging", "alert", "detection"],
    "Backup strategy": ["backup", "restore", "recovery copy"],
    "Access control": ["access control", "least privilege", "permissions", "account"],
}

found = [area for area, keywords in areas.items() if any(word in report for word in keywords)]
if found:
    print("Improvement areas identified:")
    for area in found:
        print("-", area)
else:
    print("No listed improvement areas found.")
