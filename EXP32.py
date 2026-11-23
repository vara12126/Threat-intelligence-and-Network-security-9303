# LAB 32: CIA Triad Violation Checker
# Aim: Report CIA principles supported by failed security properties.

properties = [
    {"name": "Data is encrypted at rest", "principle": "Confidentiality", "status": True},
    {"name": "Records are protected from unauthorized changes", "principle": "Integrity", "status": False},
    {"name": "Service is available to users", "principle": "Availability", "status": True},
]

violations = {
    item["principle"] for item in properties
    if not item["status"]
}
for item in properties:
    print(item["name"] + ":", "PASS" if item["status"] else "FAIL")
if violations:
    print("CIA principle(s) violated:", ", ".join(sorted(violations)))
else:
    print("No CIA principle violations detected.")
