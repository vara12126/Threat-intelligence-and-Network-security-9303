# LAB 36: Compliance Standard Recommender
# Aim: Suggest a likely standard based on the system or data description.

description = input("Describe the system or data: ").lower()
standards = {
    "PCI-DSS": ["payment card", "cardholder", "credit card", "card data"],
    "HIPAA": ["patient", "healthcare", "medical record", "protected health information"],
    "GDPR": ["eu resident", "personal data", "european union", "gdpr"],
    "SOX": ["financial reporting", "public company", "accounting control", "sox"],
}

matches = [
    standard for standard, keywords in standards.items()
    if any(keyword in description for keyword in keywords)
]
if matches:
    print("Likely applicable standard(s):", ", ".join(matches))
else:
    print("No listed standard matched. Confirm scope with a compliance professional.")
print("This keyword match is educational and is not a compliance determination.")
