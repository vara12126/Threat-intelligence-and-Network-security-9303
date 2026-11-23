# LAB 29: Incident Containment Recommender
# Aim: Suggest a containment action based on a described incident.

incident = input("Describe the security incident: ").lower()
strategies = [
    (["ransomware", "malware", "infected endpoint"], "Isolate affected endpoint(s) from the network."),
    (["stolen password", "compromised account", "account takeover"], "Disable or lock the affected account and revoke sessions."),
    (["data exfiltration", "large outbound transfer"], "Restrict the suspected egress path and preserve network evidence."),
    (["exposed database", "public storage", "misconfigured cloud"], "Restrict public access and preserve configuration evidence."),
    (["ddos", "denial of service"], "Apply approved traffic filtering or upstream DDoS protection."),
]

recommendations = [
    advice for keywords, advice in strategies
    if any(keyword in incident for keyword in keywords)
]
if recommendations:
    for recommendation in recommendations:
        print("Recommended containment:", recommendation)
else:
    print("No matching scenario. Escalate to the incident-response lead for assessment.")
print("Follow your organization's incident-response procedures.")
