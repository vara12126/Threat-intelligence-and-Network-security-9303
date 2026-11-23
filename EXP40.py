# LAB 40: Security Tool Recommender
# Aim: Match a plain-English security task to a suitable example tool.

task = input("Describe the security task: ").lower()
tools = {
    "Wireshark": ["analyze packets", "network traffic", "packet capture"],
    "Nmap": ["discover hosts", "scan ports", "network inventory"],
    "YARA": ["match malware patterns", "malware rules", "file signatures"],
    "Splunk": ["search logs", "correlate events", "siem"],
    "Burp Suite": ["test web application", "web security", "http requests"],
    "ClamAV": ["scan files", "antivirus", "malware scan"],
}

scores = {
    tool: sum(keyword in task for keyword in keywords)
    for tool, keywords in tools.items()
}
best_score = max(scores.values())
if best_score == 0:
    print("No matching tool found. Add more detail about the security task.")
else:
    recommendations = [tool for tool, score in scores.items() if score == best_score]
    print("Recommended tool(s):", ", ".join(recommendations))
