"""
Practical 40: Cybersecurity Tool Recommendation Engine
Subject: Threat Intelligence and Network Security

Aim:
    To build a keyword-driven recommendation system matching security analyst
    operational requirements to industry-standard cybersecurity tools.
"""

def recommend_tool(task_description):
    tool_database = {
        "Wireshark": {
            "keywords": ["packet", "pcap", "network traffic", "protocol inspection", "tcpdump", "wireshark"],
            "reason": "Premier deep packet inspection and network protocol analyzer."
        },
        "Qualys": {
            "keywords": ["vulnerability scan", "cve", "patch audit", "misconfiguration", "qualys", "asset discovery"],
            "reason": "Enterprise cloud-based vulnerability management and compliance scanning."
        },
        "Splunk": {
            "keywords": ["siem", "log aggregation", "correlation", "search query", "splunk", "dashboard"],
            "reason": "Industry-standard SIEM for large-scale security log indexing and correlation."
        },
        "Snort": {
            "keywords": ["intrusion detection", "signature matching", "ids", "ips", "snort", "network rule"],
            "reason": "Open-source signature-driven network intrusion detection and prevention engine."
        },
        "MISP": {
            "keywords": ["threat intelligence", "ioc sharing", "malware attributes", "misp", "threat feed", "cti platform"],
            "reason": "Leading open-source threat intelligence sharing and IOC management platform."
        },
        "Wazuh": {
            "keywords": ["endpoint monitoring", "edr", "fim", "file integrity", "wazuh", "host ids"],
            "reason": "Comprehensive host-based endpoint detection, response, and integrity monitoring."
        }
    }

    desc_lower = task_description.lower()
    for tool, data in tool_database.items():
        if any(kw in desc_lower for kw in data["keywords"]):
            return tool, data["reason"]

    return "General Security Suite", "Combine open-source tools tailored to operational workflow."


def main():
    print("=" * 74)
    print("  Practical 40: Cybersecurity Tool Recommendation Engine")
    print("=" * 74)

    tasks = [
        "Capture raw Ethernet frames and inspect TCP handshake flags for packet analysis.",
        "Perform scheduled CVE vulnerability scanning and patch gap discovery on web servers.",
        "Aggregate system logs across 500 servers for SIEM correlation and dashboarding.",
        "Deploy signature-based network intrusion detection to block known exploit patterns.",
        "Share structured IOC indicators and malware threat feeds with external certs.",
        "Implement endpoint file integrity monitoring (FIM) and host anomaly detection."
    ]

    for idx, t in enumerate(tasks, 1):
        tool, justification = recommend_tool(t)
        print(f"\n[SECURITY TASK #{idx}]")
        print(f"Objective   : {t}")
        print(f"Recommended : {tool}")
        print(f"Capability  : {justification}")
        print("-" * 74)


if __name__ == "__main__":
    main()
