"""
Practical 29: Incident Containment Strategy Recommendation
Subject: Threat Intelligence and Network Security

Aim:
    To analyze security incident descriptions and recommend the most effective
    containment strategy to halt threat spread while minimizing business disruption.
"""

def recommend_containment(incident_desc):
    strategies = {
        "Isolate Endpoint": {
            "keywords": ["ransomware", "lateral movement", "worm", "endpoint malware", "encrypting"],
            "action": "Disconnect host from corporate LAN/WiFi and preserve RAM memory dump."
        },
        "Disable Compromised Account": {
            "keywords": ["credential", "session hijack", "password spray", "unauthorized login", "mfa bypass"],
            "action": "Terminate active sessions, revoke refresh tokens, and reset account credentials."
        },
        "Block Malicious IP / Domain": {
            "keywords": ["c2 beacon", "ddos", "brute-force", "external scanning", "exfiltration ip"],
            "action": "Add source/destination to perimeter firewall and DNS sinkhole blacklists."
        },
        "Quarantine Suspicious File": {
            "keywords": ["malicious attachment", "dropper", "phishing payload", "macro", "trojan file"],
            "action": "Isolate file into secure sandbox quarantine and purge from mail server."
        },
        "Segment Network Subnet": {
            "keywords": ["scada", "ot network", "vlan", "broadcast flood", "server farm breach"],
            "action": "Apply strict egress ACLs and isolate VLAN to restrict zone communications."
        }
    }

    desc_lower = incident_desc.lower()
    for strat, details in strategies.items():
        if any(kw in desc_lower for kw in details["keywords"]):
            return strat, details["action"]

    return "General Containment", "Enforce heightened monitoring and conduct live triage."


def main():
    print("=" * 72)
    print("  Practical 29: Incident Response Containment Decision Engine")
    print("=" * 72)

    scenarios = [
        "A finance workstation is actively encrypting shared files with unknown extensions.",
        "Employee Alice reported unexpected MFA prompts followed by logins from an overseas IP.",
        "Internal database server is transmitting high-frequency C2 beacon signals to 198.51.100.99.",
        "A malicious Excel attachment containing an obfuscated macro dropper was opened by HR."
    ]

    for idx, sc in enumerate(scenarios, 1):
        strategy, action = recommend_containment(sc)
        print(f"\n[INCIDENT SCENARIO #{idx}]")
        print(f"Description : {sc}")
        print(f"Strategy    : {strategy}")
        print(f"Action Step : {action}")
        print("-" * 72)


if __name__ == "__main__":
    main()
