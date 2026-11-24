"""
Practical 30: SIEM Cross-Source Log Correlation
Subject: Threat Intelligence and Network Security

Aim:
    To correlate events across Firewall, VPN, and Windows Security logs to uncover
    a coordinated brute-force account compromise invisible in isolation.
"""

def correlate_sources(firewall_logs, vpn_logs, windows_logs):
    findings = []
    
    # 1. Inspect VPN logs for repeated failures
    vpn_failures = {}
    vpn_successes = {}
    for entry in vpn_logs:
        ip = entry["ip"]
        user = entry["user"]
        if entry["status"] == "FAILED":
            vpn_failures[ip] = vpn_failures.get(ip, 0) + 1
        elif entry["status"] == "SUCCESS":
            vpn_successes[ip] = user

    # 2. Correlate with firewall gateway traffic
    for ip, user in vpn_successes.items():
        if vpn_failures.get(ip, 0) >= 3:
            fw_match = any(f["src_ip"] == ip and f["action"] == "PERMIT" for f in firewall_logs)
            win_match = any(w["user"] == user and w["event_id"] == 4672 for w in windows_logs)

            if fw_match and win_match:
                findings.append({
                    "attacker_ip": ip,
                    "compromised_user": user,
                    "failed_attempts": vpn_failures[ip],
                    "correlated_rule": "CORR-RULE-30: External VPN Brute-Force into Domain Privileged Elevation",
                    "severity": "CRITICAL (P1)"
                })

    return findings


def main():
    print("=" * 72)
    print("  Practical 30: Multi-Source SIEM Log Correlation Engine")
    print("=" * 72)

    firewall_logs = [
        {"src_ip": "198.51.100.75", "dest_port": 443, "action": "PERMIT", "service": "VPN-Gateway"}
    ]

    vpn_logs = [
        {"time": "02:14:10", "ip": "198.51.100.75", "user": "admin_dave", "status": "FAILED"},
        {"time": "02:14:22", "ip": "198.51.100.75", "user": "admin_dave", "status": "FAILED"},
        {"time": "02:14:35", "ip": "198.51.100.75", "user": "admin_dave", "status": "FAILED"},
        {"time": "02:15:02", "ip": "198.51.100.75", "user": "admin_dave", "status": "SUCCESS"}
    ]

    windows_logs = [
        {"time": "02:15:20", "user": "admin_dave", "event_id": 4624, "desc": "Successful Interactive Logon"},
        {"time": "02:15:25", "user": "admin_dave", "event_id": 4672, "desc": "Special Privileges Assigned (Domain Admin)"}
    ]

    print("\n[SOURCE 1: FIREWALL LOGS]")
    for e in firewall_logs:
        print(f"  Traffic from {e['src_ip']} to port {e['dest_port']}: {e['action']}")

    print("\n[SOURCE 2: VPN AUTHENTICATION LOGS]")
    for e in vpn_logs:
        print(f"  [{e['time']}] {e['user']} from {e['ip']}: {e['status']}")

    print("\n[SOURCE 3: WINDOWS SECURITY LOGS]")
    for e in windows_logs:
        print(f"  [{e['time']}] Event {e['event_id']}: {e['desc']} for user {e['user']}")

    correlations = correlate_sources(firewall_logs, vpn_logs, windows_logs)

    print("\n" + "=" * 72)
    print("  SIEM CORRELATION ALERT")
    print("=" * 72)
    for c in correlations:
        print(f"Alert Severity : {c['severity']}")
        print(f"Detection Rule : {c['correlated_rule']}")
        print(f"Attacker IP    : {c['attacker_ip']}")
        print(f"Victim Account : {c['compromised_user']}")
        print(f"Failed Count   : {c['failed_attempts']} failed logins preceding compromise")
        print("Threat Verdict : High-confidence unauthorized external account takeover!")


if __name__ == "__main__":
    main()
