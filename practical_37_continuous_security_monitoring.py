"""
Practical 37: Continuous Security Monitoring Simulation
Subject: Threat Intelligence and Network Security

Aim:
    To simulate a continuous monitoring loop evaluating streaming user login
    events against baseline behavior, alerting on off-hours, foreign IPs, and unknowns.
"""

def monitor_login_events(event_stream, baseline_users, approved_subnets):
    log_alerts = []

    for event in event_stream:
        anomalies = []
        user = event["user"]
        ip = event["ip"]
        hour = int(event["time"].split(":")[0])

        # 1. Unknown account
        if user not in baseline_users:
            anomalies.append(f"Unregistered user account '{user}'")

        # 2. Suspicious time (outside 08:00 - 18:00 business window)
        if hour < 8 or hour >= 18:
            anomalies.append(f"Off-hours authentication at {event['time']}")

        # 3. Abnormal IP subnet
        if not any(ip.startswith(prefix) for prefix in approved_subnets):
            anomalies.append(f"External/Untrusted IP subnet {ip}")

        status = "ALERT" if anomalies else "NORMAL"
        log_alerts.append({
            "event": event,
            "status": status,
            "anomalies": anomalies
        })

    return log_alerts


def main():
    print("=" * 72)
    print("  Practical 37: Continuous Security Monitoring Simulation")
    print("=" * 72)

    baseline_users = ["alice", "bob", "carol", "sysadmin"]
    approved_subnets = ["192.168.1.", "10.0.0."]

    event_stream = [
        {"time": "09:15:00", "user": "alice",    "ip": "192.168.1.25"},
        {"time": "14:30:00", "user": "bob",      "ip": "10.0.0.45"},
        {"time": "02:45:00", "user": "carol",    "ip": "192.168.1.100"},
        {"time": "11:20:00", "user": "intruder", "ip": "203.0.113.88"}
    ]

    print("Baseline Business Hours: 08:00 - 18:00 | Approved Subnets: 192.168.1.0/24, 10.0.0.0/24\n")

    results = monitor_login_events(event_stream, baseline_users, approved_subnets)

    print(f"{'Time':<10} | {'User':<10} | {'IP Address':<15} | {'State':<8} | {'Findings'}")
    print("-" * 72)
    for r in results:
        ev = r["event"]
        anom_str = "; ".join(r["anomalies"]) if r["anomalies"] else "Verified baseline conformant"
        print(f"{ev['time']:<10} | {ev['user']:<10} | {ev['ip']:<15} | {r['status']:<8} | {anom_str}")
    print("=" * 72)


if __name__ == "__main__":
    main()
