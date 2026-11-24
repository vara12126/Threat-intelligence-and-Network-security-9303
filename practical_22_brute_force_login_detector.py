"""
Practical 22: Brute-Force Login Detection
Subject: Threat Intelligence and Network Security

Aim:
    To parse authentication logs and detect repeated failed login attempts
    followed by a successful login for a user account (credential guessing attack).
"""

def detect_brute_force(auth_logs, threshold=3):
    user_failures = {}
    alerts = []

    for log in auth_logs:
        user = log["user"]
        status = log["status"]
        ip = log["ip"]
        time = log["time"]

        if status == "FAILED":
            user_failures[user] = user_failures.get(user, 0) + 1
        elif status == "SUCCESS":
            failed_count = user_failures.get(user, 0)
            if failed_count >= threshold:
                alerts.append({
                    "user": user,
                    "ip": ip,
                    "time": time,
                    "failed_count": failed_count,
                    "status": "ALERT: Brute-Force Succeeded"
                })
            # Reset after successful resolution
            user_failures[user] = 0

    return alerts


def main():
    print("=" * 65)
    print("  Practical 22: Authentication Brute-Force Detection")
    print("=" * 65)

    sample_logs = [
        {"time": "10:00:01", "user": "admin", "ip": "192.168.1.105", "status": "FAILED"},
        {"time": "10:00:05", "user": "admin", "ip": "192.168.1.105", "status": "FAILED"},
        {"time": "10:00:09", "user": "admin", "ip": "192.168.1.105", "status": "FAILED"},
        {"time": "10:00:14", "user": "admin", "ip": "192.168.1.105", "status": "FAILED"},
        {"time": "10:00:20", "user": "admin", "ip": "192.168.1.105", "status": "SUCCESS"},
        {"time": "10:01:00", "user": "john",  "ip": "192.168.1.50",  "status": "FAILED"},
        {"time": "10:01:10", "user": "john",  "ip": "192.168.1.50",  "status": "SUCCESS"},
    ]

    print("\n[INGESTED AUTHENTICATION LOGS]")
    for entry in sample_logs:
        print(f"[{entry['time']}] User: {entry['user']:<6} | Source: {entry['ip']:<14} | Status: {entry['status']}")

    threshold = 3
    print(f"\nDetection Threshold: >= {threshold} failed attempts prior to success")
    alerts = detect_brute_force(sample_logs, threshold)

    print("\n" + "=" * 65)
    print("  DETECTION ALERTS & CORRELATION RESULT")
    print("=" * 65)
    if alerts:
        for alert in alerts:
            print(f"[!] {alert['status']}")
            print(f"    Target Username : {alert['user']}")
            print(f"    Failed Attempts : {alert['failed_count']}")
            print(f"    Attacker IP     : {alert['ip']}")
            print(f"    Breached At     : {alert['time']}")
    else:
        print("[+] No brute-force compromise detected.")


if __name__ == "__main__":
    main()
