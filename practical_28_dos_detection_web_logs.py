"""
Practical 28: Denial-of-Service (DoS) Detection from Web Server Logs
Subject: Threat Intelligence and Network Security

Aim:
    To analyze web server access logs and detect client IP addresses generating
    abnormally high request volumes exceeding rate-limit thresholds.
"""

from collections import Counter

def detect_dos(logs, rate_threshold=5):
    ip_counter = Counter([entry["client_ip"] for entry in logs])
    analysis = []

    for ip, count in ip_counter.most_common():
        status = "ALERT: DoS Attacker" if count >= rate_threshold else "Normal Traffic"
        analysis.append({
            "ip": ip,
            "requests": count,
            "status": status
        })
    return analysis


def main():
    print("=" * 65)
    print("  Practical 28: DoS Flood Detection from Web Server Logs")
    print("=" * 65)

    # Simulated access log stream within a 10-second monitoring window
    simulated_logs = [
        {"time": "14:00:01", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:01", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:02", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:02", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:03", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:03", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:04", "client_ip": "198.51.100.42", "method": "GET",  "uri": "/api/search"},
        {"time": "14:00:01", "client_ip": "192.168.1.50",  "method": "GET",  "uri": "/index.html"},
        {"time": "14:00:03", "client_ip": "192.168.1.50",  "method": "GET",  "uri": "/styles.css"},
        {"time": "14:00:02", "client_ip": "203.0.113.19",  "method": "POST", "uri": "/login"}
    ]

    print(f"Total Log Events Ingested: {len(simulated_logs)}")
    threshold = 5
    print(f"Detection Threshold       : >= {threshold} requests per time window\n")

    results = detect_dos(simulated_logs, threshold)

    print("-" * 65)
    print(f"{'Client IP Address':<18} | {'Requests':<10} | {'Status'}")
    print("-" * 65)
    for r in results:
        print(f"{r['ip']:<18} | {r['requests']:<10} | {r['status']}")
    print("-" * 65)

    flagged = [r for r in results if "ALERT" in r["status"]]
    if flagged:
        print(f"\n[!] Immediate Incident Action: Block {len(flagged)} offensive IP(s) at perimeter firewall:")
        for a in flagged:
            print(f"    -> iptables -A INPUT -s {a['ip']} -j DROP")


if __name__ == "__main__":
    main()
