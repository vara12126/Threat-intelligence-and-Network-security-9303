# LAB 30: SIEM Multi-Source Brute-Force Correlation
# Aim: Correlate firewall, Windows, and VPN events to detect a combined pattern.

firewall_log = [{"ip": "198.51.100.24", "event": "repeated_denials"}]
windows_log = [{"ip": "198.51.100.24", "event": "failed_logins", "count": 8}]
vpn_log = [{"ip": "198.51.100.24", "event": "vpn_login_success"}]

firewall_ips = {entry["ip"] for entry in firewall_log if entry["event"] == "repeated_denials"}
windows_ips = {
    entry["ip"] for entry in windows_log
    if entry["event"] == "failed_logins" and entry["count"] >= 5
}
vpn_ips = {entry["ip"] for entry in vpn_log if entry["event"] == "vpn_login_success"}

correlated_ips = firewall_ips & windows_ips & vpn_ips
if correlated_ips:
    for ip in correlated_ips:
        print("SIEM ALERT: Repeated denials, Windows failures, and VPN success from", ip)
else:
    print("No cross-source brute-force pattern found.")
