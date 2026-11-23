# LAB 34: Threat-Hunting Styles
# Aim: Search a small simulated dataset using three hunting approaches.

events = [
    {"user": "alex", "ip": "198.51.100.9", "event": "failed_login", "process": "powershell"},
    {"user": "sam", "ip": "203.0.113.8", "event": "file_access", "process": "explorer"},
    {"user": "alex", "ip": "198.51.100.9", "event": "login_success", "process": "powershell"},
]

# Hypothesis-based: look for login failures followed by success from the same IP.
failed_ips = {event["ip"] for event in events if event["event"] == "failed_login"}
hypothesis_hits = [
    event for event in events
    if event["event"] == "login_success" and event["ip"] in failed_ips
]

# Intelligence-based: search for an IP supplied by an intelligence report.
known_suspicious_ip = input("Enter a suspected IP from an intelligence report: ").strip()
intelligence_hits = [event for event in events if event["ip"] == known_suspicious_ip]

# Analytics-based: find users with multiple events.
event_counts = {}
for event in events:
    event_counts[event["user"]] = event_counts.get(event["user"], 0) + 1
analytics_hits = [user for user, count in event_counts.items() if count >= 2]

print("Hypothesis-based hits:", hypothesis_hits)
print("Intelligence-based hits:", intelligence_hits)
print("Analytics-based users with repeated events:", analytics_hits)
