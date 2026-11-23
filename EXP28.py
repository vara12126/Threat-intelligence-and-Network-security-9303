# LAB 28: Possible DoS Detection from Web Logs
# Aim: Find an IP whose request count exceeds a simple threshold.

web_log_ips = [
    "198.51.100.5", "203.0.113.2", "198.51.100.5", "198.51.100.5",
    "198.51.100.5", "203.0.113.2", "192.0.2.9", "198.51.100.5",
]
threshold = int(input("Request-count threshold for this sample: "))
request_counts = {}
for ip in web_log_ips:
    request_counts[ip] = request_counts.get(ip, 0) + 1

print("Request counts:", request_counts)
suspicious_ips = [ip for ip, count in request_counts.items() if count > threshold]
if suspicious_ips:
    print("Possible high-rate sources:", ", ".join(suspicious_ips))
else:
    print("No source exceeded the threshold.")
