# LAB 23: Signature-Based IPS with Whitelist (Simulation)
# Aim: Block simulated traffic matching a signature, except from trusted sources.
# This program does not modify real firewall or network settings.

trusted_sources = {"192.0.2.10"}
signature = "malicious-payload"
traffic = [
    {"source": "192.0.2.10", "content": "malicious-payload"},
    {"source": "198.51.100.8", "content": "malicious-payload"},
    {"source": "203.0.113.4", "content": "normal-traffic"},
]

for packet in traffic:
    if packet["source"] in trusted_sources:
        print("ALLOWED (whitelisted):", packet["source"])
    elif signature in packet["content"]:
        print("BLOCKED (signature match):", packet["source"])
    else:
        print("ALLOWED (no signature match):", packet["source"])
