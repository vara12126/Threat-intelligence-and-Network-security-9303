# LAB 27: Context-Aware Signature IDS
# Aim: Alert only when both protocol/port context and content signature match.

signatures = [
    {"protocol": "tcp", "port": 80, "content": "test-malware"},
    {"protocol": "tcp", "port": 443, "content": "suspicious-marker"},
]
packets = [
    {"protocol": "tcp", "port": 80, "payload": "test-malware"},
    {"protocol": "udp", "port": 53, "payload": "test-malware"},
    {"protocol": "tcp", "port": 443, "payload": "ordinary-data"},
]

for packet in packets:
    matched = any(
        packet["protocol"] == signature["protocol"]
        and packet["port"] == signature["port"]
        and signature["content"] in packet["payload"]
        for signature in signatures
    )
    if matched:
        print("IDS ALERT:", packet)
    else:
        print("No alert:", packet)
