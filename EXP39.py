# LAB 39: Threat Intelligence Platform (TIP) Simulation
# Aim: Normalize feed IOCs and correlate them against internal logs.

raw_iocs = [
    {"type": "IP", "value": "198.51.100.42"},
    {"type": "domain", "value": "BAD.EXAMPLE"},
    {"type": "hash", "value": "A1B2C3D4"},
]
internal_logs = [
    {"source": "firewall", "indicator_type": "ip", "indicator": "198.51.100.42"},
    {"source": "dns", "indicator_type": "domain", "indicator": "bad.example"},
]

normalized_iocs = {
    (item["type"].lower(), item["value"].strip().lower())
    for item in raw_iocs
}
for log in internal_logs:
    log_indicator = (log["indicator_type"].lower(), log["indicator"].strip().lower())
    if log_indicator in normalized_iocs:
        print(
            "TIP ALERT:",
            log_indicator[0],
            log_indicator[1],
            "matched in",
            log["source"],
            "logs",
        )
