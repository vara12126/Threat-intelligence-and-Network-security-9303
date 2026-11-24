"""
Practical 39: Threat Intelligence Platform (TIP) Pipeline Simulation
Subject: Threat Intelligence and Network Security

Aim:
    To simulate an automated TIP workflow: Feed Ingestion -> Normalization ->
    Internal Telemetry Correlation -> High-Fidelity Alert Generation.
"""

def tip_pipeline(raw_feed, internal_telemetry):
    # Step 1: Normalization
    normalized_iocs = {}
    for item in raw_feed:
        key = item["value"].lower().strip()
        normalized_iocs[key] = {
            "type": item["type"].upper(),
            "threat": item["threat"],
            "severity": item["severity"]
        }

    # Step 2: Correlation against internal telemetry
    alerts = []
    for log in internal_telemetry:
        val = log["observed_value"].lower().strip()
        if val in normalized_iocs:
            ioc = normalized_iocs[val]
            alerts.append({
                "source_host": log["host"],
                "timestamp": log["timestamp"],
                "ioc_type": ioc["type"],
                "indicator": val,
                "threat": ioc["threat"],
                "severity": ioc["severity"]
            })

    return normalized_iocs, alerts


def main():
    print("=" * 72)
    print("  Practical 39: Threat Intelligence Platform (TIP) Simulation")
    print("=" * 72)

    # Simulated external threat feed
    threat_feed = [
        {"type": "IP",     "value": "198.51.100.99", "threat": "Cobalt Strike C2", "severity": "HIGH"},
        {"type": "DOMAIN", "value": "login-fake-bank.com", "threat": "Credential Harvester", "severity": "CRITICAL"},
        {"type": "HASH",   "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat": "Ransomware Dropper", "severity": "CRITICAL"}
    ]

    # Internal endpoint and network activity telemetry
    internal_logs = [
        {"timestamp": "12:00:15", "host": "SRV-WEB-01",  "observed_value": "198.51.100.99"},
        {"timestamp": "12:05:30", "host": "W10-FINANCE", "observed_value": "login-fake-bank.com"},
        {"timestamp": "12:10:00", "host": "W10-HR",      "observed_value": "8.8.8.8"}
    ]

    print("\n--- [STAGE 1: FEED INGESTION & NORMALIZATION] ---")
    iocs, alerts = tip_pipeline(threat_feed, internal_logs)
    print(f"Successfully normalized {len(iocs)} indicators from external CTI feeds.")

    print("\n--- [STAGE 2: INTERNAL TELEMETRY CORRELATION & ALERTING] ---")
    print(f"Total Internal Logs Screened: {len(internal_logs)}")
    print(f"Correlated Detections       : {len(alerts)}\n")

    for a in alerts:
        print(f"[!] ALERT: Matched {a['ioc_type']} Threat Indicator")
        print(f"    Host Affected : {a['source_host']} at {a['timestamp']}")
        print(f"    Indicator     : {a['indicator']}")
        print(f"    Threat Class  : {a['threat']}")
        print(f"    Alert Priority: {a['severity']}")
        print("-" * 50)


if __name__ == "__main__":
    main()
