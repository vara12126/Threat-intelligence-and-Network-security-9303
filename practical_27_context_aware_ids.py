"""
Practical 27: Context-Aware Signature-Based IDS
Subject: Threat Intelligence and Network Security

Aim:
    To implement a context-aware IDS that inspects both protocol/port context
    and packet payload signatures to eliminate false positives.
"""

def inspect_traffic(packet_stream, ids_rules):
    inspections = []
    for pkt in packet_stream:
        alert_raised = False
        matching_rule = None

        for rule in ids_rules:
            # Check context (Protocol & Port)
            context_match = (pkt["proto"] == rule["proto"] and pkt["port"] == rule["port"])
            # Check payload pattern
            pattern_match = rule["pattern"].lower() in pkt["payload"].lower()

            if context_match and pattern_match:
                alert_raised = True
                matching_rule = rule["name"]
                break
            elif pattern_match and not context_match:
                # Signature present but context does not match (False positive avoided)
                pkt["fp_suppressed"] = f"Ignored pattern '{rule['pattern']}' in non-target port {pkt['port']}"

        inspections.append({
            "pkt": pkt,
            "alert": alert_raised,
            "rule": matching_rule
        })
    return inspections


def main():
    print("=" * 74)
    print("  Practical 27: Context-Aware Signature-Based IDS Simulation")
    print("=" * 74)

    rules = [
        {"name": "HTTP SQL Injection", "proto": "TCP", "port": 80, "pattern": "' OR 1=1"},
        {"name": "DNS Data Exfiltration", "proto": "UDP", "port": 53, "pattern": "base64_payload"}
    ]

    traffic = [
        {"id": 1, "proto": "TCP", "port": 80,  "payload": "GET /search?q=' OR 1=1 --"},
        {"id": 2, "proto": "TCP", "port": 25,  "payload": "Subject: Note: Code contains ' OR 1=1 in comments"},
        {"id": 3, "proto": "UDP", "port": 53,  "payload": "Query: base64_payload.attacker-dns.com"},
        {"id": 4, "proto": "TCP", "port": 80,  "payload": "GET /about.html"}
    ]

    print("\n[ACTIVE CONTEXT RULES]")
    for r in rules:
        print(f"  - {r['name']}: Proto={r['proto']} Port={r['port']} | Pattern='{r['pattern']}'")

    results = inspect_traffic(traffic, rules)

    print("\n" + "=" * 74)
    print(f"{'ID':<3} | {'Proto:Port':<11} | {'Status':<14} | {'Analysis / Justification'}")
    print("-" * 74)
    for res in results:
        p = res["pkt"]
        proto_port = f"{p['proto']}:{p['port']}"
        if res["alert"]:
            status = "ALERT TRIGGERED"
            msg = f"Match: {res['rule']} (Context & Pattern verified)"
        elif "fp_suppressed" in p:
            status = "SUPPRESSED"
            msg = f"False-Positive Filtered ({p['fp_suppressed']})"
        else:
            status = "NORMAL"
            msg = "Clean traffic (No matching pattern)"
        print(f"{p['id']:<3} | {proto_port:<11} | {status:<14} | {msg}")
    print("=" * 74)


if __name__ == "__main__":
    main()
