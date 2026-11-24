"""
Practical 31: Packet-Filtering Firewall Rule Engine
Subject: Threat Intelligence and Network Security

Aim:
    To create a simulated packet-filtering firewall demonstrating ordered rule
    evaluation, allow/deny actions, and default-deny enforcement.
"""

def evaluate_packet(packet, rule_base):
    for rule in rule_base:
        src_match = (rule["src"] == "ANY" or rule["src"] == packet["src_ip"])
        proto_match = (rule["proto"] == "ANY" or rule["proto"] == packet["proto"])
        port_match = (rule["port"] == "ANY" or rule["port"] == packet["dest_port"])

        if src_match and proto_match and port_match:
            return rule["action"], f"Matched Rule #{rule['id']} ({rule['desc']})"

    # Default policy
    return "DENY", "Implicit Default-Deny Rule"


def main():
    print("=" * 72)
    print("  Practical 31: Packet-Filtering Firewall Rule Engine")
    print("=" * 72)

    rule_base = [
        {"id": 1, "src": "192.168.1.10", "proto": "TCP", "port": 22,  "action": "ALLOW", "desc": "Admin SSH"},
        {"id": 2, "src": "ANY",          "proto": "TCP", "port": 80,  "action": "ALLOW", "desc": "Inbound Web HTTP"},
        {"id": 3, "src": "ANY",          "proto": "TCP", "port": 443, "action": "ALLOW", "desc": "Inbound Web HTTPS"},
        {"id": 4, "src": "203.0.113.88", "proto": "ANY", "port": "ANY","action": "DENY",  "desc": "Known Blacklisted Attacker"}
    ]

    packets = [
        {"id": 1, "src_ip": "192.168.1.10", "proto": "TCP", "dest_port": 22},
        {"id": 2, "src_ip": "10.0.0.15",    "proto": "TCP", "dest_port": 80},
        {"id": 3, "src_ip": "203.0.113.88", "proto": "TCP", "dest_port": 443},
        {"id": 4, "src_ip": "172.16.0.4",   "proto": "UDP", "dest_port": 53},
        {"id": 5, "src_ip": "10.0.0.99",    "proto": "TCP", "dest_port": 3389}
    ]

    print("\n[ACTIVE FIREWALL RULE BASE (Sequential Evaluation)]")
    for r in rule_base:
        print(f"  Rule #{r['id']}: {r['action']} {r['proto']} from {r['src']} to port {r['port']} -> {r['desc']}")
    print("  Default Rule: DENY ALL (Implicit drop)")

    print("\n" + "=" * 72)
    print(f"{'Pkt':<4} | {'Traffic Details':<25} | {'Verdict':<7} | {'Matching Reason'}")
    print("-" * 72)
    for pkt in packets:
        action, reason = evaluate_packet(pkt, rule_base)
        details = f"{pkt['proto']} {pkt['src_ip']} -> :{pkt['dest_port']}"
        print(f"{pkt['id']:<4} | {details:<25} | {action:<7} | {reason}")
    print("=" * 72)


if __name__ == "__main__":
    main()
