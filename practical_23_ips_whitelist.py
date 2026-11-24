"""
Practical 23: Intrusion Prevention System with Whitelist
Subject: Threat Intelligence and Network Security

Aim:
    To demonstrate a simplified signature-based Intrusion Prevention System (IPS)
    that drops malicious traffic while exempting trusted whitelisted hosts.
"""

def run_ips(traffic_stream, signatures, whitelist):
    results = []
    for pkt in traffic_stream:
        src = pkt["src_ip"]
        payload = pkt["payload"]
        
        # Check whitelist first (false-positive reduction)
        if src in whitelist:
            results.append({
                "pkt": pkt,
                "action": "ALLOWED",
                "reason": f"Whitelisted Host ({whitelist[src]})"
            })
            continue

        # Signature matching
        matched_sig = None
        for sig_name, sig_pattern in signatures.items():
            if sig_pattern.lower() in payload.lower():
                matched_sig = sig_name
                break

        if matched_sig:
            results.append({
                "pkt": pkt,
                "action": "BLOCKED",
                "reason": f"Signature Match: {matched_sig}"
            })
        else:
            results.append({
                "pkt": pkt,
                "action": "ALLOWED",
                "reason": "Clean Traffic (No Signature Match)"
            })
    return results


def main():
    print("=" * 70)
    print("  Practical 23: Signature-Based IPS with Whitelist Filtering")
    print("=" * 70)

    signatures = {
        "SQL Injection Attack": "' or '1'='1",
        "Directory Traversal": "../../etc/passwd",
        "Cross-Site Scripting": "<script>alert(1)</script>"
    }

    whitelist = {
        "10.0.0.99": "Authorized Internal Security Scanner",
        "192.168.1.10": "Central Admin Bastion"
    }

    traffic = [
        {"id": 1, "src_ip": "203.0.113.15", "dest_port": 80, "payload": "GET /login?user=' or '1'='1"},
        {"id": 2, "src_ip": "10.0.0.99",    "dest_port": 80, "payload": "GET /test?file=../../etc/passwd"},
        {"id": 3, "src_ip": "198.51.100.8", "dest_port": 80, "payload": "POST /comment payload=<script>alert(1)</script>"},
        {"id": 4, "src_ip": "192.168.1.55", "dest_port": 443,"payload": "GET /index.html"}
    ]

    print("\n[ACTIVE SIGNATURES]")
    for name, pattern in signatures.items():
        print(f"  - {name}: \"{pattern}\"")

    print("\n[WHITELISTED SOURCES]")
    for ip, desc in whitelist.items():
        print(f"  - {ip}: {desc}")

    evaluations = run_ips(traffic, signatures, whitelist)

    print("\n" + "=" * 70)
    print(f"{'ID':<3} | {'Source IP':<14} | {'Action':<8} | {'Reason'}")
    print("-" * 70)
    for ev in evaluations:
        pkt = ev["pkt"]
        print(f"{pkt['id']:<3} | {pkt['src_ip']:<14} | {ev['action']:<8} | {ev['reason']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
