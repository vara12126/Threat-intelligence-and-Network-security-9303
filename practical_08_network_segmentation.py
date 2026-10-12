"""
Practical 08: Network Segmentation & Lateral Movement Prevention Simulator
Subject: Threat Intelligence and Network Security

Aim:
    To model a multi-tier segmented enterprise network architecture:
      - Segment 1: Guest Wi-Fi Zone (VLAN 10 - 192.168.10.0/24)
      - Segment 2: Employee Workstation Zone (VLAN 20 - 192.168.20.0/24)
      - Segment 3: Application Server Zone / DMZ (VLAN 30 - 192.168.30.0/24)
      - Segment 4: Sensitive Database Zone (VLAN 40 - 10.10.40.0/24)
    and enforce Access Control Lists (ACLs) to validate permitted traffic and
    block unauthorized lateral movement attempts.
"""

import ipaddress
import sys

# Network segment definitions with subnets and security tiers
SEGMENTS = {
    "GUEST": {
        "name": "Guest Wi-Fi Segment (VLAN 10)",
        "subnet": ipaddress.ip_network("192.168.10.0/24"),
        "trust_level": "Untrusted / External"
    },
    "EMPLOYEE": {
        "name": "Employee Workstation Segment (VLAN 20)",
        "subnet": ipaddress.ip_network("192.168.20.0/24"),
        "trust_level": "Medium / Corporate Users"
    },
    "SERVER": {
        "name": "Application Server DMZ (VLAN 30)",
        "subnet": ipaddress.ip_network("192.168.30.0/24"),
        "trust_level": "High / Business Services"
    },
    "DATABASE": {
        "name": "Sensitive Database Vault (VLAN 40)",
        "subnet": ipaddress.ip_network("10.10.40.0/24"),
        "trust_level": "Critical / Restricted Crown Jewels"
    },
    "INTERNET": {
        "name": "External Public Internet",
        "subnet": None,
        "trust_level": "Untrusted / Public Web"
    }
}

# Firewall Access Control List (ACL) Matrix
# Format: (Source_Segment, Destination_Segment, Allowed_Ports, Description)
ACL_RULES = [
    # Guest Rules
    ("GUEST", "INTERNET", [80, 443], "Allow guest outbound web navigation"),
    # Employee Rules
    ("EMPLOYEE", "INTERNET", [80, 443, 53], "Allow employee internet and DNS"),
    ("EMPLOYEE", "SERVER", [80, 443, 22], "Allow employee access to web services and admin SSH"),
    # Server Rules
    ("SERVER", "DATABASE", [3306, 5432], "Allow application server queries to database (SQL)"),
    ("SERVER", "INTERNET", [443, 123], "Allow server package updates and NTP sync"),
]


def identify_segment(ip_str: str) -> str:
    """Resolves an IP address to its corresponding network segment."""
    if ip_str == "INTERNET" or ip_str == "0.0.0.0":
        return "INTERNET"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for seg_key, seg_info in SEGMENTS.items():
            if seg_info["subnet"] and ip_obj in seg_info["subnet"]:
                return seg_key
        return "INTERNET"
    except ValueError:
        return "INTERNET"


def evaluate_packet(src_ip: str, dst_ip: str, port: int, protocol: str = "TCP") -> dict:
    """
    Evaluates packet flow through segmentation firewall ACLs.
    Identifies allowed business flows vs prohibited lateral movements.
    """
    src_seg = identify_segment(src_ip)
    dst_seg = identify_segment(dst_ip)

    # Check ACL table
    for rule_src, rule_dst, allowed_ports, desc in ACL_RULES:
        if src_seg == rule_src and dst_seg == rule_dst:
            if port in allowed_ports:
                return {
                    "action": "PERMIT",
                    "src_seg": src_seg,
                    "dst_seg": dst_seg,
                    "rule": desc,
                    "reason": f"Authorized flow: {src_seg} -> {dst_seg} on port {port}."
                }

    # If no rule matches, default implicit deny
    # Check if this represents an unauthorized lateral movement attempt
    is_lateral = (src_seg in ["GUEST", "EMPLOYEE"] and dst_seg in ["EMPLOYEE", "DATABASE", "SERVER"])
    action_type = "BLOCKED - LATERAL MOVEMENT DETECTED" if is_lateral else "BLOCKED - IMPLICIT DENY"

    return {
        "action": action_type,
        "src_seg": src_seg,
        "dst_seg": dst_seg,
        "rule": "Default Implicit Deny Rule 999",
        "reason": f"Security violation: Direct connection from {src_seg} to {dst_seg} on port {port} is prohibited."
    }


# Realistic enterprise connection scenarios
TEST_SCENARIOS = [
    {
        "name": "Guest Navigating Web (Normal)",
        "src": "192.168.10.45",
        "dst": "INTERNET",
        "port": 443,
        "proto": "TCP"
    },
    {
        "name": "Employee Accessing Internal Web App (Normal)",
        "src": "192.168.20.15",
        "dst": "192.168.30.10",
        "port": 443,
        "proto": "TCP"
    },
    {
        "name": "Web Server Querying Database (Normal)",
        "src": "192.168.30.10",
        "dst": "10.10.40.5",
        "port": 3306,
        "proto": "TCP"
    },
    {
        "name": "Compromised Employee Workstation Pivoting to DB (Lateral Attack)",
        "src": "192.168.20.88",
        "dst": "10.10.40.5",
        "port": 3306,
        "proto": "TCP"
    },
    {
        "name": "Rogue Guest Scanning Employee Workstations (Lateral Reconnaissance)",
        "src": "192.168.10.99",
        "dst": "192.168.20.15",
        "port": 445,
        "proto": "TCP"
    },
    {
        "name": "Guest Attempting Direct Database Access (Hostile Breach Attempt)",
        "src": "192.168.10.99",
        "dst": "10.10.40.5",
        "port": 5432,
        "proto": "TCP"
    }
]


def display_simulation_report(scenarios: list):
    """Outputs firewall inspection log and segmentation evaluation table."""
    print("\n" + "=" * 80)
    print("      NETWORK SEGMENTATION & LATERAL MOVEMENT ENFORCEMENT REPORT")
    print("=" * 80)
    print("Configured Network Zones:")
    for key, data in SEGMENTS.items():
        subnet_str = str(data["subnet"]) if data["subnet"] else "Public WAN"
        print(f"  * [{key:<8}] {data['name']:<42} | Subnet: {subnet_str}")
    print("-" * 80)
    print(f"{'#':<3} {'SCENARIO / TRAFFIC FLOW':<36} {'PORT':<6} {'FIREWALL ACTION':<20} {'RESULT'}")
    print("-" * 80)

    blocked_attacks = 0
    permitted_flows = 0

    for idx, sc in enumerate(scenarios, 1):
        decision = evaluate_packet(sc["src"], sc["dst"], sc["port"], sc["proto"])
        status_tag = "[ALLOWED]" if decision["action"] == "PERMIT" else "[DENIED]"
        flow_str = f"{sc['src']} -> {sc['dst']}"
        action_short = decision["action"].split(" - ")[0]

        print(f"{idx:<3} {sc['name'][:35]:<36} {sc['port']:<6} {action_short:<20} {status_tag}")
        print(f"    Flow: {flow_str} ({decision['src_seg']} -> {decision['dst_seg']})")
        print(f"    Decision Reason: {decision['reason']}")
        print(f"    Matching Rule  : {decision['rule']}")
        print("    " + "." * 74)

        if decision["action"] == "PERMIT":
            permitted_flows += 1
        else:
            blocked_attacks += 1

    print("-" * 80)
    print(f"SUMMARY: Total Tests: {len(scenarios)} | Permitted: {permitted_flows} | Blocked Threats: {blocked_attacks}")
    print("\nSECURITY CONCLUSION:")
    print("  - Strict network micro-segmentation successfully isolated the Crown Jewels (Database).")
    print("  - Direct lateral pivoting from Employee workstations and Guest VLAN was thwarted,")
    print("    forcing all database transactions to traverse hardened application proxies.")
    print("=" * 80 + "\n")


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 08: Network Segmentation Simulator")
    print("======================================================================")
    print("Running enterprise traffic flow audit across configured network segments...")
    display_simulation_report(TEST_SCENARIOS)


if __name__ == "__main__":
    main()
