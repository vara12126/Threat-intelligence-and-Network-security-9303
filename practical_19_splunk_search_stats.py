"""
Practical 19: Splunk Search Filter and Stats Count Simulation
Subject: Threat Intelligence and Network Security

Aim:
    To simulate the core analytical operations of the Splunk Search Processing
    Language (SPL) within a Python environment, reproducing:
    1. Search Filtering (Filtering security events by key-value conditions)
    2. Statistical Aggregation (Calculating 'stats count by <field>')

Description:
    Splunk is the industry-leading Security Information and Event Management (SIEM)
    and log analytics platform. Security Operations Center (SOC) analysts construct
    SPL queries (e.g., `index=security severity=high | stats count by source`) to
    filter millions of log entries and produce statistical breakdowns during threat hunting
    and incident triage.
"""

import sys

# Simulated enterprise dataset of 10 security logs across firewall, auth, and endpoint
SPLUNK_DATASET = [
    # Firewall events (4)
    {
        "event_id": "EVT-1001",
        "timestamp": "2026-10-29T08:15:20Z",
        "source": "firewall",
        "event_type": "traffic_drop",
        "severity": "high",
        "user": "N/A",
        "status": "blocked",
        "ip": "203.0.113.88",
        "description": "Inbound connection on disallowed port 23 (Telnet) dropped."
    },
    {
        "event_id": "EVT-1002",
        "timestamp": "2026-10-29T08:15:45Z",
        "source": "firewall",
        "event_type": "traffic_allow",
        "severity": "low",
        "user": "N/A",
        "status": "allowed",
        "ip": "192.168.1.100",
        "description": "Outbound HTTPS web session permitted to port 443."
    },
    {
        "event_id": "EVT-1003",
        "timestamp": "2026-10-29T08:16:02Z",
        "source": "firewall",
        "event_type": "ddos_spike",
        "severity": "high",
        "user": "N/A",
        "status": "blocked",
        "ip": "198.51.100.12",
        "description": "SYN flood threshold exceeded from external IP."
    },
    {
        "event_id": "EVT-1004",
        "timestamp": "2026-10-29T08:16:30Z",
        "source": "firewall",
        "event_type": "traffic_allow",
        "severity": "low",
        "user": "N/A",
        "status": "allowed",
        "ip": "192.168.1.105",
        "description": "Internal DNS query allowed to corporate resolver."
    },

    # Authentication events (3)
    {
        "event_id": "EVT-1005",
        "timestamp": "2026-10-29T08:17:10Z",
        "source": "authentication",
        "event_type": "login_failure",
        "severity": "medium",
        "user": "admin",
        "status": "failed",
        "ip": "198.51.100.44",
        "description": "Password authentication failed for privileged user."
    },
    {
        "event_id": "EVT-1006",
        "timestamp": "2026-10-29T08:17:14Z",
        "source": "authentication",
        "event_type": "login_failure",
        "severity": "medium",
        "user": "admin",
        "status": "failed",
        "ip": "198.51.100.44",
        "description": "Repeated password authentication failed."
    },
    {
        "event_id": "EVT-1007",
        "timestamp": "2026-10-29T08:18:00Z",
        "source": "authentication",
        "event_type": "login_success",
        "severity": "low",
        "user": "alice",
        "status": "success",
        "ip": "192.168.1.150",
        "description": "SSO Kerberos ticket granted for user alice."
    },

    # Endpoint events (3)
    {
        "event_id": "EVT-1008",
        "timestamp": "2026-10-29T08:19:12Z",
        "source": "endpoint",
        "event_type": "process_create",
        "severity": "low",
        "user": "alice",
        "status": "executed",
        "ip": "192.168.1.150",
        "description": "User launched chrome.exe from system path."
    },
    {
        "event_id": "EVT-1009",
        "timestamp": "2026-10-29T08:20:05Z",
        "source": "endpoint",
        "event_type": "suspicious_script",
        "severity": "high",
        "user": "bob",
        "status": "quarantined",
        "ip": "192.168.1.180",
        "description": "Encoded PowerShell script blocked by EDR behavior engine."
    },
    {
        "event_id": "EVT-1010",
        "timestamp": "2026-10-29T08:21:40Z",
        "source": "endpoint",
        "event_type": "usb_mount",
        "severity": "medium",
        "user": "bob",
        "status": "audited",
        "ip": "192.168.1.180",
        "description": "Removable USB mass storage device connected."
    }
]


def filter_splunk_search(dataset: list, search_field: str, search_val: str) -> list:
    """
    Simulates Splunk's initial search stage: field=value.
    Case-insensitive matching.
    """
    field_lower = search_field.lower().strip()
    val_lower = search_val.lower().strip()

    matches = []
    for evt in dataset:
        if field_lower in evt:
            actual = str(evt[field_lower]).lower()
            if actual == val_lower or val_lower in actual:
                matches.append(evt)
    return matches


def stats_count_by(dataset: list, group_by_field: str) -> dict:
    """
    Simulates Splunk SPL: `| stats count by <field>`.
    Returns a dictionary of counts grouped by field values.
    """
    field_lower = group_by_field.lower().strip()
    counts = {}

    for evt in dataset:
        val = evt.get(field_lower, "UNKNOWN")
        counts[val] = counts.get(val, 0) + 1

    return counts


def execute_splunk_simulation(search_query: str = "severity=high", group_field: str = "source"):
    """Runs search filtering and aggregation on the dataset."""
    print("=" * 70)
    print("PRACTICAL 19: SPLUNK SEARCH AND STATS SIMULATION")
    print("=" * 70)
    print(f"Dataset Size: {len(SPLUNK_DATASET)} total events")
    print("Simulated SPL Command:")
    print(f"  index=security {search_query} | stats count by {group_field}")
    print("-" * 70)

    # Parse search query (field=value)
    if "=" in search_query:
        s_field, s_val = search_query.split("=", 1)
    else:
        s_field, s_val = "severity", search_query

    # Operation 1: Search filter
    filtered_events = filter_splunk_search(SPLUNK_DATASET, s_field, s_val)
    print(f"\nSearch: {search_query}")
    print(f"Matching Events: {len(filtered_events)}")

    if filtered_events:
        print("Matching Event Details:")
        for ev in filtered_events:
            print(f"  [{ev['event_id']}] {ev['timestamp']} | src={ev['source']} | type={ev['event_type']} | sev={ev['severity']}")
            print(f"           desc: {ev['description']}")
    else:
        print(f"  (No events matched the condition '{search_query}')")

    # Operation 2: Stats count by field across total dataset
    print(f"\nStats: count by {group_field}")
    grouped_counts = stats_count_by(SPLUNK_DATASET, group_field)

    for group_val, cnt in grouped_counts.items():
        bar = "=" * cnt
        print(f"{group_val}: {cnt}  {bar}")

    print("\nSearch and aggregation completed.")
    print("-" * 70)
    print("Environment Notice: This is a Python simulation reproducing Splunk SPL logic.")
    print("No external Splunk Enterprise or Cloud instance is required.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Practical 19: Splunk Search and Aggregation Simulator")
    print("======================================================================")
    print("Available Fields: source, severity, event_type, status, user, ip")
    print("Examples of Splunk searches:")
    print("  [1] severity=high")
    print("  [2] status=failed")
    print("  [3] source=firewall")
    print("-" * 70)

    try:
        query_input = input("Enter search filter (e.g., severity=high) [Enter for default]: ").strip()
    except (EOFError, KeyboardInterrupt):
        query_input = ""

    if not query_input:
        query_input = "severity=high"

    try:
        group_input = input("Enter grouping field for stats (e.g., source) [Enter for default]: ").strip()
    except (EOFError, KeyboardInterrupt):
        group_input = ""

    if not group_input:
        group_input = "source"

    execute_splunk_simulation(query_input, group_input)


if __name__ == "__main__":
    main()
