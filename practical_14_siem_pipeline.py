"""
Practical 14: End-to-End SIEM Architecture Simulation
Subject: Threat Intelligence and Network Security

Aim:
    To simulate the end-to-end operational pipeline of a Security Information
    and Event Management (SIEM) system across four core stages:
    1. Event Collection (Ingesting multi-source heterogeneous security logs)
    2. Event Normalization (Parsing and standardizing schema fields)
    3. Event Correlation (Applying detection rules across events)
    4. Alerting (Generating actionable high-fidelity security alerts)

Description:
    SIEM platforms are the central brain of modern Security Operations Centers.
    Disparate devices (firewalls, active directory domain controllers, endpoint agents)
    emit logs in diverse formats. The SIEM ingests them, maps them to a common data model
    (CDM), correlates patterns across time and hosts (such as brute force or malware execution),
    and alerts analysts to investigate.
"""

import sys
import json
from datetime import datetime

# Sample heterogeneous raw events simulating real enterprise telemetry
RAW_EVENTS_DATASET = [
    # Event 1: Normal firewall traffic
    {
        "source_format": "firewall_syslog",
        "raw_text": "2026-10-29T10:00:01Z FW-EDGE-01 action=ALLOW proto=TCP src=192.168.1.15 dst=93.184.216.34 dport=443"
    },
    # Event 2: Auth failure (Brute force attempt 1)
    {
        "source_format": "auth_json",
        "raw_dict": {
            "time": "2026-10-29T10:00:15Z",
            "host": "AUTH-SRV-01",
            "event": "user_login_failed",
            "username": "admin",
            "client_ip": "198.51.100.77"
        }
    },
    # Event 3: Auth failure (Brute force attempt 2)
    {
        "source_format": "auth_json",
        "raw_dict": {
            "time": "2026-10-29T10:00:18Z",
            "host": "AUTH-SRV-01",
            "event": "user_login_failed",
            "username": "admin",
            "client_ip": "198.51.100.77"
        }
    },
    # Event 4: Auth failure (Brute force attempt 3 - threshold trigger)
    {
        "source_format": "auth_json",
        "raw_dict": {
            "time": "2026-10-29T10:00:22Z",
            "host": "AUTH-SRV-01",
            "event": "user_login_failed",
            "username": "admin",
            "client_ip": "198.51.100.77"
        }
    },
    # Event 5: Normal endpoint activity
    {
        "source_format": "endpoint_edr",
        "raw_dict": {
            "timestamp": "2026-10-29T10:01:05Z",
            "endpoint": "WS-FINANCE-02",
            "process": "notepad.exe",
            "command_line": "notepad.exe report.txt",
            "user": "corporate\\sarah"
        }
    },
    # Event 6: Suspicious endpoint activity (Encoded PowerShell / privilege manipulation)
    {
        "source_format": "endpoint_edr",
        "raw_dict": {
            "timestamp": "2026-10-29T10:02:10Z",
            "endpoint": "WS-FINANCE-02",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... -nop -w hidden",
            "user": "corporate\\sarah"
        }
    }
]


def normalize_event(raw_item: dict) -> dict:
    """
    Normalizes diverse log formats into a unified Common Data Model (CDM) dictionary:
    {timestamp, source, event_type, severity, details}
    """
    fmt = raw_item.get("source_format")

    if fmt == "firewall_syslog":
        text = raw_item.get("raw_text", "")
        parts = text.split()
        if len(parts) < 4:
            raise ValueError("Malformed firewall syslog entry.")
        ts = parts[0]
        device = parts[1]
        kv = {}
        for token in parts[2:]:
            if "=" in token:
                k, v = token.split("=", 1)
                kv[k] = v
        action = kv.get("action", "UNKNOWN")
        severity = "LOW" if action == "ALLOW" else "MEDIUM"
        return {
            "timestamp": ts,
            "source": f"firewall:{device}",
            "event_type": "network_traffic",
            "severity": severity,
            "details": {
                "action": action,
                "src_ip": kv.get("src", "0.0.0.0"),
                "dst_ip": kv.get("dst", "0.0.0.0"),
                "dport": kv.get("dport", "0")
            }
        }

    elif fmt == "auth_json":
        data = raw_item.get("raw_dict", {})
        if not data or "event" not in data:
            raise ValueError("Malformed authentication log entry.")
        event_name = data.get("event", "auth_event")
        is_failure = "fail" in event_name.lower()
        return {
            "timestamp": data.get("time", datetime.utcnow().isoformat()),
            "source": f"auth:{data.get('host', 'unknown')}",
            "event_type": "authentication",
            "severity": "MEDIUM" if is_failure else "LOW",
            "details": {
                "user": data.get("username", "anonymous"),
                "status": "FAILED" if is_failure else "SUCCESS",
                "client_ip": data.get("client_ip", "0.0.0.0")
            }
        }

    elif fmt == "endpoint_edr":
        data = raw_item.get("raw_dict", {})
        if not data or "process" not in data:
            raise ValueError("Malformed endpoint event entry.")
        proc = data.get("process", "").lower()
        cmd = data.get("command_line", "")
        # Suspicious heuristic
        is_suspicious = any(flag in cmd.lower() for flag in ["-enc", "-nop", "mimikatz", "vssadmin", "bypass"])
        return {
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
            "source": f"endpoint:{data.get('endpoint', 'unknown')}",
            "event_type": "process_creation",
            "severity": "HIGH" if is_suspicious else "LOW",
            "details": {
                "process": data.get("process"),
                "command_line": cmd,
                "user": data.get("user", "SYSTEM"),
                "suspicious_indicators": is_suspicious
            }
        }

    else:
        raise ValueError(f"Unsupported source format: {fmt}")


def run_correlation(normalized_events: list) -> list:
    """
    Applies correlation rules across normalized security events:
    Rule 1: Multiple failed login attempts (Threshold >= 3 from same IP/user)
    Rule 2: Suspicious endpoint activity (Obfuscated or dangerous execution)
    """
    findings = []

    # Rule 1: Brute force / repeated failed authentication
    failed_logins = {}
    for ev in normalized_events:
        if ev["event_type"] == "authentication" and ev["details"].get("status") == "FAILED":
            key = (ev["details"].get("user"), ev["details"].get("client_ip"))
            failed_logins[key] = failed_logins.get(key, 0) + 1

    for (user, src_ip), count in failed_logins.items():
        if count >= 3:
            findings.append({
                "rule_id": "CORR-RULE-001",
                "rule_name": "Multiple failed login attempts",
                "severity": "HIGH",
                "alert_title": "Repeated authentication failures",
                "evidence": f"{count} consecutive failed login attempts detected for user '{user}' from IP {src_ip}."
            })

    # Rule 2: Suspicious endpoint activity
    for ev in normalized_events:
        if ev["event_type"] == "process_creation" and ev["details"].get("suspicious_indicators"):
            findings.append({
                "rule_id": "CORR-RULE-002",
                "rule_name": "Suspicious endpoint activity",
                "severity": "HIGH",
                "alert_title": "Suspicious endpoint behavior",
                "evidence": f"Host {ev['source']} executed obfuscated command: '{ev['details']['command_line'][:45]}...' by {ev['details']['user']}."
            })

    return findings


def execute_siem_pipeline(events_dataset: list):
    """Executes the full 4-stage SIEM pipeline simulation."""
    print("=" * 70)
    print("PRACTICAL 14: SIEM PIPELINE SIMULATION")
    print("=" * 70)

    # STAGE 1: Collection
    print("\nStage 1: Collection")
    raw_count = len(events_dataset)
    print(f"Raw events collected: {raw_count}")

    # STAGE 2: Normalization
    print("\nStage 2: Normalization")
    normalized_events = []
    malformed_count = 0
    for idx, raw in enumerate(events_dataset, 1):
        try:
            norm = normalize_event(raw)
            normalized_events.append(norm)
        except Exception as e:
            malformed_count += 1
            print(f"  [Warning] Event {idx} malformed: {e}")

    print(f"Successfully normalized: {len(normalized_events)}")
    if malformed_count > 0:
        print(f"Discarded/Malformed events: {malformed_count}")

    # STAGE 3: Correlation
    print("\nStage 3: Correlation")
    correlation_matches = run_correlation(normalized_events)
    for match in correlation_matches:
        print(f"Rule matched: {match['rule_name']}")

    # STAGE 4: Alerting
    print("\nStage 4: Alerting")
    for idx, alert in enumerate(correlation_matches, 1):
        print(f"Alert {idx}: {alert['alert_title']} - {alert['severity']}")
        print(f"         Rule: {alert['rule_id']} | Evidence: {alert['evidence']}")

    print("\nSIEM pipeline completed.")
    print("=" * 70 + "\n")


def main():
    execute_siem_pipeline(RAW_EVENTS_DATASET)


if __name__ == "__main__":
    main()
