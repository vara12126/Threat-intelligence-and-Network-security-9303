"""
Practical 24: Security Baseline Compliance Checker
Subject: Threat Intelligence and Network Security

Aim:
    To compare an organization's current system configurations against
    a standardized minimum baseline and report compliance posture.
"""

def audit_baseline(baseline, current_settings):
    audit_results = []
    passed = 0

    for control, req in baseline.items():
        actual = current_settings.get(control, "NOT CONFIGURED")
        
        # Comparison logic
        if isinstance(req["expected"], int):
            status = "PASS" if actual >= req["expected"] else "FAIL"
        else:
            status = "PASS" if actual == req["expected"] else "FAIL"

        if status == "PASS":
            passed += 1

        audit_results.append({
            "control": control,
            "required": req["display"],
            "current": str(actual),
            "status": status
        })

    compliance_pct = (passed / len(baseline)) * 100
    return audit_results, compliance_pct


def main():
    print("=" * 72)
    print("  Practical 24: Security Baseline Configuration Audit")
    print("=" * 72)

    baseline = {
        "Min Password Length": {"expected": 14, "display": ">= 14 chars"},
        "Multi-Factor Auth":   {"expected": "ENABLED", "display": "ENABLED"},
        "Screen Lock Timeout": {"expected": 15, "display": "<= 15 mins"},
        "Disk Encryption":     {"expected": "ENABLED", "display": "ENABLED"},
        "Host Firewall":       {"expected": "ACTIVE", "display": "ACTIVE"},
        "Antivirus Definitions":{"expected": "CURRENT", "display": "CURRENT"}
    }

    current_config = {
        "Min Password Length": 8,            # Fails
        "Multi-Factor Auth":   "ENABLED",    # Passes
        "Screen Lock Timeout": 15,           # Passes
        "Disk Encryption":     "DISABLED",   # Fails
        "Host Firewall":       "ACTIVE",     # Passes
        "Antivirus Definitions":"CURRENT"    # Passes
    }

    results, pct = audit_baseline(baseline, current_config)

    print(f"\n{'Security Control':<24} | {'Required':<14} | {'Current':<14} | {'Status'}")
    print("-" * 72)
    for r in results:
        print(f"{r['control']:<24} | {r['required']:<14} | {r['current']:<14} | {r['status']}")
    print("-" * 72)

    print(f"\nOverall Compliance Score: {pct:.1f}%")
    failed = [r['control'] for r in results if r['status'] == 'FAIL']
    if failed:
        print(f"[!] Action Required: Remediation needed for {len(failed)} non-compliant control(s):")
        for f in failed:
            print(f"    - {f}")
    else:
        print("[+] System conforms 100% to mandatory baseline.")


if __name__ == "__main__":
    main()
