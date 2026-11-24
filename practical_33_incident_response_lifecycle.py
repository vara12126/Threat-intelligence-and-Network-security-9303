"""
Practical 33: Incident Response Lifecycle Phase Classification
Subject: Threat Intelligence and Network Security

Aim:
    To classify incident response operational actions into NIST SP 800-61
    lifecycle phases: Preparation, Identification, Containment, Eradication,
    Recovery, and Lessons Learned.
"""

def classify_ir_action(action_desc):
    phases = {
        "Preparation": ["tabletop", "policy", "baseline", "playbook", "hardening", "backup config", "training"],
        "Identification": ["siem alert", "triage", "scope", "anomaly", "suspicious log", "detected", "ioc match"],
        "Containment": ["isolate", "quarantine", "block ip", "disable user", "segment vlan", "sever connection"],
        "Eradication": ["remove malware", "delete backdoor", "reimage", "patch vulnerability", "revoke certificate"],
        "Recovery": ["restore from backup", "reconnect host", "system validation", "return to service", "production"],
        "Lessons Learned": ["post-mortem", "incident report", "gap analysis", "root cause meeting", "review policy"]
    }

    desc_lower = action_desc.lower()
    for phase, keywords in phases.items():
        if any(kw in desc_lower for kw in keywords):
            return phase

    return "General Operations"


def main():
    print("=" * 74)
    print("  Practical 33: Incident Response Lifecycle Phase Classifier")
    print("=" * 74)

    soc_actions = [
        "Conducted a red team simulation exercise and updated the SOC incident playbook.",
        "SIEM alert triggered indicating multiple failed logins from external IP 198.51.100.22.",
        "Network engineers isolated the compromised web server from the corporate VLAN.",
        "Security analysts removed the webshell backdoor and patched Apache Struts vulnerability.",
        "Restored database cluster from clean offline backup and verified integrity in production.",
        "Conducted a post-mortem review meeting to document timeline and security control gaps."
    ]

    print(f"\n{'Action Description':<50} | {'IR Lifecycle Phase'}")
    print("-" * 74)
    for act in soc_actions:
        phase = classify_ir_action(act)
        print(f"{act[:48] + '..':<50} | {phase}")
    print("=" * 74)


if __name__ == "__main__":
    main()
