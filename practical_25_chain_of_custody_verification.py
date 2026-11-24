"""
Practical 25: Digital Forensics Chain of Custody Verification
Subject: Threat Intelligence and Network Security

Aim:
    To verify digital forensic evidence records using SHA-256 hashes
    and timestamp chronological sequences to ensure evidentiary integrity.
"""

import hashlib

def calculate_evidence_hash(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()

def verify_chain_of_custody(evidence_ledger):
    anomalies = []
    
    for i, record in enumerate(evidence_ledger):
        # 1. Integrity check: recorded hash vs current hash
        calc_hash = calculate_evidence_hash(record["data"].encode('utf-8'))
        if calc_hash != record["recorded_hash"]:
            anomalies.append(f"Hash mismatch at step {i+1} by {record['custodian']} (Data Tampered)")

        # 2. Chronological sequence check
        if i > 0:
            if record["timestamp"] < evidence_ledger[i-1]["timestamp"]:
                anomalies.append(f"Timestamp anomaly at step {i+1} (Chronological violation)")
            if record["previous_custodian"] != evidence_ledger[i-1]["custodian"]:
                anomalies.append(f"Broken custody transfer link between step {i} and {i+1}")

    return anomalies


def main():
    print("=" * 72)
    print("  Practical 25: Digital Forensics Chain of Custody Verification")
    print("=" * 72)

    evidence_content = "Disk image partition dump: MD5 verified, Sector 0-4096"
    initial_hash = calculate_evidence_hash(evidence_content.encode('utf-8'))

    # Ledger of custody transfers
    ledger = [
        {
            "step": 1,
            "custodian": "Officer Alice",
            "previous_custodian": "Scene of Crime",
            "timestamp": "2026-11-20 09:00:00",
            "action": "Seizure & Imaging",
            "data": evidence_content,
            "recorded_hash": initial_hash
        },
        {
            "step": 2,
            "custodian": "Forensic Analyst Bob",
            "previous_custodian": "Officer Alice",
            "timestamp": "2026-11-20 11:30:00",
            "action": "Evidence Vault Storage",
            "data": evidence_content,
            "recorded_hash": initial_hash
        },
        {
            "step": 3,
            "custodian": "Lab Lead Carol",
            "previous_custodian": "Forensic Analyst Bob",
            "timestamp": "2026-11-20 14:15:00",
            "action": "Forensic Analysis",
            "data": evidence_content,
            "recorded_hash": initial_hash
        }
    ]

    print("\n[EVIDENCE CUSTODY LEDGER]")
    print(f"{'Step':<5} | {'Custodian':<20} | {'Timestamp':<20} | {'Action'}")
    print("-" * 72)
    for record in ledger:
        print(f"{record['step']:<5} | {record['custodian']:<20} | {record['timestamp']:<20} | {record['action']}")

    print(f"\nInitial Evidence SHA-256 Hash: {initial_hash}")

    anomalies = verify_chain_of_custody(ledger)

    print("\n" + "=" * 72)
    print("  VERIFICATION RESULT")
    print("=" * 72)
    if not anomalies:
        print("[+] Chain of Custody: INTACT & VERIFIED")
        print("[+] Hash Integrity   : ALL CHECKS PASSED (No tampering)")
        print("[+] Timestamp Order  : VALID CHRONOLOGICAL SEQUENCE")
        print("[+] Custodial Links  : CONTINUOUS & UNBROKEN")
    else:
        print("[!] Chain of Custody compromised:")
        for err in anomalies:
            print(f"    - {err}")


if __name__ == "__main__":
    main()
