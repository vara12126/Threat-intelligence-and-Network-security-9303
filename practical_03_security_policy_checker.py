"""
Practical 03: Information Security Policy Compliance Checker
Subject: Threat Intelligence and Network Security

Aim:
    To analyze a draft organizational Information Security Policy (ISP),
    audit it against standard governance frameworks (ISO/IEC 27001 / NIST CSF),
    and check for the five mandatory structural pillars:
      1. Scope
      2. Roles and Responsibilities
      3. Enforcement and Compliance
      4. Review Cycle
      5. Approval Authority
"""

import sys
import re

# Policy evaluation framework with regex patterns and semantic indicators
POLICY_PILLARS = {
    "Scope": {
        "description": "Defines applicable personnel, locations, hardware, cloud, and digital assets.",
        "patterns": [
            r"\bscope\b", r"\bapplies to\b", r"\ball employees\b", r"\bcontractors\b",
            r"\bcorporate network\b", r"\bdevices\b", r"\binformation assets\b"
        ],
        "weight": 20
    },
    "Roles and Responsibilities": {
        "description": "Specifies duties for CISO, IT Administrators, Data Owners, and end-users.",
        "patterns": [
            r"\broles?\b", r"\bresponsibilit(y|ies)\b", r"\bciso\b", r"\badministrator\b",
            r"\bmanagement\b", r"\bsecurity team\b", r"\bincident response team\b", r"\bduties\b"
        ],
        "weight": 20
    },
    "Enforcement": {
        "description": "Outlines non-compliance consequences, penalties, disciplinary actions, or legal recourse.",
        "patterns": [
            r"\benforce(ment)?\b", r"\bdisciplinary\b", r"\bpenalt(y|ies)\b", r"\btermination\b",
            r"\bnon-compliance\b", r"\bsuspension\b", r"\baction will be taken\b", r"\bbreach\b"
        ],
        "weight": 20
    },
    "Review Cycle": {
        "description": "Mandates periodic audit intervals (e.g., annual review, quarterly updates).",
        "patterns": [
            r"\bannual review\b", r"\bannually\b", r"\bevery year\b", r"\bevery 12 months\b",
            r"\bquarterly\b", r"\breview cycle\b", r"\baudit cycle\b", r"\bperiodic revision\b"
        ],
        "weight": 20
    },
    "Approval Authority": {
        "description": "Formal sign-off by executive leadership, Board, CIO, or CISO.",
        "patterns": [
            r"\bapprov(ed|al)\b", r"\bsign-off\b", r"\bboard of directors\b", r"\bcio\b",
            r"\bchief information security officer\b", r"\bexecutive management\b", r"\bauthorized by\b"
        ],
        "weight": 20
    }
}


def audit_security_policy(policy_text: str) -> dict:
    """
    Evaluates policy text against all 5 governance pillars,
    computing presence, evidence snippets, and an overall compliance score.
    """
    results = {}
    total_score = 0
    text_lower = policy_text.lower()

    for pillar, data in POLICY_PILLARS.items():
        matched_indicators = []
        for pattern in data["patterns"]:
            matches = re.findall(pattern, text_lower)
            if matches:
                matched_indicators.append(pattern.replace(r"\b", "").replace("?", ""))

        is_present = len(matched_indicators) > 0
        score = data["weight"] if is_present else 0
        total_score += score

        results[pillar] = {
            "present": is_present,
            "score": score,
            "max_score": data["weight"],
            "indicators": list(set(matched_indicators)),
            "description": data["description"]
        }

    return {
        "total_score": total_score,
        "max_possible": sum(d["weight"] for d in POLICY_PILLARS.values()),
        "pillars": results
    }


def display_audit_report(policy_title: str, policy_text: str, audit_data: dict):
    """Prints a structured governance audit report with actionable remediation."""
    print("\n" + "=" * 75)
    print("         INFORMATION SECURITY POLICY AUDIT REPORT")
    print("=" * 75)
    print(f"Policy Title   : {policy_title}")
    print(f"Document Length: {len(policy_text.split())} words / {len(policy_text)} characters")
    print(f"Compliance     : {audit_data['total_score']} / {audit_data['max_possible']} points "
          f"({(audit_data['total_score']/audit_data['max_possible'])*100:.1f}%)")
    print("-" * 75)
    print(f"{'GOVERNANCE PILLAR':<28} {'STATUS':<12} {'POINTS':<8} {'MATCHED EVIDENCE'}")
    print("-" * 75)

    missing_pillars = []
    for pillar, info in audit_data["pillars"].items():
        status = "[PRESENT]" if info["present"] else "[MISSING]"
        pts = f"{info['score']}/{info['max_score']}"
        evidence = ", ".join(info["indicators"][:3]) if info["indicators"] else "None detected"
        print(f"{pillar:<28} {status:<12} {pts:<8} {evidence}")
        if not info["present"]:
            missing_pillars.append((pillar, info["description"]))

    print("-" * 75)
    print("COMPLIANCE RATING:")
    pct = (audit_data["total_score"] / audit_data["max_possible"]) * 100
    if pct == 100:
        grade = "EXCELLENT - Complete Policy Baseline"
    elif pct >= 80:
        grade = "SATISFACTORY - Minor Clauses Missing"
    elif pct >= 60:
        grade = "NEEDS REVISION - Critical Governance Gaps"
    else:
        grade = "NON-COMPLIANT - Major Governance Deficiencies"
    print(f"  Result: {grade}")

    print("\nRECOMMENDED ACTIONS / GAPS TO ADDRESS:")
    if missing_pillars:
        for idx, (pillar, desc) in enumerate(missing_pillars, 1):
            print(f"  {idx}. Missing '{pillar}':")
            print(f"     -> Action: {desc}")
    else:
        print("  - All five core governance pillars are present. Ready for formal audit review.")
    print("=" * 75 + "\n")


SAMPLE_DRAFT_POLICY = """
GLOBAL ENTERPRISE INFORMATION SECURITY POLICY (DRAFT v1.2)
1. PURPOSE & SCOPE:
This policy applies to all employees, contractors, and third-party vendors accessing
corporate network resources, cloud databases, and information assets.

2. ROLES & RESPONSIBILITIES:
The CISO oversees policy implementation. IT Administrators are responsible for access controls.
All employees must safeguard authentication credentials and report suspicious activities.

3. ENFORCEMENT & DISCIPLINARY ACTIONS:
Any intentional breach or non-compliance will trigger disciplinary action up to and
including immediate contract termination and legal prosecution under applicable laws.

4. APPROVAL AUTHORITY:
This policy is formally signed and approved by the Chief Information Security Officer (CISO)
and the Board of Directors on October 12, 2026.
"""


def main():
    print("======================================================================")
    print("  Cybersecurity Lab - Practical 03: Security Policy Checker")
    print("======================================================================")
    print("Options:")
    print("  [1] Analyze Default Draft Policy (demonstrating missing Review Cycle)")
    print("  [2] Enter Custom Draft Security Policy text")
    print("-" * 70)

    try:
        choice = input("Enter choice (1/2, default 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if choice == "2":
        print("Enter/paste your draft policy lines (Enter an empty line to finish):")
        lines = []
        while True:
            try:
                line = input()
                if not line:
                    break
                lines.append(line)
            except (EOFError, KeyboardInterrupt):
                break
        policy_text = "\n".join(lines) if lines else SAMPLE_DRAFT_POLICY
        title = "Custom Draft Security Policy"
    else:
        policy_text = SAMPLE_DRAFT_POLICY
        title = "Global Enterprise Information Security Policy (Draft v1.2)"

    audit_result = audit_security_policy(policy_text)
    display_audit_report(title, policy_text, audit_result)


if __name__ == "__main__":
    main()
