"""
Practical 35: Principle of Least Privilege Access Audit
Subject: Threat Intelligence and Network Security

Aim:
    To audit enterprise user access rights against baseline role definitions,
    detecting privilege creep, unauthorized access, and policy violations.
"""

def audit_privileges(role_baseline, users):
    audit_report = []

    for u in users:
        role = u["role"]
        assigned = set(u["assigned_permissions"])
        expected = set(role_baseline.get(role, []))

        excess = assigned - expected
        missing = expected - assigned

        compliant = len(excess) == 0

        audit_report.append({
            "user": u["username"],
            "role": role,
            "excess": list(excess),
            "missing": list(missing),
            "status": "COMPLIANT" if compliant else "VIOLATION (Excess Privileges)"
        })

    return audit_report


def main():
    print("=" * 74)
    print("  Practical 35: Least Privilege Access & Permission Creep Audit")
    print("=" * 74)

    role_matrix = {
        "Software Engineer": ["read_repo", "commit_code", "access_dev_cluster"],
        "QA Specialist":     ["read_repo", "run_test_suite", "access_qa_cluster"],
        "HR Manager":        ["read_employee_records", "edit_payroll_records"]
    }

    users = [
        {
            "username": "alice_dev",
            "role": "Software Engineer",
            "assigned_permissions": ["read_repo", "commit_code", "access_dev_cluster"]
        },
        {
            "username": "bob_qa",
            "role": "QA Specialist",
            "assigned_permissions": ["read_repo", "run_test_suite", "access_qa_cluster", "drop_production_db", "admin_portal"]
        },
        {
            "username": "carol_hr",
            "role": "HR Manager",
            "assigned_permissions": ["read_employee_records", "edit_payroll_records", "commit_code"]
        }
    ]

    report = audit_privileges(role_matrix, users)

    print(f"\n{'User':<12} | {'Role':<18} | {'Status':<30}")
    print("-" * 74)
    for r in report:
        print(f"{r['user']:<12} | {r['role']:<18} | {r['status']:<30}")
        if r["excess"]:
            print(f"   -> Unauthorized excess permissions to revoke: {', '.join(r['excess'])}")
    print("=" * 74)


if __name__ == "__main__":
    main()
