# LAB 35: Least-Privilege Access Audit
# Aim: Flag user accounts with permissions beyond their role requirements.

required_permissions = {
    "analyst": {"read_logs", "create_report"},
    "admin": {"read_logs", "create_report", "manage_users", "configure_system"},
    "guest": {"read_public_docs"},
}
accounts = [
    {"user": "alex", "role": "analyst", "permissions": {"read_logs", "create_report", "manage_users"}},
    {"user": "sam", "role": "guest", "permissions": {"read_public_docs"}},
]

for account in accounts:
    role = account["role"]
    if role not in required_permissions:
        print("Review required: unknown role for", account["user"])
        continue
    excess = account["permissions"] - required_permissions[role]
    if excess:
        print(account["user"], "has excess permissions:", ", ".join(sorted(excess)))
    else:
        print(account["user"], "matches least-privilege role permissions.")
