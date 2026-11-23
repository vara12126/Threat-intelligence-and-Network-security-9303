# LAB 24: Security Control Baseline Checker
# Aim: Compare current configuration with minimum required settings.

baseline = {
    "password_min_length": 12,
    "mfa_enabled": True,
    "automatic_updates": True,
    "firewall_enabled": True,
}
current = {
    "password_min_length": int(input("Current minimum password length: ")),
    "mfa_enabled": input("Is MFA enabled? (yes/no): ").strip().lower() == "yes",
    "automatic_updates": input("Are automatic updates enabled? (yes/no): ").strip().lower() == "yes",
    "firewall_enabled": input("Is the firewall enabled? (yes/no): ").strip().lower() == "yes",
}

failures = []
for control, required in baseline.items():
    if isinstance(required, int):
        if current[control] < required:
            failures.append(control + " (required: " + str(required) + ")")
    elif current[control] != required:
        failures.append(control)

if failures:
    print("Controls below baseline:")
    for control in failures:
        print("-", control)
else:
    print("All checked controls meet the baseline.")
