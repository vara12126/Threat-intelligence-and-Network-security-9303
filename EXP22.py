# LAB 22: Brute-Force Pattern Detection in Authentication Logs
# Aim: Find repeated failures followed by a successful login for one user.
# Enter records as user,status separated by commas; use a blank line to finish.

target_user = input("Enter user account to check: ").strip()
records = []
print("Enter log records such as alex,failed or alex,success. Blank line ends input.")
while True:
    line = input("Log> ").strip()
    if not line:
        break
    parts = [part.strip() for part in line.split(",")]
    if len(parts) == 2 and parts[1].lower() in {"failed", "success"}:
        records.append((parts[0], parts[1].lower()))
    else:
        print("Invalid record; use user,failed or user,success.")

failed_count = 0
detected = False
for user, status in records:
    if user == target_user:
        if status == "failed":
            failed_count += 1
        elif failed_count >= 3:
            detected = True
            break
        else:
            failed_count = 0

if detected:
    print("Alert: Repeated failed logins followed by success for", target_user)
else:
    print("No brute-force pattern detected for", target_user)
