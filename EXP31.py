# LAB 31: Packet-Filtering Firewall Rule Engine
# Aim: Demonstrate first-match rule ordering and default-deny behavior.

rules = [
    {"action": "allow", "protocol": "tcp", "port": 443},
    {"action": "deny", "protocol": "tcp", "port": 443},
    {"action": "allow", "protocol": "tcp", "port": 22},
]
packet = {
    "protocol": input("Packet protocol (tcp/udp): ").strip().lower(),
    "port": int(input("Packet destination port: ")),
}

decision = "deny (default)"
for rule in rules:
    if packet["protocol"] == rule["protocol"] and packet["port"] == rule["port"]:
        decision = rule["action"]
        break
print("Firewall decision:", decision.upper())
print("The first matching rule wins; moving the deny-443 rule above allow-443 changes the result.")
