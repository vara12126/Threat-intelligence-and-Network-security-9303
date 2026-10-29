"""
Practical 16: Defense-in-Depth Simulation
Subject: Threat Intelligence and Network Security

Aim:
    To model and simulate a multi-layered security architecture (Defense-in-Depth)
    evaluating diverse cyber attack scenarios through an ordered chain of independent
    defensive controls, demonstrating how layered controls mitigate single points of failure.

Description:
    Defense-in-Depth is a core cybersecurity strategy that deploys redundant, layered
    defensive mechanisms throughout an enterprise. If an adversary evades perimeter
    defenses (such as an email filter), internal layers (such as network firewalls,
    NIPS, endpoint EDR, and application controls) provide subsequent opportunities
    for detection and prevention.
"""

import sys

# Define security control layers and their detection capabilities
SECURITY_LAYERS = [
    {
        "id": 1,
        "name": "Email Security Gateway",
        "description": "Inspects inbound emails for spoofed headers (SPF/DKIM/DMARC), known malicious attachments, and phishing links.",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Email Gateway blocked message: SPF/DMARC failure or blacklisted phishing sender.")
            if "spoofed" in text or "phishing link" in text or "dmarc_fail" in flags
            else ("PASSED", "Email bypassed gateway: Clean reputation or encrypted attachment prevented static inspection.")
        )
    },
    {
        "id": 2,
        "name": "Endpoint Protection",
        "description": "Monitors host process execution, memory integrity, and file-system activity for malware behavior.",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Endpoint protection stopped the attack: Behavioral engine detected malicious execution / ransomware behavior.")
            if "malicious attachment" in text or "ransomware" in text or "macro execution" in text or "mimikatz" in text or "edr_trigger" in flags
            else ("PASSED", "Endpoint allowed execution: File signed by trusted certificate or inert in memory.")
        )
    },
    {
        "id": 3,
        "name": "Network Firewall",
        "description": "Enforces stateful network traffic filtering by port, protocol, and IP reputation.",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Firewall blocked packet: Unauthorized port or connection to blacklisted C2 IP.")
            if "blocked port" in text or "unauthorized port" in text or "firewall_drop" in flags
            else ("PASSED", "Firewall passed traffic: Permitted service port (e.g., standard HTTPS 443).")
        )
    },
    {
        "id": 4,
        "name": "Network Intrusion Detection/Prevention",
        "description": "Performs deep packet inspection against known exploit signatures and traffic anomalies.",
        "inspect": lambda text, flags: (
            ("BLOCKED", "NIDS/NIPS blocked stream: Signature matched known CVE exploit pattern or network scan.")
            if "exploit signature" in text or "buffer overflow" in text or "nips_signature" in flags
            else ("PASSED", "NIDS/NIPS passed payload: Encrypted payload or novel evasion pattern observed.")
        )
    },
    {
        "id": 5,
        "name": "Application Security Controls",
        "description": "Enforces web application firewalls, role-based access control (RBAC), and input validation.",
        "inspect": lambda text, flags: (
            ("BLOCKED", "Application controls blocked request: SQL injection, cross-site scripting, or unauthorized privilege request detected.")
            if "sql injection" in text or "sqli" in text or "xss" in text or "waf_trigger" in flags
            else ("PASSED", "Application controls permitted request.")
        )
    }
]

# Standard demonstration scenarios
PRESET_SCENARIOS = {
    "1": {
        "title": "Malicious email attachment",
        "narrative": "Malicious email attachment with encrypted payload bypassing email filters.",
        "flags": ["edr_trigger"]
    },
    "2": {
        "title": "Spoofed phishing email with known malicious link",
        "narrative": "Inbound spoofed email impersonating CEO with known phishing link.",
        "flags": ["dmarc_fail"]
    },
    "3": {
        "title": "Web Application SQL Injection attack",
        "narrative": "Attacker submits SQL injection payload over HTTPS port 443 against customer portal.",
        "flags": ["waf_trigger"]
    },
    "4": {
        "title": "Advanced polymorphic zero-day APT scenario",
        "narrative": "Nation-state zero-day utilizing legitimate stolen administrative certificates across perimeter.",
        "flags": []
    }
}


def simulate_defense_in_depth(scenario_text: str, flags: list = None) -> dict:
    """
    Evaluates an attack scenario through the ordered chain of defensive layers.
    Stops at the first layer that blocks the attack.
    """
    if flags is None:
        flags = []
        
    text_lower = scenario_text.lower()
    layer_results = []
    final_status = "ATTACK COMPROMISED SYSTEM"
    final_explanation = "The attack evaded all deployed security controls in this simulation."
    blocked_by_layer = None

    for layer in SECURITY_LAYERS:
        decision, explanation = layer["inspect"](text_lower, flags)
        layer_results.append({
            "layer_id": layer["id"],
            "name": layer["name"],
            "decision": decision,
            "explanation": explanation
        })

        if decision == "BLOCKED":
            final_status = "ATTACK BLOCKED"
            blocked_by_layer = layer["name"]
            if layer["id"] == 1:
                final_explanation = f"{layer['name']} stopped the attack at the enterprise perimeter."
            elif layer["id"] == 2:
                final_explanation = f"{layer['name']} stopped the attack after it passed the first layer."
            else:
                final_explanation = f"{layer['name']} stopped the attack after {layer['id'] - 1} previous layers permitted transit."
            break

    return {
        "scenario": scenario_text,
        "layers": layer_results,
        "final_status": final_status,
        "blocked_by": blocked_by_layer,
        "explanation": final_explanation
    }


def display_simulation_report(result: dict):
    """Displays formatted Defense-in-Depth simulation output."""
    print("\n" + "=" * 70)
    print("PRACTICAL 16: DEFENSE-IN-DEPTH SIMULATION")
    print("=" * 70)
    print(f"Attack Scenario: {result['scenario']}\n")

    for item in result["layers"]:
        print(f"Layer {item['layer_id']} - {item['name']}: {item['decision']}")
        print(f"        Detail: {item['explanation']}")

    print("-" * 70)
    print(f"Final Result: {result['final_status']}")
    print(f"Explanation : {result['explanation']}")
    print("-" * 70)
    print("Strategic Takeaway: Defense-in-depth ensures that the failure of any single")
    print("defensive control does not result in catastrophic compromise. However,")
    print("defense-in-depth reduces risk significantly but does not guarantee 100% protection.")
    print("=" * 70 + "\n")


def main():
    print("======================================================================")
    print("  Practical 16: Defense-in-Depth Multi-Layer Attack Simulation")
    print("======================================================================")
    print("Available Demonstration Scenarios:")
    for key, data in PRESET_SCENARIOS.items():
        print(f"  [{key}] {data['title']}")
    print("-" * 70)

    try:
        choice = input("Select a scenario [1-4] or enter custom text (default 1): ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "1"

    if not choice:
        choice = "1"

    if choice in PRESET_SCENARIOS:
        selected = PRESET_SCENARIOS[choice]
        scenario_text = selected["title"]
        flags = selected["flags"]
    else:
        scenario_text = choice
        flags = []

    res = simulate_defense_in_depth(scenario_text, flags)
    display_simulation_report(res)


if __name__ == "__main__":
    main()
