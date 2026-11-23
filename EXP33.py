# LAB 33: Incident Response Lifecycle Classifier
# Aim: Tag an action as a lifecycle phase using keywords.

action = input("Describe the incident-response action: ").lower()
phases = {
    "Preparation": ["playbook", "training", "prepare", "backup plan"],
    "Identification": ["investigate", "detect", "confirm", "identify"],
    "Containment": ["isolate", "block", "disable account", "contain"],
    "Eradication": ["remove malware", "delete malware", "eradicate", "patch vulnerability"],
    "Recovery": ["restore", "resume service", "recover", "rebuild"],
    "Lessons Learned": ["post-incident", "lessons learned", "review", "improve"],
}

matches = [phase for phase, words in phases.items() if any(word in action for word in words)]
if matches:
    print("Likely incident-response phase:", ", ".join(matches))
else:
    print("Phase could not be identified.")
