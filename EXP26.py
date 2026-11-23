# LAB 26: Simplified Static and Dynamic Malware Analysis
# Aim: Hash and scan sample text, then inspect a simulated behavior log.
# Never execute an unknown sample. This exercise analyzes text only.

import hashlib

sample_text = input("Enter harmless sample text to analyze: ")
sample_hash = hashlib.sha256(sample_text.encode("utf-8")).hexdigest()
suspicious_apis = ["CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", "WinExec"]
print("Static analysis SHA-256:", sample_hash)
static_matches = [api for api in suspicious_apis if api.lower() in sample_text.lower()]
print("Suspicious API strings:", static_matches if static_matches else "None found")

behavior_log = input("Enter simulated behavior log: ").lower()
behaviors = ["created persistence", "contacted remote host", "modified startup", "encrypted files"]
dynamic_matches = [behavior for behavior in behaviors if behavior in behavior_log]
print("Simulated dynamic-analysis findings:", dynamic_matches if dynamic_matches else "None found")
