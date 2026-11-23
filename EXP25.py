# LAB 25: Evidence Chain-of-Custody Verification
# Aim: Check hash links and non-decreasing timestamps in custody records.

records = [
    {"timestamp": 100, "previous_hash": "GENESIS", "record_hash": "hash-A"},
    {"timestamp": 120, "previous_hash": "hash-A", "record_hash": "hash-B"},
    {"timestamp": 130, "previous_hash": "hash-B", "record_hash": "hash-C"},
]

valid = True
for index, record in enumerate(records):
    expected_previous = "GENESIS" if index == 0 else records[index - 1]["record_hash"]
    if record["previous_hash"] != expected_previous:
        print("Broken hash link at record", index + 1)
        valid = False
    if index > 0 and record["timestamp"] < records[index - 1]["timestamp"]:
        print("Timestamp moved backwards at record", index + 1)
        valid = False

if valid:
    print("Custody sequence has linked hashes and non-decreasing timestamps.")
else:
    print("Custody sequence verification failed.")
print("Note: This demonstration checks supplied links; it does not calculate cryptographic record hashes.")
