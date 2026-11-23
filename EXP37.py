# LAB 37: Continuous Login Monitoring Simulation
# Aim: Compare a stream of login events with a simple baseline.

baseline_locations = {"office", "home"}
baseline_hours = set(range(7, 20))
events = [
    {"user": "alex", "location": "office", "hour": 10},
    {"user": "alex", "location": "unknown_country", "hour": 2},
    {"user": "sam", "location": "home", "hour": 18},
]

print("Monitoring login event stream...")
for event in events:
    anomalies = []
    if event["location"] not in baseline_locations:
        anomalies.append("unusual location")
    if event["hour"] not in baseline_hours:
        anomalies.append("unusual time")
    if anomalies:
        print("ANOMALY:", event, "-", ", ".join(anomalies))
    else:
        print("Normal login:", event)
