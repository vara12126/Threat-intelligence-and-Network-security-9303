# LAB 38: Qualitative Risk Scoring
# Aim: Calculate a 1-25 risk score from likelihood and impact ratings.

likelihood = int(input("Likelihood rating (1-5): "))
impact = int(input("Impact rating (1-5): "))
if not 1 <= likelihood <= 5 or not 1 <= impact <= 5:
    raise ValueError("Likelihood and impact must each be between 1 and 5.")

score = likelihood * impact
if score <= 4:
    level = "Low"
elif score <= 9:
    level = "Medium"
elif score <= 16:
    level = "High"
else:
    level = "Critical"

print("Risk score:", score, "out of 25")
print("Risk level:", level)
