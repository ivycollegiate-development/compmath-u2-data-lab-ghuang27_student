
import csv
import matplotlib.pyplot as plt

# Read the cleaned data
rows = []
with open("data/u2_campus_threat_daily_clean.csv") as file:
    reader = csv.DictReader(file)
    rows = list(reader)

dates = [row["date"] for row in rows]
phishing = [int(row["phishing_reports"]) for row in rows]
failed = [int(row["failed_logins"]) for row in rows]

# Chart 1: Daily threats over time
plt.figure(figsize=(10, 5))
plt.plot(dates, phishing, label="Phishing Reports")
plt.plot(dates, failed, label="Failed Logins")

plt.title("Daily Phishing Reports and Failed Logins")
plt.xlabel("Date")
plt.ylabel("Number of Reports / Logins")
plt.xticks(range(0, len(dates), 7), rotation=45)
plt.legend()
plt.tight_layout()
plt.savefig("chart1_timeline.png")
plt.clf()

# Chart 2: Weekday vs Weekend
from datetime import datetime

def is_weekend(d):
    return datetime.strptime(d, "%Y-%m-%d").weekday() >= 5

wd, we = [], []

for row in rows:
    (we if is_weekend(row["date"]) else wd).append(
        int(row["phishing_reports"])
    )

avg_wd = sum(wd) / len(wd)
avg_we = sum(we) / len(we)

print(f"Weekday: {avg_wd:.2f}")
print(f"Weekend: {avg_we:.2f}")

plt.figure(figsize=(6, 4))
plt.bar(["Weekday", "Weekend"], [avg_wd, avg_we])
plt.text(0, avg_wd, f"{avg_wd:.2f}", ha="center", va="bottom")
plt.text(1, avg_we, f"{avg_we:.2f}", ha="center", va="bottom")

plt.title("Phishing Reports Are Higher on Weekdays")
plt.xlabel("Day Type")
plt.ylabel("Average Phishing Reports")
plt.ylim(bottom=0)
plt.tight_layout()
plt.savefig("chart2_weekday_weekend.png")
plt.clf()

# Chart 3: Login Success Rate Distribution

rates = [float(row["login_success_rate"]) for row in rows]

plt.figure(figsize=(8, 5))
plt.hist(rates, bins=10, edgecolor="black")

plt.title("Distribution of Login Success Rates")
plt.xlabel("Login Success Rate")
plt.ylabel("Number of Days")
plt.xlim(0, 1)
plt.tight_layout()
plt.savefig("chart3_success_rate.png")
plt.clf()
