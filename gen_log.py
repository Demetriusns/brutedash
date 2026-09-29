"""Generate a realistic test auth.log (session #1 generator, verbatim).

30 lines, two attacker IPs, and one bug-bait line with no IP at the end.
"""
import random

random.seed(9)
lines = []
attackers = ["203.0.113.44", "198.51.100.23"]
for i in range(30):
    ip = random.choice(attackers + ["192.0.2.10", "192.0.2.11"])
    outcome = "Failed password" if random.random() < 0.6 else "Accepted password"
    lines.append(f"Sep 9 13:{i:02d}:00 srv sshd[2211]: {outcome} for root from {ip} port 51{i}00")
lines.append("Sep 9 13:59:59 srv sshd[2211]: Failed password for invalid user admin")
open("auth.log", "w").write("\n".join(lines))
print("wrote auth.log:", len(lines), "lines")
