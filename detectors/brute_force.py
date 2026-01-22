from collections import defaultdict

THRESHOLD = 2 # You can tune this

def detect_brute_force(events):
  failed_attempts=defaultdict(int)

  for event in events:
    if event["status"] == "failed":
      failed_attempts[event["ip"]] += 1
  
  alerts = []
  for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
      alerts.append({
        "type": "SSH Brute Force",
        "ip": ip,
        "attempts": count
      })
  
  return alerts