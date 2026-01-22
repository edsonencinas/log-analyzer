from collections import defaultdict
from datetime import timedelta

FAILED_THRESHOLD = 5     # X attempts
TIME_WINDOW = timedelta(minutes=2)  # Y minutes

def detect_brute_force(events):
  failed_events = [
    e for e in events if e["status"] == "failed"
  ]

  # Group failures by IP
  events_by_ip=defaultdict(list)
  for event in failed_events:
    events_by_ip[event["ip"]].append(event["timestamp"])
  
  alerts=[]

  for ip, timestamps in events_by_ip.items():
    timestamps.sort()

    for i in range(len(timestamps)):
      window_start = timestamps[i]
      window_end = window_start + TIME_WINDOW

      # Count attempts inside time window
      attempts = [
        t for t in timestamps
        if window_start <= t <=window_end
      ]

      if len(attempts) >=FAILED_THRESHOLD:
        alerts.append({
          "type":"Brute Force Attack",
          "ip": ip,
          "attempts": len(attempts),
          "time_window": f"{TIME_WINDOW}"
        })

        break # prevent buplicate alerts per IP
  
  return alerts