from collections import defaultdict
from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=10)


def detect_ip_change_after_failures(events):
    # Group events by user
    events_by_user = defaultdict(list)
    for event in events:
        events_by_user[event["user"]].append(event)

    alerts = []

    for user, user_events in events_by_user.items():
        # Sort events chronologically
        user_events.sort(key=lambda x: x["timestamp"])

        failed_events = []

        for event in user_events:
            if event["status"] == "failed":
                failed_events.append(event)

            elif event["status"] == "success":
                # Failures within time window
                recent_failures = [
                    f
                    for f in failed_events
                    if event["timestamp"] - f["timestamp"] <= TIME_WINDOW
                ]

                if len(recent_failures) < FAILED_THRESHOLD:
                    continue

                failure_ips = {f["ip"] for f in recent_failures}

                # IP changed?
                if event["ip"] not in failure_ips:
                    alerts.append(
                        {
                            "type": "Credential Compromise (IP Change)",
                            "user": user,
                            "failed_attempts": len(recent_failures),
                            "failure_ips": list(failure_ips),
                            "success_ip": event["ip"],
                            "success_time": event["timestamp"],
                            "severity": "HIGH",
                        }
                    )
                    break  # One alert per user

    return alerts
