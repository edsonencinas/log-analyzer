from collections import defaultdict
from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def detect_account_lockout(events):
    failed_events = [e for e in events if e["status"] == "failed"]

    # Group failed logins by user
    events_by_user = defaultdict(list)
    for event in failed_events:
        events_by_user[event["user"]].append(event["timestamp"])

    alerts = []

    for user, timestamps in events_by_user.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + TIME_WINDOW

            attempts = [t for t in timestamps if window_start <= t <= window_end]

            if len(attempts) >= FAILED_THRESHOLD:
                alerts.append(
                    {
                        "type": "Account Lockout Risk",
                        "user": user,
                        "attempts": len(attempts),
                        "time_window": str(TIME_WINDOW),
                    }
                )
                break

    return alerts
