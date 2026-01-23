from collections import defaultdict
from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=10)


def detect_credential_compromise(events):
    # Group events by user
    events_by_user = defaultdict(list)
    for event in events:
        events_by_user[event["user"]].append(event)

    alerts = []

    for user, user_events in events_by_user.items():
        # sort by time
        user_events.sort(key=lambda x: x["timestamp"])

        failed_times = []

        for event in user_events:
            if event["status"] == "failed":
                failed_times.append(event["timestamp"])

            elif event["status"] == "success":
                # count recent failures before success
                recent_failures = [
                    t for t in failed_times if event["timestamp"] - t <= TIME_WINDOW
                ]

                if len(recent_failures) >= FAILED_THRESHOLD:
                    alerts.append(
                        {
                            "type": "Possible Credential Compromise",
                            "user": user,
                            "failed_attempts": len(recent_failures),
                            "success_time": event["timestamp"],
                            "time_window": str(TIME_WINDOW),
                        }
                    )
                    break  # one alert per user

    return alerts
