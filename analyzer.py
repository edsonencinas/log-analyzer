from parser.auth_parser import parse_auth_log
from detectors.brute_force import detect_brute_force
from detectors.account_lockout import detect_account_lockout
from detectors.credential_compromise import detect_credential_compromise


def read_log(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def main():
    logs = read_log("logs/auth.log")

    events = []
    for line in logs:
        event = parse_auth_log(line)
        if event:
            events.append(event)

    alerts_bruteforce = detect_brute_force(events)
    alerts_lockout = detect_account_lockout(events)
    alerts_compromise = detect_credential_compromise(events)
    # for testing pupose only to be deleted later on ----------------------
    print(alerts_bruteforce)
    print(alerts_lockout)
    print(alerts_compromise)

    for alert in alerts_bruteforce:
        print("ALERT DETECTED")
        print(f"Type: {alert['type']}")
        print(f"IP: {alert['ip']}")
        print(f"Failed Attempts: {alert['attempts']}")
        print("-" * 30)

    for alert in alerts_lockout:
        print("ALERT DETECTED")
        print(f"Type: {alert['type']}")
        print(f"User: {alert['user']}")
        print(f"Failed Attempts: {alert['attempts']}")
        print("-" * 30)

    for alert in alerts_compromise:
        print("ALERT DETECTED")
        print(f"Type: {alert['type']}")
        print(f"User: {alert['user']}")
        print(f"Failed Attempts Before Success: {alert['failed_attempts']}")
        print(f"Success Time: {alert['success_time']}")
        print("-" * 30)


if __name__ == "__main__":
    main()
