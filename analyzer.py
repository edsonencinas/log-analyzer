from parser.auth_parser import parse_auth_log
from detectors.brute_force import detect_brute_force

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

    alerts = detect_brute_force(events)

    for alert in alerts:
        print("ALERT DETECTED")
        print(f"Type: {alert['type']}")
        print(f"IP: {alert['ip']}")
        print(f"Failed Attempts: {alert['attempts']}")
        print("-" * 30)
   

if __name__ == "__main__":
    main()