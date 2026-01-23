from parser.auth_parser import parse_auth_log
from detectors.brute_force import detect_brute_force
from detectors.account_lockout import detect_account_lockout
from detectors.credential_compromise import detect_credential_compromise
from detectors.ip_change_after_failures import detect_ip_change_after_failures
from detectors.risk_engine import calculate_risk
from utils.json_exporter import export_to_json
from mitre.tagger import tag_with_mitre
from alerts.alert_manager import AlertManager


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

    alert_manager = AlertManager()
    export_to_json(events, "output/events.json")

    alerts_bruteforce = detect_brute_force(events)
    alerts_lockout = detect_account_lockout(events)
    alerts_compromise = detect_credential_compromise(events)
    alerts_ip_change = detect_ip_change_after_failures(events)

    all_alerts = []
    all_alerts.extend(alerts_bruteforce)
    all_alerts.extend(alerts_lockout)
    all_alerts.extend(alerts_compromise)
    all_alerts.extend(alerts_ip_change)

    # MITRE tagging
    all_alerts = [tag_with_mitre(alert) for alert in all_alerts]

    filtered_alerts = [
        alert for alert in all_alerts if alert_manager.should_alert(alert)
    ]

    export_to_json(filtered_alerts, "output/alerts.json")

    risk_results = calculate_risk(filtered_alerts)

    export_to_json(risk_results, "output/risk_summary.json")

    # Console output
    for r in risk_results:
        print(f"{r['entity']} → {r['risk_level']} ({r['risk_score']})")

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

    for alert in alerts_ip_change:
        print("ALERT DETECTED")
        print(f"Type: {alert['type']}")
        print(f"User: {alert['user']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"Failure IPs: {', '.join(alert['failure_ips'])}")
        print(f"Success IP: {alert['success_ip']}")
        print(f"Severity: {alert['severity']}")
        print("-" * 40)

    print("\n=== RISK SUMMARY ===")
    for r in risk_results:
        print(f"Entity: {r['entity']}")
        print(f"Risk Score: {r['risk_score']}")
        print(f"Risk Level: {r['risk_level']}")
        print("Detections:")
        for d in r["detections"]:
            print(f" - {d['type']} (+{d['score']})")
        print("-" * 40)


if __name__ == "__main__":
    main()
