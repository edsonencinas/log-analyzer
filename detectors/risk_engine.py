from collections import defaultdict

RISK_WEIGHTS = {
    "Brute Force Attack": 30,
    "Account Lockout Risk": 40,
    "Possible Credential Compromise": 60,
    "Credential Compromise (IP Change)": 80,
}


def calculate_risk(alerts):
    risk_scores = defaultdict(int)
    detailed = defaultdict(list)

    for alert in alerts:
        weight = RISK_WEIGHTS.get(alert["type"], 10)

        # determine entity (user preferred, else IP)
        entity = alert.get("user") or alert.get("ip")

        risk_scores[entity] += weight
        detailed[entity].append({"type": alert["type"], "score": weight})

    results = []

    for entity, score in risk_scores.items():
        if score >= 100:
            level = "CRITICAL"
        elif score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        results.append(
            {
                "entity": entity,
                "risk_score": score,
                "risk_level": level,
                "detections": detailed[entity],
            }
        )

    return results
