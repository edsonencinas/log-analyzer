from mitre.attack_mapping import MITRE_MAPPING


def tag_with_mitre(alert):
    mapping = MITRE_MAPPING.get(alert["type"])

    if not mapping:
        return alert

    alert["mitre"] = {
        "tactic": mapping["tactic"],
        "technique": mapping["technique"],
        "technique_id": mapping["technique_id"],
    }

    return alert
