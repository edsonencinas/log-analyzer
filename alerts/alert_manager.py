from datetime import datetime, timedelta, timezone

# Cooldown per aler type (realistic values)
COOLDOWNS = {
    "Brute Force Attack": timedelta(minutes=15),
    "Account Lockout Risk": timedelta(minutes=30),
    "Possible Credential Compromise": timedelta(hours=1),
    "Credential Compromise (IP Change)": timedelta(hours=2),
}


class AlertManager:
    def __init__(self):
        # Stores last alert time per unique alert key
        self.last_alert_time = {}

    def _get_entity(self, alert):
        return alert.get("user") or alert.get("ip")

    def should_alert(self, alert):
        entity = self._get_entity(alert)
        alert_type = alert["type"]
        key = f"{alert_type}|{entity}"

        now = datetime.now(timezone.utc)
        cooldown = COOLDOWNS.get(alert_type, timedelta(minutes=10))

        last_time = self.last_alert_time.get(key)

        if last_time and now - last_time < cooldown:
            return False

        # Allow alert and update last alert time
        self.last_alert_time[key] = now
        return True
