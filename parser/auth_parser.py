from datetime import datetime
import re

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s[\d:]+)\s+'
    r'.*sshd.*'
    r'(Failed|Accepted) password for (invalid user )?(?P<user>\w+)\s+from\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_auth_log(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    
    # Convert timestamp sting -> datetime
    timestamp_str = match.group("timestamp")
    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")

    return {
        "timestamp": timestamp,
        "user": match.group("user"),
        "ip": match.group("ip"),
        "status": "failed" if "Failed password" in line else "success"
    }