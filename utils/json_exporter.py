import json
from datetime import datetime


def json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def export_to_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4, default=json_serializer)
