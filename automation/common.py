"""Small shared helpers."""
import json
from datetime import datetime


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
