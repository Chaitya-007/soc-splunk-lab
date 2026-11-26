"""CloudTrail detection: an access key used from a new IP for sensitive IAM actions."""
from collections import Counter, defaultdict

SENSITIVE = {"CreateUser", "AttachUserPolicy", "PutUserPolicy", "CreateAccessKey",
             "StopLogging", "DeleteTrail"}


def suspicious_key_use(events):
    by_key = defaultdict(list)
    for e in events:
        key = e["userIdentity"].get("accessKeyId")
        if key:
            by_key[key].append(e)
    alerts = []
    for key, evs in by_key.items():
        baseline = Counter(e["sourceIPAddress"] for e in evs).most_common(1)[0][0]
        odd = [e for e in evs if e["sourceIPAddress"] != baseline]
        risky = [e["eventName"] for e in odd if e["eventName"] in SENSITIVE]
        if odd and risky:
            alerts.append({
                "rule": "aws_access_key_new_ip_sensitive_actions", "severity": "high",
                "access_key_id": key, "user": evs[0]["userIdentity"]["userName"],
                "baseline_ip": baseline, "source_ip": odd[0]["sourceIPAddress"],
                "actions_from_new_ip": [e["eventName"] for e in odd],
                "sensitive_actions": risky, "mitre": ["T1078.004", "T1136.003", "T1098"]})
    return alerts
