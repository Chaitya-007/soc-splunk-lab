#!/usr/bin/env python3
"""Generate synthetic, reproducible log data for the SOC lab.

Everything is fictional: IPs come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and users/hosts are made up.
Four attack scenarios are hidden inside normal-looking background noise:

  1. RDP brute force that ends in a successful logon, then follow-on activity
  2. Okta impossible travel
  3. Okta MFA push fatigue
  4. Leaked AWS access key used from a new IP to create an admin user

Run:  python3 data/generate_logs.py
"""
import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(1337)
OUT = Path(__file__).parent / "sample"
OUT.mkdir(exist_ok=True)
DAY = datetime(2026, 11, 20, 4, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def at(minutes):
    return DAY + timedelta(minutes=minutes)


def write(name, key, rows):
    rows.sort(key=lambda r: r[key])
    with open(OUT / name, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    print(f"{name}: {len(rows)} events")


# ---------------------------------------------------------------- Windows
def windows_events():
    users = ["asha.k", "rohan.m", "meera.s", "dev.p", "svc.backup"]
    hosts = ["WS-PUNE-01", "WS-PUNE-02", "WS-PUNE-03", "SRV-FILE-01"]
    apps = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r"C:\Windows\explorer.exe",
    ]
    ev = []
    for _ in range(220):  # normal logons
        ev.append({"timestamp": iso(at(random.uniform(0, 600))), "EventCode": 4624,
                   "Computer": random.choice(hosts), "TargetUserName": random.choice(users),
                   "IpAddress": f"10.10.{random.randint(1, 4)}.{random.randint(10, 200)}",
                   "LogonType": random.choice([2, 3])})
    for _ in range(12):  # ordinary typo failures
        ev.append({"timestamp": iso(at(random.uniform(0, 600))), "EventCode": 4625,
                   "Computer": random.choice(hosts), "TargetUserName": random.choice(users),
                   "IpAddress": f"10.10.{random.randint(1, 4)}.{random.randint(10, 200)}",
                   "LogonType": 2})
    for _ in range(60):  # ordinary processes
        app = random.choice(apps)
        ev.append({"timestamp": iso(at(random.uniform(0, 600))), "EventCode": 4688,
                   "Computer": random.choice(hosts), "SubjectUserName": random.choice(users),
                   "NewProcessName": app, "CommandLine": f'"{app}"',
                   "ParentProcessName": r"C:\Windows\explorer.exe"})

    # Scenario 1: brute force from one external IP, then success, then follow-on
    ip, host, t0 = "203.0.113.45", "SRV-FILE-01", 195.0
    targets = ["administrator", "admin", "admin.svc", "backup"]
    for i in range(60):
        ev.append({"timestamp": iso(at(t0 + i * 4 / 60 + random.uniform(0, 0.03))),
                   "EventCode": 4625, "Computer": host,
                   "TargetUserName": random.choice(targets), "IpAddress": ip, "LogonType": 3})
    t_ok = t0 + 60 * 4 / 60 + 0.1
    ev.append({"timestamp": iso(at(t_ok)), "EventCode": 4624, "Computer": host,
               "TargetUserName": "admin.svc", "IpAddress": ip, "LogonType": 10})
    enc = base64.b64encode("whoami".encode("utf-16-le")).decode()  # harmless payload
    follow = [
        (1, 4688, r"C:\Windows\System32\whoami.exe", "whoami /all"),
        (2, 4688, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         f"powershell.exe -nop -w hidden -enc {enc}"),
        (3, 4688, r"C:\Windows\System32\net.exe", "net user helpdesk2 <redacted> /add"),
    ]
    for dm, code, proc, cmd in follow:
        ev.append({"timestamp": iso(at(t_ok + dm)), "EventCode": code, "Computer": host,
                   "SubjectUserName": "admin.svc", "NewProcessName": proc,
                   "CommandLine": cmd, "ParentProcessName": r"C:\Windows\System32\cmd.exe"})
    ev.append({"timestamp": iso(at(t_ok + 3.1)), "EventCode": 4720, "Computer": host,
               "SubjectUserName": "admin.svc", "TargetUserName": "helpdesk2", "IpAddress": "-"})
    return ev


# ------------------------------------------------------------------- Okta
def okta(ts, user, etype, result, ip, city, country, lat, lon):
    return {"published": iso(ts), "eventType": etype,
            "actor": {"alternateId": f"{user}@example.com", "displayName": user},
            "outcome": {"result": result},
            "client": {"ipAddress": ip,
                       "userAgent": {"rawUserAgent": "Mozilla/5.0"},
                       "geographicalContext": {"city": city, "country": country,
                                               "geolocation": {"lat": lat, "lon": lon}}}}


def okta_events():
    people = {  # user: (city, country, lat, lon, ip, last_background_minute)
        "asha.k": ("Pune", "India", 18.52, 73.86, "198.51.100.10", 325),
        "rohan.m": ("Pune", "India", 18.52, 73.86, "198.51.100.11", 600),
        "meera.s": ("Mumbai", "India", 19.07, 72.88, "198.51.100.20", 600),
        "dev.p": ("Pune", "India", 18.52, 73.86, "198.51.100.12", 600),
    }
    ev = []
    for _ in range(80):
        user = random.choice(list(people))
        city, country, lat, lon, ip, last = people[user]
        ev.append(okta(at(random.uniform(0, last)), user, "user.session.start", "SUCCESS",
                       ip, city, country, lat, lon))
    # Scenario 2: impossible travel (Pune -> Frankfurt in 40 minutes)
    ev.append(okta(at(330), "asha.k", "user.session.start", "SUCCESS",
                   "198.51.100.10", "Pune", "India", 18.52, 73.86))
    ev.append(okta(at(370), "asha.k", "user.session.start", "SUCCESS",
                   "192.0.2.77", "Frankfurt", "Germany", 50.11, 8.68))
    # Scenario 3: MFA push fatigue against rohan.m
    for i in range(5):
        ev.append(okta(at(400 + i * 0.5), "rohan.m", "user.mfa.okta_verify.deny_push",
                       "FAILURE", "203.0.113.99", "Lagos", "Nigeria", 6.52, 3.38))
    ev.append(okta(at(403), "rohan.m", "user.authentication.auth_via_mfa", "SUCCESS",
                   "203.0.113.99", "Lagos", "Nigeria", 6.52, 3.38))
    return ev


# ------------------------------------------------------------- CloudTrail
def ct(ts, user, key, ip, agent, source, name, params=None):
    return {"eventTime": iso(ts), "eventSource": source, "eventName": name,
            "awsRegion": "ap-south-1", "sourceIPAddress": ip, "userAgent": agent,
            "userIdentity": {"type": "IAMUser", "userName": user, "accessKeyId": key},
            "requestParameters": params, "eventType": "AwsApiCall"}


def cloudtrail_events():
    boto = "Boto3/1.34.0 Python/3.11.6"
    cli = "aws-cli/2.15.0 Python/3.11.6 Linux/5.15"
    leaked = "AKIAIOSFODNN7EXAMPLE"
    ev = []
    for _ in range(35):
        ev.append(ct(at(random.uniform(0, 600)), "ci-deploy", leaked, "198.51.100.20", boto,
                     "s3.amazonaws.com", random.choice(["PutObject", "ListBucket", "GetObject"])))
    for _ in range(30):
        ev.append(ct(at(random.uniform(0, 600)), "devops.asha", "AKIAEXAMPLE00000001A",
                     "198.51.100.10", cli, "ec2.amazonaws.com",
                     random.choice(["DescribeInstances", "DescribeSecurityGroups"])))
    # Scenario 4: the CI key is used from a new IP
    ip, t = "203.0.113.77", 480
    steps = [
        ("sts.amazonaws.com", "GetCallerIdentity", None),
        ("iam.amazonaws.com", "ListUsers", None),
        ("s3.amazonaws.com", "ListBuckets", None),
        ("iam.amazonaws.com", "CreateUser", {"userName": "backup-admin"}),
        ("iam.amazonaws.com", "AttachUserPolicy",
         {"userName": "backup-admin", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        ("iam.amazonaws.com", "CreateAccessKey", {"userName": "backup-admin"}),
    ]
    for i, (src, name, params) in enumerate(steps):
        ev.append(ct(at(t + i * 0.7), "ci-deploy", leaked, ip, cli, src, name, params))
    return ev


if __name__ == "__main__":
    write("windows_security.json", "timestamp", windows_events())
    write("okta_system.json", "published", okta_events())
    write("cloudtrail.json", "eventTime", cloudtrail_events())
