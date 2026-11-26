"""Okta System Log detections: impossible travel and MFA push fatigue."""
import math
from collections import defaultdict
from datetime import timedelta

from .common import parse_ts


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def impossible_travel(events, max_kmh=900, min_km=500):
    """Two successful sign-ins by one user that would need a speed above max_kmh."""
    logins = defaultdict(list)
    for e in events:
        if e["eventType"] == "user.session.start" and e["outcome"]["result"] == "SUCCESS":
            c = e["client"]
            logins[e["actor"]["alternateId"]].append(
                (parse_ts(e["published"]), c["ipAddress"], c["geographicalContext"]))
    alerts = []
    for user, rows in logins.items():
        rows.sort(key=lambda r: r[0])
        for (t1, ip1, g1), (t2, ip2, g2) in zip(rows, rows[1:]):
            km = haversine_km(g1["geolocation"]["lat"], g1["geolocation"]["lon"],
                              g2["geolocation"]["lat"], g2["geolocation"]["lon"])
            hours = (t2 - t1).total_seconds() / 3600
            if km >= min_km and hours > 0 and km / hours > max_kmh:
                alerts.append({
                    "rule": "okta_impossible_travel", "severity": "medium", "user": user,
                    "from": f"{g1['city']} ({ip1})", "to": f"{g2['city']} ({ip2})",
                    "source_ip": ip2, "distance_km": round(km), "minutes_apart": round(hours * 60),
                    "required_speed_kmh": round(km / hours), "mitre": ["T1078"]})
    return alerts


def mfa_fatigue(events, threshold=3, window_min=10):
    """Several denied MFA pushes for one user in a short window."""
    window = timedelta(minutes=window_min)
    denies = defaultdict(list)
    for e in events:
        if e["eventType"] == "user.mfa.okta_verify.deny_push":
            denies[e["actor"]["alternateId"]].append((parse_ts(e["published"]), e))
    alerts = []
    for user, rows in denies.items():
        rows.sort(key=lambda r: r[0])
        times = [r[0] for r in rows]
        best, j, start = 0, 0, None
        for i, t in enumerate(times):
            while t - times[j] > window:
                j += 1
            if i - j + 1 > best:
                best, start = i - j + 1, times[j]
        if best >= threshold:
            ip = rows[0][1]["client"]["ipAddress"]
            later_ok = any(e["eventType"] == "user.authentication.auth_via_mfa"
                           and e["actor"]["alternateId"] == user
                           and e["client"]["ipAddress"] == ip
                           and parse_ts(e["published"]) >= start for e in events)
            alerts.append({
                "rule": "okta_mfa_push_fatigue",
                "severity": "high" if later_ok else "medium", "user": user,
                "source_ip": ip, "denied_pushes": best, "window_minutes": window_min,
                "mfa_success_afterwards": later_ok, "mitre": ["T1621"]})
    return alerts
