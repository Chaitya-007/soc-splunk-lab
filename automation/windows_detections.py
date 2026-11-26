"""Brute-force detection for Windows Security logs (4625 / 4624 / 4688 / 4720)."""
from collections import defaultdict
from datetime import timedelta

from .common import parse_ts


def detect_bruteforce(events, threshold=10, window_min=5):
    """Alert when one source IP causes >= threshold failed logons inside the window.

    Severity goes from medium to high if the same IP later logs on successfully,
    and the alert lists what the compromised account did next.
    """
    window = timedelta(minutes=window_min)
    ordered = sorted(events, key=lambda x: x["timestamp"])
    fails = defaultdict(list)
    for e in ordered:
        if e["EventCode"] == 4625 and e.get("IpAddress"):
            fails[e["IpAddress"]].append((parse_ts(e["timestamp"]), e))
    alerts = []
    for ip, rows in fails.items():
        times = [r[0] for r in rows]
        best, start, end, j = 0, None, None, 0
        for i, t in enumerate(times):
            while t - times[j] > window:
                j += 1
            if i - j + 1 > best:
                best, start, end = i - j + 1, times[j], t
        if best < threshold:
            continue
        in_win = [r[1] for r in rows if start <= r[0] <= end]
        success = next((e for e in ordered
                        if e["EventCode"] == 4624 and e.get("IpAddress") == ip
                        and parse_ts(e["timestamp"]) >= start), None)
        follow = []
        if success:
            t_ok = parse_ts(success["timestamp"])
            follow = [{"time": e["timestamp"], "event": e["EventCode"],
                       "detail": e.get("CommandLine") or f"account created: {e.get('TargetUserName')}"}
                      for e in ordered
                      if parse_ts(e["timestamp"]) >= t_ok
                      and e.get("SubjectUserName") == success["TargetUserName"]
                      and e["EventCode"] in (4688, 4720)
                      and e["Computer"] == success["Computer"]]
        alerts.append({
            "rule": "windows_bruteforce_then_success" if success else "windows_bruteforce",
            "severity": "high" if success else "medium",
            "source_ip": ip, "host": in_win[0]["Computer"],
            "failures_in_window": best, "window_minutes": window_min,
            "first_failure": start.isoformat(), "last_failure": end.isoformat(),
            "accounts_targeted": sorted({e["TargetUserName"] for e in in_win}),
            "success_after_failures": bool(success),
            "compromised_account": success["TargetUserName"] if success else None,
            "follow_on_activity": follow,
            "mitre": ["T1110.001", "T1078", "T1059.001", "T1136.001"] if success else ["T1110.001"],
        })
    return alerts
