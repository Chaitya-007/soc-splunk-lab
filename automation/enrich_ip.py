"""Offline IP enrichment: internal vs external, plus a local (fictional) blocklist."""
import csv
import ipaddress
from pathlib import Path

INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def load_blocklist(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["ip"]: row for row in csv.DictReader(fh)}


def enrich(ip, blocklist):
    addr = ipaddress.ip_address(ip)
    internal = any(addr in net for net in INTERNAL)
    hit = blocklist.get(ip)
    if internal:
        verdict = "internal"
    elif hit:
        verdict = "listed-malicious"
    else:
        verdict = "external-unknown"
    return {"ip": ip, "scope": "internal" if internal else "external",
            "intel_tag": hit["tag"] if hit else None, "verdict": verdict}


if __name__ == "__main__":
    import sys
    bl = load_blocklist(Path(__file__).parent.parent / "data/threat_intel/blocklist.csv")
    for a in sys.argv[1:]:
        print(enrich(a, bl))
