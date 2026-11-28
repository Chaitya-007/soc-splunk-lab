# SOC Lab: Splunk Investigation, Detections and Triage Automation

A small, reproducible SOC project. It generates **synthetic** Windows, Okta and AWS CloudTrail logs with four attacks hidden in normal activity, then shows how to find each attack in **Splunk (SPL)**, how to turn it into a **detection rule**, and how to **automate the triage** with Python.

> **Honest scope:** this is a learning lab built on fictional data (IPs from the RFC 5737 documentation ranges, made-up users). It is not production work and does not claim to be.

## What is inside

| Folder | What it holds |
|---|---|
| `data/generate_logs.py` | Creates the three log files in `data/sample/` |
| `data/threat_intel/blocklist.csv` | A tiny fictional threat-intel list used for enrichment |
| `spl/queries.spl` | 7 SPL searches, each with a one-line "why" |
| `splunk/props.conf` | Source type settings so Splunk reads timestamps and JSON correctly |
| `detections/` | 3 Sigma-style rules (brute-force burst, encoded PowerShell, Okta MFA fatigue) |
| `automation/` | Python detections, IP enrichment and `run_triage.py`, which chains them and writes a report |
| `reports/` | Generated `triage_summary.md` and `alerts.json`, plus a written investigation report |
| `tests/` | Unit tests that prove each detection fires on the attack and not on normal noise |
| `resume/` | My resume |

## The four scenarios

| # | Scenario | Where | MITRE ATT&CK |
|---|---|---|---|
| 1 | Brute force from one IP, then a successful RDP logon, then `whoami`, encoded PowerShell and a new user | Windows Security | T1110.001, T1078, T1059.001, T1136.001 |
| 2 | Impossible travel: Pune login, then Frankfurt 40 minutes later | Okta | T1078 |
| 3 | MFA push fatigue: 5 denied pushes, then an approved one | Okta | T1621 |
| 4 | Leaked CI access key used from a new IP to create an admin user | CloudTrail | T1078.004, T1136.003, T1098 |

## Run it

```bash
python3 data/generate_logs.py            # optional: sample data is already included
python3 -m unittest discover -s tests -v # 6 tests
python3 -m automation.run_triage         # writes reports/triage_summary.md
```

No third-party Python packages are needed.

Output of the last command on the included data:

```
4 alerts -> reports/triage_summary.md
  [HIGH  ] windows_bruteforce_then_success  203.0.113.45  listed-malicious
  [MEDIUM] okta_impossible_travel  192.0.2.77  external-unknown
  [HIGH  ] okta_mfa_push_fatigue  203.0.113.99  listed-malicious
  [HIGH  ] aws_access_key_new_ip_sensitive_actions  203.0.113.77  listed-malicious
```

## Use it in Splunk

1. Install Splunk (a free trial or Splunk Free works) and create an index named `soc_lab`.
2. Copy `splunk/props.conf` into `$SPLUNK_HOME/etc/apps/search/local/` and restart.
3. Add the three files from `data/sample/` (Settings > Add Data > Upload) with sourcetypes `windows:security`, `okta:system` and `aws:cloudtrail`, index `soc_lab`.
4. Check that event times show **2026-11-20**, then run the searches in `spl/queries.spl` over "All time".

## How the automation works

`run_triage.py` runs each detection, enriches every source IP (internal or external, listed in the blocklist or not), adds MITRE tags and recommended response steps, and writes one summary. The idea is the same as a SOAR playbook in miniature: do the repeated lookups automatically so the analyst only decides.

## Limits and next steps

- Data is synthetic and small; thresholds (10 failures in 5 minutes, 900 km/h) are examples, not tuned values.
- Enrichment is offline; a real version would call a threat-intel API.
- Next: turn the triage flow into a real SOAR playbook, add a phishing-email scenario, and measure false positives against noisier data.

## Author

Chaitanya Asole.
