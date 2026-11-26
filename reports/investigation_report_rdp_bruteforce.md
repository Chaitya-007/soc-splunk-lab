# Investigation Report: RDP brute force followed by account compromise

> Based on the synthetic lab dataset in `data/sample/windows_security.json`. All names and IPs are fictional.

| | |
|---|---|
| Alert | `windows_bruteforce_then_success` (HIGH) |
| Host | SRV-FILE-01 |
| Source IP | 203.0.113.45 (listed in the lab blocklist as an RDP brute-force scanner) |
| Account compromised | admin.svc |
| MITRE ATT&CK | T1110.001 Password Guessing, T1078 Valid Accounts, T1059.001 PowerShell, T1136.001 Local Account |

## Summary
One external IP made 60 failed logons against four accounts in under four minutes, then logged on successfully as `admin.svc` over RDP. The attacker then ran discovery and PowerShell commands and created a new local user, `helpdesk2`.

## Timeline (UTC, 2026-11-20)
| Time | Event |
|---|---|
| 07:15:01 | First of 60 failed logons (4625) from 203.0.113.45 |
| 07:18:57 | Last failed logon; accounts targeted: administrator, admin, admin.svc, backup |
| 07:19:06 | Successful logon (4624, type 10 RDP) as admin.svc from the same IP |
| 07:20:06 | `whoami /all` (4688) |
| 07:21:06 | `powershell.exe -nop -w hidden -enc ...` (4688); the encoded text decodes to `whoami` |
| 07:22:06 | `net user helpdesk2 <redacted> /add` (4688) |
| 07:22:12 | New account `helpdesk2` created (4720) |

## Scope and impact
- Only SRV-FILE-01 shows attacker activity in this dataset; the same IP does not appear anywhere else in the Windows logs.
- The attacker held an administrator-level account and created persistence, so the host is treated as compromised.

## Root cause (likely)
RDP reachable from the internet with a guessable password on `admin.svc`, and no account lockout or MFA.

## Containment and remediation
1. Disable `admin.svc`, reset its password, and remove `helpdesk2`.
2. Isolate SRV-FILE-01 and review it for other persistence (scheduled tasks, services).
3. Block 203.0.113.45 and search for it in all other log sources.
4. Remove direct internet RDP; require VPN and MFA; enable lockout.

## Detection improvements
- Detection `win_bruteforce_burst.yml` fires at 10 failures in 5 minutes; this attack made 60.
- Detection `win_encoded_powershell.yml` catches the `-enc` command.
- Automation: `automation/run_triage.py` produced this alert, enriched the IP and listed follow-on activity without manual searching.
