# Find-PasswordSpray

Password spraying (ATT&CK T1110.003) is a brute-force variant in which an attacker tries one or a few passwords against MANY distinct accounts, rather than many passwords against one account, so that no single account crosses its lockout threshold. The tell-tale signature is a burst of authentication failures for a large number of distinct target accounts from a single source in a short window, frequently followed by a single successful logon once a weak password is guessed.

Find-PasswordSpray reads Security events 4625 (failed logon), 4771 and 4768 (Kerberos pre-authentication / AS-REQ failures), and 4624 / successful 4768 (for success correlation) - live, from exported .evtx, or from pre-parsed event objects - and emits IRToolKit.Finding objects for per-source sprays, likely-compromised accounts, and distributed low-and-slow sprays. The tool is read-only; it writes files only when -OutputPath is given.

| | |
|---|---|
| ATT&CK | T1110.003 (Brute Force: Password Spraying) |
| Event IDs | 4625, 4771, 4768 (failures), 4624 and successful 4768 (success correlation) - all Security channel |
| Log sources | DC Security log (Kerberos; domain-wide view) and member-server Security logs (NTLM / local 4625 / 4624) |
| Requires | DC and member servers: Advanced Audit Policy > Logon/Logoff > Audit Logon = Success and Failure; Account Logon > Audit Kerberos Authentication Service = Failure |

## What it detects

Failures are normalised into one pool. The 4625 path by default keeps only spray-relevant reasons - bad password (SubStatus/Status 0xc000006a) and unknown user (0xc0000064), decoded with ConvertFrom-IRNtStatus - so lockout, expired-password, disabled-account and logon-hours storms do not inflate the distinct-account count (-IncludeAllFailureReasons overrides this; events whose Status and SubStatus are both absent/zero are kept so data is not silently dropped). On the Kerberos path (4771 and 4768) only Status 0x18 (KDC_ERR_PREAUTH_FAILED - bad password) counts. Each failure is grouped by source: the source IP, or 'ws:' plus the WorkstationName when the IP is local/'-'. Sources matching -ExcludeSource are dropped entirely. Counting is by DISTINCT target account, so a single account failing many times (lockout / targeted brute force) is intentionally never flagged.

### RULE 1 - Password spray, many accounts failing from one source (High/High)
Fires when one source accumulates failures for at least -Threshold (default 10) distinct target accounts within a -WindowMinutes (default 30) sliding window. The finding reports the distinct-account count, the dominant failure reason, the event IDs involved, sample accounts, and carries Extra.DistinctAccounts / Extra.WindowMinutes for filtering.

### RULE 2 - Password spray likely succeeded (Critical/High)
Fires when the SAME source has a successful logon (4624, or a successful 4768) for one of the sprayed accounts between the start of a Rule 1 burst and -SuccessWindowMinutes (default 60) after it ends. The finding names the likely-compromised account and the logon type; one finding per source+account pair.

### RULE 3 - Possible distributed / low-and-slow spray (Medium/Medium)
Evaluated over failures NOT already explained by a per-source burst. Fires when, per target domain and across ALL sources, at least -Threshold distinct accounts fail within the longer -SlowWindowMinutes (default 120) window while no single source crossed the per-source threshold - a spray spread across hosts to stay under per-source detection. Distinct-account counting means a single stale credential failing many times contributes 1 and cannot trigger this rule on its own. Lower confidence by design: confirm the sources.

### RULE 4 - Large-scale spray / enumeration escalation (folded into RULE 1, High/High)
When a single source sprays at least -HugeThreshold (default 50) distinct accounts, the same Rule 1 finding is raised with the escalated title "Large-scale password spray / account enumeration", so the obvious case is always reported without emitting a duplicate finding for the same window.

## Required audit policy

- DC and member servers: Advanced Audit Policy > Logon/Logoff > Audit Logon = Success and Failure. Failure auditing produces the 4625 feed; Success auditing produces the 4624 events Rule 2 needs to spot the compromise.
- DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Failure. This produces the 4771 / failed-4768 feed that catches domain-wide Kerberos sprays on the DC. (Success auditing of the same subcategory additionally lets Rule 2 correlate via successful 4768s.)
- Without the Kerberos failure feed the tool only sees NTLM / local sprays (4625); without 4625 it only sees Kerberos sprays - collect both for coverage.
- See [AUDIT-POLICY](../../AUDIT-POLICY.md) for how to enable these, and run `.\Tools\AD\Get-IRAuditReadiness.ps1` to check the current posture.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| -ComputerName | local machine | Remote computer to read the live Security log from |
| -Credential | current user | Credential for the remote computer |
| -Path | - | One or more exported .evtx files, or folders containing .evtx, analysed offline |
| -InputObject | - | Pre-flattened IRToolKit event objects via the pipeline |
| -InputPath | - | JSON / CSV / CliXml file of pre-flattened events |
| -StartTime | live mode: last 7 days | Only analyse events at or after this time |
| -EndTime | - | Only analyse events at or before this time |
| -MaxEvents | 0 (unlimited) | Cap on events read per event-ID batch |
| -OutputPath | - (no files written) | Directory or file to write results to |
| -Format | Json | Export format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output (findings are still returned) |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -Threshold | 10 | Distinct target accounts failing from one source within the window to raise Rule 1 (also the distinct-account bar for Rule 3) |
| -WindowMinutes | 30 | Sliding window length in minutes for the classic per-source spray rule |
| -SuccessWindowMinutes | 60 | Minutes after a spray burst within which a success for a sprayed account is treated as a likely compromise (Rule 2) |
| -SlowWindowMinutes | 120 | Sliding window length in minutes for the distributed / low-and-slow rule (Rule 3) |
| -HugeThreshold | 50 | Distinct accounts from one source that escalate the Rule 1 title to large-scale spray / enumeration |
| -ExcludeSource | - | Source IPs and/or workstation names to ignore - known VPN / RADIUS / Exchange / NAT concentrators and auth proxies through which many users legitimately arrive from one apparent source. Matched case-insensitively against the source IP and the workstation name |
| -IncludeAllFailureReasons | off | Count every 4625 failure reason instead of only bad password (0xc000006a) and unknown user (0xc0000064) |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller against the live Security log - the tool's own first example (last 3 days).

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -StartTime (Get-Date).AddDays(-3)
```

### Single exported .evtx
Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of exported logs
Point -Path at a folder - for spray hunting, DC exports plus member-server Security logs give the fullest picture.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis to the suspected attack window.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -StartTime (Get-Date).AddDays(-2) -EndTime (Get-Date).AddDays(-1)
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe pre-collected events straight into the tool (the tool's own third example). ConvertFrom-IRWinEvent comes from the IRToolKit common module, so import it first. Include 4624 so Rule 2 can correlate successes.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4771,4768,4624} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-PasswordSpray.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -InputPath C:\Evidence\Out\DC01-events.json
```

### Writing reports
Analyse with a lower spray threshold and write CSV/JSON/HTML reports - the tool's own second example.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\DC01-Security.evtx -Threshold 8 -OutputPath C:\Evidence\Out -Format All
```

### Tuned per-source rule
Tighten the classic rule for a small environment: 5 distinct accounts within 15 minutes.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -Threshold 5 -WindowMinutes 15
```

### Tuned escalation bar
Lower the large-scale escalation so sweeps of 25+ accounts get the enumeration title.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -HugeThreshold 25
```

### Wider success correlation
Catch delayed use of a guessed password by extending the Rule 2 window to 4 hours.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -SuccessWindowMinutes 240
```

### Longer low-and-slow window
Stretch the distributed rule to 8 hours when hunting a patient actor.

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -SlowWindowMinutes 480
```

### Excluding gateways and concentrators
Ignore known aggregation points that legitimately front many users (match by IP or workstation name).

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -ExcludeSource 10.10.20.5, VPN-GW01, EXCH01
```

### Counting every 4625 failure reason
Include lockout / expired / disabled / logon-hours failures in the distinct-account count (noisier, broader).

```powershell
.\Tools\AD\Find-PasswordSpray.ps1 -Path C:\Evidence\Logs\ -IncludeAllFailureReasons
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime and -MaxEvents to this tool, and filters the consolidated report with -MinimumSeverity. Tuning parameters such as -Threshold, -ExcludeSource or -IncludeAllFailureReasons are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-PasswordSpray -Path C:\Evidence\Logs\ -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

- RULE 1 spray burst: confirm whether this source should authenticate as many accounts - the SourceIp/SourceHost (e.g. WS-10 at 10.10.20.15) and the dominant failure reason in the description are the first checks (mostly "unknown user" leans enumeration; mostly "wrong password" leans spray). Per the tool's recommendation: triage or block the source, verify the lockout policy, and check whether any sprayed account subsequently logged on successfully. A Rule 2 finding for the same source answers that last question - treat the pair as one incident.
- RULE 2 likely compromise: disable or reset the named account immediately, investigate the source host, and hunt for post-authentication activity (lateral movement, data access) from this source. This is the finding to action first; the logon type in the description tells you how the access landed (network, RDP, etc.).
- RULE 3 distributed spray: correlate the listed sources - shared infrastructure or a proxy may indicate one actor. Verify the accounts, review the lockout policy, and check for any subsequent success from these sources. Deliberately lower confidence: validate before escalating, and look for the same account set recurring across windows.
- RULE 4 escalated title: same handling as Rule 1, but at HugeThreshold scale assume account enumeration as well - review which of the attempted names actually exist and consider forced password resets for the sprayed population.

## False positives and tuning

- A misconfigured service or application with stale credentials can fail for several accounts from one host. Validate, then suppress a confirmed-benign source with -ExcludeSource.
- A vulnerability scanner or a shared kiosk can mimic a small spray; raise -Threshold (and/or shorten -WindowMinutes) or exclude the validated source with -ExcludeSource.
- VPN / RADIUS / Exchange / NAT concentrators and auth proxies funnel many users (and some failures) through one apparent source - the classic structural false positive for per-source counting. List them in -ExcludeSource.
- A single account failing many times is lockout / targeted brute force, not spray, and is intentionally excluded by distinct-account counting - no tuning needed.
- Lockout / expired-password / disabled / logon-hours storms are excluded from the 4625 path by default; only use -IncludeAllFailureReasons when you accept that extra noise for coverage.
- The Rule 3 distributed heuristic is deliberately low confidence - confirm the sources before acting; widen -SlowWindowMinutes only when hunting, not for steady-state alerting.

## Related tools

- [Find-ASREPRoasting](Find-ASREPRoasting.md) - its Kerberos user-enumeration rule (unknown principals) catches the recon sweep that often precedes a spray from the same IP.
- [Find-Kerberoasting](Find-Kerberoasting.md) - after a spray lands, roasting SPN accounts is a common next step from the same foothold.
- [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) - pivot here if a sprayed-then-compromised account starts showing ticket anomalies (downgrades, TGS without TGT).

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
