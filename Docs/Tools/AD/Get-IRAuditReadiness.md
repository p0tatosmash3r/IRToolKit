# Get-IRAuditReadiness

Reports whether the Windows audit policy and event-log settings needed by the IRToolKit AD
detections are actually enabled, so you know a hunt will have the data it depends on. Every
detection is only as good as the events being logged: this readiness check inspects the local (or
remote) host's advanced audit policy subcategories and key event-log sizes/retention, and reports
each gap as a finding so you can fix logging before (or explain findings after) a hunt.

This tool audits logging posture; it does not detect attacks. It emits Informational / Low / Medium
/ High "findings" describing gaps (same `IRToolKit.Finding` schema as the detection tools), is
read-only apart from the optional report files written with `-OutputPath`, and requires local
administrator rights to read the audit policy (`auditpol`). Run it elevated on the DC.

| | |
|---|---|
| ATT&CK | n/a - defensive logging posture (readiness) |
| Event IDs | n/a - reads `auditpol` output, event-log metadata and the Script Block Logging registry value, not events |
| Log sources | Advanced audit policy (auditpol); metadata of the Security, System, Microsoft-Windows-PowerShell/Operational and (optional) Microsoft-Windows-Sysmon/Operational logs; `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` |
| Requires | Windows PowerShell 5.1+; `Common\IRToolKit.Common.psm1` (auto-located up to five levels above the script); local admin (elevation) for accurate audit-policy results; for `-ComputerName`: WinRM (audit policy via Invoke-Command) plus remote event-log access (RPC) for log metadata |

## What it checks

### Advanced audit policy subcategories

The tool parses `auditpol /get /category:* /r` and evaluates the subcategories the AD tools depend
on. Matching is by substring, so related subcategories containing the same text (for example
`Special Logon` under the `Logon` check) are evaluated too; a subcategory absent from the auditpol
output is skipped silently.

| Subcategory check | Severity if gapped | Needed for |
|---|---|---|
| Kerberos Authentication Service | High | AS-REQ events 4768 (AS-REP roasting, golden/forged TGT anomalies) |
| Kerberos Service Ticket Operations | High | TGS events 4769 (Kerberoasting, silver tickets) |
| Credential Validation | Medium | NTLM validation 4776 and failures (password spray) |
| Logon | High | Logon success/failure 4624/4625 (spray, lateral movement) |
| Account Lockout | Low | Lockouts 4740 (brute force / spray side effects) |
| Directory Service Access | High | Object access 4662 (DCSync, dangerous ACL use) |
| Directory Service Changes | High | Attribute changes 5136 (RBCD, shadow credentials, ADCS, delegation) |
| Security Group Management | High | Group membership 4728/4732/4756 (privileged group adds) |
| User Account Management | Medium | User changes 4720/4722/4738 (account manipulation, UAC changes) |
| Computer Account Management | Medium | Computer changes 4741/4742 (delegation, machine account abuse) |
| Sensitive Privilege Use | Low | Privilege use 4672/4673 (SeDebug / token abuse detections) |
| Other Account Logon Events | Low | Additional Kerberos/NTLM detail |

Gap logic per matched subcategory row (findings have High confidence):

- Setting is `No Auditing` (or blank) - reported as "not audited at all" at the severity above.
- Success auditing is off - reported at the severity above.
- Failure auditing is off, for the checks that need failures (`Logon`, `Credential Validation`,
  `Kerberos Authentication`) - reported as a failure-auditing gap "needed for brute-force/spray
  detection"; when the listed severity is High, this failure-only gap is downgraded to Medium.

Each gap finding's `Recommendation` contains the exact remediation command, e.g.
`auditpol /set /subcategory:"Logon" /success:enable /failure:enable`.

If auditpol returns no data at all (typically because the tool is not elevated), one Medium / Low
finding titled "Audit policy could not be read" is raised instead, telling you to re-run as
administrator - audit-policy gaps cannot be verified without it.

### Event log size, retention and channel state

For each key log the tool reads the live log configuration (enabled state, maximum size, record
count, oldest/newest event) and compares the maximum size against a recommended minimum:

| Log | Recommended minimum | Severity if below / unavailable |
|---|---|---|
| Security | 1024 MB | Medium |
| Microsoft-Windows-PowerShell/Operational | 256 MB | Low |
| Microsoft-Windows-Sysmon/Operational | 512 MB | Low (optional: no finding when absent) |
| System | 64 MB | Low |

Per log it raises one of:

- **"Log not available"** (confidence Medium) - the log could not be queried (missing, disabled, or
  access denied); not raised for the optional Sysmon log.
- **"Log disabled"** (confidence High) - the channel exists but is disabled; the recommendation
  gives the `wevtutil sl "<log>" /e:true` command.
- **"Log may be too small"** (confidence Medium) - maximum size below the recommended minimum; the
  description includes the current size, the approximate retention window in days and the record
  count, and the recommendation gives the `wevtutil sl "<log>" /ms:<bytes>` command.
- **"Log OK"** (Informational, confidence High) - size at or above the minimum; the description
  records size, record count, retention days and oldest event as a baseline.

### PowerShell Script Block Logging (local host only)

On a local run the tool reads
`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging`:

- Not set to `1` - Low severity / High confidence finding "PowerShell Script Block Logging is off".
  Event 4104 is used by several tools' tooling-signature rules; the recommendation points at the
  GPO setting (Administrative Templates > Windows Components > Windows PowerShell > Turn on
  PowerShell Script Block Logging).
- Set to `1` - Informational "PowerShell Script Block Logging is on".

This registry check is skipped when `-ComputerName` is used (see Limitations).

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Remote computer to inspect (audit policy read requires admin + WinRM; log metadata requires remote event-log RPC access). |
| `-Credential` | none | Credential for the remote computer. |
| `-OutputPath` | none (no files written) | Directory or file to write the readiness report to. A directory gets `Get-IRAuditReadiness-<timestamp>.<ext>`. |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output (findings are still returned). |

This tool has no detection-tuning parameters, and (unlike the Find-* tools) no `-Path` /
`-InputPath` / `-StartTime` / `-EndTime` / `-MaxEvents`: readiness is read from the live host, not
from exported events.

## Usage

All examples are run from the repo root.

### Check the local host (run elevated, ideally on the DC)

The tool's own first example:

```powershell
.\Tools\AD\Get-IRAuditReadiness.ps1
```

### Check a remote domain controller

```powershell
.\Tools\AD\Get-IRAuditReadiness.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\iradmin)
```

### Write a readiness report

The tool's own second example, normalised to the evidence layout (HTML is the handy format for
sharing with the team that owns GPO):

```powershell
.\Tools\AD\Get-IRAuditReadiness.ps1 -OutputPath C:\Evidence\Out -Format Html
```

### Script the gaps (objects, no console noise)

```powershell
$gaps = .\Tools\AD\Get-IRAuditReadiness.ps1 -Quiet | Where-Object { $_.Severity -ne 'Informational' }
$gaps | Select-Object Severity, Title, Recommendation | Format-Table -AutoSize
```

### Sweep every domain controller

Readiness is per host: a DC with a gap is blind for every event it would have logged, and the
detections cannot tell silence from a missing audit setting. Check all DCs, not just the one you are
on, and rank the gaps across them.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
$dcs = @('dc01.corp.local', 'dc02.corp.local')     # or (Get-IRDomainControllers).Name when domain joined
$gaps = foreach ($dc in $dcs) { .\Tools\AD\Get-IRAuditReadiness.ps1 -ComputerName $dc -Quiet }
$gaps | Where-Object { $_.Severity -in 'High', 'Medium' } | Sort-Object Computer, Severity | Format-Table Computer, Severity, Title -AutoSize
```

### Relationship to Invoke-IRHunt

`Invoke-IRHunt.ps1` runs detection tools (its default `-Tool` filter is `Find-*`), so this utility
tool is not part of a default hunt - run it on its own, typically before the hunt. During a file
hunt (`-Path` / `-InputPath`) the runner would skip it anyway, because it does not accept those
source parameters. If you do target it explicitly for a live sweep, only `-ComputerName` /
`-Credential` are forwarded from the runner:

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Get-IRAuditReadiness -ComputerName dc01.corp.local
```

## Interpreting the results

- **Informational** findings are your baseline: logging that is in place ("Log OK", "Script Block
  Logging is on"). Keep them in the report as evidence of coverage at hunt time.
- **Low / Medium / High** findings are gaps, ranked by how much detection coverage the missing data
  costs: a High gap (for example Kerberos Authentication Service or Directory Service Access off)
  means a primary event feed for the AD detections does not exist on this host.
- Every gap finding's `Description` says which events and detections depend on the setting, and the
  `Recommendation` carries the exact `auditpol` / `wevtutil` / GPO fix - they can be handed to the
  platform team as-is. Prefer applying the fixes through Group Policy so all DCs stay consistent
  (see [AUDIT-POLICY](../../AUDIT-POLICY.md)).
- A small Security log maximum size is a retention problem, not just a hygiene note: on a busy DC
  the log can roll in hours, which silently shortens every tool's usable `-StartTime` window. The
  "Log may be too small" finding reports the observed retention in days - compare it against how
  quickly your team can respond.
- "Audit policy could not be read" means the rest of the audit-policy section is unverified, not
  that it is healthy. Re-run elevated before trusting the report.
- Findings describe the inspected host only. Run the tool per DC (readiness on DC01 says nothing
  about DC02).

## Limitations

- **Elevation**: reading audit policy requires local administrator rights; without them you get the
  single "Audit policy could not be read" finding instead of per-subcategory results.
- **Remote mode is partial**: audit policy is read over WinRM (`Invoke-Command` + `auditpol`), log
  metadata over the remote event-log RPC interface - both must be reachable - and the PowerShell
  Script Block Logging registry check is performed on local runs only, so a remote report omits it.
- **Subcategories only, not SACLs**: the tool verifies audit-policy subcategories, but 4662 /
  5136 coverage also needs audit ACEs on the directory objects, which it does not inspect - see the
  SACL section of [AUDIT-POLICY](../../AUDIT-POLICY.md).
- **NTDS diagnostics are not checked**: Directory Service event 1644 (used by
  [Find-ADReconnaissance](Find-ADReconnaissance.md) RULE 1) requires the NTDS "15 Field
  Engineering" diagnostic, which this tool does not verify.
- **Substring matching**: subcategory checks match by name substring, so a check can evaluate
  related subcategories too; subcategories missing from the auditpol output are skipped without a
  finding.
- **Live only**: there is no offline (`.evtx` / JSON) mode; the tool inspects the current state of
  the host at run time.

## Related tools

- [AUDIT-POLICY](../../AUDIT-POLICY.md) - the kit-wide logging baseline this tool verifies, including the SACL steps it cannot check.
- [EVENT-REFERENCE](../../EVENT-REFERENCE.md) - what each event ID contains and which tools read it.
- [Find-ADReconnaissance](Find-ADReconnaissance.md) and the other Find-* AD tools - the detections whose event feeds this tool validates.
- Invoke-IRHunt - run the AD detection phase once readiness is confirmed.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
