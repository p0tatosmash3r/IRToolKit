# Find-SIDHistoryInjection

Detects SID History injection - a privileged SID planted in an account's sIDHistory attribute. sIDHistory is a legitimate attribute used during domain migration (a migrated account carries its old-domain SID so it keeps access), but when a privileged SID is placed in the sIDHistory of an account an attacker controls, the account inherits that access invisibly: it is not a listed member of the group, so group-membership audits miss it. This makes it a stealthy privilege-escalation and persistence primitive.

The tool reads Security events 4765 (SID History added), 4766 (failed add attempt), 5136 (sIDHistory attribute written), 4738/4742 (account change carrying a SidHistory value), and PowerShell Operational 4104 (script-block tooling signatures), and emits one `IRToolKit.Finding` per detection - with privileged additions surfaced immediately as Critical and non-privileged additions rolled up into a single counted High finding per (actor, source-domain) so a bulk legitimate migration is one finding, not one per account. Findings carry Severity, Confidence, Technique/TechniqueName, Title, Description, Account, Target, Computer, EventIds, Evidence and Recommendation. The tool is read-only and writes files only when `-OutputPath` is given.

A SID is treated as privileged when its RID is a privileged group RID (512/518/519/520 and the other RIDs in the module table), when it is the domain Administrator (RID 500), or when it is a built-in privileged SID (for example S-1-5-32-544).

| | |
|---|---|
| ATT&CK | T1134.005 (Access Token Manipulation: SID-History Injection) |
| Event IDs | 4765, 4766, 4738, 4742, 5136 (Security); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Domain controller Security logs; PowerShell Operational logs from the host that ran the tooling (RULE 5) |
| Requires | Account Management > Audit User Account Management = Success and DS Access > Audit Directory Service Changes = Success (SACL) on DCs; optionally PowerShell Script Block Logging |

## What it detects

### RULE 1 - SID History added via 4765 (Critical/High or High/High)
Fires on event 4765 (SID History was added to an account). The added SID is taken from the structured SID fields (SourceSid / SidList / SidHistory / NewSid), falling back to the rendered message, and the account's own SID and the actor's SID are excluded so a change made by the built-in Administrator does not read as a RID-500 injection. Critical/High when any added SID is privileged (the injection attack). A non-privileged addition is not emitted here - it is accumulated and rolled up (see the aggregate finding below).

### RULE 2 - sIDHistory attribute written via 5136 (Critical/High or High/High)
Fires on event 5136 Value-Added on the sIDHistory attribute (Value Deleted is skipped). This is the authoritative attribute-level signal. Same privileged-versus-not split as RULE 1: a privileged SID is an immediate Critical, a non-privileged SID feeds the aggregate.

### RULE 3 - Failed attempt to add SID History via 4766 (High/Medium or Medium/Medium)
Fires on event 4766 (a SID History addition attempt failed). Severity is High when any attempted SID is privileged, otherwise Medium; Confidence Medium. A failed attempt still shows that someone tried to inject SID history and often precedes a successful attempt by another path.

### RULE 4 - Account change carrying a SidHistory value via 4738/4742 (Critical/High or High/High)
A fallback for environments where 4765/5136 are not audited: a 4738 (user) or 4742 (computer) account change whose SidHistory field now carries a SID value. SIDs are extracted and run through the same privileged-versus-not split (privileged -> Critical immediately, non-privileged -> aggregate).

### Aggregate - non-privileged sIDHistory additions (High/Medium)
The non-privileged additions collected by RULEs 1, 2 and 4 are grouped by (actor, source-domain SID prefix) into a single High/Medium finding with the account count and sample SIDs. This keeps a bulk legitimate migration to one counted finding instead of one per account, while still flagging that an sIDHistory addition outside a controlled migration is abnormal. SIDs matching `-KnownMigrationSid` are suppressed before aggregation.

### RULE 5 - SID-history injection tooling in a PowerShell script block via 4104 (High/Medium)
Fires when a 4104 script block (or its message text) matches a SID-history tooling signature - the signatures named in the source are `Add-ADDBSidHistory`, `sid::add`, `sid::patch`, `Invoke-Mimikatz`, `mimikatz` and `Set-ADDBAccountPassword`. The finding carries a short excerpt and points triage at correlating with 4765/5136 additions on the DCs in the same window.

## Required audit policy

On domain controllers:

- Account Management > Audit User Account Management = Success -> 4765 / 4766 / 4738. Note that 4765/4766 require SAM / account-management SID-history auditing and are NOT on by default.
- DS Access > Audit Directory Service Changes = Success, with a SACL covering the sIDHistory attribute -> 5136. Also not guaranteed by default.
- Enable at least one of the two paths above for coverage; with neither, RULEs 1-3 and the 5136 path of RULE 2 are silent and only the 4738/4742 fallback (RULE 4) can fire - and only if those events are audited.

Optionally, on hosts where injection tooling might run:

- PowerShell Script Block Logging -> 4104 for RULE 5. Without it, RULE 5 is silent.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Read the live Security log of this remote computer (Live mode). |
| `-Credential` | none | Credential for the remote computer. |
| `-Path` | none | One or more exported `.evtx` files, or folders containing `.evtx`, analysed offline. |
| `-InputObject` | none | Pre-flattened IRToolKit event objects via the pipeline. |
| `-InputPath` | none | JSON / CSV / CliXml file of pre-flattened events. |
| `-StartTime` | last 7 days in Live mode; unbounded for files | Only analyse events at or after this time. |
| `-EndTime` | none | Only analyse events at or before this time. |
| `-MaxEvents` | 0 (unlimited) | Cap on events read per event-ID batch. |
| `-OutputPath` | none | Directory or file to write results to (directory gets `Find-SIDHistoryInjection-<timestamp>.<ext>`). |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output. |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-KnownMigrationSid` | none | SIDs (exact) or domain-SID prefixes (for example `S-1-5-21-1111-2222-3333`) known to be legitimate migration source SIDs. A non-privileged sIDHistory addition matching one is suppressed; privileged SIDs are always reported regardless. |

This tool does not accept `-NoADLookup` or `-DomainController`.

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller; Live mode analyses the local Security log (and PowerShell Operational for RULE 5) for the last 7 days by default.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1
```

### Single exported .evtx
Hunt SID History injection in one exported DC Security log (the tool's own first example).

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of exported logs
Point `-Path` at a folder; every `.evtx` in it is analysed - useful when the Security and PowerShell logs were exported side by side.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Bound the analysis window.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -StartTime (Get-Date).AddDays(-30)
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\irlead)
```

### Pipeline input
Pipe pre-collected events through `ConvertFrom-IRWinEvent`. Import the common module first - the converter lives there.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4765,4766,5136,4738,4742} -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-SIDHistoryInjection.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON/CSV/CliXml.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -InputPath C:\Evidence\Out\dc01-events.json
```

### Writing reports
Export findings; a directory gets timestamped `Csv`/`Json`/`Html` files with `-Format All`.

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Suppressing a known migration source domain
Add the legitimate source-domain SID prefix(es) so a bulk non-privileged migration is suppressed while any privileged SID still surfaces as Critical (adapted from the tool's own second example).

```powershell
.\Tools\AD\Find-SIDHistoryInjection.ps1 -StartTime (Get-Date).AddDays(-30) -KnownMigrationSid S-1-5-21-9-8-7 -OutputPath C:\Evidence\Out -Format All
```

### Via the phase runner
`Invoke-IRHunt` forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`, `-EndTime` and `-MaxEvents` to this tool (it accepts no `-DomainController`), and filters the consolidated report with `-MinimumSeverity`. The `-KnownMigrationSid` tuning is NOT forwarded - run the tool directly to suppress a known migration.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-SIDHistoryInjection -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -MinimumSeverity High
```

## Triage: reading the findings

### RULEs 1, 2, 4 - privileged SID injected (Critical)
Treat as privilege escalation / persistence. Clear the injected SID from the account's sIDHistory (for example `Set-ADUser -Remove`, or `ntdsutil`), reset and investigate the account, and review how the actor obtained the ability to write sIDHistory (the DsAddSidHistory privilege, DCShadow, or an offline ntds.dit edit). A privileged SID in sIDHistory is essentially never a legitimate migration artefact.

### Aggregate - non-privileged additions (High)
Confirm an authorised migration added these SIDs. If a migration is confirmed, add the legitimate source-domain SID prefix to `-KnownMigrationSid` to suppress the finding on future runs. If there was no migration, this is SID History injection: clear the values and investigate the actor.

### RULE 3 - failed attempt (4766)
Investigate the actor and source host; a failed injection attempt often precedes a successful one via another path (DCShadow, offline ntds.dit edit). A privileged attempted SID raises this to High.

### RULE 5 - tooling in a script block (4104)
Identify the user and process. Correlate with 4765 / 5136 sIDHistory additions on the DCs in the same window, and inspect sIDHistory across privileged-adjacent accounts.

## False positives and tuning

- A genuine domain migration (ADMT) adds sIDHistory in bulk, but those SIDs come from the source domain (a different domain SID) and are ordinary user RIDs, so they surface at High via the aggregate finding, not Critical. Add the known source-domain SIDs or prefixes to `-KnownMigrationSid` to suppress them.
- A privileged SID in sIDHistory is essentially never a legitimate migration artefact and stays Critical regardless of `-KnownMigrationSid`.

## Related tools

- [Find-PrivilegedGroupChange](Find-PrivilegedGroupChange.md) - the visible counterpart; SID History injection grants the same access WITHOUT a membership event, so run both.
- [Find-DCShadow](Find-DCShadow.md) - DCShadow is one of the paths used to write sIDHistory; pivot there when the write has no corresponding 4765/5136.
- [Find-TrustAbuse](Find-TrustAbuse.md) - weakened SID filtering on a trust enables cross-trust SID-history escalation; check it when the injected SID is cross-domain.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
