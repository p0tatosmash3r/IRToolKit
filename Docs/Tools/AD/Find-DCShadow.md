# Find-DCShadow

DCShadow (the mimikatz `lsadump::dcshadow` technique) lets an attacker who already holds high
privilege push malicious changes into Active Directory through the REPLICATION channel instead of a
normal LDAP write, so the change (SID history, group membership, primaryGroupID, a backdoor ACL)
appears on every DC without a corresponding "normal" modification event on a real DC. To do it the
attacker briefly turns a machine into a transient DC: an nTDSDSA object ("NTDS Settings") is created
under the Configuration partition, a Global Catalog SPN (`GC/...`) and the Directory Replication
Service SPN carrying the DRSUAPI RPC interface GUID `E3514235-4B06-11D1-AB04-00C04FC2DCD2` are added
to the computer, replication is triggered, and the objects are torn down again - the rogue DC exists
only for seconds to minutes.

Find-DCShadow reads Security events 4742, 5136, 5137, 5141 and 4662 from domain controller logs, plus
PowerShell script block events (4104), and emits `IRToolKit.Finding` objects (see
[CONVENTIONS](../../CONVENTIONS.md)). The tool is read-only and writes files only when `-OutputPath`
is given.

| | |
|---|---|
| ATT&CK | T1207 (Rogue Domain Controller) |
| Event IDs | 4742, 5136, 5137, 5141, 4662 (Security); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Domain controller Security logs; optionally the PowerShell Operational log |
| Requires | On DCs: Audit Directory Service Changes, Audit Directory Service Access (both with SACLs) and Audit Computer Account Management, all = Success |

## What it detects

### RULE 1 - Replication (DRS/GC) SPN added to a non-DC computer (Critical/High)

Triggers when the DRS replication SPN (carrying the DRSUAPI interface GUID `E3514235-...`) or a `GC/`
SPN is added to a computer that is not in the known-DC list, seen either in a 4742 computer-account
change (the `ServicePrincipalNames` field) or a 5136 value-add on `servicePrincipalName` (value
deletions are ignored). Registering replication capability on a non-DC is the defining DCShadow setup
step, so the finding is Critical with High confidence. When no DC list is available the finding keeps
its severity and confidence but carries the caveat that a legitimate DC could not be excluded -
supply `-DomainController` to confirm.

### RULE 2 - nTDSDSA object created (High/High; Critical when transient)

Triggers on a 5137 creating an nTDSDSA object (object class `nTDSDSA`, or a DN under
`CN=NTDS Settings` / `CN=Servers,...,CN=Sites,CN=Configuration`) - a new domain controller registered
in the directory. On its own this is High/High ("nTDSDSA object created (new domain controller
registered)"). If a 5141 deletion of the same object DN follows within `-CorrelationMinutes` (default
60), the finding escalates to Critical with the title "Transient nTDSDSA object (rogue DC appeared
then was removed - DCShadow)", carries both events as evidence, and states the gap in minutes: the
appear-then-vanish DC is DCShadow's signature and is the pattern a real promotion will NOT show. Note
that this rule is not filtered by the DC list - a genuine promotion also creates an nTDSDSA object and
is reported for confirmation against change control.

### RULE 3 - nTDSDSA object deleted (Medium/Medium)

Triggers on a 5141 deleting an nTDSDSA object that was NOT paired with a creation inside the
correlation window (a paired delete is already reported inside the Critical RULE 2 finding). A
standalone deletion is either a legitimate DC demotion or the cleanup phase of a DCShadow rogue DC
whose creation is not in the analysed dataset (for example, outside the collected time range), hence
the moderate Medium/Medium rating.

### RULE 4 - Replication push/topology rights used by a non-DC (High/High)

Triggers on a 4662 whose `Properties` field contains one of the replication PUSH / topology
extended-right GUIDs - `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Synchronize),
`1131f6ac-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Manage-Topology),
`9923a32a-3607-11d2-b9be-0000f87a36b2` (DS-Install-Replica) - exercised by a subject that is not a
known DC. This is the write/topology side of replication (the read side belongs to
[Find-DCSync](Find-DCSync.md)). Severity is High; confidence is High when a DC list is available and
Medium (with a caveat) when it is not.

### RULE 5 - DCShadow tooling in PowerShell script block (High/High)

Triggers on a 4104 script block matching one of the DCShadow tool signatures: `lsadump::dcshadow`,
`dcshadow`, `DsReplicaAdd`, `DsAddEntry`, `Invoke-Mimikatz`, `mimikatz`. Each matching script block
produces one High/High finding with a 300-character excerpt.

## Required audit policy

All on the domain controllers:

- DS Access > **Audit Directory Service Changes = Success** -> 5137 / 5141 (object create/delete) and
  5136 (attribute changes). Needs a SACL on the Configuration naming context for the nTDSDSA events.
  Without it, RULE 2 and RULE 3 are silent and RULE 1 loses its 5136 source.
- Account Management > **Audit Computer Account Management = Success** -> 4742 (RULE 1's other
  source).
- DS Access > **Audit Directory Service Access = Success** (with SACL) -> 4662 (RULE 4 is silent
  without it).
- Optional: **PowerShell Script Block Logging** -> 4104 (RULE 5 is silent without it).
- Check your posture with `.\Tools\AD\Get-IRAuditReadiness.ps1`.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Live mode: read the event log from this remote computer. |
| `-Credential` | none | Credential for the remote computer. |
| `-Path` | none | One or more exported `.evtx` files, or folders containing `.evtx`, analysed offline. |
| `-InputObject` | none | Pre-flattened IRToolKit event objects via the pipeline. |
| `-InputPath` | none | JSON / CSV / CliXml file of pre-flattened events. |
| `-StartTime` | live mode: last 7 days | Only analyse events at or after this time. |
| `-EndTime` | none | Only analyse events at or before this time. |
| `-MaxEvents` | 0 (unlimited) | Cap on events read per event-ID batch. |
| `-OutputPath` | none (console only) | Directory or file to write results to; no files are written without it. |
| `-Format` | Json | Export format: Csv, Json, Html or All. |
| `-Quiet` | off | Suppress console status output. |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-DomainController` | none | Existing DC names / IPs. A target that is a known DC is treated as legitimate for the SPN rule (RULE 1), and a known-DC subject is excluded from the push-rights rule (RULE 4); offline, this also supplies the DC list. Without it, RULE 1 findings carry a could-not-exclude caveat and RULE 4 confidence drops to Medium. |
| `-CorrelationMinutes` | 60 | Window (minutes) in which an nTDSDSA create (5137) followed by a delete (5141) of the same object is treated as a transient rogue DC and escalated to Critical. |
| `-NoADLookup` | off | Skip live AD DC discovery; the DC list is then built solely from `-DomainController`. |

## Usage

### Live hunt on this DC

Run on a domain controller; live mode covers the last 7 days by default.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -DomainController DC01, DC02
```

### Single exported .evtx

Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02
```

### Folder of exported logs

Point `-Path` at a folder of exports. Collect from EVERY DC - the rogue-DC events land on whichever
DC processed the registration.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02
```

### Time-boxed window

Bound the hunt to the suspect window. (Tool help example 2, which also writes reports.)

```powershell
.\Tools\AD\Find-DCShadow.ps1 -StartTime (Get-Date).AddDays(-3) -OutputPath C:\Evidence\Out -Format All
```

### Remote host

Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst) -DomainController DC01, DC02
```

### Pipeline input

Pipe pre-flattened events in. `ConvertFrom-IRWinEvent` lives in the common module, so import it
first.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4742, 5136, 5137, 5141, 4662 } -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-DCShadow.ps1 -DomainController DC01, DC02
```

### Pre-parsed JSON

Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -InputPath C:\Evidence\DC01-events.json -DomainController DC01, DC02
```

### Writing reports

`-OutputPath` writes result files; `-Format All` produces Csv, Json and Html (default is Json).

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -OutputPath C:\Evidence\Out -Format All
```

### Offline with -DomainController

Hunt rogue-DC registration across exported DC logs; name the legitimate DCs so their SPNs and
replication activity are not reflagged. Without the list, RULE 1 reports every DRS/GC SPN addition
(including on real DCs) with a caveat, and RULE 4 confidence drops to Medium. (Tool help example 1.)

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController DC01, DC02
```

### Widening the transient-DC correlation

If the dataset suggests a slower appear-then-vanish cycle (e.g. cleanup hours later), widen the
create-to-delete pairing window.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -CorrelationMinutes 240
```

### Skipping live AD discovery

`-NoADLookup` skips live AD DC discovery, so the DC list is built solely from `-DomainController` -
use it on a domain-joined analyst host when only the named DCs should be treated as legitimate.

```powershell
.\Tools\AD\Find-DCShadow.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01, DC02
```

### Running via Invoke-IRHunt

The phase runner forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`,
`-EndTime`, `-MaxEvents` and (to tools that accept it) `-DomainController`, and filters the
consolidated report with `-MinimumSeverity`. Tool-specific tuning such as `-CorrelationMinutes` is
NOT forwarded - run the tool directly when you need it.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-DCShadow -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

### RULE 1 - Replication (DRS/GC) SPN added to a non-DC computer

Confirm first whether the target host is an authorised NEW domain controller (a planned promotion
adds exactly these SPNs). If not, this is DCShadow: remove the SPNs and the nTDSDSA object, treat the
actor account and the source host as compromised, hunt for replicated changes (sIDHistory, group
membership, ACLs) pushed in the same window, and review who holds replication / DS-Install-Replica
rights. Corroborate with RULE 2/3 nTDSDSA events and RULE 4 push-rights findings for the same host
and window.

### RULE 2 - nTDSDSA object created / transient rogue DC

Confirm against change control whether a DC was being promoted at that time. The transient (Critical)
variant - created then deleted within the window - is the defining DCShadow pattern and is not
produced by a normal promotion; treat the actor and source as compromised, remove any leftovers, and
hunt for the changes it replicated (sIDHistory, group membership, ACL / primaryGroupID edits) in the
surrounding window.

### RULE 3 - nTDSDSA object deleted

Confirm against change control whether a DC was demoted. If not, hunt for a matching nTDSDSA creation
and replicated changes just BEFORE this time - you may be looking at the cleanup half of a DCShadow
whose creation is outside the collected window; widen `-StartTime` and re-run.

### RULE 4 - Replication push/topology rights used by a non-DC

Confirm the principal is an authorised DC (and that your `-DomainController` list is complete). If
not, treat as DCShadow / replication abuse: investigate the source host and restrict replication
rights on the naming contexts to domain controllers only.

### RULE 5 - DCShadow tooling in PowerShell script block

Identify the user and process that ran the script block. Correlate with nTDSDSA create/delete,
replication-SPN additions, and 4662 replication rights from the same host and window - tooling plus
any directory artefact is a confirmed incident.

## False positives and tuning

- A LEGITIMATE domain controller promotion (dcpromo / `Install-ADDSDomainController`) performs the
  exact same steps - it creates an nTDSDSA object and adds the GC and DRS SPNs - so a real, planned
  new DC trips RULE 1 and RULE 2. Pass existing DCs via `-DomainController` so they are not reflagged,
  and confirm any new DC against change control (then add it to `-DomainController` for future runs).
- The transient create+delete correlation (the Critical RULE 2 variant) is the pattern a real
  promotion will NOT show; tune its pairing window with `-CorrelationMinutes`.
- Demoting a DC legitimately deletes its nTDSDSA object (RULE 3). Confirm against change control.

## Related tools

- [Find-DCSync](Find-DCSync.md) - the read side of replication abuse (Get-Changes rights); run it on
  the same logs, since DCShadow operators commonly hold both capabilities.
- [Find-SIDHistoryInjection](Find-SIDHistoryInjection.md) - sIDHistory is a favourite payload pushed
  via DCShadow; hunt it in the window around a rogue-DC finding.
- [Find-PrivilegedGroupChange](Find-PrivilegedGroupChange.md) - privileged-group membership is
  another DCShadow payload; check for changes that lack normal modification events.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
