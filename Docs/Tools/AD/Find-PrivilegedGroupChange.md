# Find-PrivilegedGroupChange

Detects additions to (and removals from) privileged Active Directory groups - Domain Admins, Enterprise Admins, Schema Admins, the built-in Administrators group, and capability groups such as DnsAdmins, Backup Operators, Account/Server/Print Operators and Group Policy Creator Owners - including the stealth "temporary elevation" pattern where the same member is added and removed again within minutes. Adding an attacker-controlled principal to one of these groups is one of the most direct privilege-escalation and persistence actions in a domain.

The tool reads Security group-membership-change events from domain controllers (4728/4756/4732 member added, 4729/4757/4733 member removed), pre-filters to changes whose target group is privileged (decided from the module's static well-known SID/RID and group-name tables - no live AD queries, so it is safe to run fully offline against exported logs), and emits one `IRToolKit.Finding` object per change plus a correlation finding for each add-then-remove pair. Findings carry Severity, Confidence, Technique/TechniqueName, Title, Description, Account, Target, Computer, EventIds, Evidence and Recommendation. The tool is read-only and writes files only when `-OutputPath` is given.

| | |
|---|---|
| ATT&CK | T1098 (Account Manipulation), T1078.002 (Valid Accounts: Domain Accounts) |
| Event IDs | 4728, 4756, 4732 (member added) and 4729, 4757, 4733 (member removed) - Security log. Related group-lifecycle events 4727/4731/4754/4735/4737/4755/4764 are documented for the analyst but not scored. |
| Log sources | Domain controller Security logs (collect from every DC - the change is logged on the DC that serviced the write) |
| Requires | Advanced Audit Policy > Account Management > Audit Security Group Management = Success on domain controllers |

## What it detects

### RULE 1 - Principal added to privileged group (High or Critical/High)
Fires on every 4728 (global), 4732 (local/built-in) or 4756 (universal) whose target group is privileged, reporting who (SubjectUserName) added which member (MemberName DN / MemberSid) to which group and the group scope. Severity is Critical for the domain-crown groups - Domain Admins (RID 512), Schema Admins (RID 518), Enterprise Admins (RID 519) and the built-in Administrators group (S-1-5-32-544), matched by SID/RID or name - because those confer domain-level control; every other privileged group stays High. When `-KnownAdmin` is supplied, the description also states whether the actor is in the list (see RULE 4).

### RULE 2 - Principal removed from privileged group (Medium/Medium)
Fires on every 4729/4733/4757 against a privileged group. Removals matter because attackers remove accounts to undo a temporary elevation or to evict legitimate administrators. Correlate with a preceding add of the same member and with the actions taken while the member was in the group.

### RULE 3 - Rapid add-then-remove from privileged group (High/Medium; Informational/Low when both actors are known admins)
Correlates adds and removes on the key (group, member) - group SID with a name fallback, member SID with a DN/CN fallback - and fires when the same member was added to and removed from the same privileged group within `-StealthWindowMinutes` (default 30), with the elapsed minutes in the description. This "temporary elevation" pattern strongly suggests an attacker granting rights, acting, then cleaning up. When `-KnownAdmin` is supplied and BOTH the add actor and the remove actor are in the list, the finding is down-ranked to Informational/Low as a PAM / just-in-time elevation workflow and shown as context only.

### RULE 4 - Actor anomaly on a privileged add (High or Critical/High - emitted within RULE 1)
Not a separate finding: when `-KnownAdmin` is supplied, each RULE 1 add performed by a subject that is NOT in the list is explicitly called out in the finding description as an unexpected principal performing a privileged-group change. Adds by listed actors are annotated as "in the known-admin list - confirm the change was authorised"; without `-KnownAdmin` the actor is simply noted for verification.

### RULE 5 - Capability-group adds (High/High - via RULE 1)
Groups that are privileged by capability rather than by a well-known RID (DnsAdmins, Backup Operators, Account/Server/Print Operators, Group Policy Creator Owners, ...) are matched by the module's privileged-group NAME list, so adds to them already fire RULE 1 - at High, never Critical, since their domain-specific RIDs are not the crown-group RIDs.

## Required audit policy

- Advanced Audit Policy > Account Management > Audit Security Group Management = Success on every domain controller. This produces 4728/4729/4732/4733/4756/4757 - the only events the tool scores. Without it, every rule is silent.
- Collect the Security log from all DCs: a membership change is recorded only on the DC that performed the write, so a single-DC export can miss changes made elsewhere.
- No DS-Access SACL and no PowerShell logging are needed; this tool does not read 5136 or 4104.

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
| `-OutputPath` | none | Directory or file to write results to (directory gets `Find-PrivilegedGroupChange-<timestamp>.<ext>`). |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output. |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-StealthWindowMinutes` | 30 | Maximum minutes between a privileged-group ADD and a matching REMOVE of the same member for the RULE 3 temporary-elevation finding to fire. |
| `-KnownAdmin` | none | Account names (sAMAccountName or DOMAIN\user) expected to legitimately manage privileged group membership. Adds by anyone else are called out (RULE 4); an add-then-remove where both actors are listed is down-ranked to Informational (RULE 3). |
| `-NoADLookup` | off | Accepted for interface parity with other IRToolKit tools; this detection uses only static reference tables and performs no live AD look-ups, so the switch has no effect. |
| `-DomainController` | none | Accepted for interface parity; not used by this tool (no DC-to-DC exclusion is performed). |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller; Live mode analyses the local Security log for the last 7 days by default.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1
```

### Single exported .evtx
Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of exported logs
Point `-Path` at a folder; every `.evtx` in it is analysed.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Bound the analysis window; this is the tool's own first example (last 14 days on the local DC).

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -StartTime (Get-Date).AddDays(-14)
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\irlead)
```

### Pipeline input
Pipe pre-collected events through `ConvertFrom-IRWinEvent`. Import the common module first - the converter lives there.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4732,4756,4729,4733,4757} -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-PrivilegedGroupChange.ps1 -StealthWindowMinutes 15
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON/CSV/CliXml.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -InputPath C:\Evidence\Out\dc01-events.json
```

### Writing reports
Export findings; a directory gets timestamped `Csv`/`Json`/`Html` files with `-Format All`.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Tightening the stealth window
Shorten `-StealthWindowMinutes` when 30 minutes is too generous for your environment (or widen it to catch slower cleanup).

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\Logs\ -StealthWindowMinutes 10
```

### Known-admin list
Supply the accounts expected to manage privileged groups: adds by anyone else are flagged (RULE 4), and PAM/JIT add-then-remove cycles performed entirely by listed accounts drop to Informational (RULE 3). This is the tool's own second example.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\DC01-Security.evtx -KnownAdmin 'dom_admin1','tier0svc' -OutputPath C:\Evidence\Out -Format All
```

### Interface-parity switches
`-NoADLookup` and `-DomainController` are accepted so one command template works across the whole AD phase, but they change nothing here - this tool never queries AD and performs no DC exclusion.

```powershell
.\Tools\AD\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01,DC02
```

### Via the phase runner
`Invoke-IRHunt` forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`, `-EndTime`, `-MaxEvents` and (to tools that accept it) `-DomainController`, and filters the consolidated report with `-MinimumSeverity`. Tool-specific tuning (`-StealthWindowMinutes`, `-KnownAdmin`) is NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-PrivilegedGroupChange -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

### RULE 1 - Principal added to privileged group
Confirm the change against change control first: actor, member and ticket. If unauthorised, remove the principal, reset the affected and actor credentials, and investigate the actor account and source host for compromise. A Critical finding means a crown group (Domain Admins / Enterprise Admins / Schema Admins / Administrators) - treat as a likely privilege-escalation or persistence action. The RULE 4 annotation ("NOT in the supplied known-admin list") is your fastest filter for which adds to look at first.

### RULE 2 - Principal removed from privileged group
Confirm the removal was expected. Correlate with a preceding add of the same member (possible temporary elevation - RULE 3 does this automatically within its window) and with the actions taken while the member was in the group. A removal of a legitimate administrator can be an eviction.

### RULE 3 - Rapid add-then-remove (temporary elevation)
Treat the actor account and source host as suspect. Review every action taken during the elevation window - DCSync, backups, GPO edits, credential dumps - and reset affected credentials. The finding lists both actors and the elapsed minutes; an Informational variant (both actors in `-KnownAdmin`) is shown as context for a PAM/JIT workflow, but still deserves a spot check that the elevation itself was ticketed.

## False positives and tuning

- Legitimate administrator onboarding, role changes, help-desk staff adding users to operator groups, and IAM / provisioning automation all produce ADD events. Validate the actor, the member and whether a change-control record exists before escalating; supply `-KnownAdmin` so unexpected actors are called out and expected ones are labelled.
- A planned maintenance window that grants then revokes access can resemble the RULE 3 stealth pattern - confirm it was authorised. Listing the PAM/automation accounts in `-KnownAdmin` down-ranks those cycles to Informational; `-StealthWindowMinutes` controls how close the add and remove must be.

## Related tools

- [Find-SIDHistoryInjection](Find-SIDHistoryInjection.md) - privilege gained WITHOUT appearing as a group member; check it when membership audits come back clean.
- [Find-DCSync](Find-DCSync.md) - hunt what an account did during a RULE 3 elevation window (replication-based credential theft).
- [Find-GPOAbuse](Find-GPOAbuse.md) - Group Policy Creator Owners adds often precede GPO tampering; pivot there after a capability-group add.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
