# Find-DCSync

DCSync abuses Active Directory replication: any principal that holds the `DS-Replication-Get-Changes`
and `DS-Replication-Get-Changes-All` extended rights can ask a domain controller to replicate secrets -
including every account's password hash and the krbtgt key - by issuing the MS-DRSR `DsGetNCChanges`
call. Tools such as mimikatz `lsadump::dcsync` and Impacket `secretsdump` do exactly this. Because
replication is a normal DC-to-DC operation, the abuse is only distinguishable by the identity of the
requester: a legitimate request comes from a domain controller, a malicious one from a user or a non-DC
machine account.

Find-DCSync reads Security event 4662 (directory service access) from a domain controller's log, plus
PowerShell script block events (4104), and emits `IRToolKit.Finding` objects (Severity, Confidence,
Technique, Account, Target, EventIds, Evidence, Recommendation - see
[CONVENTIONS](../../CONVENTIONS.md)). The tool is read-only and writes files only when `-OutputPath`
is given.

| | |
|---|---|
| ATT&CK | T1003.006 (OS Credential Dumping: DCSync) |
| Event IDs | 4662 (Security - Directory Service Access); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Domain controller Security log; optionally the PowerShell Operational log of DCs and suspect hosts |
| Requires | DS Access > Audit Directory Service Access = Success on DCs, plus a SACL on the domain head auditing the replication extended rights |

## What it detects

Rule numbers follow the tool source; the current implementation contains RULE 1 and RULE 3 (there is
no RULE 2).

### RULE 1 - DCSync directory replication by non-DC account (Critical/High)

Triggers on a 4662 whose `Properties` field contains one or more of the replication extended-right
GUIDs - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes),
`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All),
`89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set) - where the
subject is neither a known domain controller nor an analyst-approved account from
`-KnownReplicationAccount`. Events are grouped into one finding per subject account; if
Get-Changes-All was exercised, the finding notes that all domain secrets (every password hash and the
krbtgt key - a full DCSync) can be replicated. Severity is Critical, except that a subject whose name
matches the Azure AD Connect / Entra sync naming pattern (`MSOL_<hex>`, `AAD_<hex>`, `AADConnect`,
`ADSync`, `SYNC_<hex>`, or a name containing "AAD Connect") is down-ranked to Low with the title
"Directory replication by a likely Azure AD Connect / sync account (confirm)" instead of alarming on
first run. Confidence is High when a DC list is available, and drops to Medium (with an explicit
caveat in the description) when no DC list could be built, because DC-to-DC replication could not be
excluded.

### RULE 3 - DCSync tooling in PowerShell script block (Critical/High)

Triggers on a 4104 script block matching one of the DCSync tool signatures: `dcsync`, `lsadump`,
`DsGetNCChanges`, `secretsdump`, `Invoke-DCSync`, `Get-ADReplAccount`. Script block logging captures
the code even when it never touched disk, so this catches tooling staged through PowerShell. Each
matching script block produces one Critical/High finding with a 300-character excerpt.

## Required audit policy

- DC: Advanced Audit Policy > DS Access > **Audit Directory Service Access = Success**, PLUS a SACL
  that audits the replication rights on the domain head (the domainDNS object). Without the SACL the
  4662 events are never written and RULE 1 is silent.
- Optional: **PowerShell Script Block Logging** (event 4104 in Microsoft-Windows-PowerShell/Operational)
  for RULE 3; without it RULE 3 is silent.
- Check your posture with `.\Tools\AD\Get-IRAuditReadiness.ps1` before relying on the absence of
  findings.

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
| `-DomainController` | none | DC names / IPs used to recognise (and exclude) legitimate domain-controller replication. Supply when running offline / not domain joined; without any DC list, RULE 1 confidence drops to Medium and findings carry a caveat. |
| `-KnownReplicationAccount` | none | Service accounts that legitimately hold replication rights (e.g. Azure AD Connect `MSOL_*` accounts). 4662 replication events from these subjects are not reported. |
| `-NoADLookup` | off | Skip the implicit live discovery of domain controllers (the tool performs no per-object AD enrichment). DC exclusion then relies solely on the names supplied through `-DomainController`. |

## Usage

### Live hunt on this DC

Run on (or against) a domain controller; live mode covers the last 7 days by default. Always name the
DCs so DC-to-DC replication is excluded. (Tool help example 1.)

```powershell
.\Tools\AD\Find-DCSync.ps1 -DomainController DC01, DC02
```

### Single exported .evtx

Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02
```

### Folder of exported logs

Point `-Path` at a folder; every `.evtx` in it is analysed.

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02
```

### Time-boxed window

Bound the analysis to the incident window with `-StartTime` / `-EndTime`.

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx -StartTime '2026-09-01 00:00' -EndTime '2026-09-15 00:00' -DomainController DC01
```

### Remote host

Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-DCSync.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst) -DomainController DC01, DC02
```

### Pipeline input

Pipe pre-flattened events in. `ConvertFrom-IRWinEvent` lives in the common module, so import it first.
(Tool help example 3.)

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662 } -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-DCSync.ps1 -DomainController DC01
```

### Pre-parsed JSON

Re-analyse events previously flattened to JSON / CSV / CliXml (e.g. from a SIEM export).

```powershell
.\Tools\AD\Find-DCSync.ps1 -InputPath C:\Evidence\DC01-events.json -DomainController DC01, DC02
```

### Writing reports

Findings go to the pipeline by default; `-OutputPath` additionally writes files. `-Format All`
produces Csv, Json and Html (default is Json).

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -OutputPath C:\Evidence\Out -Format All
```

### Offline with -DomainController

When the analysis machine is not joined to the investigated domain, the tool cannot discover the DC
list itself; pass every DC name so legitimate DC-to-DC replication is excluded. Without it, DC
exclusion cannot be performed: the tool warns, RULE 1 confidence drops to Medium, and each finding
carries the caveat "DC exclusion could not be performed".

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02
```

### Suppressing an approved replication account

Azure AD Connect / Entra sync accounts legitimately replicate; after verifying yours, suppress it.
(Tool help example 2.)

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -KnownReplicationAccount MSOL_a1b2c3 -OutputPath C:\Evidence\Out -Format All
```

### Skipping live AD discovery

On a domain-joined analysis box that is NOT part of the investigated domain, stop the tool from
trusting its own domain's DC list and supply the right one explicitly.

```powershell
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController dc01.corp.local, DC02
```

### Running via Invoke-IRHunt

The phase runner forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`,
`-EndTime`, `-MaxEvents` and (to tools that accept it) `-DomainController`, and filters the
consolidated report with `-MinimumSeverity`. Tool-specific tuning such as `-KnownReplicationAccount`
is NOT forwarded - run the tool directly when you need it.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-DCSync -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

### RULE 1 - DCSync directory replication by non-DC account

Confirm first whether the subject account is an authorised domain controller or an approved
replication service (e.g. Azure AD Connect). Check which rights were exercised: Get-Changes-All means
every password hash and the krbtgt key were replicable, not just partial attributes. Corroborate with
the subject's logon events around the same time to find the source host, and with RULE 3 / 4104 hits
from that host. If the principal is not authorised, treat it as domain-wide credential compromise:
reset the krbtgt password twice, rotate privileged and service-account credentials, investigate the
source host for mimikatz / secretsdump, and restrict the `DS-Replication-Get-Changes*` rights on the
domain head to domain controllers only.

### Likely Azure AD Connect / sync account (the Low variant)

Confirm the named account really is your directory-sync account (check its creation date, owner and
the host it ran from). If it is, add it to `-KnownReplicationAccount` to suppress future findings. If
it is NOT your sync account, an attacker may be masquerading as one - treat the finding as Critical.

### RULE 3 - DCSync tooling in PowerShell script block

Identify the user and process that ran the script block (correlate 4103/4688 on the same host).
Correlate with 4662 replication events from the same host and window; a signature hit plus a RULE 1
finding from the same machine is a confirmed incident. Treat the host as compromised.

## False positives and tuning

- Domain controllers replicate constantly and legitimately generate 4662 with these GUIDs. DC
  subjects MUST be excluded: supply `-DomainController` whenever you run offline / not domain joined.
- Azure AD Connect / directory-sync service accounts (typically `MSOL_*`) legitimately hold
  Get-Changes and Get-Changes-All. The tool auto-downgrades name-pattern matches to Low; after
  verifying the account, suppress it with `-KnownReplicationAccount`.
- Read-only domain controllers use Get-Changes-In-Filtered-Set as part of normal operation - make
  sure RODCs are in your `-DomainController` list.

## Related tools

- [Find-DCShadow](Find-DCShadow.md) - the push side of replication abuse: rogue DC registration and
  replication write/topology rights (this tool owns the read side).
- [Find-NTLMRelay](Find-NTLMRelay.md) - a relayed DC authentication can be used to grant replication
  rights; pivot there if the DCSync subject recently appeared in relay findings.
- [Find-ZerologonActivity](Find-ZerologonActivity.md) - DCSync is the classic follow-on to a
  Zerologon machine-account reset; check it when the subject is a computer account.
- [Find-GoldenGMSA](Find-GoldenGMSA.md) - other 4662-based secret reads (KDS root key / gMSA
  managed passwords) by non-DC principals.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
