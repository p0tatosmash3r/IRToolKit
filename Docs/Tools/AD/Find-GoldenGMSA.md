# Find-GoldenGMSA

A group Managed Service Account (gMSA) password is never stored; a domain controller computes it on
demand from the forest KDS root key (held under CN=Master Root Keys,CN=Group Key Distribution
Service,CN=Services,CN=Configuration,...) plus the gMSA's SID and password id, and exposes it through
the computed msDS-ManagedPassword attribute to the principals listed in the gMSA's
msDS-GroupMSAMembership. In a Golden gMSA attack (ATT&CK T1555, Credentials from Password Stores) an
actor who can read the KDS root key once can thereafter compute the password of ANY gMSA in the
forest offline and indefinitely, without being in the allowed-principals list and without touching a
DC again. The one detectable moment is the KDS root key read; after that the forgery is offline and
silent. Named tooling: GoldenGMSA, gMSADumper, DSInternals.

Find-GoldenGMSA reads the domain controller's Security log (4662 directory-object access and 5136
directory-object changes) plus PowerShell Operational 4104 for tooling signatures, and emits
IRToolKit.Finding objects. It is read-only and writes files only when -OutputPath is given.

| | |
|---|---|
| ATT&CK | T1555 - Credentials from Password Stores (KDS root key / gMSA credential theft) |
| Event IDs | 4662, 5136 (Security, DC); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log; PowerShell Operational from any host that ran tooling |
| Requires | DS Access > Directory Service Access = Success with a SACL on the KDS root key object / Group Key Distribution Service container and on the gMSA objects (4662); Directory Service Changes = Success with SACL (5136); optional PowerShell Script Block Logging |

## What it detects

### RULE 1 - KDS root key read by a non-DC, Golden gMSA key theft (Critical/High, Critical/Medium with no DC list)
A 4662 whose ObjectName is under Master Root Keys / Group Key Distribution Service, where the
SubjectUserName is NOT a domain controller. DCs read the KDS root key constantly as part of normal
gMSA operation and are excluded via the DC lookup; any other reader has obtained the forest secret
from which every gMSA password is derived. Confidence is High when a DC list is available to
exclude legitimate readers, and Medium (with a caveat in the description) when no DCs are known, so
a legitimate DC reader could not be ruled out.

### RULE 2 - gMSA managed-password blob retrieved (High/Medium for a user account; Medium/Medium for a machine account, only with -IncludeMachineReaders)
A 4662 whose Properties contain the msDS-ManagedPassword GUID
(e362ed86-b728-0842-b27d-2dea7a9df218), meaning the gMSA password blob was read. A gMSA password
should be read by the service host's MACHINE account; a USER account reading the blob is the
gMSADumper-style direct retrieval and is reported High/Medium. DC readers are always excluded, and
accounts passed via -ExpectedGmsaReader are suppressed. Machine-account reads are the normal path
and are numerous, so they are only reported - at Medium/Medium - when -IncludeMachineReaders is set.

### RULE 3 - gMSA password-retrieval principals changed, msDS-GroupMSAMembership (High/Medium)
A 5136 Value Added on msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword): the
actor granted an account the right to retrieve the gMSA's password, a persistence /
privilege-to-credential step. Value-deleted operations are skipped, since it is the addition that
grants retrieval.

### RULE 4 - Golden gMSA / gMSA credential tooling in PowerShell script blocks (High/High)
A 4104 script block matching attack-specific tooling: GoldenGMSA, Get-GoldenGMSAPassword,
gMSADumper, msKds-RootKeyData, ConvertFrom-ADManagedPasswordBlob or Get-ADDBServiceAccount. Dual-use
RSAT strings (Get-ADServiceAccount, msDS-ManagedPassword, Get-KdsRootKey) are deliberately NOT
signatures, because they appear in routine gMSA administration; the KDS read (RULE 1) and the
user-account blob retrieval (RULE 2) are the behavioural signals. The finding carries a
300-character excerpt for triage.

## Required audit policy

- DC: DS Access > Audit Directory Service Access = Success, with a SACL on the KDS root key object /
  the Group Key Distribution Service container and on the gMSA objects -> 4662 for RULE 1 and
  RULE 2. The KDS root key object is NOT audited by default; without a SACL on it RULE 1 has nothing
  to read, so adding a SACL on the Group Key Distribution Service container as a tripwire is
  recommended.
- DC: DS Access > Audit Directory Service Changes = Success, with SACL -> 5136 for RULE 3.
- Optional: PowerShell Script Block Logging -> 4104 for RULE 4.

See [AUDIT-POLICY](../../AUDIT-POLICY.md) for the kit-wide policy baseline.

## Parameters

The source parameters are mutually exclusive modes: live (-ComputerName/-Credential, the default),
exported files (-Path), pipeline objects (-InputObject) or a pre-parsed file (-InputPath).

### Source and output

| Name | Default | Purpose |
|---|---|---|
| -ComputerName | local machine | Live mode: remote computer to read the Security log from |
| -Credential | current user | Credential for the remote computer |
| -Path | - | One or more exported .evtx files, or folders containing .evtx, analysed offline |
| -InputObject | - | Pre-flattened IRToolKit event objects via the pipeline |
| -InputPath | - | JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents) |
| -StartTime | last 7 days (live mode only) | Only analyse events at or after this time |
| -EndTime | - | Only analyse events at or before this time |
| -MaxEvents | 0 (unlimited) | Cap on events read per event-ID batch |
| -OutputPath | - (no files written) | Directory or file for the report; a directory gets Find-GoldenGMSA-<timestamp>.<ext> |
| -Format | Json | Report format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output; findings are still returned as objects |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -NoADLookup | off | Skip live AD DC discovery; the DC list is then built solely from -DomainController |
| -DomainController | - | Domain controller names / IPs. Readers that are DCs are excluded from RULE 1 / RULE 2 (DCs read KDS material and compute gMSA passwords normally); offline, this is how the DC list is supplied |
| -ExpectedGmsaReader | - | Machine / service accounts known to legitimately retrieve gMSA passwords; suppressed in RULE 2 |
| -IncludeMachineReaders | off | Also report machine-account reads of msDS-ManagedPassword in RULE 2 (off by default, as machine reads are the normal path and are numerous) |

Note: on a non-domain-joined analysis host the DC lookup is built from -DomainController, so always
pass your DCs for offline analysis; without them, RULE 1 cannot exclude a legitimate DC reader and
its findings carry a caveat (and drop to Medium confidence).

## Usage

### Live hunt on a DC
Run on (or against) a domain controller; without -StartTime, live mode covers the last 7 days. Pass
your DCs so legitimate KDS reads are excluded.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -StartTime (Get-Date).AddDays(-30) -DomainController dc01.corp.local, dc02.corp.local
```

### Single exported .evtx
Analyse one exported DC Security log offline, supplying the DC list.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02
```

### Multi-source collection
Pass several DCs' Security logs together.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController dc01.corp.local, dc02.corp.local
```

### Folder of exported logs
A folder passed to -Path is expanded to every .evtx inside it.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\Logs\ -DomainController dc01.corp.local, dc02.corp.local
```

### Time-boxed window
Constrain the analysis window in any source mode. The KDS read may be old, so widen the window when
hunting the key theft itself.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\Logs\ -StartTime '2026-07-01' -EndTime '2026-09-15' -DomainController dc01.corp.local
```

### Remote host
Read a remote DC's live logs over the event log API.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst) -DomainController dc01.corp.local, dc02.corp.local
```

### Pipeline input
Pipe pre-flattened events in. ConvertFrom-IRWinEvent comes from the kit module, so import it first.
Only the event IDs you pipe in are analysed, so include 4662 and 5136 as needed.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662 } -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-GoldenGMSA.ps1 -DomainController DC01, DC02
```

### Pre-parsed JSON
Re-analyse events exported earlier (Export-IREvents JSON, CSV or CliXml).

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -InputPath C:\Evidence\Out\dc01-events.json -DomainController DC01, DC02
```

### Writing reports
Findings are written only when -OutputPath is given; -Format All writes Csv, Json and Html.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -StartTime (Get-Date).AddDays(-30) -ExpectedGmsaReader SQLSVC01$, WEB01$ -OutputPath C:\Evidence\Out -Format All
```

### Suppressing known service hosts (-ExpectedGmsaReader)
List the machine / service accounts that legitimately retrieve gMSA passwords so RULE 2 does not
flag them.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -ExpectedGmsaReader SQLSVC01$, WEB01$
```

### Reviewing machine-account reads (-IncludeMachineReaders)
Opt in to seeing machine-account reads of the managed-password blob (Medium/Medium). Expect volume,
since machine reads are the normal retrieval path.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -IncludeMachineReaders
```

### Skipping live AD discovery (-NoADLookup)

`-NoADLookup` skips live AD DC discovery, so the DC list is built solely from `-DomainController` -
use it on a domain-joined analyst host when only the named DCs should be excluded as readers.

```powershell
.\Tools\AD\Find-GoldenGMSA.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01, DC02
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime,
-MaxEvents and (to tools that accept it) -DomainController, and filters the consolidated report with
-MinimumSeverity. The tuning parameters (-ExpectedGmsaReader, -IncludeMachineReaders, -NoADLookup)
are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-GoldenGMSA -Path C:\Evidence\DC01-Security.evtx -DomainController dc01.corp.local, dc02.corp.local -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

- RULE 1: Treat every gMSA in the forest as compromised, because their passwords can now be computed
  offline. Roll the affected gMSA credentials and plan a KDS root key rotation (which requires
  recreating / reprovisioning gMSAs), investigate how the actor obtained DC-level read access, and
  add a SACL tripwire on the Group Key Distribution Service container. If the finding is Medium
  confidence with a "no DC list" caveat, re-run with -DomainController to confirm the reader is not a
  legitimate DC.
- RULE 2: Confirm the reader is an authorised host for that gMSA (add it to -ExpectedGmsaReader if
  so). If not, treat the gMSA as compromised, roll its credential, and review its
  msDS-GroupMSAMembership.
- RULE 3: Confirm the change was authorised. If not, remove the added principal from
  msDS-GroupMSAMembership, treat the gMSA as compromised, and roll its credential.
- RULE 4: Identify the user and process that ran the script block, then correlate with KDS root key
  reads (4662, RULE 1) and gMSA managed-password retrievals (RULE 2) from the same host and window.

## False positives and tuning

- Domain controllers read the KDS root key and compute gMSA passwords as normal operation; supply
  them via -DomainController so those reads are excluded (machine-account-is-DC checks handle the
  rest). Without a DC list, RULE 1 and RULE 2 cannot exclude DC readers and the findings carry a
  caveat.
- Authorised service hosts legitimately retrieve their gMSA passwords - add their machine accounts
  to -ExpectedGmsaReader so RULE 2 does not report them, and leave -IncludeMachineReaders off unless
  you are specifically reviewing machine reads.
- Backup / directory-sync products may read KDS material; confirm the reader before escalating.

## Related tools

- [Find-ADCSAbuse](Find-ADCSAbuse.md) - shares the steal-a-secret-once, forge-offline shape against
  certificates, and the 4662 directory-access source; pivot there if the same actor also abused
  AD CS.
- [Find-ShadowCredentials](Find-ShadowCredentials.md) - another credential-takeover technique read
  from DC Security logs; pivot there when the actor wrote key credentials onto accounts.
- [Find-GPOAbuse](Find-GPOAbuse.md) - shares the 5136 directory-change source; pivot there when the
  actor who changed gMSA membership also edits GPOs.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
