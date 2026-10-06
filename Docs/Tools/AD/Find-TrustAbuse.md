# Find-TrustAbuse

Detects Active Directory trust abuse - malicious trust creation, modification or removal, and the SID-filtering weakening that makes cross-trust SID-history escalation possible - from Windows Security and PowerShell event logs. A domain or forest trust lets principals from one domain authenticate into another; SID filtering (quarantine) is the boundary that stops a controlled trusted side from forging SID-history / ExtraSids across the trust. The tool watches the trust object itself and the commands that change it; it reads logs only.

It reads the trust-lifecycle and policy-change events (4706 created, 4707 removed, 4716 trust-info modified, 4865/4866/4867 forest-trust name-suffix routing), the attribute-level 5136 changes on the trustedDomain object (paired old->new via OpCorrelationID), 4688 process-creation command lines and 4104 PowerShell script blocks, and emits one `IRToolKit.Finding` per detection (Severity, Confidence, Technique/TechniqueName, Title, Description, Account, Target, Computer, EventIds, Evidence, Recommendation). The tool is read-only and writes files only when `-OutputPath` is given.

| | |
|---|---|
| ATT&CK | T1484.002 (Domain Policy Modification: Domain Trust Modification); enables T1134.005 (SID-History Injection) |
| Event IDs | 4706, 4707, 4716, 4865, 4866, 4867, 5136, 4688 (Security); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Domain controller Security logs; PowerShell Operational logs from the host that ran any trust tooling (RULEs 4 and 5) |
| Requires | Policy Change > Audit Authentication Policy Change = Success; DS Access > Audit Directory Service Changes = Success (SACL on trustedDomain); Audit Process Creation (+ command line); PowerShell Script Block Logging |

## What it detects

### RULE 1 - Dangerous trust configuration change (Medium to Critical)
Reads trust-attribute changes from 5136 on the trustedDomain object (precise old->new, paired by OpCorrelationID) and from 4716 (new state only). The severity is the highest of the dangerous observations found in the resulting trustAttributes / encryption state:

- SID filtering disabled - the QUARANTINED_DOMAIN bit (0x4) cleared, or the SidFilteringEnabled field reading Disabled -> High.
- TREAT_AS_EXTERNAL (0x40) set on a forest trust (0x8) -> Critical (this is the cross-forest SID-history escalation condition); set on a non-forest trust -> High.
- Cross-forest TGT delegation enabled - ENABLE_TGT_DELEGATION (0x800) set, or NO_TGT_DELEGATION (0x200) cleared -> High.
- NTLM auth-target validation disabled - DISABLE_AUTH_TARGET_VALIDATION (0x1000) set -> High.
- RC4 downgrade of the trust key - USES_RC4_ENCRYPTION (0x80) set on a non-MIT trust, or msDS-SupportedEncryptionTypes set RC4-only -> Medium (emitted as its own "Trust encryption downgraded to RC4" finding from the 5136 encryption path).

Confidence is High when the change was observed as an old->new transition (5136 with both values), Medium when only the new state is known (4716, or a 5136 add with no paired delete).

### RULE 2 - New domain/forest trust created (Medium/Medium, or escalated/High)
Fires on event 4706. Baseline Medium/Medium; raised to the top dangerous observation's severity and High confidence when the new trust already has SID filtering disabled or a dangerous attribute (treat-as-external, TGT delegation). The finding records trust type, direction and SID-filtering state.

### RULE 3 - Trust removed / routing entry changed (Medium)
Fires on event 4707 (trust removed, Confidence Low) and on 4865/4866/4867 (a forest-trust name-suffix / TLN routing entry added, removed or modified, Confidence Low). Trust teardown and routing changes are routine during decommissioning but can also be disruption, track-covering, or name-based routing abuse.

### RULE 4 - Trust-modifying command executed (Medium or High/High)
Matches trust-changing commands in 4688 command lines and 4104 script blocks (comments are stripped from 4104 text first so a commented-out command does not match):

- `netdom` with a dangerous flag on the same command - `/quarantine:No`, `/enablesidhistory:Yes`, `/enabletgtdelegation:Yes`, `/authtargetvalidation:No`, `/selectiveauth:No`, or `/passwordt` -> High (technique T1134.005 for the quarantine/sidhistory flags, otherwise T1484.002).
- The .NET `SetSidFilteringStatus` / `SetSelectiveAuthenticationStatus` set to a disabling value -> High (re-enabling is a defensive action and does not fire).
- A direct `Set-ADObject` write to `trustAttributes` -> High.
- The .NET `CreateTrustRelationship` / `CreateLocalSideOfTrustRelationship` / `DeleteTrustRelationship` -> Medium.

### RULE 5 - Trust-key / credential tooling (sidecar signatures) (High or Critical, Confidence High)
Matches offensive trust-key tooling in 4104 script blocks and 4688 processes against the signatures in the sidecar data file (see below). Matching is invocation-anchored - merely naming a tool does not fire. The severity of each hit comes from its category in the data file. RULE 5 is skipped entirely when the sidecar is absent or not valid JSON; RULEs 1-4 still run.

## The RULE 5 signature sidecar

RULE 5 reads its signatures from a data file rather than embedding offensive command strings in the script, so the detector does not self-quarantine under AMSI/EDR. The benign-admin trust commands (netdom, .NET, Set-ADObject) are detected inline in RULE 4 and do not depend on the sidecar.

- File name: `Find-TrustAbuse.signatures.json`.
- Resolution order: the path given in `-SignatureFile` if supplied; otherwise beside the script first (a standalone build or local drop-in), then the central `Common\Signatures\Find-TrustAbuse.signatures.json`.
- Graceful degrade: if the file is missing, RULE 5 is skipped and the tool logs a Detail status; if it is present but not valid JSON, RULE 5 is disabled with a Warning. Either way RULEs 1-4 still run.
- Standalone builds: `Build-Standalone.ps1` copies the sidecar next to the standalone tool, so RULE 5 keeps working in a single-folder deployment.

The repo sidecar at `Common\Signatures\Find-TrustAbuse.signatures.json` categorises each signature as `crit`, `high`, `bin` or `mod`, which maps to the finding severity for a hit. The exact tokens live in that file, not in the script or this document.

## Required audit policy

On domain controllers:

- Policy Change > Audit Authentication Policy Change = Success -> 4706 / 4707 / 4716 / 4865-4867 (on by default in most DC baselines). Without it, RULEs 1b (4716), 2 and 3 are silent.
- DS Access > Audit Directory Service Changes = Success, with a SACL on the trustedDomain objects -> 5136 (gives the precise old->new attribute diff; not guaranteed by default). Without it, RULE 1 loses its high-confidence transition path and the RC4-downgrade detection.
- Audit Process Creation with command-line capture -> 4688, and PowerShell Script Block Logging -> 4104. Without these, RULEs 4 and 5 are silent.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Read the live logs of this remote computer (Live mode). |
| `-Credential` | none | Credential for the remote computer. |
| `-Path` | none | One or more exported `.evtx` files, or folders containing `.evtx`, analysed offline. |
| `-InputObject` | none | Pre-flattened IRToolKit event objects via the pipeline. |
| `-InputPath` | none | JSON / CSV / CliXml file of pre-flattened events. |
| `-StartTime` | last 7 days in Live mode; unbounded for files | Only analyse events at or after this time. |
| `-EndTime` | none | Only analyse events at or before this time. |
| `-MaxEvents` | 0 (unlimited) | Cap on events read per event-ID batch. |
| `-OutputPath` | none | Directory or file to write results to (directory gets `Find-TrustAbuse-<timestamp>.<ext>`). |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output. |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-ExcludeAccount` | none | Known-good trust administrators / migration (ADMT) service accounts whose trust changes are suppressed. Matched on the bare name (UPN / DOMAIN\ / trailing-`$` aware). |
| `-IncludeAnonymousResets` | off | Also report ANONYMOUS-LOGON trust-info modifications. Automatic trust-password resets fire 4716/5136 as ANONYMOUS LOGON (S-1-5-7, LogonId 0x3E6) and are excluded by default unless they carry a dangerous end-state; this switch includes them. |
| `-SignatureFile` | beside the tool, else `Common\Signatures\Find-TrustAbuse.signatures.json` | Path to the RULE 5 signature data file (see the sidecar section). |

This tool does not accept `-NoADLookup` or `-DomainController`.

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller; Live mode analyses the local logs for the last 7 days by default.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1
```

### Single exported .evtx
Hunt trust abuse in one exported DC Security log, suppressing a known trust admin (the tool's own first example).

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeAccount CORP\trustadmin
```

### Folder of exported logs
Point `-Path` at a folder; every `.evtx` in it is analysed - useful when the Security and PowerShell logs were exported together.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Bound the analysis window (adapted from the tool's own second example).

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -StartTime (Get-Date).AddDays(-30) -OutputPath C:\Evidence\Out -Format All
```

### Remote host
Read the live logs of a remote DC.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\irlead)
```

### Pipeline input
Pipe pre-collected events through `ConvertFrom-IRWinEvent`. Import the common module first - the converter lives there.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4706,4707,4716,4865,4866,4867,5136,4688} -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-TrustAbuse.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON/CSV/CliXml.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -InputPath C:\Evidence\Out\dc01-events.json
```

### Writing reports
Export findings; a directory gets timestamped `Csv`/`Json`/`Html` files with `-Format All`.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Excluding known trust administrators
Suppress changes made by trusted trust-admin or ADMT service accounts so only unexpected actors remain.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\Logs\ -ExcludeAccount 'CORP\trustadmin','admt_svc'
```

### Including automatic trust-password resets
Add the ANONYMOUS-LOGON trust-info modifications that are excluded by default, when you want to review every 4716/5136 regardless of actor.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -IncludeAnonymousResets
```

### Pointing at a specific signature file
Override the sidecar location - for example a reviewed copy under the evidence tree.

```powershell
.\Tools\AD\Find-TrustAbuse.ps1 -Path C:\Evidence\Logs\ -SignatureFile C:\Evidence\Out\Find-TrustAbuse.signatures.json
```

### Via the phase runner
`Invoke-IRHunt` forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`, `-EndTime` and `-MaxEvents` to this tool (it accepts no `-DomainController`), and filters the consolidated report with `-MinimumSeverity`. The tuning parameters (`-ExcludeAccount`, `-IncludeAnonymousResets`, `-SignatureFile`) are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-TrustAbuse -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

### RULE 1 / RULE 2 - dangerous trust configuration change / new trust
Confirm the change was authorised (change control, a trust-admin actor, a migration window). If not, restore SID filtering / selective authentication (for example `netdom /quarantine:Yes`, `/enablesidhistory:no`, or `Set-ADObject` on trustAttributes), rotate the trust password, and hunt for cross-realm forged-TGT use (4769 for krbtgt/REALM) and SID-history writes that follow. A Critical RULE 1 means TREAT_AS_EXTERNAL on a forest trust - the cross-forest escalation condition - so escalate immediately. For a new trust (RULE 2), confirm it is an authorised M&A / migration; if not, remove it and review what the trusted domain can now reach.

### RULE 3 - trust removed / routing entry changed
Confirm the removal or routing change was planned. Unexpected teardown can be disruption or track-covering after trust abuse; unexpected TLN additions or toggles can enable name-based routing abuse across the forest trust.

### RULE 4 - trust-modifying command
These commands disable SID filtering / selective auth or create/delete trusts. Confirm the change was authorised; if unexpected, treat as trust tampering and restore the protections.

### RULE 5 - trust-key / credential tooling
Identify the user and process. A trust-key dump enables forging inter-realm TGTs into or across the trust - rotate the trust password(s) and correlate with 4769 krbtgt/REALM anomalies and trust-attribute changes.

## False positives and tuning

- Mergers and acquisitions create trusts (4706); domain migrations with ADMT legitimately run `/quarantine:No` or `/enablesidhistory:yes` and write SID history; decommissioning removes trusts (4707/4866). Distinguish by change control, the acting account (trust admin / ADMT service account versus an unexpected one), the window, and whether cross-realm ticket anomalies follow. Add the known trust admins to `-ExcludeAccount`.
- Automatic trust-password resets fire 4716/5136 as ANONYMOUS LOGON (S-1-5-7, LogonId 0x3E6) and are excluded by default unless they carry a dangerous end-state; use `-IncludeAnonymousResets` only when you specifically want to review them.

## Related tools

- [Find-SIDHistoryInjection](Find-SIDHistoryInjection.md) - the escalation that weakened SID filtering on a trust enables; run it after a RULE 1 SID-filtering finding.
- [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) - cross-realm 4769 anomalies that corroborate a forged inter-realm TGT after trust-key theft.
- [Find-DelegationAbuse](Find-DelegationAbuse.md) - account-level delegation; cross-forest TGT delegation flagged here is the trust-object counterpart.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
