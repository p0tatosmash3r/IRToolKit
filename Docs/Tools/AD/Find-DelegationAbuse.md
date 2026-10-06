# Find-DelegationAbuse

Detects changes that configure or weaken Kerberos delegation on Active Directory accounts, across three variants the tool scores: unconstrained delegation (the TRUSTED_FOR_DELEGATION flag), constrained delegation / S4U (the msDS-AllowedToDelegateTo target list, and the protocol-transition flag TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION), and resource-based constrained delegation, RBCD (the msDS-AllowedToActOnBehalfOfOtherIdentity attribute). These settings are legitimate for front-end services and gMSAs, but when set on the wrong object they are a well-known privilege-escalation and lateral-movement foothold, so each change is worth confirming against change control.

The tool reads two sources from domain-controller Security logs: 5136 directory-object modifications - the authoritative, attribute-level record of the three delegation attributes and of userAccountControl value adds - and 4742/4738 computer/user account changes, whose OldUacValue/NewUacValue are diffed and whose AllowedToDelegateTo field is parsed. Each flagged change emits one `IRToolKit.Finding` (Severity, Confidence, Technique/TechniqueName, Title, Description, Account, Target, Computer, EventIds, Evidence, Recommendation). The tool is read-only and writes files only when `-OutputPath` is given.

| | |
|---|---|
| ATT&CK | T1558.003 (Steal or Forge Kerberos Tickets - unconstrained-delegation findings), T1134 (Access Token Manipulation - constrained / RBCD findings), T1484 (Domain Policy Modification) |
| Event IDs | 5136 (directory object modified), 4742 (computer account changed), 4738 (user account changed) - all Security log |
| Log sources | Domain controller Security logs |
| Requires | DS Access > Audit Directory Service Changes = Success (plus a SACL on the audited objects) and Account Management > Audit Computer/User Account Management = Success, all on DCs |

## What it detects

### RULE 1 - Resource-based constrained delegation (RBCD) configured (High, or Critical/High)
Triggers on a 5136 Value-Added of msDS-AllowedToActOnBehalfOfOtherIdentity - an RBCD security descriptor written onto a target object. Confidence High. Severity is High by default and Critical when the modified object is a known Domain Controller (control of a DC is then at stake). DC recognition comes from live AD discovery when reachable, otherwise from `-DomainController`; when no DCs are known the finding notes the DC status could not be checked and stays High.

### RULE 2 - Unconstrained delegation enabled (High/High)
Triggers when TRUSTED_FOR_DELEGATION is turned on: a 5136 userAccountControl Value-Added that decodes to that flag, or a 4742/4738 whose OldUacValue -> NewUacValue diff adds it (also matched via the `%%2104` change string, or the rendered "Trusted For Delegation" enabled text). Enabling this outside a DC is abnormal and is the setting that makes an account a TGT-theft target, so it is worth prompt confirmation.

### RULE 3 - Constrained delegation target / protocol transition (Medium/Medium, or High/High)
Triggers when constrained delegation is set or changed: a 5136 Value-Added on msDS-AllowedToDelegateTo (the authoritative confirmation of an actual add), or a 4742/4738 whose AllowedToDelegateTo field lists targets, or the protocol-transition flag being added (TRUSTED_TO_AUTH_FOR_DELEGATION in the 5136 decode, TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION in the SAM diff, or the `%%2114` / "Trusted To Authenticate For Delegation" enabled text). Base severity Medium/Medium; raised to High/High when protocol transition is enabled (the account no longer needs the impersonated user to authenticate, a common escalation primitive) or when RULE 4 applies.

### RULE 4 - Constrained delegation to a sensitive (DC) SPN (raises RULE 3 to High/High)
Not a separate finding: when a constrained-delegation target SPN (service class ldap/, host/, cifs/ or http/) resolves to a known Domain Controller, the RULE 3 finding is raised to High/High and its title becomes "Constrained delegation to sensitive (DC) SPN" - delegation to a DC SPN effectively grants delegation to the directory itself. This escalation needs a known-DC list (live discovery or `-DomainController`); without it the finding stays at its base severity.

## Required audit policy

All on domain controllers:

- DS Access > Audit Directory Service Changes = Success, and a SACL (Write Property) on the delegation attributes of the audited objects. This produces 5136 - the authoritative, attribute-level source for RULE 1 and the confirming signal for RULE 3. Without it, RBCD (RULE 1) has no event at all and the other rules rely solely on the coarser 4742/4738.
- Account Management > Audit Computer Account Management = Success -> 4742.
- Account Management > Audit User Account Management = Success -> 4738.

RULE 1 fires only from 5136, so it goes silent without Directory Service Changes auditing. RULE 2 and RULE 3 fire from 5136 and/or 4742/4738.

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
| `-OutputPath` | none | Directory or file to write results to (directory gets `Find-DelegationAbuse-<timestamp>.<ext>`). |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output. |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-DomainController` | none | Extra DC names / IPs so DC-targeted RBCD (RULE 1 Critical) and delegation to a DC SPN (RULE 4) can be recognised when running offline or not domain joined. Without a known-DC list those escalations cannot be applied and the finding stays at its base severity. |
| `-NoADLookup` | off | Skip live AD discovery of domain controllers and rely only on `-DomainController`. Live discovery is attempted only when AD is reachable, so this is already a no-op when run offline. |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller; Live mode analyses the local Security log for the last 7 days by default. Pass `-DomainController` so DC-targeted escalations apply (the tool's own first example).

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -DomainController DC01,DC02
```

### Single exported .evtx
Analyse one exported DC Security log offline (the tool's own second example).

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -OutputPath C:\Evidence\Out -Format All
```

### Folder of exported logs
Point `-Path` at a folder; every `.evtx` in it is analysed.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -Path C:\Evidence\Logs\ -DomainController DC01,DC02
```

### Time-boxed window
Bound the analysis window.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -StartTime (Get-Date).AddDays(-30) -EndTime (Get-Date).AddDays(-1) -DomainController DC01
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\irlead) -DomainController DC01,DC02
```

### Pipeline input
Pipe pre-collected events through `ConvertFrom-IRWinEvent`. Import the common module first - the converter lives there (the tool's own third example, adapted).

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136,4742,4738} -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-DelegationAbuse.ps1 -DomainController DC01
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON/CSV/CliXml.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -InputPath C:\Evidence\Out\dc01-events.json -DomainController DC01
```

### Writing reports
Export findings; a directory gets timestamped `Csv`/`Json`/`Html` files with `-Format All`.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Supplying a DC list offline
When the collection is offline or not domain joined, pass every DC name and IP so RULE 1 can escalate DC-targeted RBCD to Critical and RULE 4 can recognise delegation to a DC SPN.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -Path C:\Evidence\Logs\ -DomainController dc01.corp.local,dc02.corp.local,10.10.20.10
```

### Forcing the offline DC path
Add `-NoADLookup` to skip live DC discovery even on a domain-joined analyst host, so only the names you pass are treated as DCs.

```powershell
.\Tools\AD\Find-DelegationAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -NoADLookup -DomainController DC01,DC02
```

### Via the phase runner
`Invoke-IRHunt` forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`, `-EndTime`, `-MaxEvents` and (because this tool accepts it) `-DomainController`, and filters the consolidated report with `-MinimumSeverity`. There are no other tuning parameters to run directly for.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-DelegationAbuse -Path C:\Evidence\DC01-Security.evtx -DomainController DC01,DC02 -OutputPath C:\Evidence\Out -MinimumSeverity High
```

## Triage: reading the findings

### RULE 1 - RBCD configured
Confirm the write was authorised. If not, clear msDS-AllowedToActOnBehalfOfOtherIdentity on the target, treat the actor and any account referenced in the descriptor as compromised, and review who holds write access to the target object. A Critical finding means the target was a DC - escalate immediately.

### RULE 2 - Unconstrained delegation enabled
Remove TRUSTED_FOR_DELEGATION unless the host is a DC that must have it. Add privileged accounts to Protected Users or mark them sensitive and not delegable, and investigate the actor who made the change.

### RULE 3 / RULE 4 - Constrained delegation / protocol transition / DC SPN
Confirm the delegation target is expected. 4738/4742 report the full current msDS-AllowedToDelegateTo value on every account change (not a diff), so corroborate with the 5136 attribute-level event before acting. Remove unexpected SPNs, disable protocol transition where it is not required, and never allow delegation to DC SPNs. Investigate the actor.

## False positives and tuning

- 4738/4742 report the full current msDS-AllowedToDelegateTo value on every account change, not a diff, so an unrelated change to an account that already has constrained delegation can surface here. The 5136 attribute-level events are the authoritative confirmation of an actual add - enable Directory Service Changes auditing and lean on the 5136 findings. There is no suppression parameter; triage uses the 5136 corroboration.
- Legitimate delegation onboarding (a new front-end service, a gMSA) sets these attributes too. Validate the actor (SubjectUserName) and the modified object before escalating.
- Supplying an accurate `-DomainController` list is what drives the correct RULE 1 Critical and RULE 4 High escalations; an incomplete list under-rates DC-targeted findings rather than over-rating benign ones.

## Related tools

- [Find-ShadowCredentials](Find-ShadowCredentials.md) - msDS-KeyCredentialLink writes, another object-attribute escalation often chained with RBCD.
- [Find-TrustAbuse](Find-TrustAbuse.md) - cross-forest TGT delegation is enabled on the trust object rather than an account; pivot there for trust-level delegation.
- [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) - service-ticket (4769) anomalies that can follow a delegation change.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
