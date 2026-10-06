# Find-ShadowCredentials

Shadow Credentials is an account-takeover technique that abuses the msDS-KeyCredentialLink attribute
of a user or computer object - the attribute that holds the certificate / public-key pairs used for
Kerberos PKINIT (the same mechanism behind Windows Hello for Business and FIDO2). Where an actor has
write access to a target object that they do not own, a key credential written onto that object can
subsequently authenticate as the target without the account password ever changing. Named tooling
includes Whisker, pyWhisker, ntlmrelayx --shadow-credentials, certipy shadow and
Set-ADComputer / Add-ADComputerKeyCredential.

Find-ShadowCredentials reads the domain controller's Security log (5136 directory-object
modifications and 4768 Kerberos TGT requests) plus PowerShell Operational 4104 for tooling
signatures, and emits IRToolKit.Finding objects. It is read-only and writes files only when
-OutputPath is given. The signal that separates an attack from benign Windows Hello enrollment is the
actor-not-equal-to-target comparison, backed by the add-to-PKINIT correlation in RULE 3.

| | |
|---|---|
| ATT&CK | T1098.001 - Account Manipulation: Additional Credentials (Key Credential / Shadow Credentials); the tool's help also references T1556 - Modify Authentication Process |
| Event IDs | 5136, 4768 (Security, DC); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log; PowerShell Operational from any host that ran tooling |
| Requires | DS Access > Directory Service Changes = Success with SACL auditing of writes on the relevant objects / msDS-KeyCredentialLink; Kerberos Authentication Service = Success for 4768; optional PowerShell Script Block Logging |

## What it detects

### RULE 1 - Shadow credential (key credential) added to another principal (High/High; Critical/High for a DC target)
A 5136 on msDS-KeyCredentialLink with OperationType Value Added (%%14674) where the actor
(SubjectUserName) is NOT the same principal as the target object (the CN of ObjectDN). An actor
writing a key onto an object they do not own is the takeover signature, because legitimate
self-service Windows Hello / FIDO2 enrollment writes the actor's OWN object. The finding is raised to
Critical when the target object is a domain controller, since a DC key credential enables full domain
compromise. Two softer outcomes exist:

- Self-enrollment (actor CN equals target CN) is treated as benign and suppressed by default; it is
  surfaced only as Informational/Low, and only when -SelfEnrollmentIsBenign is set to $false.
- When the target is a USER object whose CN looks like a display name (it contains whitespace, so it
  is not a sAMAccountName), the self-vs-other comparison cannot be made reliably offline, so the add
  is down-ranked to Informational/Low ("self vs other undetermined"). It is still tracked for RULE 3,
  which will escalate to Critical if a correlating PKINIT logon follows.

### RULE 2 - Shadow credential (key credential) removed from another principal (Medium/Medium)
A 5136 on msDS-KeyCredentialLink with OperationType Value Deleted (%%14675) by a principal other than
the target. This can be cleanup following a takeover or routine administration, so it is reported at
Medium for correlation. Removal of one's own key is skipped as routine.

### RULE 3 - Shadow credential add followed by PKINIT logon (Critical/High)
A RULE 1-tracked add on target T by a different actor, followed within -PkinitWindowMinutes
(default 60) by a SUCCESSFUL PKINIT TGT request for T - a 4768 with PreAuthType 16 or 17 and a
success status (status 0x0 / empty). The add-then-PKINIT sequence, correlated by normalised target
name and time window, is the strongest confirmation that the newly written key credential is being
used, and is reported Critical. One correlation finding is emitted per add.

### RULE 4 - Shadow Credentials tooling in PowerShell script blocks (Medium/High)
A 4104 script block matching a Shadow Credentials signature: Whisker, pyWhisker,
msDS-KeyCredentialLink, KeyCredential, Set-ADComputer with a KeyCredential argument,
Add-ADComputerKeyCredential, or shadowcred. The finding carries a 300-character excerpt for triage.

## Required audit policy

- DC: DS Access > Audit Directory Service Changes = Success, with SACL auditing of Write on the
  relevant objects (ideally on msDS-KeyCredentialLink) -> 5136. Without it RULE 1, RULE 2 and the add
  side of RULE 3 are silent.
- DC: Account Logon > Audit Kerberos Authentication Service = Success -> 4768 for the PKINIT side of
  RULE 3.
- Optional: PowerShell Script Block Logging -> 4104 for RULE 4.

See [AUDIT-POLICY](../../AUDIT-POLICY.md) for the kit-wide policy baseline.

## Parameters

The source parameters are mutually exclusive modes: live (-ComputerName/-Credential, the default),
exported files (-Path), pipeline objects (-InputObject) or a pre-parsed file (-InputPath).

### Source and output

| Name | Default | Purpose |
|---|---|---|
| -ComputerName | local machine | Live mode: remote computer to read the event logs from |
| -Credential | current user | Credential for the remote computer |
| -Path | - | One or more exported .evtx files, or folders containing .evtx, analysed offline |
| -InputObject | - | Pre-flattened IRToolKit event objects via the pipeline |
| -InputPath | - | JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents) |
| -StartTime | last 7 days (live mode only) | Only analyse events at or after this time |
| -EndTime | - | Only analyse events at or before this time |
| -MaxEvents | 0 (unlimited) | Cap on events read per event-ID batch |
| -OutputPath | - (no files written) | Directory or file for the report; a directory gets Find-ShadowCredentials-<timestamp>.<ext> |
| -Format | Json | Report format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output; findings are still returned as objects |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -NoADLookup | off | Skip live Active Directory look-ups (DC auto-discovery for the DC-target escalation) even when the host is domain joined |
| -DomainController | - | Extra DC names / IPs to treat as DCs; used to recognise a key-credential write onto a DC object (escalates RULE 1 to Critical) when running offline |
| -PkinitWindowMinutes | 60 | Maximum minutes between a key-credential add and a subsequent PKINIT TGT request for the same target to correlate them as RULE 3 |
| -SelfEnrollmentIsBenign | $true | When $true, a self-enrollment add (actor CN equals target CN) is suppressed as benign Windows Hello / FIDO2; set $false to surface every add (self-enrollment adds then reported Informational) |

## Usage

### Live hunt on a DC
Run on (or against) a domain controller; without -StartTime, live mode covers the last 7 days.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -StartTime (Get-Date).AddDays(-14)
```

### Single exported .evtx
Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Multi-source collection
Pass several DCs' Security logs together so adds on one DC correlate with PKINIT logons recorded on
another.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController dc01.corp.local, dc02.corp.local
```

### Folder of exported logs
A folder passed to -Path is expanded to every .evtx inside it.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window in any source mode.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\Logs\ -StartTime '2026-09-01' -EndTime '2026-09-15'
```

### Remote host
Read a remote DC's live logs over the event log API.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe pre-flattened events in. ConvertFrom-IRWinEvent comes from the kit module, so import it first.
Only the event IDs you pipe in are analysed, so include both 5136 and 4768 if you want the RULE 3
correlation.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5136, 4768 } -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-ShadowCredentials.ps1
```

### Pre-parsed JSON
Re-analyse events exported earlier (Export-IREvents JSON, CSV or CliXml).

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -InputPath C:\Evidence\Out\dc01-events.json
```

### Writing reports
Findings are written only when -OutputPath is given; -Format All writes Csv, Json and Html.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02 -OutputPath C:\Evidence\Out -Format All
```

### Widening the add-to-logon window (-PkinitWindowMinutes)
If a delay between the write and its use is plausible, widen the RULE 3 correlation window.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx -PkinitWindowMinutes 240
```

### Surfacing self-enrollment adds (-SelfEnrollmentIsBenign)
During a focused Windows Hello rollout review, surface the self-enrollment adds too (reported
Informational). Note this is a [bool] parameter, so pass the value explicitly.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx -SelfEnrollmentIsBenign $false
```

### Analysing on a non-domain workstation (-NoADLookup)
On an analysis host joined to a different domain, skip AD look-ups and supply the case's DCs
explicitly so the DC-target escalation still works.

```powershell
.\Tools\AD\Find-ShadowCredentials.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController dc01.corp.local, dc02.corp.local
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime,
-MaxEvents and (to tools that accept it) -DomainController, and filters the consolidated report with
-MinimumSeverity. The tuning parameters (-PkinitWindowMinutes, -SelfEnrollmentIsBenign, -NoADLookup)
are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-ShadowCredentials -Path C:\Evidence\DC01-Security.evtx -DomainController dc01.corp.local -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

- RULE 1: Verify whether the actor is authorised to write msDS-KeyCredentialLink on the target
  (resolve the target's sAMAccountName if the CN is a display name). If not authorised, treat the
  target as compromised: inspect and clear its msDS-KeyCredentialLink (KeyCredentials), reset the
  account, and audit write permissions (GenericWrite / WriteProperty / WriteDacl) on the object. A
  DC target is a domain-wide emergency. For an Informational "self vs other undetermined" finding,
  resolve ownership before deciding - a different principal confirms a takeover.
- RULE 2: Correlate the removal with a preceding key-credential add on the same object and any PKINIT
  logons for it, and confirm the removal was expected; it can be cleanup after a takeover.
- RULE 3: Treat the target account as compromised. Clear the attacker key credential from
  msDS-KeyCredentialLink, reset the account (twice for krbtgt-adjacent or DC targets), isolate the
  PKINIT source host, and hunt for UnPAC-the-hash / ticket reuse.
- RULE 4: Identify the user and process that ran the script block, then correlate with 5136
  msDS-KeyCredentialLink writes and 4768 PKINIT logons from the same host and timeframe.

## False positives and tuning

- Windows Hello for Business and FIDO2 security-key enrollment legitimately write
  msDS-KeyCredentialLink on the user's OWN object (actor equals target); these are suppressed by the
  self-enrollment exclusion (leave -SelfEnrollmentIsBenign at its default) unless you deliberately
  want to review them.
- Azure AD / Entra hybrid join and the ADFS / NGC (ngccredprov) service accounts also write the
  attribute. Because the discriminator is a HEURISTIC comparison of SubjectUserName against the CN of
  ObjectDN, an enrollment service whose SubjectUserName does not match the object CN can be
  misclassified - validate the actor, the target and the source host before escalating.
- A USER object whose CN is a display name cannot be compared to a sAMAccountName offline; the tool
  deliberately down-ranks that case to Informational and leans on the RULE 3 correlation instead.

## Related tools

- [Find-ADCSAbuse](Find-ADCSAbuse.md) - the other certificate-credential takeover path (the ESC
  family and certificate-logon anomalies); pivot there when a suspicious PKINIT logon traces back to
  a CA-issued certificate rather than a key-credential write.
- [Find-GoldenGMSA](Find-GoldenGMSA.md) - another credential-theft technique that also reads from
  DC Security logs; pivot there when the same actor had DC-level access.
- [Find-GPOAbuse](Find-GPOAbuse.md) - shares the 5136 directory-change source; pivot there when the
  actor who wrote a key credential also edits GPOs.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
