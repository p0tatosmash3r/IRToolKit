# Find-GPOAbuse

A principal with write access to a Group Policy Object - or who can create and link one - can push a
change (a scheduled task, a logon/startup script, Restricted Groups membership, or a user-rights
assignment) to every computer or user the GPO applies to. This is ATT&CK T1484.001, Domain Policy
Modification: Group Policy Modification. A GPO has two halves: the Group Policy Container (GPC) in AD
(CN={GUID},CN=Policies,CN=System,..., objectClass groupPolicyContainer) and the Group Policy Template
(GPT) files in SYSVOL (\\CORP.LOCAL\SYSVOL\CORP.LOCAL\Policies\{GUID}\ ... GptTmpl.inf,
ScheduledTasks.xml, scripts); it is linked to a scope via the gPLink attribute. Named tooling:
SharpGPOAbuse, New-GPOImmediateTask, PowerGPOAbuse, pyGPOAbuse.

Find-GPOAbuse watches all three halves. It reads the domain controller's Security log (5136/5137
directory changes, 5145 detailed file share, 4663 file access, 4688 process creation) and PowerShell
Operational 4104, and emits IRToolKit.Finding objects. It is read-only and writes files only when
-OutputPath is given. The design separates strong attack signals - a code-executing client-side
extension added, a GPO ACL change, a link to the DC OU or domain root, a SYSVOL task/script write, or
named tooling - which always fire, from routine authoring edits, which are Medium and can be
suppressed for known GPO admins via -ExcludeAccount.

| | |
|---|---|
| ATT&CK | T1484.001 - Domain Policy Modification: Group Policy Modification |
| Event IDs | 5136, 5137, 5145, 4663, 4688 (Security, DC); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log (and SYSVOL file-access auditing); PowerShell Operational and 4688 from the host that ran tooling |
| Requires | DS Access > Directory Service Changes = Success (SACL on the Policies container / OUs); Object Access > Detailed File Share = Success or a SACL on SYSVOL; File System auditing; Audit Process Creation with command line; PowerShell Script Block Logging |

## What it detects

### RULE 1 - Group Policy Container modified (5136 on a groupPolicyContainer; severity depends on the attribute)
A 5136 Value Added / modified on a groupPolicyContainer object (or a DN under CN=Policies,CN=System):

- gPCMachineExtensionNames / gPCUserExtensionNames where a code-executing client-side extension GUID
  is added - Scheduled Tasks (aadced64-746c-4633-a97c-d61349046527), Scripts
  (42b5faae-6536-11d2-ae5a-0000f87571e3) or the TCPIP / scheduled-task CSE
  (cdeafc3d-948d-49dd-ab12-e578ba4af7aa) - is Critical/High and is never suppressed, because the GPO
  will now process that code-delivering policy type on every target in scope.
- The same attributes with only a non-code settings category added are Medium/Low routine authoring,
  suppressed for -ExcludeAccount admins.
- nTSecurityDescriptor (the GPO ACL) changed is High/Medium - a GPO-takeover step that lets a
  principal push policy to every system in scope.
- Any other attribute (versionNumber, gPCFileSysPath, displayName, flags) is Medium/Low routine
  edit, suppressed for -ExcludeAccount admins.

### RULE 2 - GPO link (gPLink) changed on a sensitive scope (High/Medium on the DC OU / domain root; Medium/Low otherwise)
A 5136 on gPLink. When the object is the Domain Controllers OU or the domain root (DN beginning
DC=), the change is High/Medium: it applies - or, when the value is cleared / deleted, removes - a
GPO to the most sensitive systems, which can also silently disable a security baseline. Any other
gPLink change is Medium/Low and suppressed for -ExcludeAccount admins.

### RULE 3 - New Group Policy Object created (5137) (Medium/Low)
A 5137 creating a groupPolicyContainer. On its own a new GPO is routine administration, but it is
also the first step before a malicious link, so it is reported Medium and suppressed for
-ExcludeAccount admins.

### RULE 4 - GPO SYSVOL policy file written, GPT tampering (High/Medium for code files; Medium/Medium for policy files)
A 5145 (detailed file share) or 4663 (file access) write to a file under a SYSVOL ...\Policies\{GUID}\
path (the \policies\ requirement keeps the legacy NETLOGON \scripts\ share from matching). Code /
privilege files - ScheduledTasks.xml, scripts.ini, psscripts.ini, or a file in a Scripts\ folder -
are High/Medium and never suppressed, the GPT-side write that SharpGPOAbuse / pyGPOAbuse perform.
GptTmpl.inf and Registry.pol are rewritten on nearly every GPO save and are Medium/Medium,
suppressed for -ExcludeAccount admins. Write intent is confirmed from the access-right text or by
decoding the numeric AccessMask, so a write logged with only the hex mask is still caught.

### RULE 5 - GPO-abuse tooling executed (High/Medium)
Named tooling INVOKED in a 4104 script block or a 4688 process: SharpGPOAbuse, pyGPOAbuse,
PowerGPOAbuse, New-GPOImmediateTask, Invoke-GPOImmediateTask, Set-GPOImmediateTask or
Add-GPOGroupMember. The match is anchored to an actual invocation, so merely naming a tool - opening
its output, a detection rule, or passing the name as a file argument to another command - does not
fire. The finding carries a 300-character excerpt (4104) or the command line (4688).

## Required audit policy

- DC: DS Access > Audit Directory Service Changes = Success, with a SACL on the Policies container
  and the OUs -> 5136 (RULE 1, RULE 2) and 5137 (RULE 3). Without it the directory-side rules are
  silent.
- DC: Object Access > Audit Detailed File Share = Success (or a SACL on SYSVOL) -> 5145, and File
  System auditing -> 4663, for RULE 4. Without SYSVOL auditing the GPT-tampering rule is silent.
- Audit Process Creation with command line -> 4688, and PowerShell Script Block Logging -> 4104, for
  RULE 5.

See [AUDIT-POLICY](../../AUDIT-POLICY.md) for the kit-wide policy baseline.

## Parameters

The source parameters are mutually exclusive modes: live (-ComputerName/-Credential, the default),
exported files (-Path), pipeline objects (-InputObject) or a pre-parsed file (-InputPath). This tool
has no -NoADLookup or -DomainController parameter - it does not need DC awareness, since its sensitive
scopes (the Domain Controllers OU and the domain root) are recognised from the object DN.

### Source and output

| Name | Default | Purpose |
|---|---|---|
| -ComputerName | local machine | Live mode: remote computer to read the logs from |
| -Credential | current user | Credential for the remote computer |
| -Path | - | One or more exported .evtx files, or folders containing .evtx, analysed offline |
| -InputObject | - | Pre-flattened IRToolKit event objects via the pipeline |
| -InputPath | - | JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents) |
| -StartTime | last 7 days (live mode only) | Only analyse events at or after this time |
| -EndTime | - | Only analyse events at or before this time |
| -MaxEvents | 0 (unlimited) | Cap on events read per event-ID batch |
| -OutputPath | - (no files written) | Directory or file for the report; a directory gets Find-GPOAbuse-<timestamp>.<ext> |
| -Format | Json | Report format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output; findings are still returned as objects |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -ExcludeAccount | - | Known GPO administrators / management service accounts (bare name, DOMAIN\name or UPN). Their ROUTINE edits are suppressed (RULE 1 Medium attribute / non-code CSE edits, RULE 2 Medium links, RULE 3 new GPOs, RULE 4 policy-file writes); the strong signals (code-executing CSE added, GPO ACL change, DC/domain-root link, SYSVOL task/script write, tooling) are NEVER suppressed, so a compromised admin is still caught |

## Usage

### Live hunt on a DC
Run on (or against) a domain controller; without -StartTime, live mode covers the last 7 days.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -StartTime (Get-Date).AddDays(-14)
```

### Single exported .evtx
Analyse one exported DC Security log offline, suppressing routine edits by known GPO admins.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeAccount gpoadmin, CORP\gpo_svc
```

### Multi-source collection
Pass several DCs' Security logs together (GPO changes replicate, but SYSVOL writes and process
events are logged on the host where they happened).

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx
```

### Folder of exported logs
A folder passed to -Path is expanded to every .evtx inside it.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window in any source mode.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -Path C:\Evidence\Logs\ -StartTime '2026-09-01' -EndTime '2026-09-15'
```

### Remote host
Read a remote DC's live logs over the event log API.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe pre-flattened events in. ConvertFrom-IRWinEvent comes from the kit module, so import it first.
Only the event IDs you pipe in are analysed, so include the directory, SYSVOL and process IDs you
need (for example 5136, 5137, 5145, 4663, 4688).

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5136, 5137, 5145, 4663, 4688 } -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-GPOAbuse.ps1
```

### Pre-parsed JSON
Re-analyse events exported earlier (Export-IREvents JSON, CSV or CliXml).

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -InputPath C:\Evidence\Out\dc01-events.json
```

### Writing reports
Findings are written only when -OutputPath is given; -Format All writes Csv, Json and Html.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -StartTime (Get-Date).AddDays(-14) -OutputPath C:\Evidence\Out -Format All
```

### Suppressing routine edits by known GPO admins (-ExcludeAccount)
List the accounts and service accounts that routinely author GPOs; their Medium routine edits are
hidden while the strong attack signals still fire.

```powershell
.\Tools\AD\Find-GPOAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeAccount gpoadmin, 'CORP\gpo_svc', gpmgmt@corp.local
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime and
-MaxEvents to this tool (it does not accept -DomainController, so that is not forwarded), and filters
the consolidated report with -MinimumSeverity. The tuning parameter -ExcludeAccount is NOT forwarded
- run the tool directly to suppress known GPO admins.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-GPOAbuse -Path C:\Evidence\DC01-Security.evtx -MinimumSeverity Medium -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

- RULE 1 (code-executing CSE added, Critical): Confirm the GPO edit was authorised. If not, inspect
  the GPO's SYSVOL folder for ScheduledTasks.xml / scripts and remove them, unlink the GPO, and treat
  targets in scope as potentially compromised. (ACL change, High): confirm the delegation was
  authorised; if not, restore the GPO ACL, identify who was granted write, and review the GPO
  contents. (Routine attribute / non-code CSE, Medium): confirm against change control and correlate
  with SYSVOL writes and ACL / CSE changes on the same GPO.
- RULE 2: Confirm the link change was authorised. If not, restore or remove it, and inspect the
  linked GPO(s) for malicious scheduled tasks / scripts / Restricted Groups settings - a link to the
  DC OU or domain root is the highest priority.
- RULE 3: Confirm the GPO was created by an authorised admin, then watch for it being linked
  (gPLink) and for scheduled-task / script content in its SYSVOL folder.
- RULE 4 (code file, High): Inspect the written file (an immediate scheduled task, startup script,
  or Restricted Groups entry), remove malicious content, unlink / disable the GPO, and treat targets
  in scope as compromised. (Policy file, Medium): confirm the edit was authorised and compare the
  file against its previous version to see which setting changed.
- RULE 5: Confirm whether the execution was authorised, then correlate with 5136 GPO edits, gPLink
  changes and SYSVOL writes from the same host and window.

## False positives and tuning

- Administrators edit GPOs routinely, and every edit bumps versionNumber and can touch
  gPCMachineExtensionNames; these land as Medium routine edits and are suppressible for known GPO
  admins via -ExcludeAccount.
- GptTmpl.inf / Registry.pol are rewritten on nearly every GPO save, so RULE 4 reports them only at
  Medium and suppresses them for -ExcludeAccount admins - while ScheduledTasks.xml / script writes
  stay High and are never suppressed.
- The strong signals (code-executing CSE added, GPO ACL changed, link to the DC OU / domain root,
  SYSVOL task/script write, named tooling) are the attack indicators and are deliberately never
  suppressed, so a compromised admin account on the -ExcludeAccount list is still caught. Confirm GPO
  changes against change control.

## Related tools

- [Find-ADCSAbuse](Find-ADCSAbuse.md) - also driven by 5136 directory changes; pivot there when the
  actor who edits GPOs also touches certificate templates.
- [Find-ShadowCredentials](Find-ShadowCredentials.md) - another 5136-based takeover technique; pivot
  there when the same actor writes key credentials onto accounts.
- [Find-GoldenGMSA](Find-GoldenGMSA.md) - shares the DC Security-log source; pivot there when the
  actor had DC-level access to directory secrets.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
