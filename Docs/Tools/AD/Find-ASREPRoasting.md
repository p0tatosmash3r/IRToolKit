# Find-ASREPRoasting

AS-REP Roasting abuses accounts configured with "Do not require Kerberos pre-authentication" (userAccountControl flag DONT_REQ_PREAUTH / 0x400000). For such an account, any unauthenticated principal can send an AS-REQ and the KDC returns an AS-REP whose encrypted portion is derived from the account's password, which the attacker cracks offline. Tooling includes Rubeus (asreproast), PowerSploit / Empire (Invoke-ASREPRoast, Get-ASREPHash) and Impacket (GetNPUsers.py); RC4 (etype 0x17) AS-REPs are the easiest to crack, so most tooling prefers RC4.

Find-ASREPRoasting reads Security event 4768 (Kerberos Authentication Service) from a domain controller - live, from exported .evtx, or from pre-parsed event objects - plus PowerShell 4104 script blocks for tooling signatures, and emits IRToolKit.Finding objects for roastable accounts, roast sweeps, Kerberos username enumeration, honeypot hits, and roasting tooling in script blocks. The tool is read-only; it writes files only when -OutputPath is given.

| | |
|---|---|
| ATT&CK | T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting) |
| Event IDs | 4768 (Security), 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log; optionally PowerShell/Operational from any host for Rule 5 |
| Requires | DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Success and Failure (PowerShell Script Block Logging optional for Rule 5) |

## What it detects

Pre-filtering: machine accounts (TargetUserName ending in '$') are ignored for the roast rules; IP addresses are normalised; local / loopback source addresses are excluded from burst grouping (a single roastable account is still reported). Only PreAuthType exactly 0 is treated as "no pre-authentication" - PreAuthType 2 (PA-ENC-TIMESTAMP) and 15/16/17 (PKINIT / smart card) are never flagged. Weak encryption means RC4 or DES (0x1, 0x3, 0x17, 0x18).

### RULE 1 - No-preauth success: roastable accounts and roast sweeps (High or Medium)
A 4768 with PreAuthType exactly 0 AND Status 0x0 for a non-machine account means the KDC issued a ticket without pre-authentication - the account genuinely does not require pre-auth and is AS-REP roastable. Two finding shapes:

- Roast sweep (High, Confidence Medium): at least -Threshold (default 3) distinct accounts received a no-preauth AS-REP from one source IP within -WindowMinutes (default 10) - multiple roastable accounts harvested from one host. Confidence is raised to High when any ticket in the sweep used RC4/DES, or when AD context (Rule 4) confirms DONT_REQ_PREAUTH on a swept account.
- Single roastable account (per account+IP): High/High when the AS-REP used RC4/DES (trivially crackable offline); Medium/Medium when it used AES (still crackable offline given a weak password). AD confirmation of DONT_REQ_PREAUTH raises Confidence to High.

### RULE 2 - Kerberos user enumeration, unknown principals (Medium/Medium)
Fires when at least -EnumThreshold (default 10) distinct non-existent account names (4768 Status 0x6, KDC_ERR_C_PRINCIPAL_UNKNOWN) are queried from one source IP within the window. This is consistent with a username sweep (e.g. Impacket GetNPUsers against a wordlist) that typically precedes an AS-REP roast or a password spray.

### RULE 3 - AS-REQ for honeypot account (Critical/High)
Any AS-REQ with PreAuthType 0 for a -HoneypotAccount fires immediately, regardless of status, one finding per account+IP. Decoy accounts have no legitimate use; a roast attempt against one indicates an active attacker.

### RULE 4 - AD confirmation (confidence escalation, not a standalone finding)
When AD is reachable and -NoADLookup is not set, each flagged account's userAccountControl is read; if DONT_REQ_PREAUTH is set, the finding description gains "confirmed roastable" context and its Confidence is raised to High.

### RULE 5 - AS-REP roasting tooling in PowerShell script block (High/High)
Fires when a PowerShell 4104 script block matches an AS-REP roasting signature: Rubeus, asreproast, Invoke-ASREPRoast, Get-ASREPHash, GetNPUsers, or ASREP. One finding per matching script block, with a 300-character excerpt in the description.

## Required audit policy

- DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Success and Failure. Success auditing feeds Rule 1 (and Rule 3); Failure auditing is required for the Rule 2 enumeration signal (Status 0x6 events) - without it Rule 2 is silent.
- Optional: PowerShell Script Block Logging (event 4104, Microsoft-Windows-PowerShell/Operational). Without it Rule 5 is silent; the other rules are unaffected.
- See [AUDIT-POLICY](../../AUDIT-POLICY.md) for how to enable these, and run `.\Tools\AD\Get-IRAuditReadiness.ps1` to check the current posture.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| -ComputerName | local machine | Remote computer to read the live Security log from |
| -Credential | current user | Credential for the remote computer |
| -Path | - | One or more exported .evtx files, or folders containing .evtx, analysed offline |
| -InputObject | - | Pre-flattened IRToolKit event objects via the pipeline |
| -InputPath | - | JSON / CSV / CliXml file of pre-flattened events |
| -StartTime | live mode: last 7 days | Only analyse events at or after this time |
| -EndTime | - | Only analyse events at or before this time |
| -MaxEvents | 0 (unlimited) | Cap on events read per event-ID batch |
| -OutputPath | - (no files written) | Directory or file to write results to |
| -Format | Json | Export format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output (findings are still returned) |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -Threshold | 3 | Distinct no-preauth accounts from one IP within the window to raise the Rule 1 roast sweep. The default requires three so that a couple of legitimately pre-auth-disabled accounts behind a shared egress / NAT IP do not look like a sweep |
| -WindowMinutes | 10 | Sliding window length in minutes for the burst rules |
| -EnumThreshold | 10 | Distinct non-existent accounts (Status 0x6) from one IP within the window to raise the Rule 2 user-enumeration finding |
| -HoneypotAccount | - | Decoy account names; any no-preauth AS-REQ for one fires a Critical Rule 3 finding |
| -NoADLookup | off | Skip the live Active Directory DONT_REQ_PREAUTH confirmation (Rule 4) |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller against the live Security log (default window: last 7 days).

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1
```

### Single exported .evtx
Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of exported logs
Point -Path at a folder; every .evtx inside is loaded (include the PowerShell/Operational export to feed Rule 5).

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window - this is the tool's own first example (last 14 days).

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -StartTime (Get-Date).AddDays(-14) -EndTime (Get-Date)
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe events you already collected. ConvertFrom-IRWinEvent comes from the IRToolKit common module, so import it first.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-ASREPRoasting.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -InputPath C:\Evidence\Out\DC01-events.json
```

### Writing reports
Write findings to disk in every format.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Tuned sweep threshold and window
Loosen the sweep rule where several accounts legitimately share an egress IP: require 5 distinct accounts over a 30-minute window.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -Threshold 5 -WindowMinutes 30
```

### Tuned enumeration threshold
Lower the user-enumeration bar on a quiet DC to catch smaller wordlists.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -EnumThreshold 5
```

### Honeypot account
Flag any no-preauth AS-REQ for a decoy account (the tool's own second example).

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -HoneypotAccount svc_decoy -OutputPath C:\Evidence\Out -Format All
```

### Offline analysis without AD
Skip the DONT_REQ_PREAUTH confirmation when analysing on a non-domain workstation.

```powershell
.\Tools\AD\Find-ASREPRoasting.ps1 -Path C:\Evidence\Logs\ -NoADLookup
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime and -MaxEvents to this tool, and filters the consolidated report with -MinimumSeverity. Tuning parameters such as -Threshold, -EnumThreshold or -HoneypotAccount are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-ASREPRoasting -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

- RULE 1 single roastable account: first confirm whether the account legitimately needs DONT_REQ_PREAUTH (the finding's AD context note tells you when the flag is confirmed). Per the tool's recommendation: if it is not required, clear the flag and reset the password; either way ensure the account has a long, random password. An RC4/DES AS-REP (High/High) deserves faster action than an AES one.
- RULE 1 roast sweep: the source IP pulled AS-REPs for several roastable accounts at once - that is harvesting, not configuration drift. Confirm whether these accounts should have pre-authentication disabled, clear DONT_REQ_PREAUTH where it is not required, rotate their passwords, and investigate the source host for AS-REP cracking tooling. Escalate when any swept account is privileged or later shows a successful logon from the same source.
- RULE 2 enumeration: investigate the source host; Kerberos name enumeration from a workstation or non-admin host often precedes AS-REP roasting or password spraying. Corroborate with a Rule 1 sweep or a Find-PasswordSpray burst from the same IP shortly after.
- RULE 3 honeypot: treat the source host as compromised; isolate it, hunt for AS-REP cracking tooling, and reset any exposed account passwords. No benign explanation exists for a decoy account receiving an AS-REQ.
- RULE 5 script block: identify the user and process that ran the script block and correlate with 4768 no-preauth events from the same host. A signature hit plus Rule 1 findings from the same computer is a roast in progress.

## False positives and tuning

- A few legacy or appliance accounts are legitimately configured without pre-authentication; a single no-preauth success for such an account is expected and is reported at Medium (AES) or High (RC4) so the analyst can confirm the configuration. The sweep and enumeration rules are the stronger signals.
- Smart-card (PKINIT) logons use PreAuthType 15/16/17 and are never flagged; PA-ENC-TIMESTAMP (PreAuthType 2) is likewise never flagged - no tuning needed.
- Several legitimately pre-auth-disabled accounts authenticating through a shared egress / NAT IP can resemble a sweep; raise -Threshold (and/or shorten -WindowMinutes) so the sweep rule only fires above the known-benign account count.
- Service-desk or identity tooling that probes many usernames can trip the enumeration rule; raise -EnumThreshold after validating the source.

## Related tools

- [Find-Kerberoasting](Find-Kerberoasting.md) - the companion offline-cracking attack against SPN service accounts; the same actor often runs both from the same host.
- [Find-PasswordSpray](Find-PasswordSpray.md) - Rule 2's username enumeration also precedes sprays; check the same source IP for spray bursts.
- [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) - pivot here if a roasted account's cracked key appears to be reused (encryption downgrade / overpass-the-hash patterns).

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
