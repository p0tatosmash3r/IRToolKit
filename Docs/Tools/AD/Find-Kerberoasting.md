# Find-Kerberoasting

Kerberoasting abuses the fact that any authenticated principal can request a Kerberos service ticket (TGS) for any account with a servicePrincipalName. When the service runs under a user account, the ticket is encrypted with that account's password-derived key, so an attacker can collect tickets and crack the passwords offline. RC4 (etype 0x17) tickets are the easiest to crack, so tooling typically requests RC4 even for AES-capable accounts - itself a detectable downgrade.

Find-Kerberoasting reads Security event 4769 (Kerberos Service Ticket Operations) from a domain controller - live, from exported .evtx, or from pre-parsed event objects - plus PowerShell 4104 script blocks for tooling signatures, and emits IRToolKit.Finding objects for ticket-request bursts, weak-cipher requests, honeypot hits, and Kerberoast tooling in script blocks. The tool is read-only; it writes files only when -OutputPath is given.

| | |
|---|---|
| ATT&CK | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) |
| Event IDs | 4769 (Security), 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log; optionally PowerShell/Operational from any host for Rule 5 |
| Requires | DC: Advanced Audit Policy > Account Logon > Audit Kerberos Service Ticket Operations = Success (PowerShell Script Block Logging optional for Rule 5) |

## What it detects

Before any rule runs, the 4769 set is pre-filtered to roastable candidates: successful requests only (Status 0x0), service accounts that are user accounts (ServiceName not ending in '$'), excluding krbtgt / kadmin (by exact name, by 'krbtgt/...' / 'kadmin/...' referral prefix, and by the -502 ServiceSid), excluding self-requests (a user requesting a ticket to their own SPN), and excluding any requester listed in -ExcludeRequester. Honeypot accounts are matched before this filtering, so Rule 4 sees every 4769 for a decoy regardless of status. Weak encryption means RC4 or DES ticket encryption types (0x1, 0x3, 0x17, 0x18).

When Active Directory is reachable (and -NoADLookup is not set), flagged service accounts are enriched with two notes: adminCount=1 (privileged/protected service account) and "AES-capable but an RC4 ticket was issued" (encryption downgrade, read from msDS-SupportedEncryptionTypes). Any AD note on a burst finding raises its Confidence to High.

### RULE 1 - Kerberoasting burst, weak RC4/DES tickets (High/High)
Fires when one requester+source IP obtains RC4/DES tickets for at least -RC4Threshold (default 3) distinct user service accounts within a -WindowMinutes (default 10) sliding window. Requesting many user-service tickets with deliberately weak encryption is the classic Kerberoast pattern and is rarely legitimate at volume. By default only user-account requesters feed this rule (-IncludeMachineRequesters folds machine requesters in; their weak requests otherwise surface via Rule 3). A single weak-cipher request that is not part of a burst is reported separately as "Weak-cipher service ticket request (RC4/DES)" at Medium/Medium - low volume, but the ticket is still crackable offline.

### RULE 2 - Kerberoasting burst, many service accounts, any cipher (High/Medium)
Fires when one requester+source IP requests tickets for at least -Threshold (default 10) distinct user service accounts within the window, regardless of encryption type. This catches AES-only and opsec-aware roasting that Rule 1 misses. The pool includes machine-account requesters by default, so a SYSTEM-context roast requesting AES tickets is still caught. Confidence starts at Medium (volume alone is weaker evidence than a cipher downgrade) and is raised to High when AD context notes (adminCount=1, AES-capable downgrade) attach to the finding.

### RULE 3 - Machine account requested RC4 user-service tickets (Medium/Medium)
Fires per machine-account requester+IP that obtained RC4/DES tickets for user service accounts. Machine accounts rarely roast user services; this pattern suggests a compromised host running tooling under SYSTEM (scheduled task, service, PsExec -s).

### RULE 4 - Service ticket requested for honeypot account (Critical/High)
Any 4769 whose ServiceName matches a -HoneypotAccount fires immediately, one finding per requester+IP, regardless of ticket status or encryption type. Honeypot (decoy) service accounts have no legitimate use, so a single request is high-signal evidence of an active attacker enumerating and roasting SPNs.

### RULE 5 - Kerberoasting tooling in PowerShell script block (High/High)
Fires when a PowerShell 4104 script block matches a Kerberoast tooling signature: KerberosRequestorSecurityToken, Invoke-Kerberoast, Get-DomainSPNTicket, Request-SPNTicket, GetUserSPNs, Rubeus, kerberoast, or Add-Type combined with IdentityModel. One finding per matching script block, with a 300-character excerpt in the description.

## Required audit policy

- DC: Advanced Audit Policy > Account Logon > Audit Kerberos Service Ticket Operations = Success. Without it there are no 4769 events and Rules 1-4 are silent.
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
| -Threshold | 10 | Distinct user service accounts (any cipher) from one requester+IP within the window to raise the Rule 2 volume burst |
| -RC4Threshold | 3 | Distinct user service accounts requested with RC4/DES from one requester+IP within the window to raise the Rule 1 weak-cipher burst |
| -WindowMinutes | 10 | Sliding window length in minutes for both burst rules |
| -HoneypotAccount | - | Decoy service account names; any 4769 for one fires a Critical Rule 4 finding |
| -ExcludeRequester | - | Known-good requester accounts (e.g. SCCM / SCOM / vCenter service accounts) skipped entirely, matched on the bare name |
| -IncludeMachineRequesters | off | Also evaluate the Rule 1 weak-cipher burst for machine-account requesters (the Rule 2 volume burst already includes them; machine weak requests otherwise surface via Rule 3) |
| -NoADLookup | off | Skip the live Active Directory enrichment (adminCount, AES-capable downgrade notes) |
| -DomainController | - | Extra DC names / IPs; per the tool help, for recognising machine-account requesters when analysing offline. Accepted (and forwarded by Invoke-IRHunt); the current rule logic identifies machine accounts by the trailing '$' |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller against the live Security log (default window: last 7 days).

```powershell
.\Tools\AD\Find-Kerberoasting.ps1
```

### Single exported .evtx
Analyse one exported DC Security log offline.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of exported logs
Point -Path at a folder; every .evtx inside is loaded (include the PowerShell/Operational export to feed Rule 5).

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window - this is the tool's own first example (last 14 days).

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -StartTime (Get-Date).AddDays(-14) -EndTime (Get-Date)
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe events you already collected. ConvertFrom-IRWinEvent comes from the IRToolKit common module, so import it first.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-Kerberoasting.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -InputPath C:\Evidence\Out\DC01-events.json
```

### Writing reports
Write findings to disk in every format.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Tuned thresholds
Tighten the burst rules for a small environment: volume rule at 5 distinct services, weak-cipher rule at 2, over a 30-minute window.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -Threshold 5 -RC4Threshold 2 -WindowMinutes 30
```

### Honeypot account
Flag any ticket request for a decoy SPN account (the tool's own second example).

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -HoneypotAccount svc_decoy -OutputPath C:\Evidence\Out -Format All
```

### Excluding known-busy requesters
Skip validated monitoring / management accounts that legitimately pull many service tickets.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeRequester svc_sccm, svc_scom, svc_vcenter
```

### Including machine requesters in the weak-cipher burst
Fold machine-account requesters into Rule 1 when hunting SYSTEM-context roasting.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -IncludeMachineRequesters
```

### Offline analysis without AD
Skip AD enrichment on a non-domain analysis workstation and name the DCs seen in the export.

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01, DC02
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime, -MaxEvents and -DomainController (this tool accepts it), and filters the consolidated report with -MinimumSeverity. Tuning parameters such as -Threshold, -RC4Threshold, -HoneypotAccount or -ExcludeRequester are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-Kerberoasting -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

- RULE 1 / RULE 2 bursts: confirm whether the requester (Account) has any business enumerating service tickets - start with the source host behind SourceIp and what ran there in the burst window. Corroborate with a Rule 5 hit from the same host, with the AD context notes in the description (adminCount=1 targets and AES-capable downgrades are the accounts to worry about first), and with authentication activity for the Target service accounts after the burst. Per the tool's recommendation: reset/rotate the exposed service-account passwords, move them to (g)MSA where possible, review for weak passwords, and investigate the source host for offline cracking tooling. Escalate when privileged service accounts were swept or when a sprayed service account authenticates from a new host afterwards.
- Weak-cipher single (Medium): verify the service account still needs RC4; move it to AES / gMSA and ensure a strong password, and confirm the request is expected from this source. One Medium for a known legacy app is expected noise; the same requester appearing repeatedly across days is not.
- RULE 3 machine requester: investigate the source host for a process running as SYSTEM issuing service-ticket requests (Rubeus, Invoke-Kerberoast). A machine account requesting user-service RC4 tickets is rarely benign - escalate if the host also shows Rule 5 hits or new scheduled tasks/services.
- RULE 4 honeypot: treat the requesting account and source host as compromised; isolate and investigate immediately. There is no benign explanation for a decoy SPN being requested - this is a drop-everything finding.
- RULE 5 script block: identify the user and process that ran the script block and correlate with 4769 bursts from the same host. A signature hit plus a burst from the same computer is a confirmed roast in progress.

## False positives and tuning

- Legacy applications and some SQL / SharePoint / Exchange components legitimately request many service tickets, occasionally over RC4. A single Medium RC4 finding for a known legacy app is expected; the burst rules are the stronger signal. Raise -RC4Threshold / -Threshold or widen review rather than ignoring bursts.
- Vulnerability scanners and account-discovery tools can mimic a burst. Validate the requester and the source host before escalating; add validated scanner accounts to -ExcludeRequester.
- Busy monitoring / management accounts (SCCM, SCOM, vCenter) can request many distinct service tickets every poll cycle and trip the Rule 2 volume rule. Add validated accounts to -ExcludeRequester.
- Noisy small environments: shorten -WindowMinutes or raise -Threshold to make the volume rule stricter; lower them on a quiet DC to catch slower roasts.

## Related tools

- [Find-ASREPRoasting](Find-ASREPRoasting.md) - the companion offline-cracking attack against accounts without Kerberos pre-authentication; the same actor often runs both.
- [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) - pivot here after a roast: its encryption-downgrade rule explicitly catches overpass-the-hash reuse of a cracked Kerberoast key.
- [Find-PasswordSpray](Find-PasswordSpray.md) - the other bulk credential-guessing precursor; check the same source IP for spray bursts.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
