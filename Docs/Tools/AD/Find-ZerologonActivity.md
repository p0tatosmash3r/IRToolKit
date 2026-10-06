# Find-ZerologonActivity

CVE-2020-1472 ("Zerologon") is a flaw in the Netlogon secure-channel cryptography that lets an
unauthenticated attacker with network access to a domain controller impersonate a machine account and
set that account's password to EMPTY in AD - most damagingly the DC's own computer account, which
yields domain compromise. This tool looks for the forensic artefacts the attack and the Microsoft
hardening leave behind; it does NOT test or exploit anything.

Find-ZerologonActivity reads Security event 4742 and the System-log NETLOGON events 5805 and
5827-5831 from domain controllers, plus PowerShell script block events (4104), and emits
`IRToolKit.Finding` objects (see [CONVENTIONS](../../CONVENTIONS.md)). The tool is read-only and
writes files only when `-OutputPath` is given.

| | |
|---|---|
| ATT&CK | T1210 (Exploitation of Remote Services); CVE-2020-1472 (Zerologon) |
| Event IDs | 4742 (Security); 5805, 5827, 5828, 5829, 5830, 5831 (System, source NETLOGON); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Domain controller Security AND System logs; optionally the PowerShell Operational log |
| Requires | Account Management > Audit Computer Account Management = Success on DCs, plus the DC System log (August 2020+ Netlogon update for 5827-5831) |

## What it detects

### RULE 1 - Machine-account password changed by ANONYMOUS LOGON (Critical/High)

Triggers on a 4742 where the target is a COMPUTER account and the subject is ANONYMOUS LOGON (by name
or SID `S-1-5-7`). Machine-account passwords are rotated by the machine itself over an authenticated
channel, never anonymously - an anonymous machine password change is the Zerologon reset signature
with essentially no benign cause. Severity is Critical when the target is a known domain controller
(the full-compromise case) and High for any other computer account; confidence is High either way.
Without a DC list the finding stays High and notes that `-DomainController` would confirm whether the
target is a DC (which would raise it to Critical).

### RULE 2 - Vulnerable Netlogon secure-channel connections, 5827-5831 (High/Medium)

Triggers on the August-2020+ Netlogon hardening events in the System log (source NETLOGON), grouped
by event ID, machine account and logging DC so one chatty device yields one finding: 5827/5828 mean a
vulnerable connection from a machine / trust account was DENIED (the hardening blocked it, but a
vulnerable client - or an exploitation attempt - reached the DC); 5829 means a vulnerable connection
was ALLOWED because enforcement mode is not on, which is both exposure and a usable channel for the
attack. 5827/5828/5829 findings are High and escalate to Critical when the named account is a known
DC; 5830/5831 (allowed by the group-policy exception list) are Medium. Confidence is Medium for all
of RULE 2.

### RULE 3 - Burst of Netlogon authentication failures (High/Medium)

Triggers when the number of Netlogon session-setup failures (System 5805) for ONE machine account on
one DC reaches `-FailureBurstThreshold` (default 20) within `-WindowMinutes` (default 10), consistent
with the repeated attempts the exploit makes before it succeeds. The 5805 account name lives only in
the rendered message, so events whose account cannot be parsed are excluded from the burst - offline,
where the NETLOGON message may not render, this rule simply does not fire rather than mis-fire.

### RULE 4 - Zerologon tooling in PowerShell script block (High/High)

Triggers on a 4104 script block matching one of the Zerologon tool signatures: `zerologon`,
`CVE-2020-1472`, `NetrServerPasswordSet2`, `NetrServerAuthenticate3`, `Invoke-Zerologon`,
`set_empty_pw`, `reinstall_original_pw`. Each matching script block produces one High/High finding
with a 300-character excerpt.

## Required audit policy

- Security log (domain controllers): Account Management > **Audit Computer Account Management =
  Success** -> 4742. Without it RULE 1 is silent.
- System log (domain controllers), source NETLOGON -> 5805 and 5827-5831. PULL THE SYSTEM LOG, not
  just Security - the hardening / vulnerable-channel events live there, and RULES 2 and 3 are silent
  without it. The 5827-5831 events only exist on hosts with the August 2020 (or later) Netlogon
  update installed.
- RULE 3 additionally needs the 5805 message text to render (the machine account is only in the
  message); when it cannot be parsed the rule stays quiet.
- Optional: **PowerShell Script Block Logging** -> 4104 (RULE 4 is silent without it).
- Check your posture with `.\Tools\AD\Get-IRAuditReadiness.ps1`.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Live mode: read the event logs from this remote computer. |
| `-Credential` | none | Credential for the remote computer. |
| `-Path` | none | One or more exported `.evtx` files, or folders containing `.evtx`, analysed offline. Include the System log export. |
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
| `-DomainController` | none | DC names / IPs. A DC machine account whose password is reset anonymously is escalated to Critical (RULE 1), and a DC account in the 5827-5829 events escalates those findings to Critical too; offline, this also supplies the DC list. |
| `-FailureBurstThreshold` | 20 | Number of Netlogon auth failures (5805) for one machine account within the window that raises the RULE 3 burst finding. |
| `-WindowMinutes` | 10 | Sliding window length in minutes for the failure-burst rule. |
| `-NoADLookup` | off | Skip live AD DC discovery; the DC list is then built solely from `-DomainController`. |

## Usage

### Live hunt on this DC

Run on a domain controller; live mode reads the local Security and System logs for the last 7 days by
default.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -DomainController DC01, DC02
```

### Single exported .evtx

For a quick check of one export. For full coverage always include the System log too (next scenario) -
Security alone only feeds RULE 1.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02
```

### Folder of exported logs

Point `-Path` at a folder containing the Security AND System exports from each DC. (Tool help
example 1 names the pair explicitly.)

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC01-System.evtx -DomainController DC01, DC02
```

### Time-boxed window

Zerologon hunting often needs to look back further than a week. (Tool help example 2, which also
writes reports.)

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -StartTime (Get-Date).AddDays(-30) -OutputPath C:\Evidence\Out -Format All
```

### Remote host

Read the live logs of a remote DC.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst) -DomainController DC01, DC02
```

### Pipeline input

Pipe pre-flattened events in. `ConvertFrom-IRWinEvent` lives in the common module, so import it
first. If you pipe the System / NETLOGON IDs, add `-IncludeMessage` so the machine account can be
parsed from the rendered message.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4742 } -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-ZerologonActivity.ps1 -DomainController DC01
```

### Pre-parsed JSON

Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -InputPath C:\Evidence\DC01-events.json -DomainController DC01, DC02
```

### Writing reports

`-OutputPath` writes result files; `-Format All` produces Csv, Json and Html (default is Json).

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -OutputPath C:\Evidence\Out -Format All
```

### Offline with -DomainController

Offline, the DC list cannot be discovered - pass it so a reset or vulnerable-channel event naming a
DC account is escalated to Critical. Without it, RULE 1 stays High with a note (and RULE 2 cannot
escalate), so a DC compromise could look one notch less urgent than it is.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02
```

### Tuning the failure-burst rule

Lower the threshold / widen the window on quiet networks, or raise it where flaky legacy hosts
produce steady 5805 noise.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\DC01-System.evtx -DomainController DC01 -FailureBurstThreshold 10 -WindowMinutes 30
```

### Skipping live AD discovery

`-NoADLookup` skips live AD DC discovery, so the DC list is built solely from `-DomainController` -
use it on a domain-joined analyst host when only the named DCs should be treated as legitimate.

```powershell
.\Tools\AD\Find-ZerologonActivity.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01, DC02
```

### Running via Invoke-IRHunt

The phase runner forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`,
`-EndTime`, `-MaxEvents` and (to tools that accept it) `-DomainController`, and filters the
consolidated report with `-MinimumSeverity`. Tool-specific tuning such as `-FailureBurstThreshold`
and `-WindowMinutes` is NOT forwarded - run the tool directly when you need it.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-ZerologonActivity -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

### RULE 1 - Machine-account password changed by ANONYMOUS LOGON

Treat the domain as compromised if the target is a DC. Immediately reset the affected
machine-account password TWICE (the computer object, and if a DC also run the standard krbtgt
double-reset and restore the DC machine password via reset-machine-account procedures), apply the
latest Netlogon update and enforce secure-channel enforcement mode, and hunt for follow-on DCSync /
domain-admin activity from the same window. This finding has essentially no benign cause - treat it
as a true positive until proven otherwise.

### RULE 2 - Vulnerable Netlogon connections (5827-5831)

Identify the machine account named in the event first. If it is a known legacy / non-Windows device,
update or isolate it; if it is unexpected - especially a DC account, which is never a legacy-device
false positive - treat it as Zerologon activity. A 5829 means the DC accepted a non-secure channel:
move all DCs to Netlogon enforcement mode so vulnerable channels are refused, and for 5830/5831
confirm the group-policy exception is still required.

### RULE 3 - Burst of Netlogon authentication failures

Check whether a machine password change (4742) or a 5827-5831 event for the same account follows the
burst - that sequence is the exploit succeeding. If the account is a DC, treat as Zerologon and
respond immediately. A broken secure channel on a legacy host can also cause 5805 - confirm the
source before escalating.

### RULE 4 - Zerologon tooling in PowerShell script block

Identify the user and process that ran the script block, and correlate with 4742 anonymous
machine-password changes and 5805 / 5827-5831 Netlogon events on the DCs in the same window. Tooling
plus any RULE 1-3 artefact is a confirmed incident.

## False positives and tuning

- Legitimate but old / non-Windows devices (some NAS, appliances, printers, older Samba, pre-2020
  Windows) use the vulnerable Netlogon channel and will raise 5827/5828 (denied) or 5829 (allowed).
  Identify the machine account named in the event and confirm it is a known legacy device before
  discounting. There is no suppression list for RULE 2 - the fix is to update or isolate the device.
  A DC machine account appearing there is never a legacy-device false positive.
- RULE 1 (anonymous machine-password change) has essentially no benign cause and should be treated as
  a true positive until proven otherwise.
- Steady 5805 noise from hosts with a broken secure channel can reach the burst threshold; raise
  `-FailureBurstThreshold` or shrink `-WindowMinutes` after confirming the source is benign.

## Related tools

- [Find-DCSync](Find-DCSync.md) - DCSync is the classic follow-on once a DC machine account is
  reset; run it over the same window.
- [Find-NTLMRelay](Find-NTLMRelay.md) - the other machine-account authentication abuse (coercion and
  relay); check it when a machine account behaves anomalously but RULE 1 did not fire.
- [Find-PrivilegedGroupChange](Find-PrivilegedGroupChange.md) - hunt follow-on privilege grants after
  a suspected Zerologon compromise.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
