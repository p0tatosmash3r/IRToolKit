# Find-NTLMRelay

An NTLM relay attack captures or coerces a victim's NTLM authentication and forwards (relays) it to a
target service, authenticating AS the victim without ever knowing the password. The relay is driven
from an attacker host (Impacket ntlmrelayx, Responder, Inveigh, MultiRelay) and the victim is often a
computer account coerced via PetitPotam / PrinterBug / Coercer / SpoolSample. The high-value variant
coerces a domain controller or server machine account and relays it to LDAP (for RBCD / DCSync
rights) or to AD CS web enrollment (ESC8) for a certificate - a path to full domain compromise. The
attack is largely network-level, so this tool hunts the clean log-based signals it leaves on the
relayed-to hosts (DCs, servers, the CA).

Find-NTLMRelay reads Security events 4624, 4625 and 4776, plus PowerShell script block events (4104),
and emits `IRToolKit.Finding` objects (see [CONVENTIONS](../../CONVENTIONS.md)). The tool is
read-only and writes files only when `-OutputPath` is given.

| | |
|---|---|
| ATT&CK | T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay) |
| Event IDs | 4624, 4625, 4776 (Security); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Security logs of the relayed-to hosts (DCs, servers, CA); 4776 is logged on the DCs |
| Requires | Audit Logon = Success and Failure on relayed-to hosts, plus Audit Credential Validation = Success and Failure on DCs |

## What it detects

### RULE 1 - Machine account NTLM network logon (High/Medium)

Triggers when a COMPUTER account performs an NTLM network logon (4624/4625, LogonType 3,
authentication package NTLM, or Negotiate resolving to an NTLM/LM LmPackageName). Machines
authenticate to domain resources with Kerberos; an inbound NTLM logon by a machine account is
characteristic of a coerced machine whose authentication was relayed. Findings are grouped per
machine account and source; loopback self-logons are skipped (a missing `-` source IP is kept, since
a coerced logon may lack one), and accounts on `-ExcludeMachineAccount` are suppressed. Severity
escalates from High/Medium to Critical/High when the machine is a known domain controller (a relayed
DC equals domain compromise) or is listed in `-PrivilegedAccount`. This rule is deliberately NOT
affected by `-ExcludeSource`, so a gateway exclusion can never silently hide a relayed DC.

### RULE 2 - Many accounts authenticated via NTLM from one source (High/Medium)

Triggers when one source (source IP, or workstation name when the IP is local) authenticates via NTLM
as a number of DISTINCT accounts reaching `-Threshold` (default 5) within `-WindowMinutes` (default
10) - the behaviour of a relay / Responder host replaying many captured identities. The finding lists
the accounts and how many of them are computer accounts. Sources named in `-ExcludeSource` (matched
against the source IP and the workstation name) and local-source logons are not counted.

### RULE 3 - NTLM credential-validation spike from one workstation (Medium/Medium)

Triggers when NTLM credential validations (4776, seen on the DC) for a number of distinct accounts
reaching `-Threshold` come from one workstation name within `-WindowMinutes` - consistent with
Responder / relay credential harvesting. 4776 carries no source IP, only the workstation name, and
the relay host can set that name freely, so treat it as a lead to corroborate rather than an
identification. `-ExcludeSource` is honoured against the workstation name.

### RULE 4 - NTLMv1 / LM network logon (Medium/Medium)

Triggers on network logons whose `LmPackageName` is "NTLM V1" or "LM" - a downgrade that is trivially
relayable and whose response is crackable offline. Findings are grouped per account and source;
severity rises to High when the downgraded principal is a machine account or is listed in
`-PrivilegedAccount`.

### RULE 5 - NTLM relay / coercion tooling in PowerShell script block (High/High)

Triggers on a 4104 script block matching one of the relay / coercion tool signatures: `Invoke-Inveigh`,
`Inveigh`, `ntlmrelayx`, `Responder`, `PetitPotam`, `PrinterBug`, `Coercer`, `MultiRelay`,
`SpoolSample`, `Invoke-Petit`, `ntlmrelay`, `smbrelay`, `Get-SpoolStatus`. Each matching script block
produces one High/High finding with a 300-character excerpt.

## Required audit policy

- Logon/Logoff > **Audit Logon = Success and Failure** -> 4624 / 4625 on the relayed-to hosts (DCs,
  servers, CA). Without it RULES 1, 2 and 4 are silent. Collect the logs from the hosts an attacker
  would relay TO, not from the victim workstations.
- Account Logon > **Audit Credential Validation = Success and Failure** -> 4776 on the domain
  controllers. Without it RULE 3 is silent.
- Optional: **PowerShell Script Block Logging** -> 4104 (RULE 5 is silent without it).
- Check your posture with `.\Tools\AD\Get-IRAuditReadiness.ps1`.

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
| `-DomainController` | none | DC names / IPs. Used to recognise a relayed DC machine account (RULE 1 escalates to Critical) and, offline, to supply the DC list when the host is not domain joined. |
| `-Threshold` | 5 | Distinct accounts from one source (RULE 2) or one workstation (RULE 3) within the window that raise a relay / harvest burst. |
| `-WindowMinutes` | 10 | Sliding window length in minutes for the burst rules. |
| `-ExcludeSource` | none | Source IPs / workstation names ignored by the burst rules (RULE 2 and RULE 3) - known Terminal Server / Citrix / VPN / NAT concentrators through which many accounts legitimately authenticate from one apparent source. Matched against the source IP and the workstation name. Does NOT suppress RULE 1. |
| `-ExcludeMachineAccount` | none | Computer accounts whose NTLM network logon is confirmed benign (e.g. a backup / clustering / appliance computer account) and should be suppressed from RULE 1. Matched on the bare machine name (with or without a trailing `$`, UPN, or `DOMAIN\` prefix). |
| `-PrivilegedAccount` | none | Account names (users or machines) whose relayed NTLM logon should be escalated to Critical (RULE 1); also raises RULE 4 to High for those accounts. |
| `-NoADLookup` | off | Skip live AD DC discovery; the DC list is then built solely from `-DomainController`. |

## Usage

### Live hunt on this DC

Run on (or against) a domain controller - the most valuable relay target - with live mode covering
the last 7 days by default.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -DomainController DC01, DC02
```

### Single exported .evtx

Analyse one exported Security log from a relayed-to host.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01, DC02
```

### Folder of exported logs

Point `-Path` at a folder of exports from the DCs, key servers and the CA.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02
```

### Time-boxed window

Bound the analysis to the incident window.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -StartTime '2026-09-28 00:00' -EndTime '2026-09-30 00:00' -DomainController DC01, DC02
```

### Remote host

Read the live Security log of a remote host.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst) -DomainController DC01, DC02
```

### Pipeline input

Pipe pre-flattened events in. `ConvertFrom-IRWinEvent` lives in the common module, so import it
first.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625, 4776 } -ErrorAction Ignore |
    ConvertFrom-IRWinEvent |
    .\Tools\AD\Find-NTLMRelay.ps1 -DomainController DC01, DC02
```

### Pre-parsed JSON

Re-analyse events previously flattened to JSON / CSV / CliXml.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -InputPath C:\Evidence\DC01-events.json -DomainController DC01, DC02
```

### Writing reports

`-OutputPath` writes result files; `-Format All` produces Csv, Json and Html (default is Json).

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -OutputPath C:\Evidence\Out -Format All
```

### Offline with -DomainController

Hunt relayed machine-account logons across exported DC logs; name the DCs so a relayed DC machine
account is escalated to Critical. Without the list, a relayed DC is still reported by RULE 1 but only
at High/Medium - the headline escalation needs the DC names. (Tool help example 1.)

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController DC01, DC02
```

### Ignoring a multi-user gateway

A Terminal Server / Citrix / VPN / NAT egress legitimately authenticates many accounts from one
source and trips the burst rules; exclude it by IP or name. RULE 1 is never suppressed by this list.
(Tool help example 2, time-boxed to the last two days.)

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -StartTime (Get-Date).AddDays(-2) -ExcludeSource 10.10.20.50 -OutputPath C:\Evidence\Out -Format All
```

### Tuning the burst rules

Lower the distinct-account threshold / widen the window on small networks where a relay would touch
fewer accounts.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -Threshold 3 -WindowMinutes 30
```

### Suppressing a confirmed-benign machine account

After verifying that a backup / clustering / appliance computer account legitimately uses NTLM,
suppress its RULE 1 findings.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -ExcludeMachineAccount BACKUP01$
```

### Escalating crown-jewel accounts

Escalate relayed NTLM logons of named accounts (users or machines) to Critical even when they are not
DCs - e.g. the CA or a tier-0 file server.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -PrivilegedAccount FS01$, adm-backup
```

### Skipping live AD discovery

`-NoADLookup` skips live AD DC discovery, so the DC list is built solely from `-DomainController` -
use it on a domain-joined analyst host when only the named DCs should be treated as legitimate.

```powershell
.\Tools\AD\Find-NTLMRelay.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController DC01, DC02
```

### Running via Invoke-IRHunt

The phase runner forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`,
`-EndTime`, `-MaxEvents` and (to tools that accept it) `-DomainController`, and filters the
consolidated report with `-MinimumSeverity`. Tool-specific tuning such as `-Threshold`,
`-ExcludeSource`, `-ExcludeMachineAccount` and `-PrivilegedAccount` is NOT forwarded - run the tool
directly when you need it.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-NTLMRelay -Path C:\Evidence\Logs\ -DomainController DC01, DC02 -MinimumSeverity High -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

### RULE 1 - Machine account NTLM network logon

Confirm first whether this machine legitimately uses NTLM (rare - usually backup, clustering or
appliance accounts). If not, hunt for coercion (PetitPotam / PrinterBug) and a relay host at the
source IP, check for resulting RBCD / shadow-credential / certificate changes on this computer
object, and enforce SMB and LDAP signing plus Extended Protection for Authentication (EPA). A
Critical finding naming a DC account is the domain-compromise path (relay to LDAP or AD CS) - treat
it as an incident until disproven.

### RULE 2 - Many accounts via NTLM from one source

Confirm whether the source is a legitimate multi-user host (Terminal Server / VPN / proxy); if so,
add it to `-ExcludeSource` and re-run. Otherwise treat it as a relay host: isolate it, and enforce
SMB/LDAP signing and EPA so relayed authentication is rejected. Corroborate with RULE 1 hits from the
same source and with RULE 5 tooling findings.

### RULE 3 - NTLM credential-validation spike from one workstation

Correlate the workstation name with a known host - remember the relay host chooses the name it
presents, so an unknown or impossible name is itself a signal. If unknown or spoofed, treat as
Responder / relay activity: disable LLMNR and NBT-NS to remove the poisoning vector, and enforce
SMB/LDAP signing. This is a lead to corroborate against RULES 1, 2 and 5 rather than a standalone
conviction.

### RULE 4 - NTLMv1 / LM network logon

Identify why NTLMv1/LM is in use and remove it: set LmCompatibilityLevel to 5 (NTLMv2 only) via GPO
and restrict NTLM where possible. NTLMv1 should not exist in a modern domain; a machine or privileged
account downgraded to NTLMv1 deserves the same follow-up as a RULE 1 hit.

### RULE 5 - Relay / coercion tooling in PowerShell script block

Identify the user and process that ran the script block. Correlate with NTLM logons / 4776 from the
same host, and hunt for coerced machine-account authentication and resulting directory changes
(RBCD, shadow credentials, certificates) in the same window.

## False positives and tuning

- NTLM is still used legitimately: accessing a share or service by IP address (rather than name)
  forces NTLM, and some backup agents, clustering, SCCM, scanners and legacy / appliance devices use
  it. Those are usually USER or specific service accounts - a COMPUTER-account NTLM logon (RULE 1) is
  the much stronger signal.
- A Terminal Server / Citrix / VPN / NAT egress can authenticate as many accounts from one source and
  trip RULE 2/3; add such hosts to `-ExcludeSource`. Treat RULE 2/3 as leads to corroborate, and
  RULE 1 (especially a DC) and RULE 5 as the high-confidence signals.
- Some environments have a few computer accounts that legitimately use NTLM (backup, clustering,
  appliances). Each produces one RULE 1 finding per source; after verifying them, tune out
  confirmed-benign ones with `-ExcludeMachineAccount`. A machine authenticating from its own routable
  IP is still reported - the tool cannot know each machine's own address offline.

## Related tools

- [Find-ShadowCredentials](Find-ShadowCredentials.md) - msDS-KeyCredentialLink writes are a common
  outcome of relaying a machine account to LDAP; hunt them on the relayed object.
- [Find-DelegationAbuse](Find-DelegationAbuse.md) - RBCD configuration is the other classic
  relay-to-LDAP outcome.
- [Find-ADCSAbuse](Find-ADCSAbuse.md) - relay to AD CS web enrollment (ESC8) yields a certificate;
  check issuance around a RULE 1 window.
- [Find-DCSync](Find-DCSync.md) - replication rights granted via relay lead straight to DCSync; run
  it over the same window.
- [Find-ZerologonActivity](Find-ZerologonActivity.md) - the other machine-account authentication
  abuse against DCs; its Netlogon artefacts corroborate coercion timelines.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
