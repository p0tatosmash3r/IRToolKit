# Find-ADReconnaissance

Detects Active Directory reconnaissance and enumeration - BloodHound/SharpHound, PowerView,
ldapdomaindump, AdFind and similar collection - from the footprints it leaves in the Directory
Service, Security and PowerShell event logs. Before moving laterally or escalating, an attacker maps
the domain (users, groups, computers, ACLs, trusts, GPOs, local-admin relationships); this is
overwhelmingly done with large LDAP queries plus mass local-group enumeration, and those are exactly
the artefacts this tool hunts.

The tool is read-only: it reads event logs (live, remote, exported `.evtx`, or pre-parsed events),
enumerates nothing itself, and writes files only when `-OutputPath` is given. Findings are emitted
as `IRToolKit.Finding` objects on the pipeline.

| | |
|---|---|
| ATT&CK | T1087.002 (Domain Account Discovery), T1069.002 (Permission Groups Discovery: Domain Groups); related context: T1482 (Domain Trust Discovery), T1018 (Remote System Discovery). Findings are tagged T1087.002 (RULES 1, 3, 4) or T1069.002 (RULE 2). |
| Event IDs | 1644 (Directory Service); 4798, 4799, 4688 (Security); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | Directory Service log (DCs), Security log (DCs and the member hosts being enumerated), PowerShell Operational log |
| Requires | Windows PowerShell 5.1+; `Common\IRToolKit.Common.psm1` (auto-located up to five levels above the script); event-log read rights for live mode (local Administrators or Event Log Readers); NTDS Field Engineering diagnostics on DCs for RULE 1 |

## What it detects

### RULE 1 - Expensive / recon LDAP queries, event 1644 (High/Medium or Medium/Low)

Directory Service event 1644 records expensive/inefficient LDAP searches on a DC. The rule reads
1644 with the rendered message included and without a channel-name filter (`-NoLogNameFilter`), so a
SIEM export that relabelled the channel is still read. The client is taken from the
`Client`/`ClientIPAddress`/`IpAddress`/`CallerIPAddress` fields (falling back to the `Client:` line
of the message), with a trailing `:port` stripped only for dotted IPv4 and bracketed IPv6 so a bare
IPv6 client is left intact. Two shapes:

- **Signature shape (High severity / Medium confidence)** - any 1644 whose LDAP filter carries a
  BloodHound/SharpHound-, PowerView- or ldapdomaindump-characteristic token: `samAccountType=805306368`
  / `805306369`, `objectClass=trustedDomain` / `objectCategory=trustedDomain` / `(objectClass=domainTrust)`
  / `trustAttributes`, `groupPolicyContainer`, the LAPS attributes (`ms-Mcs-AdmPwd`, `msLAPS-Password`),
  `msDS-AllowedToDelegateTo`, `msDS-GroupMSAMembership`, `ntSecurityDescriptor`, and
  `servicePrincipalName=*` sweeps. One finding per client, listing the matched signatures.
- **Volume shape (Medium severity / Low confidence)** - at least `-Threshold` (default 20)
  non-signature 1644 events from one client within a `-WindowMinutes` (default 10) sliding window.
  High query volume from one client can be enumeration or a noisy but legitimate scanner.

`-ExcludeAccount` is honoured against both the client IP and the issuing account recorded in the
event (modern 1644 builds log a `User` field), so a scanner on DHCP can be suppressed by its service
account and not only by IP.

### RULE 2 - Mass local-group / membership enumeration, events 4798/4799 (High/High or High/Medium)

Security events 4798 (user local-group membership enumerated) and 4799 (security-enabled local group
membership enumerated) are logged by the host *being enumerated*. Events are keyed to one principal
by subject SID when present (a domain SID is the same on every host, while five hosts' local
`Administrator` accounts have five different SIDs and are not merged), else by `DOMAIN\name`; events
with neither are dropped so blank-subject noise cannot fabricate a synthetic burst. By default
SYSTEM / LOCAL SERVICE / NETWORK SERVICE and machine (`$`) accounts are ignored (they enumerate
local groups routinely - GPO, SCCM, EDR); pass `-IncludeMachineAndSystem` to keep them. Two shapes:

- **Host-spread shape (High severity / High confidence)** - ONE principal enumerating on at least
  `-HostThreshold` (default 5) DIFFERENT hosts within the `-WindowMinutes` window. An admin
  enumerates one host; SharpHound's local-admin / session collection walks the computer list, so the
  distinct-host spread is the signature even when the raw event count is small. Host identity is the
  lower-cased first DNS label (`SRV0` and `srv0.corp.local` are one host). Because 4798/4799 come
  from the enumerated hosts, this shape needs the member-host logs (a SIEM export or several files)
  in one run.
- **Volume shape (High severity / Medium confidence)** - at least `-Threshold` (default 20)
  4798/4799 events from one principal within the window. A principal already reported by the
  host-spread shape is skipped, so one collection run yields one finding.

### RULE 3 - BloodHound / PowerView tooling in a PowerShell script block, event 4104 (High/Medium)

Script-block text (falling back to the rendered message) is matched against AD-recon tooling
signatures kept inline in the script: `Invoke-BloodHound`, `SharpHound`, the PowerView
`Get-Domain*` / `Get-Net*` family (`Get-DomainUser`, `Get-DomainComputer`, `Get-DomainGroup`,
`Get-NetUser`, `Get-NetComputer`, `Get-NetSession`, `Get-NetLocalGroup`, `Get-DomainTrust`,
`Get-NetDomainTrust`, `Get-DomainGPO`), `Invoke-ShareFinder`, `Invoke-UserHunter`,
`Find-DomainShare`, and `ldapdomaindump`. One finding per matching script block, with a 300-character
excerpt.

### RULE 4 - Recon tooling executed as a process, event 4688 (High or Medium / Medium)

Process-creation events are matched on the image *leaf* only (anchored, never as a bare substring of
the whole command line and path - opening SharpHound output in Notepad, or a binary run from a
directory named `adfind`, does not self-flag):

- **High**: `sharphound.exe`, `adfind.exe`.
- **Medium**: `dsquery.exe`, `csvde.exe`, `ldifde.exe`; `nltest.exe` with a
  `/dclist`, `/domain_trusts` or `/trusted_domains` argument; `net.exe` / `net1.exe` with a
  `group`, `user` or `accounts` argument combined with `/domain`. These branches need command-line
  auditing to be useful.

Confidence is Medium for both tiers. `-ExcludeAccount` is matched against the subject and the image
leaf.

## Required audit policy

- **Directory Service log (DCs)**: event 1644 requires the NTDS diagnostic **"15 Field
  Engineering" = 5** (or expensive/inefficient-search logging). This is **off by default - RULE 1 is
  silent without it**.
- **Security (DCs / member hosts)**: 4798/4799 come from "Audit Security Group Management" /
  built-in membership-enumeration auditing **on the hosts being enumerated** - collect the member-host
  Security logs for the RULE 2 host-spread shape.
- **Security 4688 with command-line auditing** for RULE 4 (the `nltest` / `net ... /domain` branches
  depend on the command line).
- **PowerShell Script Block Logging** (event 4104) for RULE 3.

See [AUDIT-POLICY](../../AUDIT-POLICY.md) for the kit-wide logging baseline.

## Parameters

### Source and output

| Name | Default | Purpose |
|---|---|---|
| `-ComputerName` | local machine | Remote computer to read the live logs from. |
| `-Credential` | none | Credential for the remote computer. |
| `-Path` | none | One or more exported `.evtx` files, or folders containing `.evtx` files, analysed offline (include the Directory Service log for RULE 1). |
| `-InputObject` | none | Pre-flattened IRToolKit event objects via the pipeline. |
| `-InputPath` | none | JSON / CSV / CliXml file of pre-flattened events. |
| `-StartTime` | live mode: last 7 days | Only analyse events at or after this time. |
| `-EndTime` | none | Only analyse events at or before this time. |
| `-MaxEvents` | 0 (unlimited) | Cap on events read per event-ID batch. |
| `-OutputPath` | none (no files written) | Directory or file to write results to. A directory gets `Find-ADReconnaissance-<timestamp>.<ext>`. |
| `-Format` | `Json` | Export format: `Csv`, `Json`, `Html` or `All`. |
| `-Quiet` | off | Suppress console status output (findings are still returned). |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| `-Threshold` | 20 | Events from one principal / client within the window to raise a volume burst (RULE 1 volume shape, RULE 2 volume shape). |
| `-WindowMinutes` | 10 | Sliding-window length in minutes for the burst rules. |
| `-HostThreshold` | 5 | Distinct hosts on which ONE principal enumerated local groups / memberships within the window to raise the RULE 2 host-spread finding. |
| `-ExcludeAccount` | none | Principals / hosts (users, machine accounts, or IPs) known to perform legitimate bulk enumeration - vulnerability scanners, inventory tools, EDR. Matched (UPN / `DOMAIN\` / trailing-`$` aware) against the 1644 client IP and issuing account, the 4798/4799 subject name / SID / caller process, and the 4688 subject / image leaf. |
| `-IncludeMachineAndSystem` | off | Include SYSTEM / LOCAL SERVICE / NETWORK SERVICE and machine (`$`) accounts in RULE 2 (for example when hunting SharpHound run under SYSTEM). |

## Usage

All examples are run from the repo root.

### Live hunt on the local DC (last 7 days by default)

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1
```

### Hunt exported DC logs (Directory Service + Security together)

The tool's own example, against one exported Directory Service and one Security log:

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\DC01-DirectoryService.evtx, C:\Evidence\DC01-Security.evtx
```

### Single exported Security log

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\DC01-Security.evtx
```

### Folder of collected logs (DC plus member hosts)

A folder is expanded to the `.evtx` files it directly contains. Collecting the member-host Security
logs into one folder is what makes the RULE 2 host-spread shape possible:

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed hunt

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -StartTime (Get-Date).AddDays(-2) -EndTime (Get-Date)
```

### Remote domain controller, live

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\iradmin)
```

### Pipeline input (pre-flattened events)

Import the common module first so `ConvertFrom-IRWinEvent` is available. Use `-IncludeMessage` when
piping 1644 - RULE 1 falls back to the rendered message for the client and filter text:

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 1644 } -ErrorAction Ignore -ComputerName dc01.corp.local | ConvertFrom-IRWinEvent -IncludeMessage | .\Tools\AD\Find-ADReconnaissance.ps1
```

### Pre-parsed JSON (SIEM / earlier export)

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -InputPath C:\Evidence\Logs\dc01-events.json
```

### Writing reports

The tool's own example - two-day window, scanner exclusions, all report formats:

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -StartTime (Get-Date).AddDays(-2) -ExcludeAccount NESSUS_SVC,CMDB01$ -OutputPath C:\Evidence\Out -Format All
```

### Tuning the burst volume and window

Raise `-Threshold` and widen `-WindowMinutes` in an estate where applications legitimately issue
many directory queries:

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\DC01-DirectoryService.evtx -Threshold 50 -WindowMinutes 30
```

### Tuning the host-spread threshold

In a small estate where SharpHound would only reach a handful of hosts, lower `-HostThreshold`:

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\Logs\ -HostThreshold 3
```

### Excluding known bulk enumerators

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\Logs\ -ExcludeAccount NESSUS_SVC,CMDB01$,10.10.20.50
```

### Hunting enumeration run as SYSTEM or a machine account

```powershell
.\Tools\AD\Find-ADReconnaissance.ps1 -Path C:\Evidence\Logs\ -IncludeMachineAndSystem
```

### Via the phase runner

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-ADReconnaissance -Path C:\Evidence\Logs\ -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

Invoke-IRHunt forwards only `-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`,
`-EndTime` and `-MaxEvents` (plus `-DomainController` to tools that accept it, which this tool does
not), and filters the consolidated report with `-MinimumSeverity`. The tuning parameters
(`-Threshold`, `-WindowMinutes`, `-HostThreshold`, `-ExcludeAccount`, `-IncludeMachineAndSystem`)
are NOT forwarded - run the tool directly to use them.

## Triage: reading the findings

Findings are `IRToolKit.Finding` objects: `Severity`, `Confidence`, `Technique` / `TechniqueName`,
`Title`, `Description`, `Account`, `SourceIp`, `Target`, `Computer`, `EventIds`, `Evidence` (up to
the first 200 flattened events per finding) and `Recommendation`.

- **RULE 1 findings**: `Account` / `SourceIp` carry the LDAP client, `Target` the matched signature
  list (signature shape), `Computer` the DC. First question: is this client an authorised scanner /
  inventory tool? If not, treat as pre-attack reconnaissance and identify who was logged on at that
  client at that time.
- **RULE 2 findings**: `Account` is the enumerating principal; the description lists the enumerated
  hosts and caller processes. Pivot to 4624 logon type 3 by the same account on the enumerated hosts
  to find the source host, then correlate with 1644 recon and tooling from that host.
- **RULE 3 / RULE 4 findings**: name the tool or cmdlet seen and the host. `sharphound` / `adfind`
  executions are rarely legitimate; `dsquery` / `csvde` / `ldifde` / `nltest` / `net ... /domain`
  are dual-use - review the arguments and the running account.
- The strongest case is convergence: the same principal or host appearing across RULE 1 (LDAP),
  RULE 2 (membership enumeration) and RULE 3/4 (tooling) inside one window.

## False positives and tuning

- **Vulnerability scanners (Nessus, Qualys, Tenable), asset-inventory / CMDB tools, EDR and some
  management suites** perform large LDAP queries and mass local-group enumeration as normal operation
  and will trip RULE 1 / RULE 2. Add their service accounts / hosts / IPs to `-ExcludeAccount` and
  treat these rules as "who is enumerating the directory" leads, corroborated by RULE 3 / RULE 4
  tooling.
- RULE 2 already drops SYSTEM / LOCAL SERVICE / NETWORK SERVICE and machine accounts by default;
  only use `-IncludeMachineAndSystem` deliberately (for example hunting SharpHound under SYSTEM),
  expecting GPO/SCCM/EDR noise.
- RULE 1's volume shape is Low confidence by design: raise `-Threshold` / widen `-WindowMinutes`
  rather than ignoring it, and let the signature shape carry the weight.
- `-ExcludeAccount` matching is name-normalised: `CORP\NESSUS_SVC`, `NESSUS_SVC@corp.local`,
  `NESSUS_SVC` and `CMDB01$` all match their bare forms.

## Related tools

- [Get-IRAuditReadiness](Get-IRAuditReadiness.md) - verify the audit policy and log sizes before hunting (note: it does not check the NTDS Field Engineering diagnostic RULE 1 needs).
- Find-Kerberoasting / Find-ASREPRoasting - the usual next step after directory recon (SPN and pre-auth sweeps).
- Find-DCSync - recon of replication rights often precedes DCSync.
- Invoke-IRHunt - run the whole AD phase against the same evidence.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
