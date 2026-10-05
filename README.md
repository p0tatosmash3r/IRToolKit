# IRToolKit

A PowerShell incident-response toolkit for hunting attacker activity in Windows event logs. Each
detection is a standalone script that reads the Security, PowerShell, Sysmon, and other logs, decodes
the relevant events, and emits standardized **findings** (severity, ATT&CK technique, account, source,
evidence, and a recommended next step).

Tools run the same way against four sources, so you can triage live or work entirely offline from
collected evidence:

- the **local** live event log,
- a **remote** host (`-ComputerName` / `-Credential`),
- exported **`.evtx`** files (`-Path`),
- pre-parsed **JSON/CSV** events (`-InputPath`, or piped `-InputObject`).

Everything targets **Windows PowerShell 5.1** and also runs on PowerShell 7+. No modules or RSAT are
required; optional Active Directory enrichment is used only when the host is domain-joined and is
read-only.

## Quick start

```powershell
# One detection against the local Security log (last 14 days)
.\Tools\AD\Find-Kerberoasting.ps1 -StartTime (Get-Date).AddDays(-14)

# Same detection against an exported DC log, with CSV+JSON+HTML output
.\Tools\AD\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All

# Run the whole AD phase and build one consolidated report
.\Invoke-IRHunt.ps1 -Phase AD -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Report -Format All -DomainController DC01,DC02

# Check that the host is actually logging what the detections need
.\Tools\AD\Get-IRAuditReadiness.ps1
```

Collect a DC's Security log for offline analysis with:

```powershell
wevtutil epl Security C:\Evidence\DC01-Security.evtx
```

### Hunting an incident across multiple hosts (offline)

For a real AD incident, pull the Security log from every affected domain controller (each DC only records
the requests it served, and DCs replicate to each other, so no single log is complete), the PowerShell
Operational log from each for the event 4104 tooling rules, the **System** log from each DC (the Netlogon
Zerologon events 5805/5827-5831 live there, not in Security), and — if AD CS is in scope — the CA host's
Security log (certificate issuance events 4886/4887 live on the CA, not the DCs).

Export on each source host (elevated):

```powershell
# On each DC
wevtutil epl Security C:\Evidence\DC01-Security.evtx
wevtutil epl System   C:\Evidence\DC01-System.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\DC01-PowerShell.evtx
# On the CA host (if AD CS is in scope)
wevtutil epl Security C:\Evidence\CA-Security.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\CA-PowerShell.evtx
```

Copy the files to the analysis box, then run the whole phase over all of them at once. Separate every
file with a comma (a space breaks the list); list each log once. Give `-DomainController` your DCs in
every form they appear in the logs (short name, FQDN, and IP) so DC-to-DC replication is excluded
correctly; do NOT list the CA there (it is not a domain controller):

```powershell
.\Invoke-IRHunt.ps1 -Phase AD `
  -Path C:\Evidence\CA-Security.evtx, C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx, C:\Evidence\DC01-System.evtx, C:\Evidence\DC02-System.evtx, C:\Evidence\CA-PowerShell.evtx, C:\Evidence\DC01-PowerShell.evtx, C:\Evidence\DC02-PowerShell.evtx `
  -DomainController DC01,DC02,DC01.corp.local,DC02.corp.local,10.0.0.11,10.0.0.12 `
  -OutputPath C:\Evidence\Report -Format All
```

Each tool reads the event IDs it needs from whichever file contains them, so mixed Security / PowerShell
/ CA logs in one `-Path` list is expected. A mistyped path is reported as a warning and the rest still
run. Open the HTML report in `C:\Evidence\Report` and work top-down from Critical. Tool-specific options
(`-HoneypotAccount`, `-ExcludeRequester`, `-ExpectedDomain`, `-PrivilegedUpn`, `-KnownReplicationAccount`)
are not forwarded by the runner; run the individual tool for those (see each tool's `-?` help).

If the collected logs are all in one folder, point `-Path` at the folder instead of listing files - it
picks up every `.evtx` in it:

```powershell
.\Invoke-IRHunt.ps1 -Phase AD `
  -Path C:\ADLogs `
  -DomainController DC01,DC01.corp.local,10.0.0.10 `
  -OutputPath C:\Results\Out -Format All
```

Add `-MinimumSeverity High` for a focused view that drops the routine Medium/Low noise (benign driver
installs, legacy RC4, single admin actions) and keeps only High and Critical:

```powershell
.\Invoke-IRHunt.ps1 -Phase AD `
  -Path C:\ADLogs `
  -DomainController DC01,DC01.corp.local,10.0.0.10 `
  -MinimumSeverity High `
  -OutputPath C:\Results\Out-Focused -Format All
```

## What is covered now (Active Directory phase)

| Tool | ATT&CK | Detects |
|---|---|---|
| Find-Kerberoasting | T1558.003 | TGS requests for user service accounts; RC4/volume bursts; honeypot SPNs; tooling |
| Find-ASREPRoasting | T1558.004 | AS-REQs for accounts without pre-auth; roast sweeps; user enumeration; tooling |
| Find-DCSync | T1003.006 | Replication-rights (DS-Replication-Get-Changes) use by a non-DC; tooling |
| Find-KerberosTicketAnomaly | T1558.001/.002, T1550.003 | Golden/silver ticket and pass-the-ticket anomalies (RC4 downgrade, TGS without TGT, krbtgt-as-client, realm mismatch) |
| Find-PasswordSpray | T1110.003 | One/few passwords against many accounts from a source; spray-then-success |
| Find-PrivilegedGroupChange | T1098, T1078.002 | Adds/removes to Domain/Enterprise/Schema Admins, builtin Administrators, DnsAdmins, etc.; stealth add-then-remove |
| Find-DelegationAbuse | T1558.003, T1134, T1484 | Unconstrained/constrained delegation changes and resource-based constrained delegation (RBCD) writes |
| Find-ShadowCredentials | T1556, T1098.001 | msDS-KeyCredentialLink writes (Whisker/pyWhisker); add-then-PKINIT takeover |
| Find-ADCSAbuse | T1649 | AD CS ESC abuses: attacker-supplied SAN, dangerous template changes, cert-logon anomalies, altSecurityIdentities |
| Find-NTLMRelay | T1557.001 | Relayed/coerced machine accounts, NTLM harvesting bursts, NTLMv1 downgrade, relay/coercion tooling |
| Find-DCShadow | T1207 | Rogue DC registration: DRS/GC SPN added to a non-DC, transient nTDSDSA object, replication push rights, tooling |
| Find-ZerologonActivity | T1210 / CVE-2020-1472 | Anonymous machine-account password reset, vulnerable Netlogon channel (5827-5831), auth-failure burst, tooling |
| Find-GoldenGMSA | T1555 | KDS root key read by a non-DC, gMSA managed-password retrieval, retrieval-principal changes, tooling |
| Find-SIDHistoryInjection | T1134.005 | Privileged SID injected into sIDHistory (4765/5136/4738), failed attempts, tooling |
| Find-ADReconnaissance | T1087.002 / T1069.002 / T1482 | BloodHound/SharpHound LDAP recon (1644), mass group enumeration (4798/4799), recon tooling & processes |
| Find-GPOAbuse | T1484.001 | GPO client-side-extension/ACL/gPLink changes (5136), new GPOs (5137), SYSVOL policy-file writes (5145/4663), GPO-abuse tooling (SharpGPOAbuse etc.) |
| Find-SkeletonKey | T1556.001 | Kerberos RC4 encryption downgrade across many accounts (4768), LSASS sensitive-privilege use (4673), suspicious driver/service install (7045/4697), credential-theft tooling (4104/4688), multi-signal DC correlation |
| Find-TrustAbuse | T1484.002 / T1134.005 | Trust create/modify/remove (4706/4707/4716/4865-4867), SID-filtering & treat-as-external weakening via trustAttributes transitions (5136), dangerous netdom/.NET trust commands, trust-key tooling (Mimikatz lsadump::trust, Rubeus) |
| Get-IRAuditReadiness | n/a | Whether the audit policy and logs needed by the detections are actually enabled |

See `Docs/COVERAGE.md` for the full attack-chain matrix and what is planned for other phases.

## Output

Every detection returns `IRToolKit.Finding` objects, so you can filter and pipe them:

```powershell
.\Tools\AD\Find-Kerberoasting.ps1 -Path .\DC01.evtx | Where-Object Severity -in 'Critical','High' |
    Sort-Object TimeCreated | Format-Table TimeCreated, Title, Account, SourceIp
```

`-OutputPath` writes CSV (triage in Excel), JSON (re-ingest or pipe to other tools), or HTML (a
self-contained report with collapsible evidence). `-Format All` writes all three.

Severities follow a consistent scale: **Critical** (near-certain domain compromise), **High** (strong
signal needing immediate triage), **Medium** (suspicious, plausible in some environments), **Low**
(hygiene), **Informational** (context). Each finding also carries a **Confidence** reflecting how
specific the evidence is.

## Required logging

The detections depend on audit policy that is not all on by default. Run `Get-IRAuditReadiness.ps1`
(elevated, ideally on the DC) for a per-host report, or see `Docs/AUDIT-POLICY.md`. In short, enable on
domain controllers: Kerberos Authentication Service and Service Ticket Operations, Directory Service
Access and Changes (with a SACL on the domain head), Security Group Management, User/Computer Account
Management, and Logon/Account Lockout. Enable PowerShell Script Block Logging (event 4104) for the
tooling-signature rules.

## Deploying a single file

To drop one dependency-free script onto an evidence host, inline the shared module:

```powershell
.\Build-Standalone.ps1 -Tool Find-Kerberoasting -OutputDirectory C:\Deploy
```

The standalone under `C:\Deploy\AD\Find-Kerberoasting.ps1` behaves identically with no `Common\` folder.

Note: the inlined standalones embed the full module, which includes offensive-tool name signatures and,
for `Get-IRAuditReadiness`, audit-configuration command strings. Some endpoint-security products
quarantine or lock such a single file on write (the non-inlined tools under `Tools\` run fine). If a
standalone is reported "written but not readable back," add an AV exclusion for the output folder or
unblock the file; the detection tools are normally run in place from `Tools\` where this does not occur.

## Testing

```powershell
.\Tests\Invoke-IRTests.ps1            # syntax + help checks, then every tool's test
.\Tests\Invoke-IRTests.ps1 -Filter *DCSync*
```

Each tool ships synthetic sample data (`Tests/SampleData/<Phase>/<Tool>.json`) with both malicious and
benign events and a test (`Tests/<Phase>/<Tool>.Test.ps1`) asserting the malicious cases fire, the
benign look-alikes do not, and empty input is handled cleanly. `Tests/Common` covers the shared module
with real `.evtx` fixtures (`Tests/SampleData/Common`, public-domain samples from the
[EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) corpus). The AD suite is
also exercised end-to-end against that corpus; gaps it exposed are fed back as detections and
regression tests.

## Repository layout

```
Common/            Shared module (IRToolKit.Common.psm1) + display format
Docs/              CONVENTIONS, COVERAGE matrix, AUDIT-POLICY, EVENT-REFERENCE
Templates/         Find-Template.ps1 - copy to start a new tool
Tools/AD/          Active Directory attack detections (this delivery)
Tools/<Phase>/     Future phases (see COVERAGE.md)
Tests/             Harness, per-tool tests, sample data
Invoke-IRHunt.ps1  Run every tool in a phase and build one consolidated report
Build-Standalone.ps1  Inline the module into each tool for single-file deployment
```

## Safety

Tools only read logs and (optionally, read-only) Active Directory. They never modify the system, and
they never write files unless you pass `-OutputPath`. They are built for authorized incident response,
threat hunting, and detection engineering on systems you are responsible for.

## Writing a new tool

Copy `Templates/Find-Template.ps1`, follow `Docs/CONVENTIONS.md`, add sample data and a test, and run
`Tests\Invoke-IRTests.ps1`. The conventions document the standard parameter block, the finding schema,
the helper API, and the Windows PowerShell 5.1 gotchas the kit works around.
