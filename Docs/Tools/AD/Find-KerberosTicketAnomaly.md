# Find-KerberosTicketAnomaly

Attackers who obtain the right key material can mint or replay Kerberos tickets instead of authenticating normally: a Golden Ticket (TGT forged with the stolen krbtgt hash), a Silver Ticket (TGS forged with a service account's hash), or Pass-the-Ticket (a ticket stolen on one host and replayed from another). Forged tickets leave artefacts on the KDC: RC4 encryption for otherwise-AES principals, service tickets with no preceding AS-REQ, blank / foreign / lower-case realms, absurd lifetimes, or the krbtgt account itself appearing as a client.

Find-KerberosTicketAnomaly reads Security events 4768 (AS-REQ / TGT) and 4769 (TGS) from a domain controller - live, from exported .evtx, or from pre-parsed event objects - plus PowerShell 4104 script blocks for tooling signatures, and emits IRToolKit.Finding objects for each anomaly class. The tool is heuristic: offline it cannot know the environment baseline, so confidence is kept deliberately honest and false positives are documented per rule. It is read-only and writes files only when -OutputPath is given.

| | |
|---|---|
| ATT&CK | T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1550.003 (Pass the Ticket) |
| Event IDs | 4768 and 4769 (Security), 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | DC Security log; optionally PowerShell/Operational from any host for Rule 6 |
| Requires | DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Success and Audit Kerberos Service Ticket Operations = Success (PowerShell Script Block Logging optional for Rule 6) |

## What it detects

Both event sets are normalised once: RC4 means etype 0x17/0x18, AES means 0x11-0x14, machine accounts (trailing '$') and cross-realm referrals (ServiceName 'krbtgt/...' or 'kadmin/...') are tagged and excluded from the rules below where noted. Source IPs implicated by a high-specificity rule (Rules 1, 4 and 7) are remembered and used to corroborate Rule 2.

### RULE 1 - Kerberos encryption downgrade (High/Medium)
Fires per principal that obtained an RC4 TGT (4768) while the same principal is demonstrably AES-capable. AES capability is shown either by an AES TGT for the same principal (classic downgrade - a common Golden Ticket artefact, since older mimikatz forges RC4 by default), or by an AES service ticket (4769) the principal requested as a client while having no AES TGT at all - the overpass-the-hash pattern, where the AS-REQ was made with a cracked / forged RC4 key (e.g. from a Kerberoast) but the account otherwise lives in an AES world. Because the baseline is unknown offline, only a same-principal downgrade is flagged. A non-upper-case TGT realm is appended to the description as a further forged-key tell. krbtgt and machine accounts are excluded.

### RULE 2 - Service tickets without a preceding TGT (High when corroborated, else one Informational rollup)
Fires per principal whose 4769 service-ticket requests have NO successful 4768 TGT within -TgtLookbackMinutes (default 10080 = 7 days) before the first TGS - consistent with a forged service ticket (Silver Ticket) or a stolen TGT replayed from another host (Pass-the-Ticket). Because a missing in-window TGT is ALSO the normal case on a short / windowed export (the TGT predates the export), a bare miss is never raised per principal: it becomes a per-principal High finding only when corroborated by an attacker-associated source IP (Confidence High), an RC4 service ticket, or a blank / mismatched realm (Confidence Medium). All uncorroborated TGT-less principals are summarised in ONE Informational/Low finding so a partial export cannot flood the report. The rule is only evaluated when the dataset contains some successful 4768 traffic; machine accounts, referrals and krbtgt are excluded.

### RULE 3 - Anomalous TGT options / lifetime (High/Medium lifetime; Informational/Low options)
Evaluated over successful RC4 TGTs for non-machine, non-krbtgt principals. An explicit ticket lifetime beyond -MaxTicketLifetimeYears (default 10) raises a High/Medium "Abnormal Kerberos ticket lifetime" finding - forged tickets are frequently minted with multi-year lifetimes. This only applies when the event schema actually carries a lifetime field (TicketLifetime / Lifetime / TicketLifetimeHours), which most 4768/4769 schemas do not. Separately, a forwardable+renewable RC4 TGT is weak supporting evidence (it is also the default for normal TGTs), so it is only emitted - once per principal, as Informational/Low context - when the source IP is already implicated by another rule.

### RULE 4 - krbtgt account authenticating as a client (Critical/High)
Fires per account+IP for any 4768/4769 whose requesting principal (TargetUserName) is krbtgt. The krbtgt account never logs on or requests tickets for itself; this is near-certain krbtgt-key abuse (Golden Ticket). The source IP is marked as attacker-associated for Rule 2 corroboration.

### RULE 5 - Forged ticket with mismatched or blank realm (High/High)
Fires per account+realm for a 4769 whose TargetDomainName is blank, or - only when -ExpectedDomain is supplied - differs from the expected domain. Forged golden/silver tickets frequently present a blank or incorrect realm. Machine accounts, referrals and krbtgt are excluded. Leave -ExpectedDomain unset for multi-domain datasets.

### RULE 6 - Kerberos ticket-forging tooling in PowerShell script block (Medium/Medium)
Fires when a PowerShell 4104 script block matches a ticket-forging signature: kerberos::golden, kerberos::ptt, Invoke-Mimikatz, mimikatz, Rubeus, ticketer, asktgt, golden, silver, or ptt. One finding per matching script block, with a 300-character excerpt. Broad keywords can hit benign scripts, hence Medium - treat as a lead.

### RULE 7 - Lower / mixed-case client realm in a service ticket (High/Medium)
The KDC writes the client principal of every 4769 it issues as NAME@REALM with the realm in UPPER CASE (copied from the TGT the KDC itself issued). A forged TGT carries the realm exactly as the forger typed it (e.g. a tool invoked with /domain:corp.local), so a non-upper-case realm is a cheap, high-signal Golden Ticket artefact. Implicated source IPs feed Rule 2. Dataset gate: if NO upper-case realm exists anywhere in the 4769 set and two or more principals are affected, the export was probably case-normalised by a SIEM / parser - the tool emits one Informational/Low note instead and does not evaluate the rule; with a single affected principal and no upper-case reference it reports at Medium/Low with a caveat.

## Required audit policy

- DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Success (4768). Without it Rules 1, 3 and 4 lose their TGT feed, and Rule 2 is skipped entirely (it requires successful 4768 traffic in the dataset).
- DC: Advanced Audit Policy > Account Logon > Audit Kerberos Service Ticket Operations = Success (4769). Without it Rules 2, 5 and 7 are silent and Rule 1 loses its overpass-the-hash variant.
- Optional: PowerShell Script Block Logging (event 4104, Microsoft-Windows-PowerShell/Operational) for Rule 6.
- Collect from EVERY DC: Rule 2 reasons about the absence of a 4768, and a TGT issued by a DC missing from the dataset looks like an anomaly.
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
| -TgtLookbackMinutes | 10080 (7 days) | How far back before a principal's first 4769 a successful 4768 TGT may be and still count as normal in Rule 2. The default covers the renewable TGT lifetime so long-lived or renewed sessions are not false positives |
| -ExpectedDomain | - | The single domain / realm the dataset is expected to belong to. When supplied, Rule 5 flags any 4769 whose TargetDomainName does not match, and Rule 2 treats a mismatched realm as corroboration. Leave unset for multi-domain datasets |
| -MaxTicketLifetimeYears | 10 | Sanity ceiling in years for an explicit ticket lifetime in Rule 3; only used when the event schema carries a lifetime field |

## Usage

All examples are run from the repo root.

### Live hunt on this DC
Run directly on a domain controller against the live Security log (default window: last 7 days).

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1
```

### Single exported .evtx
Analyse one exported DC Security log offline - the tool's own second example.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\DC01-Security.evtx -ExpectedDomain CORP.LOCAL -OutputPath C:\Evidence\Out -Format All
```

### Folder of exported logs
Point -Path at a folder of exports - ideally the Security logs of every DC, so Rule 2 can see TGTs issued elsewhere.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window - the tool's own first example (last 7 days against a known realm).

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -StartTime (Get-Date).AddDays(-7) -ExpectedDomain CORP.LOCAL
```

### Remote host
Read the live Security log of a remote DC.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -ComputerName dc01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe events you already collected (both 4768 and 4769 - Rule 2 needs the TGTs). ConvertFrom-IRWinEvent comes from the IRToolKit common module, so import it first. Field case must be preserved for Rule 7.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768,4769} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Tools\AD\Find-KerberosTicketAnomaly.ps1
```

### Pre-parsed JSON
Re-analyse events previously flattened to JSON / CSV / CliXml. Prefer the native .evtx when hunting Rule 7 artefacts - a case-normalising parser disables that rule.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -InputPath C:\Evidence\Out\DC01-events.json
```

### Writing reports
Write findings to disk in every format.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Pinning the expected realm
In a single-domain dataset, supply the realm so Rule 5 can flag foreign or blank realms and Rule 2 gains realm corroboration.

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\Logs\ -ExpectedDomain CORP.LOCAL
```

### Tightening the TGT lookback
On a complete, multi-day export you can shorten the Rule 2 lookback so a TGS must follow its TGT more closely (here: 24 hours).

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\Logs\ -TgtLookbackMinutes 1440
```

### Lowering the lifetime ceiling
Flag explicit ticket lifetimes beyond 1 year instead of 10 (only effective when the event schema carries a lifetime field).

```powershell
.\Tools\AD\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\DC01-Security.evtx -MaxTicketLifetimeYears 1
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime and -MaxEvents to this tool, and filters the consolidated report with -MinimumSeverity. Tuning parameters (-TgtLookbackMinutes, -ExpectedDomain, -MaxTicketLifetimeYears) are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-KerberosTicketAnomaly -Path C:\Evidence\Logs\ -OutputPath C:\Evidence\Out -MinimumSeverity Medium
```

## Triage: reading the findings

- RULE 1 downgrade: confirm whether the principal legitimately uses RC4. If not, treat as a possible Golden Ticket: review 4768/4769 from the source IP and check the host for forging tooling; consider rotating the krbtgt key. For the overpass-the-hash variant, treat as likely cracked-credential reuse: correlate with a preceding Kerberoast (RC4 4769 for this account's SPN - see Find-Kerberoasting) and with what the account did next (privileged logons, group changes); reset the account's password, and for a service account rotate it to a long random password or a gMSA.
- RULE 2 TGS without TGT: first verify whether the principal obtained its TGT from a different DC not present in this dataset - that is the most common benign explanation. If the AS-REQ is genuinely absent on every DC, treat the source host as compromised: capture memory for injected tickets and reset the affected service-account / user keys. For the Informational rollup: investigate only if the export is believed complete; otherwise widen the export window to include the preceding 4768s.
- RULE 3 lifetime: compare against the domain maximum ticket lifetime policy; a lifetime far beyond policy indicates a forged ticket - isolate the source host. The forwardable+renewable context finding is supporting evidence only; correlate with downgrade and missing-TGT findings for the same principal / host before escalating.
- RULE 4 krbtgt as client: treat the domain as compromised - the krbtgt key is almost certainly known to the attacker. Rotate the krbtgt password twice (with replication between resets), hunt for Golden Ticket usage, and isolate the source host. This is the highest-priority finding this tool emits.
- RULE 5 realm mismatch: validate the realm against the true domain. A blank or foreign realm on an intra-domain request indicates a forged ticket - isolate the source host and review it for forging tooling.
- RULE 6 script block: identify the user and process that ran the script block and correlate with 4768/4769 anomalies from the same host. On its own it is a lead, not proof.
- RULE 7 lower-case realm: treat as a probable forged (Golden) ticket. Confirm the principal exists in AD and obtained a 4768 TGT from some DC; if not, isolate the source host, capture memory for injected tickets, and rotate the krbtgt key twice once the host is contained. If the finding carries the case-normalisation caveat, re-run against the native .evtx first.

## False positives and tuning

- RULE 1: some applications legitimately request RC4 for specific principals; a mixed RC4/AES history can be benign for legacy accounts. Medium confidence reflects this - validate before escalating.
- RULE 2: by far the noisiest rule. A user whose TGT came from a DC missing from the dataset looks TGT-less; short collection windows, ticket renewals, and U2U / S4U flows can all mimic the pattern. Always confirm the AS-REQ is genuinely absent on every DC before escalating. Collect all DCs' logs and widen -TgtLookbackMinutes for long-lived sessions; the uncorroborated rollup exists precisely so partial exports do not flood the report. Referral TGS (ServiceName 'krbtgt/REALM') are not silver tickets and are excluded.
- RULE 3: forwardable+renewable is the default for most normal TGTs, hence supporting-only. Raise or lower -MaxTicketLifetimeYears to match domain policy.
- RULE 5: multi-domain / multi-forest environments produce legitimate foreign realms; only use -ExpectedDomain when the dataset is from a single known domain.
- RULE 6: broad keyword matches ('golden', 'ptt', 'silver') can hit benign scripts; treat as a lead, not proof.
- RULE 7: a non-Windows Kerberos client with a lower-case realm configuration could in theory present such a TGT; AD realms are upper case by definition, so verify the client host rather than dismiss the finding. A SIEM / parser export that lower-cases fields makes every principal look forged - the dataset gate downgrades or suppresses the rule in that case; use the native .evtx for this rule.

## Related tools

- [Find-Kerberoasting](Find-Kerberoasting.md) - the usual upstream source of the cracked RC4 key behind a Rule 1 overpass-the-hash finding.
- [Find-ASREPRoasting](Find-ASREPRoasting.md) - the other offline-cracking path to a reusable Kerberos key.
- [Find-PasswordSpray](Find-PasswordSpray.md) - check the implicated source IPs for credential-guessing activity preceding the ticket anomalies.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
