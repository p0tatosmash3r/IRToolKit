# Find-ADCSAbuse

Active Directory Certificate Services misconfigurations (the ESC1-ESC14 class, ATT&CK T1649 "Steal or
Forge Authentication Certificates") let an attacker obtain a certificate that authenticates as a
privileged account - a credential that survives password resets and is valid for the certificate's
whole lifetime. Find-ADCSAbuse hunts the logged signals those abuses leave behind: requester-supplied
Subject Alternative Names in CA issuance events, on-behalf-of issuance mismatches, dangerous template
edits, explicit certificate mappings, CA ACL grants, certificate (PKINIT) logons correlated back to
who the certificate was actually issued to, and the KDC's own weak-mapping warnings.

The tool reads the CA host's Security log (4886/4887 issuance, 4882 CA permissions), the domain
controller's Security log (5136 directory changes, 4768 Kerberos TGT/PKINIT) and System log (KDC
certificate-mapping events 39/40/41), plus PowerShell Operational 4104 for tooling signatures. It
emits IRToolKit.Finding objects, is read-only, and writes files only when -OutputPath is given. Two
rules (RULE 3 and RULE 7) correlate CA issuance with DC logon events, so collect the CA host's
Security log AND the DC's Security + System logs and pass them together in one run.

| | |
|---|---|
| ATT&CK | T1649 - Steal or Forge Authentication Certificates |
| Event IDs | 4886, 4887, 4882 (Security, CA host); 5136, 4768 (Security, DC); 39, 40, 41 (System, DC, provider Microsoft-Windows-Kerberos-Key-Distribution-Center); 4104 (Microsoft-Windows-PowerShell/Operational) |
| Log sources | CA host (CA01) Security log; DC Security and System logs; PowerShell Operational from any host that ran tooling |
| Requires | Certification Authority auditing on the CA (4886/4887/4882); Directory Service Changes + Kerberos Authentication Service auditing on DCs; KB5014754 on DCs for KDC 39-41; optional PowerShell Script Block Logging |

## What it detects

### RULE 1 - ESC1 certificate request with attacker-supplied SAN (High/Medium; Critical/High on a -PrivilegedUpn match; Medium/Medium for a DNS SAN)
A 4886/4887 whose request Attributes, rendered Message or SubjectAltName field carries a
requester-supplied SAN (san:/upn=/dns=/altname) naming a different identity than the Requester.
A supplied SAN for someone else is the ESC1 enrollee-supplies-subject abuse used to mint a
certificate that authenticates as that identity. A UPN SAN is High/Medium (a requester's UPN prefix
can legitimately differ from its sAMAccountName, hence Medium confidence); a DNS SAN naming a
different host is Medium/Medium; an exact match against the -PrivilegedUpn list escalates to
Critical/High. SANs matching the requester's own identity (including naming-convention variants and,
for DNS SANs, the requester's own host label) are suppressed, and 4886/4887 pairs for the same
request are de-duplicated.

### RULE 1b - Certificate issued for a different identity than the requester, ESC3/ESC2 on-behalf-of (High/Medium per requester; Critical/High when privileged; single mismatches roll up into one Medium/Low finding)
A 4887 whose Requester matches none of the UPN / e-mail / DNS identities in the issued certificate's
SubjectAlternativeName, while the request Attributes carry no requester-supplied SAN (that case is
RULE 1) - the pattern of an Enrollment Agent (ESC3) or Any Purpose (ESC2) certificate being used to
obtain logon certificates for other principals. Naming-convention variants of the requester, a
host's own FQDN and (when a directory is reachable) the requester's real UPN count as the
requester's own identity. Because a lone mismatch is usually a benign UPN-prefix difference, a
per-requester High/Medium finding needs the requester to have obtained certificates for 2 or more
different user identities (an agent serving several users), or a -PrivilegedUpn hit
(Critical/High); all remaining single mismatches are rolled up into ONE Medium/Low review finding so
a busy CA cannot flood the report. Accounts passed via -KnownEnrollmentAgent are not reported.

### RULE 2 - Certificate template modified to a dangerous configuration (Medium/Medium; High/Medium for msPKI-Certificate-Name-Flag)
A 5136 on a pKICertificateTemplate object (or a DN under CN=Certificate Templates,CN=Public Key
Services) where a dangerous attribute was Value Added / modified: msPKI-Certificate-Name-Flag,
msPKI-Enrollment-Flag, pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy or
nTSecurityDescriptor (the template ACL). This is the template half of ESC1/ESC2/ESC4. The finding is
raised to High when the attribute is msPKI-Certificate-Name-Flag, and the description notes when the
written value sets ENROLLEE_SUPPLIES_SUBJECT (0x1), which allows a requester to supply an arbitrary
subject/SAN.

### RULE 3 - Certificate issued to one account used to authenticate as another (Critical/High; Medium/Low only with -FlagAllPkinit)
A 4768 PKINIT logon (PreAuthType 16 with certificate fields populated) whose certificate thumbprint
or serial matches a 4887 issued to a DIFFERENT requester within -CorrelationHours (default 24, in
either direction) is certificate-based impersonation (ESC1/ESC8-class) and is Critical/High; the
description also notes when the logon came from a known DC address. Without a correlating issuance a
PKINIT logon is only reported (Medium/Low) when -FlagAllPkinit is set, because smart-card and
Windows Hello environments make PKINIT normal - and even then only when NO 4887 was found for that
certificate at all (a certificate issued to the same user stays silent).

### RULE 4 - altSecurityIdentities explicit certificate mapping added, ESC14 (High/Medium)
A 5136 Value Added on altSecurityIdentities performed by an actor that is not the target principal.
Mapping a certificate the actor controls onto another principal (ESC14) lets that certificate
authenticate as the victim. Self-mappings (actor CN equals target CN) are suppressed.

### RULE 5 - AD CS abuse tooling in PowerShell script blocks (Medium/High)
A 4104 script block matching an AD CS abuse signature: Certify, Certipy, ForgeCert, PassTheCert,
Invoke-Certify, esc1, ADCS, or certreq with a SAN argument. The finding carries a 300-character
excerpt for triage.

### RULE 6 - CA security permissions changed, ESC7 (High/High for a broad grant; Low/Medium otherwise)
A 4882 renders the whole resulting CA ACL. When CA Administrator (mask 0x1) or Certificate Manager
(mask 0x2) is held by a broad principal after the change - Everyone, Authenticated Users, Anonymous
Logon, BUILTIN\Users or Guests, Domain Users / Computers / Guests, or their SIDs - that is ESC7 and
is High/High: CA Administrator can approve requests and change CA settings, Certificate Manager can
issue pending or denied requests for any identity. Any other 4882 that leaves those rights with
someone is reported Low/Medium for review, because 4882 fires on every permissions change and
renders the full ACL rather than the delta.

### RULE 7 - KDC weak / mismatched certificate mapping, System 39/40/41 (Critical/High when correlated to issuance; 41 High/High; 40 Medium/Medium; 39 Medium/Medium only on a subject mismatch)
KDC certificate-mapping events (KB5014754) from the System log: 39 = certificate valid but not
strongly mapped, 40 = certificate predates the account, 41 = the SID in the certificate does not
match the account. When the certificate serial/thumbprint matches a 4887 issued to a DIFFERENT
requester the finding is Critical/High - this exact match is deliberately NOT time-bounded, because
a certificate is used for its whole lifetime, long after -CorrelationHours. Otherwise 41 is
High/High, 40 is Medium/Medium, and 39 is reported Medium/Medium only when the certificate subject
names a different principal than the account; a bare 39 with a matching subject is configuration
hygiene and is not reported. Repeats are grouped per event/account/certificate with an occurrence
count.

## Required audit policy

- CA host: Certification Authority auditing enabled -> 4886/4887 in the Security log; the same
  subcategory logs 4882. Without it RULE 1, RULE 1b and RULE 6 are silent, and RULE 3 / RULE 7 lose
  their issuance correlation (RULE 3 then reports nothing unless -FlagAllPkinit is set).
- DC: DS Access > Audit Directory Service Changes = Success, with SACL auditing of the relevant
  objects -> 5136 for RULE 2 (certificate templates) and RULE 4 (altSecurityIdentities).
- DC: Account Logon > Audit Kerberos Authentication Service = Success -> 4768 for RULE 3.
- DC: System log, provider Microsoft-Windows-Kerberos-Key-Distribution-Center -> 39/40/41 for
  RULE 7. Logged by default once KB5014754 is installed.
- Optional: PowerShell Script Block Logging -> 4104 for RULE 5.

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
| -OutputPath | - (no files written) | Directory or file for the report; a directory gets Find-ADCSAbuse-<timestamp>.<ext> |
| -Format | Json | Report format: Csv, Json, Html or All |
| -Quiet | off | Suppress console status output; findings are still returned as objects |

### Detection tuning

| Name | Default | Purpose |
|---|---|---|
| -NoADLookup | off | Skip live Active Directory look-ups (DC auto-discovery and the RULE 1b requester-UPN resolution) even when the host is domain joined |
| -DomainController | - | Extra DC names / IPs to treat as DCs; used to annotate whether a PKINIT logon came from a DC address when running offline |
| -PrivilegedUpn | - | Privileged UPNs (e.g. administrator@corp.local); an EXACT match on a requested or issued SAN identity escalates RULE 1 / RULE 1b to Critical |
| -KnownEnrollmentAgent | - | Accounts (bare name, DOMAIN\name or UPN) that legitimately request certificates on behalf of others; RULE 1b does not report them |
| -CorrelationHours | 24 | Maximum hours between a 4887 issuance and a 4768 PKINIT use to correlate them for RULE 3 |
| -FlagAllPkinit | off | Also report (Medium/Low) PKINIT logons for which no correlating 4887 issuance was found |

## Usage

### Live hunt on the CA or a DC
Run on (or against) the host whose logs you want to sweep; without -StartTime, live mode covers the
last 7 days. In live mode the tool only sees that one host's logs, so run it on both the CA and a DC
- or better, export both and use the multi-source run below.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -StartTime (Get-Date).AddDays(-14) -PrivilegedUpn administrator@corp.local
```

### Single exported .evtx
Analyse one exported CA Security log offline.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx
```

### CA + DC logs in one run (recommended)
RULE 3 and RULE 7 correlate CA issuance (4887) with DC logons (4768, KDC 39/40/41), so pass the CA
host's Security log and the DC's Security AND System logs together. -DomainController supplies the
DC list for source-address annotation when running offline.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx, C:\Evidence\DC01-Security.evtx, C:\Evidence\DC01-System.evtx -DomainController dc01.corp.local
```

### Folder of exported logs
A folder passed to -Path is expanded to every .evtx inside it.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\Logs\
```

### Time-boxed window
Constrain the analysis window in any source mode.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\Logs\ -StartTime '2026-09-01' -EndTime '2026-09-15'
```

### Remote host
Read a remote host's live logs over the event log API.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -ComputerName ca01.corp.local -Credential (Get-Credential CORP\ir-analyst)
```

### Pipeline input
Pipe pre-flattened events in. ConvertFrom-IRWinEvent comes from the kit module, so import it first;
use -IncludeMessage so the SAN can be parsed from the rendered message text. Only the event IDs you
pipe in are analysed - the other rules see nothing.

```powershell
Import-Module .\Common\IRToolKit.Common.psm1
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4887 } -ErrorAction Ignore | ConvertFrom-IRWinEvent -IncludeMessage | .\Tools\AD\Find-ADCSAbuse.ps1
```

### Pre-parsed JSON
Re-analyse events exported earlier (Export-IREvents JSON, CSV or CliXml).

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -InputPath C:\Evidence\Out\ca01-events.json
```

### Writing reports
Findings are written only when -OutputPath is given; -Format All writes Csv, Json and Html.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx, C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

### Escalating privileged identities (-PrivilegedUpn)
Any RULE 1 / RULE 1b finding whose SAN identity exactly matches a listed UPN is raised to Critical.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx -PrivilegedUpn administrator@corp.local, da.jsmith@corp.local
```

### Suppressing approved enrollment agents (-KnownEnrollmentAgent)
Smart-card enrollment stations and MDM / NDES connectors legitimately enroll on behalf of users;
list them so RULE 1b skips them.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx -KnownEnrollmentAgent 'CORP\enrollsvc', 'ndes-svc@corp.local'
```

### Widening the issuance-to-logon window (-CorrelationHours)
If the attacker may have sat on the certificate before using it, widen the RULE 3 window (RULE 7's
exact-match correlation is never time-bounded).

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx, C:\Evidence\DC01-Security.evtx -CorrelationHours 72
```

### Surfacing every PKINIT logon (-FlagAllPkinit)
When CA logs are unavailable, opt in to seeing uncorrelated certificate logons (Medium/Low). Expect
volume in smart-card / Windows Hello environments.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -FlagAllPkinit
```

### Analysing on a non-domain workstation (-NoADLookup)
On an analysis host joined to a different domain, skip AD look-ups so nothing queries the wrong
directory, and supply the case's DCs explicitly.

```powershell
.\Tools\AD\Find-ADCSAbuse.ps1 -Path C:\Evidence\Logs\ -NoADLookup -DomainController dc01.corp.local, dc02.corp.local
```

### Via the phase runner
Invoke-IRHunt forwards only -ComputerName, -Credential, -Path, -InputPath, -StartTime, -EndTime,
-MaxEvents and (to tools that accept it) -DomainController, and filters the consolidated report with
-MinimumSeverity. The tuning parameters (-PrivilegedUpn, -KnownEnrollmentAgent, -CorrelationHours,
-FlagAllPkinit, -NoADLookup) are NOT forwarded - run the tool directly for those.

```powershell
.\Invoke-IRHunt.ps1 -Phase AD -Tool Find-ADCSAbuse -Path C:\Evidence\CA01-Security.evtx, C:\Evidence\DC01-Security.evtx, C:\Evidence\DC01-System.evtx -DomainController dc01.corp.local -MinimumSeverity Medium -OutputPath C:\Evidence\Out
```

## Triage: reading the findings

- RULE 1: Confirm the requester is authorised to enroll with a supplied subject on that template -
  and first verify the SAN UPN genuinely belongs to a different principal (a requester's UPN prefix
  can legitimately differ from its sAMAccountName). If not authorised: revoke the issued
  certificate, disable ENROLLEE_SUPPLIES_SUBJECT (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) on the template
  or require manager approval, and treat the SAN identity as potentially compromised. Corroborate
  with a RULE 3 / RULE 7 hit on the same certificate.
- RULE 1b: Confirm the requester is an authorised enrollment agent for those templates. If not,
  revoke the certificates, treat the issued identities as compromised, restrict Enrollment Agent /
  Any Purpose templates (manager approval, enrollment-agent restrictions on the CA) and audit which
  principals can enroll on them. For the Medium/Low roll-up, compare each requester-to-identity pair
  against the directory (is the SAN simply the requester's own UPN?) and the approved-agent list;
  unexplained pairs get the same treatment.
- RULE 2: Review the template change against an authorised change. Dangerous settings
  (ENROLLEE_SUPPLIES_SUBJECT, Client Authentication / Smart Card Logon / Any Purpose EKU,
  no-manager-approval, weak ACLs) enable ESC1/ESC2/ESC4; revert unauthorised changes and audit who
  can write certificate templates. Then sweep 4886/4887 for enrollments on that template since the
  change.
- RULE 3: Treat both the authenticating account and the original requester as compromised. Revoke
  the certificate, investigate how it was issued (template or enrollment-agent abuse - check RULE 1,
  1b and 2 output), reset the impacted accounts, and isolate the source host.
- RULE 4: Verify the actor is authorised to set altSecurityIdentities on the target. If not, remove
  the mapping, treat the target as compromised, and audit write permissions on the object. Prefer
  strong certificate mapping per KB5014754.
- RULE 5: Identify the user and process that ran the script block, then correlate with 4886/4887
  issuance and 4768 PKINIT logons from the same host and timeframe.
- RULE 6 (High): Remove the broad grant immediately and audit every certificate approved or issued
  since the change (4886/4887 on the CA); treat the actor as a compromised or malicious
  administrator unless the change is covered by change control. (Low): confirm the change against
  change control and that every holder is an intended PKI administration group.
- RULE 7: Identify who holds the certificate and how it was issued (4886/4887 on the CA). A SID
  mismatch (41) or an issued-to-someone-else correlation means the certificate authenticates as a
  victim account: revoke it, reset the account, and move the KDC to Full Enforcement (KB5014754) so
  weakly mapped certificates are rejected.

## False positives and tuning

- Smart-card / Windows Hello for Business environments produce many legitimate PKINIT logons. RULE 3
  therefore only fires on a correlated issued-to-someone-else certificate; leave -FlagAllPkinit off
  unless you accept the volume.
- Enrollment agents and enrollment services (smart-card stations, MDM / NDES connectors)
  legitimately request certificates on behalf of other users - pass them via -KnownEnrollmentAgent
  (RULE 1b), and remember the SAN-differs heuristic of RULE 1 can misclassify them too.
- A requester's UPN prefix often differs from its sAMAccountName; RULE 1b handles this with
  naming-convention matching, a directory UPN check and the single-mismatch roll-up, which is why a
  lone pair is only a Medium/Low review item.
- Template and altSecurityIdentities changes also happen during legitimate PKI administration -
  validate the actor and the source host before escalating (no suppression parameter; this is
  deliberate).
- RULE 6 Low findings accompany routine CA administration; check change control.
- RULE 7 event 39 is common while the domain is still in Compatibility mode, which is why a bare 39
  is only reported with a subject mismatch or a correlated issuance.

## Related tools

- [Find-ShadowCredentials](Find-ShadowCredentials.md) - the other certificate-credential takeover
  path (msDS-KeyCredentialLink + PKINIT); pivot there when a suspicious 4768 PKINIT logon has no CA
  issuance behind it.
- [Find-GoldenGMSA](Find-GoldenGMSA.md) - the same steal-a-key-once, forge-offline-forever shape
  against gMSA passwords; pivot there when the actor had DC-level read access.
- [Find-GPOAbuse](Find-GPOAbuse.md) - also driven by 5136 directory changes; pivot there when the
  actor who touched certificate templates also edits GPOs.

---
Part of IRToolKit. See [COVERAGE](../../COVERAGE.md) for the phase matrix and [CONVENTIONS](../../CONVENTIONS.md) for the finding schema.
