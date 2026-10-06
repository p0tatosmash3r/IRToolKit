# AD tool reference

One document per detection tool in `Tools/AD`: what it detects (rule by rule, with severities), the
audit policy it needs, a full parameter reference, and a worked example for every use case. For the
one-page phase matrix see [COVERAGE](../../COVERAGE.md); for the finding schema and engineering
conventions see [CONVENTIONS](../../CONVENTIONS.md).

## How every tool is run

All detection tools share the same source modes and output contract:

```powershell
# Live: the local (or a remote) machine's event logs
.\Tools\AD\Find-DCSync.ps1 -StartTime (Get-Date).AddDays(-7)

# Offline: exported .evtx files and/or folders of .evtx
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\Logs

# Pre-parsed events (JSON/CSV/CliXml) or the pipeline
.\Tools\AD\Find-DCSync.ps1 -InputPath C:\Evidence\dc01-events.json

# Reports
.\Tools\AD\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
```

Findings are `IRToolKit.Finding` objects (Severity `Critical|High|Medium|Low|Informational`,
Confidence, ATT&CK Technique, Account/SourceIp/Target/Computer, EventIds, Evidence, Recommendation).
Tools only read logs; they write files only when you pass `-OutputPath`.

`Invoke-IRHunt.ps1` runs a whole phase and builds one consolidated report. It forwards only the
source parameters (`-ComputerName`, `-Credential`, `-Path`, `-InputPath`, `-StartTime`, `-EndTime`,
`-MaxEvents`) plus `-DomainController` to tools that accept it, and filters the report with
`-MinimumSeverity`. Tool-specific tuning parameters are never forwarded - run the tool directly for
those.

## Credential theft and Kerberos abuse

| Tool | Detects | ATT&CK |
|---|---|---|
| [Find-Kerberoasting](Find-Kerberoasting.md) | RC4 / high-volume service-ticket roasting, honeypot SPN hits, AES opsec roasting | T1558.003 |
| [Find-ASREPRoasting](Find-ASREPRoasting.md) | Pre-auth-disabled AS-REP roasting sweeps and user enumeration | T1558.004 |
| [Find-KerberosTicketAnomaly](Find-KerberosTicketAnomaly.md) | Forged / stolen tickets: RC4 downgrade and overpass-the-hash, TGS-without-TGT, krbtgt-as-client, realm anomalies | T1558.001/.002, T1550.003 |
| [Find-PasswordSpray](Find-PasswordSpray.md) | Distinct-account failure bursts per source, spray-then-success, distributed low-and-slow sprays | T1110.003 |
| [Find-NTLMRelay](Find-NTLMRelay.md) | Coerced machine-account NTLM logons, relay / harvest bursts, NTLMv1 downgrade | T1557.001 |
| [Find-SkeletonKey](../../../Tools/AD/Find-SkeletonKey.ps1) | Kerberos RC4 downgrade burst, LSASS sensitive-privilege use, suspicious service / driver installs, per-DC correlation | T1556.001 |

Find-SkeletonKey is documented in its comment-based help rather than a page here - run
`Get-Help .\Tools\AD\Find-SkeletonKey.ps1 -Full` for its rules, audit policy, parameters and examples.

## Persistence and privilege escalation

| Tool | Detects | ATT&CK |
|---|---|---|
| [Find-PrivilegedGroupChange](Find-PrivilegedGroupChange.md) | Privileged-group adds / removes, rapid add-then-remove elevation | T1098, T1078.002 |
| [Find-DelegationAbuse](Find-DelegationAbuse.md) | Unconstrained / constrained / RBCD delegation changes | T1558.003, T1134, T1484 |
| [Find-ShadowCredentials](Find-ShadowCredentials.md) | msDS-KeyCredentialLink writes, add-then-PKINIT correlation | T1556, T1098.001 |
| [Find-ADCSAbuse](Find-ADCSAbuse.md) | Certificate attacks: ESC1 SAN abuse, ESC2/ESC3 on-behalf-of issuance, template tampering, ESC7 CA ACL grants, cert-logon impersonation, KDC weak mappings, ESC14 | T1649 |
| [Find-SIDHistoryInjection](Find-SIDHistoryInjection.md) | Privileged SIDs injected into sIDHistory | T1134.005 |
| [Find-GPOAbuse](Find-GPOAbuse.md) | GPO CSE / ACL / gPLink changes, new GPOs, SYSVOL policy-file writes | T1484.001 |
| [Find-GoldenGMSA](Find-GoldenGMSA.md) | KDS root key reads by non-DCs, gMSA managed-password retrieval | T1555 |

## Domain-controller and domain-integrity attacks

| Tool | Detects | ATT&CK |
|---|---|---|
| [Find-DCSync](Find-DCSync.md) | Directory-replication credential theft by non-DC principals | T1003.006 |
| [Find-DCShadow](Find-DCShadow.md) | Rogue DC registration: DRS/GC SPN adds, transient nTDSDSA objects, replication push rights | T1207 |
| [Find-ZerologonActivity](Find-ZerologonActivity.md) | Anonymous machine-account password resets, vulnerable Netlogon secure channels | T1210 / CVE-2020-1472 |
| [Find-TrustAbuse](Find-TrustAbuse.md) | Trust creation / modification, SID-filtering and TGT-delegation weakening | T1484.002, T1134.005 |

## Reconnaissance and readiness

| Tool | Detects | ATT&CK |
|---|---|---|
| [Find-ADReconnaissance](Find-ADReconnaissance.md) | BloodHound / SharpHound LDAP recon, mass and multi-host group enumeration, recon tooling | T1087.002, T1069.002, T1482 |
| [Get-IRAuditReadiness](Get-IRAuditReadiness.md) | Audit-policy and log-posture gaps that would blind the detections above | n/a |

---
Part of IRToolKit.
