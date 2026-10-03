# IRToolKit coverage matrix

Detection coverage across the attack chain. The Active Directory phase is the current delivery; the
other phases list the planned tools so the kit can grow to cover the full chain with the same
framework, finding schema, and test harness.

Legend: **[done]** shipped and tested, **[planned]** designed, not yet built.

## Active Directory / identity (delivered)

| Status | Tool | ATT&CK | Primary events | Notes |
|---|---|---|---|---|
| done | Find-Kerberoasting | T1558.003 | 4769, 4104 | RC4/volume bursts, honeypot SPNs, AES opsec roasting, AD enrichment |
| done | Find-ASREPRoasting | T1558.004 | 4768, 4104 | PreAuth=0 roast sweeps, user enumeration (0x6), honeypot |
| done | Find-DCSync | T1003.006 | 4662, 4104 | Replication rights by non-DC; DC + sync-account exclusion |
| done | Find-KerberosTicketAnomaly | T1558.001/.002, T1550.003 | 4768, 4769 | RC4 downgrade, TGS-without-TGT, krbtgt-as-client, realm mismatch |
| done | Find-PasswordSpray | T1110.003 | 4625, 4771, 4768, 4624 | Distinct-target bursts per source; spray-then-success |
| done | Find-PrivilegedGroupChange | T1098, T1078.002 | 4728/4732/4756, 4729/4733/4757 | Privileged group adds/removes; stealth add-then-remove |
| done | Find-DelegationAbuse | T1558.003, T1134, T1484 | 5136, 4742, 4738 | Unconstrained, constrained+protocol-transition, RBCD |
| done | Find-ShadowCredentials | T1556, T1098.001 | 5136, 4768, 4104 | msDS-KeyCredentialLink writes; add-then-PKINIT |
| done | Find-ADCSAbuse | T1649 | 4886/4887, 5136, 4768, 4104 | ESC1 SAN, dangerous template changes, cert-logon anomaly, ESC14 |
| done | Find-NTLMRelay | T1557.001 | 4624, 4625, 4776, 4104 | Relayed/coerced machine accounts, NTLM harvesting bursts, NTLMv1 downgrade, relay/coercion tooling |
| done | Get-IRAuditReadiness | n/a | auditpol, log metadata | Logging-posture gaps for the above |
| done | Find-DCShadow | T1207 | 4742, 5137, 5141, 4662, 4104 | Rogue DC registration (DRS/GC SPN add, transient nTDSDSA create/delete, replication push rights, tooling) |
| done | Find-ZerologonActivity | T1210 / CVE-2020-1472 | 4742, 5805, 5827-5831, 4104 | Anonymous machine-account password reset, vulnerable Netlogon channel (denied/allowed), auth-failure burst, tooling |
| done | Find-GoldenGMSA | T1555 | 4662, 5136, 4104 | KDS root key read by a non-DC, gMSA managed-password retrieval, retrieval-principal changes, tooling |
| done | Find-SIDHistoryInjection | T1134.005 | 4765, 4766, 4738, 4742, 5136, 4104 | Privileged SID injected into sIDHistory (4765/5136/4738), failed attempts, tooling |
| done | Find-ADReconnaissance | T1087.002, T1069.002, T1482 | 1644, 4798, 4799, 4688, 4104 | BloodHound/SharpHound LDAP recon, mass group enumeration, recon tooling & processes |
| done | Find-GPOAbuse | T1484.001 | 5136, 5137, 5145, 4663, 4688, 4104 | GPO CSE/ACL/gPLink changes, new GPOs, SYSVOL policy-file writes, GPO-abuse tooling |
| done | Find-SkeletonKey | T1556.001 | 4768, 4673, 7045, 4697, 4104, 4688 | Kerberos RC4 downgrade burst (master-password tell), LSASS sensitive-privilege use, suspicious driver/service install, credential-tool signatures, multi-signal DC correlation |
| done | Find-TrustAbuse | T1484.002, T1134.005 | 4706, 4707, 4716, 4865-4867, 5136, 4688, 4104 | Trust create/modify/remove, SID-filtering / treat-as-external weakening (cross-forest SID-history enabler), trust-key tooling |

## Initial access / execution / persistence / the rest of the chain (planned)

These reuse the same module, finding schema, source modes, and test harness. Planned tools by phase:

| Phase | Planned tools | Key events / sources |
|---|---|---|
| Initial Access (TA0001) | Find-PhishingExecution, Find-ExternalRemoteServices | 4688, Sysmon 1, 4624 type 10, VPN logs |
| Execution (TA0002) | Find-SuspiciousPowerShell, Find-LOLBinExecution, Find-WmiExecution, Find-ScheduledTaskExec | 4104, 4103, 4688, Sysmon 1, WMI-Activity 5857-5861 |
| Persistence (TA0003) | Find-ServicePersistence, Find-ScheduledTaskPersistence, Find-RegistryRunKeys, Find-WmiSubscription | 7045, 4697, 4698/4702, 13 (Sysmon), 19/20/21 (Sysmon) |
| Privilege Escalation (TA0004) | Find-TokenManipulation, Find-UacBypass, Find-NamedPipeImpersonation | 4673, 4674, 4688, Sysmon 1/17/18 |
| Defense Evasion (TA0005) | Find-LogClearing, Find-AuditPolicyTamper, Find-DefenderTamper, Find-Timestomping | 1102, 104, 4719, 4907, Defender 5001/5007, Sysmon 2 |
| Credential Access (TA0006) | Find-LsassAccess, Find-SamDump, Find-DpapiAbuse, Find-CredentialInFiles | Sysmon 10, 4656/4663 on SAM, 4688, 4104 |
| Discovery (TA0007) | Find-HostRecon, Find-AccountDiscovery, Find-ShareEnumeration | 4688, 5140/5145, 4798/4799 |
| Lateral Movement (TA0008) | Find-RemoteService, Find-PsExec, Find-RdpLateral, Find-WinRmLateral | 4624 type 3/10, 7045, 5140, WinRM 91/168 |
| Collection (TA0009) | Find-StagingArchive, Find-ClipboardScreenCapture | Sysmon 11, 4663, 4688 |
| C2 (TA0011) | Find-BeaconPattern, Find-DnsTunneling, Find-SuspiciousOutbound | Sysmon 3/22, 5156, DNS-Client 3008 |
| Exfiltration (TA0010) | Find-LargeTransfer, Find-CloudUpload | Sysmon 3, 5156, proxy logs |
| Impact (TA0040) | Find-RansomwareActivity, Find-ShadowCopyDeletion, Find-BcdTamper | 4688, Sysmon 1, 524 (backup), 13 |

## How a new phase is added

1. Create `Tools/<Phase>/` and copy `Templates/Find-Template.ps1` for each tool.
2. Add any shared decoders/reference tables to `Common/IRToolKit.Common.psm1` (keep it 5.1-safe).
3. Add sample data and a test per tool under `Tests/`.
4. `Invoke-IRHunt.ps1 -Phase <Phase>` runs them and consolidates automatically (it discovers
   `Tools/<Phase>/Find-*.ps1`).
