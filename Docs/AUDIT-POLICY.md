# Audit policy and logging requirements

The detections only work if the events exist. This is what to enable, and where. Run
`Tools\Get-IRAuditReadiness.ps1` (elevated, on the host you will hunt - usually a domain controller)
for a per-host report of the gaps.

Prefer configuring these through Group Policy (Computer Configuration > Policies > Windows Settings >
Security Settings > Advanced Audit Policy Configuration) so they apply consistently to all DCs. The
`auditpol` commands below set the local policy on one host for quick testing.

## Domain controllers (most AD detections read DC logs)

| Subcategory | Needed by | Command |
|---|---|---|
| Kerberos Authentication Service (Success, Failure) | Find-ASREPRoasting, Find-KerberosTicketAnomaly, Find-PasswordSpray | `auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable` |
| Kerberos Service Ticket Operations (Success) | Find-Kerberoasting, Find-KerberosTicketAnomaly | `auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable` |
| Directory Service Access (Success) | Find-DCSync, Find-ADCSAbuse | `auditpol /set /subcategory:"Directory Service Access" /success:enable` |
| Directory Service Changes (Success) | Find-DelegationAbuse, Find-ShadowCredentials, Find-ADCSAbuse | `auditpol /set /subcategory:"Directory Service Changes" /success:enable` |
| Security Group Management (Success) | Find-PrivilegedGroupChange | `auditpol /set /subcategory:"Security Group Management" /success:enable` |
| User Account Management (Success) | Find-DelegationAbuse, account-change detections | `auditpol /set /subcategory:"User Account Management" /success:enable` |
| Computer Account Management (Success) | Find-DelegationAbuse | `auditpol /set /subcategory:"Computer Account Management" /success:enable` |
| Logon / Logoff (Success, Failure) | Find-PasswordSpray (4624/4625) | `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` |
| Credential Validation (Success, Failure) | spray/brute (4776) | `auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable` |

### SACL for Directory Service Access / Changes (required for 4662 and 5136)

Enabling the subcategory is not enough; the objects must have an audit ACE. For DCSync (4662) and
attribute-change (5136) coverage, set auditing on the domain head so changes/accesses are recorded:

- In ADSI Edit or AD Users & Computers (Advanced Features), open the domain root (or the naming context)
  Security > Advanced > Auditing, and add an entry for **Everyone** auditing **"Replicating Directory
  Changes" / "All extended rights"** (for 4662) and **Write / Create / Delete** of the relevant
  properties (for 5136), applied to this object and descendants.
- 5136 "Directory Service Changes" only logs attributes whose schema has auditing in effect; the domain
  head SACL plus the subcategory is the usual baseline.

## Member servers / workstations / CA

| Subcategory / setting | Needed by | Where |
|---|---|---|
| PowerShell Script Block Logging (event 4104) | tooling-signature rules in several tools | GPO: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging. Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1` |
| Certification Services auditing (4886/4887) | Find-ADCSAbuse | On the CA: `certutil -setreg CA\AuditFilter 127` then restart CertSvc, and enable the "Certification Services" subcategory under Object Access |
| Sysmon Operational | future execution/lateral tools | Install Sysmon with a tuned config; the kit reads `Microsoft-Windows-Sysmon/Operational` |

## Log size and retention

Raise the Security log well above the default (1 MB can roll in minutes on a busy DC). A practical
baseline:

```powershell
wevtutil sl Security /ms:1073741824          # 1 GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456   # 256 MB
```

Forward events to a SIEM or WEC collector for real retention; the kit can read exported `.evtx` from
the collector offline.

## Quick check

```powershell
auditpol /get /category:* | findstr /i "Kerberos Directory Group Logon"
.\Tools\Get-IRAuditReadiness.ps1 -OutputPath C:\Evidence\Readiness -Format Html
```
