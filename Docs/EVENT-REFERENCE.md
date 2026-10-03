# Event reference

The Windows events the AD detections rely on, with the fields that matter. Field names are the
`<Data Name="...">` elements as they appear on flattened `IRToolKit.Event` objects. Use the module
decoders (see `CONVENTIONS.md`) to translate hex/code fields.

## Kerberos (domain controllers, Security log)

### 4768 - Kerberos TGT requested (Authentication Service / AS-REQ)
Used by Find-ASREPRoasting, Find-KerberosTicketAnomaly, Find-PasswordSpray.
- `TargetUserName`, `TargetDomainName`, `TargetSid` - the account requesting a TGT.
- `ServiceName` - normally `krbtgt`.
- `TicketEncryptionType` - e.g. `0x17` RC4, `0x12` AES256. `0xffffffff` on failures.
- `PreAuthType` - `0` = no pre-authentication (AS-REP roastable); `2` = PA-ENC-TIMESTAMP (password);
  `15`/`16`/`17` = PKINIT / smart card. Only `0` on a *successful* ticket is the roastable condition.
- `Status` - `0x0` success; `0x6` principal unknown (enumeration); `0x18` bad password; `0x12` client revoked.
- `IpAddress`, `IpPort` - client source. `CertIssuerName` / `CertSerialNumber` / `CertThumbprint` on PKINIT.

### 4769 - Kerberos service ticket requested (TGS)
Used by Find-Kerberoasting, Find-KerberosTicketAnomaly.
- `TargetUserName` - the principal requesting the service ticket (often `user@REALM`).
- `ServiceName` - the service account / SPN the ticket is for; a computer account ends with `$`.
- `ServiceSid` - RID `502` is krbtgt.
- `TicketEncryptionType` - `0x17` RC4 is the Kerberoasting signal; `0x12` AES.
- `TicketOptions` - hex option flags (decode with ConvertFrom-IRTicketOptions).
- `Status` - `0x0` success. `IpAddress`, `IpPort`.

### 4770 - Kerberos service ticket renewed. 4771 - Kerberos pre-authentication failed.
4771 `Status 0x18` (bad password) is a key password-spray signal on DCs. Fields `TargetUserName`,
`Status`, `IpAddress`, `PreAuthType`, `TicketEncryptionType`.

## Logon (Security log)

### 4624 - successful logon / 4625 - failed logon
Used by Find-PasswordSpray and future lateral-movement tools.
- `TargetUserName`, `TargetDomainName` - account.
- `LogonType` - `2` interactive, `3` network, `9` NewCredentials (PtH/runas netonly), `10` RDP.
- `IpAddress`, `IpPort`, `WorkstationName` - source.
- 4625 `Status` / `SubStatus` - the precise failure (`0xc000006a` bad password, `0xc0000064` no such user,
  `0xc0000234` locked out). Decode with ConvertFrom-IRNtStatus.
- `SubjectUserName` - the account that requested the logon (often `-` or a machine account).
- 4776 (Credential Validation, NTLM) carries `TargetUserName` and an error code; useful for NTLM spray.

## Directory service (domain controllers, Security log)

### 4662 - operation performed on an AD object
Used by Find-DCSync, Find-ADCSAbuse.
- `SubjectUserName`, `SubjectUserSid`, `SubjectDomainName` - who performed it.
- `ObjectName` - the object DN (the domain head for DCSync).
- `ObjectType` - object class GUID. `OperationType`. `AccessMask` - `0x100` = ControlAccess (extended right).
- `Properties` - the extended-right / property GUIDs touched. DCSync: `1131f6aa-...` (Get-Changes),
  `1131f6ad-...` (Get-Changes-All), `89e95b76-...` (Get-Changes-In-Filtered-Set). Extract with
  Get-IRGuidsFromText, resolve with Resolve-IRGuidName.

### 5136 - a directory object was modified
Used by Find-DelegationAbuse, Find-ShadowCredentials, Find-ADCSAbuse.
- `ObjectDN`, `ObjectClass` - the modified object.
- `AttributeLDAPDisplayName` - the attribute changed (e.g. `msDS-AllowedToActOnBehalfOfOtherIdentity`,
  `msDS-KeyCredentialLink`, `userAccountControl`, `servicePrincipalName`, `altSecurityIdentities`,
  `msPKI-Certificate-Name-Flag`).
- `AttributeValue` - the new value (for userAccountControl this is the LDAP bit value - decode with
  ConvertFrom-IRLdapUac, NOT the SAM decoder).
- `OperationType` - `%%14674` Value Added, `%%14675` Value Deleted.
- `SubjectUserName` - the actor. (5137 object created, 5139 moved, 5141 deleted.)

## Account management (Security log)

### 4720/4722/4723/4724/4725/4726/4738 - user account lifecycle
4738 (user changed) and 4741/4742 (computer created/changed) carry `OldUacValue` / `NewUacValue`
(SAM USER_* flags - decode with ConvertFrom-IRSamUac / Compare-IRSamUac, NOT the LDAP decoder) and a
`UserAccountControl` text field of `%%21xx` change tokens (ConvertFrom-IRUacChangeString). 4742 also
carries `AllowedToDelegateTo` and `ServicePrincipalNames`.

### Group membership
- Global group member added `4728` / removed `4729`.
- Local (builtin) group member added `4732` / removed `4733`.
- Universal group member added `4756` / removed `4757`.
Fields: `TargetUserName` (the GROUP), `TargetSid` (group SID - RID 512 Domain Admins, 519 Enterprise
Admins, 518 Schema Admins; S-1-5-32-544 builtin Administrators), `MemberName` (member DN), `MemberSid`,
`SubjectUserName` (actor). Use Test-IRPrivilegedGroup.

## Certification Services (CA host, Security log)

- `4886` request received, `4887` certificate issued/approved. Fields vary; `Requester`, `Attributes`
  (may contain a Subject Alternative Name override for ESC1), `CertificateTemplate`, `RequestId`,
  `Disposition`, often with details only in the rendered Message (read with `-IncludeMessage`).
- `4899`/`4900` template or CA security changed.

## Netlogon (domain controllers, System log, source NETLOGON)

Used by Find-ZerologonActivity. These live in the **System** log, not Security, so pull it too.
- `5805` - a session setup from a computer failed to authenticate; the referenced account is in the
  rendered Message (e.g. `... the account(s) ... is DC01$`). A rapid burst for one machine account can
  precede a Zerologon reset.
- `5827` / `5828` - a vulnerable Netlogon secure-channel connection from a machine / trust account was
  DENIED (hardening in enforcement). `5829` - a vulnerable connection was ALLOWED (enforcement off).
  `5830` / `5831` - allowed by the group-policy exception list. The machine account is in the Message
  (read with `-IncludeMessage`); these events only exist with the Aug-2020+ Netlogon update installed.
- The Zerologon password reset itself surfaces as Security `4742` where a computer account's password is
  changed by `ANONYMOUS LOGON` (SubjectUserSid `S-1-5-7`).

## PowerShell (Operational log)

### 4104 - script block logging
Used by every tool's tooling-signature rule. `ScriptBlockText` holds the executed script; match against
known offensive tool names (Rubeus, Invoke-Mimikatz, Certify/Certipy, Whisker, Invoke-Kerberoast, etc.).
`Path`, `ScriptBlockId`. Requires Script Block Logging enabled (see AUDIT-POLICY.md). 4103 is module
logging (pipeline execution detail).

## Other

- `1102` Security log cleared; `104` other log cleared (defense evasion).
- `4719` system audit policy changed; `4907` auditing settings on object changed.
- `7045` new service installed; `4697` service installed (Security).
- Sysmon Operational: `1` process create, `3` network connect, `7` image load, `8` CreateRemoteThread,
  `10` process access (LSASS), `11` file create, `13` registry set, `22` DNS query.
