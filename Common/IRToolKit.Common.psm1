#Requires -Version 5.1
<#
.SYNOPSIS
    IRToolKit shared module - common helpers used by every tool in the kit.

.DESCRIPTION
    Provides a consistent layer for:
      * Collecting Windows events (live log, remote host, exported .evtx, or pre-parsed JSON/CSV)
      * Flattening EventRecord objects into simple PSCustomObjects (EventData fields become properties)
      * Building, displaying and exporting standardized findings (CSV / JSON / HTML)
      * Decoding Kerberos / logon / NTSTATUS / UAC / DS access-mask values
      * Reference tables (privileged groups, replication GUIDs, sensitive attributes, tool indicators)
      * Burst / sliding-window detection helpers
      * Active Directory look-ups that work without RSAT ([ADSI] / System.DirectoryServices)

    Everything here must stay compatible with Windows PowerShell 5.1 AND PowerShell 7+.
    No ternary operators, no null-coalescing, no ForEach-Object -Parallel, ASCII only.
#>

Set-StrictMode -Off
$script:IRQuiet = $false
$script:IRDomainControllerCache = $null
$script:IRSchemaGuidCache = @{}

#region ---------------------------------------------------------------- Reference tables

$script:IRSeverityRank = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Informational' = 1 }

$script:IRKerberosEncryptionTypes = @{
    '0x1'        = 'DES-CBC-CRC'
    '0x3'        = 'DES-CBC-MD5'
    '0x11'       = 'AES128-CTS-HMAC-SHA1-96'
    '0x12'       = 'AES256-CTS-HMAC-SHA1-96'
    '0x13'       = 'AES256-CTS-HMAC-SHA384-192'
    '0x14'       = 'AES128-CTS-HMAC-SHA256-128'
    '0x17'       = 'RC4-HMAC'
    '0x18'       = 'RC4-HMAC-EXP'
    '0xffffffff' = 'Failure (no ticket issued)'
}

$script:IRKerberosPreAuthTypes = @{
    '0'   = 'None (logon without pre-authentication)'
    '2'   = 'PA-ENC-TIMESTAMP (password)'
    '11'  = 'PA-ETYPE-INFO'
    '15'  = 'PA-PK-AS-REP_OLD (smart card / certificate)'
    '16'  = 'PA-PK-AS-REQ (smart card / certificate - PKINIT)'
    '17'  = 'PA-PK-AS-REP (smart card / certificate)'
    '19'  = 'PA-ETYPE-INFO2'
    '20'  = 'PA-SVR-REFERRAL-INFO'
    '138' = 'PA-ENCRYPTED-CHALLENGE (FAST armoring)'
    '-'   = 'Not applicable'
}

$script:IRKerberosStatusCodes = @{
    '0x0'  = 'KDC_ERR_NONE (success)'
    '0x1'  = 'KDC_ERR_NAME_EXP (client expired)'
    '0x2'  = 'KDC_ERR_SERVICE_EXP (server expired)'
    '0x3'  = 'KDC_ERR_BAD_PVNO'
    '0x6'  = 'KDC_ERR_C_PRINCIPAL_UNKNOWN (client not found - user does not exist)'
    '0x7'  = 'KDC_ERR_S_PRINCIPAL_UNKNOWN (server/SPN not found)'
    '0x8'  = 'KDC_ERR_PRINCIPAL_NOT_UNIQUE'
    '0x9'  = 'KDC_ERR_NULL_KEY'
    '0xa'  = 'KDC_ERR_CANNOT_POSTDATE'
    '0xb'  = 'KDC_ERR_NEVER_VALID'
    '0xc'  = 'KDC_ERR_POLICY (logon hours / workstation restriction / policy)'
    '0xd'  = 'KDC_ERR_BADOPTION (often: delegation not allowed - S4U2Proxy failure)'
    '0xe'  = 'KDC_ERR_ETYPE_NOTSUPP (encryption type not supported)'
    '0xf'  = 'KDC_ERR_SUMTYPE_NOSUPP'
    '0x10' = 'KDC_ERR_PADATA_TYPE_NOSUPP (PKINIT / smart card not supported)'
    '0x11' = 'KDC_ERR_TRTYPE_NO_SUPP'
    '0x12' = 'KDC_ERR_CLIENT_REVOKED (account disabled / locked / expired)'
    '0x13' = 'KDC_ERR_SERVICE_REVOKED'
    '0x14' = 'KDC_ERR_TGT_REVOKED'
    '0x15' = 'KDC_ERR_CLIENT_NOTYET'
    '0x16' = 'KDC_ERR_SERVICE_NOTYET'
    '0x17' = 'KDC_ERR_KEY_EXPIRED (password expired)'
    '0x18' = 'KDC_ERR_PREAUTH_FAILED (bad password)'
    '0x19' = 'KDC_ERR_PREAUTH_REQUIRED (normal first AS exchange)'
    '0x1a' = 'KDC_ERR_SERVER_NOMATCH'
    '0x1b' = 'KDC_ERR_MUST_USE_USER2USER'
    '0x1f' = 'KRB_AP_ERR_BAD_INTEGRITY'
    '0x20' = 'KRB_AP_ERR_TKT_EXPIRED'
    '0x21' = 'KRB_AP_ERR_TKT_NYV'
    '0x22' = 'KRB_AP_ERR_REPEAT (replay)'
    '0x23' = 'KRB_AP_ERR_NOT_US'
    '0x24' = 'KRB_AP_ERR_BADMATCH'
    '0x25' = 'KRB_AP_ERR_SKEW (clock skew too great)'
    '0x26' = 'KRB_AP_ERR_BADADDR'
    '0x27' = 'KRB_AP_ERR_BADVERSION'
    '0x28' = 'KRB_AP_ERR_MSG_TYPE'
    '0x29' = 'KRB_AP_ERR_MODIFIED'
    '0x2a' = 'KRB_AP_ERR_BADORDER'
    '0x2c' = 'KRB_AP_ERR_BADKEYVER'
    '0x2d' = 'KRB_AP_ERR_NOKEY'
    '0x2e' = 'KRB_AP_ERR_MUT_FAIL'
    '0x2f' = 'KRB_AP_ERR_BADDIRECTION'
    '0x30' = 'KRB_AP_ERR_METHOD'
    '0x31' = 'KRB_AP_ERR_BADSEQ'
    '0x32' = 'KRB_AP_ERR_INAPP_CKSUM'
    '0x33' = 'KRB_AP_PATH_NOT_ACCEPTED'
    '0x34' = 'KRB_ERR_RESPONSE_TOO_BIG'
    '0x3c' = 'KRB_ERR_GENERIC'
    '0x3d' = 'KRB_ERR_FIELD_TOOLONG'
    '0x3e' = 'KDC_ERR_CLIENT_NOT_TRUSTED'
    '0x3f' = 'KDC_ERR_KDC_NOT_TRUSTED'
    '0x40' = 'KDC_ERR_INVALID_SIG'
    '0x41' = 'KDC_ERR_KEY_TOO_WEAK'
    '0x42' = 'KRB_AP_ERR_USER_TO_USER_REQUIRED'
    '0x43' = 'KRB_AP_ERR_NO_TGT'
    '0x44' = 'KDC_ERR_WRONG_REALM'
}

$script:IRLogonTypes = @{
    '0'  = 'System'
    '2'  = 'Interactive'
    '3'  = 'Network'
    '4'  = 'Batch'
    '5'  = 'Service'
    '7'  = 'Unlock'
    '8'  = 'NetworkCleartext'
    '9'  = 'NewCredentials (runas /netonly, pass-the-hash)'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive'
    '12' = 'CachedRemoteInteractive'
    '13' = 'CachedUnlock'
}

$script:IRNtStatusCodes = @{
    '0x0'        = 'STATUS_SUCCESS'
    '0xc000005e' = 'STATUS_NO_LOGON_SERVERS'
    '0xc0000064' = 'STATUS_NO_SUCH_USER (user name does not exist)'
    '0xc000006a' = 'STATUS_WRONG_PASSWORD'
    '0xc000006c' = 'STATUS_PASSWORD_RESTRICTION'
    '0xc000006d' = 'STATUS_LOGON_FAILURE (bad user name or password)'
    '0xc000006e' = 'STATUS_ACCOUNT_RESTRICTION'
    '0xc000006f' = 'STATUS_INVALID_LOGON_HOURS'
    '0xc0000070' = 'STATUS_INVALID_WORKSTATION'
    '0xc0000071' = 'STATUS_PASSWORD_EXPIRED'
    '0xc0000072' = 'STATUS_ACCOUNT_DISABLED'
    '0xc00000dc' = 'STATUS_INVALID_SERVER_STATE'
    '0xc0000133' = 'STATUS_TIME_DIFFERENCE_AT_DC'
    '0xc000015b' = 'STATUS_LOGON_TYPE_NOT_GRANTED'
    '0xc000018c' = 'STATUS_TRUSTED_DOMAIN_FAILURE'
    '0xc000018d' = 'STATUS_TRUSTED_RELATIONSHIP_FAILURE'
    '0xc0000192' = 'STATUS_NETLOGON_NOT_STARTED'
    '0xc0000193' = 'STATUS_ACCOUNT_EXPIRED'
    '0xc0000224' = 'STATUS_PASSWORD_MUST_CHANGE'
    '0xc0000225' = 'STATUS_NOT_FOUND'
    '0xc0000234' = 'STATUS_ACCOUNT_LOCKED_OUT'
    '0xc00002ee' = 'STATUS_UNFINISHED_CONTEXT_DELETED (error during logon)'
    '0xc0000413' = 'STATUS_AUTHENTICATION_FIREWALL_FAILED'
    '0xc000035b' = 'STATUS_BAD_TOKEN_TYPE / NTLM negotiation failure'
}

# SAM USER_* account control flags as used in the hex OldUacValue / NewUacValue
# fields of 4720 / 4738 / 4741 / 4742 (NOT the LDAP userAccountControl bit layout).
$script:IRSamUacFlags = [ordered]@{
    0x00000001 = 'ACCOUNT_DISABLED'
    0x00000002 = 'HOME_DIRECTORY_REQUIRED'
    0x00000004 = 'PASSWORD_NOT_REQUIRED'
    0x00000008 = 'TEMP_DUPLICATE_ACCOUNT'
    0x00000010 = 'NORMAL_ACCOUNT'
    0x00000020 = 'MNS_LOGON_ACCOUNT'
    0x00000040 = 'INTERDOMAIN_TRUST_ACCOUNT'
    0x00000080 = 'WORKSTATION_TRUST_ACCOUNT'
    0x00000100 = 'SERVER_TRUST_ACCOUNT'
    0x00000200 = 'DONT_EXPIRE_PASSWORD'
    0x00000400 = 'ACCOUNT_AUTO_LOCKED'
    0x00000800 = 'ENCRYPTED_TEXT_PASSWORD_ALLOWED'
    0x00001000 = 'SMARTCARD_REQUIRED'
    0x00002000 = 'TRUSTED_FOR_DELEGATION'
    0x00004000 = 'NOT_DELEGATED'
    0x00008000 = 'USE_DES_KEY_ONLY'
    0x00010000 = 'DONT_REQUIRE_PREAUTH'
    0x00020000 = 'PASSWORD_EXPIRED'
    0x00040000 = 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'
    0x00080000 = 'NO_AUTH_DATA_REQUIRED'
    0x00100000 = 'PARTIAL_SECRETS_ACCOUNT'
    0x00200000 = 'USE_AES_KEYS'
}

# LDAP userAccountControl attribute bits (for AttributeValue in 5136 and for AD look-ups)
$script:IRLdapUacFlags = [ordered]@{
    0x00000001 = 'SCRIPT'
    0x00000002 = 'ACCOUNTDISABLE'
    0x00000008 = 'HOMEDIR_REQUIRED'
    0x00000010 = 'LOCKOUT'
    0x00000020 = 'PASSWD_NOTREQD'
    0x00000040 = 'PASSWD_CANT_CHANGE'
    0x00000080 = 'ENCRYPTED_TEXT_PWD_ALLOWED'
    0x00000100 = 'TEMP_DUPLICATE_ACCOUNT'
    0x00000200 = 'NORMAL_ACCOUNT'
    0x00000800 = 'INTERDOMAIN_TRUST_ACCOUNT'
    0x00001000 = 'WORKSTATION_TRUST_ACCOUNT'
    0x00002000 = 'SERVER_TRUST_ACCOUNT'
    0x00010000 = 'DONT_EXPIRE_PASSWORD'
    0x00020000 = 'MNS_LOGON_ACCOUNT'
    0x00040000 = 'SMARTCARD_REQUIRED'
    0x00080000 = 'TRUSTED_FOR_DELEGATION'
    0x00100000 = 'NOT_DELEGATED'
    0x00200000 = 'USE_DES_KEY_ONLY'
    0x00400000 = 'DONT_REQ_PREAUTH'
    0x00800000 = 'PASSWORD_EXPIRED'
    0x01000000 = 'TRUSTED_TO_AUTH_FOR_DELEGATION'
    0x04000000 = 'PARTIAL_SECRETS_ACCOUNT'
}

# The %%21xx strings that appear in the "UserAccountControl" text field of 4720/4738/4741/4742
$script:IRUacChangeStrings = @{
    '%%2080' = 'Account Enabled'
    '%%2082' = 'Account Disabled'
    '%%2084' = "'Home Directory Required' - Enabled"
    '%%2085' = "'Home Directory Required' - Disabled"
    '%%2086' = "'Password Not Required' - Enabled"
    '%%2087' = "'Password Not Required' - Disabled"
    '%%2088' = "'Temp Duplicate Account' - Enabled"
    '%%2089' = "'Temp Duplicate Account' - Disabled"
    '%%2090' = "'Normal Account' - Enabled"
    '%%2091' = "'Normal Account' - Disabled"
    '%%2092' = "'MNS Logon Account' - Enabled"
    '%%2093' = "'MNS Logon Account' - Disabled"
    '%%2094' = "'Interdomain Trust Account' - Enabled"
    '%%2095' = "'Interdomain Trust Account' - Disabled"
    '%%2096' = "'Workstation Trust Account' - Enabled"
    '%%2097' = "'Workstation Trust Account' - Disabled"
    '%%2098' = "'Server Trust Account' - Enabled"
    '%%2099' = "'Server Trust Account' - Disabled"
    '%%2100' = "'Don't Expire Password' - Enabled"
    '%%2101' = "'Don't Expire Password' - Disabled"
    '%%2102' = "'Smartcard Required' - Enabled"
    '%%2103' = "'Smartcard Required' - Disabled"
    '%%2104' = "'Trusted For Delegation' - Enabled"
    '%%2105' = "'Trusted For Delegation' - Disabled"
    '%%2106' = "'Not Delegated' - Enabled"
    '%%2107' = "'Not Delegated' - Disabled"
    '%%2108' = "'Use DES Key Only' - Enabled"
    '%%2109' = "'Use DES Key Only' - Disabled"
    '%%2110' = "'Don't Require Preauth' - Enabled"
    '%%2111' = "'Don't Require Preauth' - Disabled"
    '%%2112' = "'Password Expired' - Enabled"
    '%%2113' = "'Password Expired' - Disabled"
    '%%2114' = "'Trusted To Authenticate For Delegation' - Enabled"
    '%%2115' = "'Trusted To Authenticate For Delegation' - Disabled"
    '%%2116' = "'Partial Secrets Account' - Enabled"
    '%%2117' = "'Partial Secrets Account' - Disabled"
    '%%2118' = "'Use AES Keys' - Enabled"
    '%%2119' = "'Use AES Keys' - Disabled"
}

# Directory Service (Active Directory object) access mask bits (4662 / 4661 / 4670 AccessMask)
$script:IRDsAccessMask = [ordered]@{
    0x00000001 = 'CreateChild'
    0x00000002 = 'DeleteChild'
    0x00000004 = 'ListChildren'
    0x00000008 = 'Self (validated write)'
    0x00000010 = 'ReadProperty'
    0x00000020 = 'WriteProperty'
    0x00000040 = 'DeleteTree'
    0x00000080 = 'ListObject'
    0x00000100 = 'ControlAccess (extended right)'
    0x00010000 = 'Delete'
    0x00020000 = 'ReadControl'
    0x00040000 = 'WriteDacl'
    0x00080000 = 'WriteOwner'
    0x00100000 = 'Synchronize'
    0x01000000 = 'AccessSystemSecurity'
    0x10000000 = 'GenericAll'
    0x20000000 = 'GenericExecute'
    0x40000000 = 'GenericWrite'
    0x80000000 = 'GenericRead'
}

# Kerberos ticket option bits as documented for events 4768/4769/4770 (bit 0 = MSB)
$script:IRTicketOptionBits = [ordered]@{
    0  = 'Reserved'
    1  = 'Forwardable'
    2  = 'Forwarded'
    3  = 'Proxiable'
    4  = 'Proxy'
    5  = 'Allow-postdate'
    6  = 'Postdated'
    7  = 'Invalid'
    8  = 'Renewable'
    9  = 'Initial'
    10 = 'Pre-authent'
    11 = 'Opt-hardware-auth'
    12 = 'Transited-policy-checked'
    13 = 'Ok-as-delegate'
    14 = 'Request-anonymous'
    15 = 'Name-canonicalize'
    26 = 'Disable-transited-check'
    27 = 'Renewable-ok'
    28 = 'Enc-tkt-in-skey'
    30 = 'Renew'
    31 = 'Validate'
}

# Extended-right / property-set GUIDs that matter for DCSync and other abuses (4662 Properties field)
$script:IRReplicationRightGuids = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Monitor-Topology'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
}

# Other well-known attribute / right GUIDs useful when decoding 4662 Properties
$script:IRWellKnownGuids = @{
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password (extended right)'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password (extended right)'
    '00000000-0000-0000-0000-000000000000' = 'All (GenericAll / entire object)'
    'e362ed86-b728-0842-b27d-2dea7a9df218' = 'msDS-ManagedPassword (gMSA password blob)'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink (Shadow Credentials)'
    '800d94d7-b7a1-42a1-b14d-7cae1423d07f' = 'msDS-AllowedToDelegateTo'
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName'
    '17eb4278-d167-11d0-b002-0000f80367c1' = 'sIDHistory'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'member'
    'bf9679e4-0de6-11d0-a285-00aa003049e2' = 'nTSecurityDescriptor'
    'bf967a7f-0de6-11d0-a285-00aa003049e2' = 'unicodePwd'
    'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user (object class)'
    'bf967a86-0de6-11d0-a285-00aa003049e2' = 'computer (object class)'
    'bf967a9c-0de6-11d0-a285-00aa003049e2' = 'group (object class)'
    '19195a5a-6da0-11d0-afd3-00c04fd930c9' = 'domainDNS (object class)'
    'bf967aa5-0de6-11d0-a285-00aa003049e2' = 'organizationalUnit (object class)'
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1' = 'groupPolicyContainer (object class)'
    'e5209ca2-3bba-11d2-90cc-00c04fd91ab1' = 'pKICertificateTemplate (object class)'
    '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'dNSHostName'
    '3e0abfd0-126a-11d0-a060-00aa006c33ed' = 'sAMAccountName'
    '46a9b11d-60ae-405a-b7e8-ff8a58d456d2' = 'tokenGroups'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Account-Restrictions (property set)'
    '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Personal-Information (property set)'
    'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Email-Information / Public-Information (property set)'
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General-Information (property set)'
    '5f202010-79a5-11d0-9020-00c04fc2d4cf' = 'Logon-Information (property set)'
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Group-Membership (property set)'
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8' = 'Private-Information (property set)'
    'ea1b7b93-5e48-46d5-bc6c-4df4fda78a35' = 'msDS-GroupMSAMembership'
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939' = 'Apply-Group-Policy (extended right)'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate (extended right)'
    'e2a36dc9-ae17-47c3-b58b-be34c55ba633' = 'Create-Inbound-Forest-Trust (extended right)'
    'ba33815a-4f93-4c76-87f3-57574bff8109' = 'Migrate-SID-History (extended right)'
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment (extended right)'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment (extended right)'
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' = 'Run-Protect-Admin-Groups-Task (extended right)'
    '280f369c-67c7-438e-ae98-1d46f3c6f541' = 'Update-Password-Not-Required-Bit (extended right)'
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' = 'Unexpire-Password (extended right)'
    '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' = 'Reanimate-Tombstones (extended right)'
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' = 'Reanimate-Tombstones (extended right)'
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' = 'DS-Query-Self-Quota (extended right)'
    '5805bc62-bdc9-4428-a5e2-947b6d6e11d1' = 'msDS-Manage-Optional-Features? (extended right)'
    '1abd7cf8-0a99-4c0e-9c5d-18e03a4a7da3' = 'Read-Only-Replication-Secret-Synchronization (extended right)'
    '014bf69c-7b3b-11d1-85f6-08002be74fab' = 'Change-Domain-Master (extended right)'
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' = 'Change-Infrastructure-Master (extended right)'
    'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-PDC (extended right)'
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Rid-Master (extended right)'
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master (extended right)'
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Monitor-Topology (extended right)'
}

# Well-known privileged group RIDs (domain relative) and built-in SIDs
$script:IRPrivilegedGroupRids = @{
    '512' = 'Domain Admins'
    '516' = 'Domain Controllers'
    '517' = 'Cert Publishers'
    '518' = 'Schema Admins'
    '519' = 'Enterprise Admins'
    '520' = 'Group Policy Creator Owners'
    '521' = 'Read-only Domain Controllers'
    '522' = 'Cloneable Domain Controllers'
    '525' = 'Protected Users'
    '526' = 'Key Admins'
    '527' = 'Enterprise Key Admins'
    '498' = 'Enterprise Read-only Domain Controllers'
}
$script:IRPrivilegedBuiltinSids = @{
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicator'
    'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-556' = 'Network Configuration Operators'
    'S-1-5-32-557' = 'Incoming Forest Trust Builders'
    'S-1-5-32-560' = 'Windows Authorization Access Group'
    'S-1-5-32-562' = 'Distributed COM Users'
    # NOTE: IIS_IUSRS (S-1-5-32-568) is intentionally NOT listed - it is the IIS worker-process identity
    # group, not a privilege-escalation path, and IIS setup routinely adds IUSR (S-1-5-17) to it, which
    # generated benign "privileged group" findings on real DC logs.
    'S-1-5-32-569' = 'Cryptographic Operators'
    'S-1-5-32-573' = 'Event Log Readers'
    'S-1-5-32-574' = 'Certificate Service DCOM Access'
    'S-1-5-32-578' = 'Hyper-V Administrators'
    'S-1-5-32-579' = 'Access Control Assistance Operators'
    'S-1-5-32-580' = 'Remote Management Users'
    'S-1-5-32-582' = 'Storage Replica Administrators'
}
# Names that are privileged even when the RID is domain-specific (e.g. DnsAdmins)
$script:IRPrivilegedGroupNames = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
    'Server Operators', 'Print Operators', 'Backup Operators', 'Replicator', 'DnsAdmins',
    'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins', 'Cert Publishers',
    'Domain Controllers', 'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers',
    'Remote Desktop Users', 'Remote Management Users', 'Hyper-V Administrators',
    'Distributed COM Users', 'Event Log Readers', 'Certificate Service DCOM Access',
    'Protected Users', 'Incoming Forest Trust Builders', 'Cryptographic Operators',
    'Network Configuration Operators', 'Storage Replica Administrators', 'Exchange Trusted Subsystem',
    'Organization Management', 'Exchange Windows Permissions', 'Exchange Organization Administrators'
)

# AD attributes whose modification (5136) is interesting
$script:IRSensitiveAttributes = @{
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'Resource-based constrained delegation (RBCD) changed'
    'msDS-AllowedToDelegateTo'                 = 'Constrained delegation target list changed'
    'msDS-KeyCredentialLink'                   = 'Shadow Credentials (key credential) added'
    'userAccountControl'                       = 'userAccountControl changed (pre-auth / delegation / DES / enabled)'
    'servicePrincipalName'                     = 'SPN changed (targeted Kerberoasting / DCShadow / noPac)'
    'sAMAccountName'                           = 'sAMAccountName changed (noPac / impersonation)'
    'dNSHostName'                              = 'dNSHostName changed (Certifried)'
    'sIDHistory'                               = 'SID history changed'
    'nTSecurityDescriptor'                     = 'Object ACL (security descriptor) changed'
    'member'                                   = 'Group membership changed'
    'primaryGroupID'                           = 'Primary group changed (hidden group membership)'
    'adminCount'                               = 'adminCount changed'
    'scriptPath'                               = 'Logon script changed'
    'msDS-SupportedEncryptionTypes'            = 'Supported Kerberos encryption types changed (downgrade)'
    'msDS-GroupMSAMembership'                  = 'gMSA password retrieval principals changed'
    'altSecurityIdentities'                    = 'Certificate / explicit mapping changed (ESC14)'
    'userCertificate'                          = 'User certificate attribute changed'
    'gPLink'                                   = 'GPO link changed'
    'gPCFileSysPath'                           = 'GPO file system path changed'
    'gPCMachineExtensionNames'                 = 'GPO machine extensions changed'
    'gPCUserExtensionNames'                    = 'GPO user extensions changed'
    'versionNumber'                            = 'GPO version changed'
    'wellKnownObjects'                         = 'Well-known object container changed'
    'msPKI-Certificate-Name-Flag'              = 'Certificate template name flag changed (ESC1/ESC4)'
    'msPKI-Enrollment-Flag'                    = 'Certificate template enrollment flag changed (ESC4)'
    'pKIExtendedKeyUsage'                      = 'Certificate template EKU changed (ESC2/ESC4)'
    'msPKI-Certificate-Application-Policy'     = 'Certificate template application policy changed (ESC4)'
    'msPKI-RA-Signature'                       = 'Certificate template RA signature requirement changed'
    'ms-Mcs-AdmPwd'                            = 'LAPS (legacy) password attribute changed'
    'msLAPS-Password'                          = 'Windows LAPS password attribute changed'
    'msLAPS-EncryptedPassword'                 = 'Windows LAPS encrypted password attribute changed'
    'trustAttributes'                          = 'Trust attributes changed'
    'trustDirection'                           = 'Trust direction changed'
    'msDS-Behavior-Version'                    = 'Functional level changed'
    'dSHeuristics'                             = 'dSHeuristics changed (anonymous access / security hardening)'
    'ms-DS-MachineAccountQuota'                = 'MachineAccountQuota changed'
    'lockoutThreshold'                         = 'Lockout policy changed'
    'minPwdLength'                             = 'Password policy changed'
}

# Default DC-only service names that should never be kerberoasted targets
$script:IRKerberoastExcludedServices = @('krbtgt', 'kadmin/changepw')

#endregion

#region ---------------------------------------------------------------- Output / status helpers

function Set-IRQuiet {
    param([bool]$Quiet = $true)
    $script:IRQuiet = $Quiet
}

function Write-IRStatus {
    <#
    .SYNOPSIS  Writes a coloured status line to the host (suppressed when Set-IRQuiet $true).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Detail')][string]$Level = 'Info'
    )
    if ($script:IRQuiet) { return }
    $prefix = '[*]'; $color = 'Cyan'
    switch ($Level) {
        'Success' { $prefix = '[+]'; $color = 'Green' }
        'Warning' { $prefix = '[!]'; $color = 'Yellow' }
        'Error'   { $prefix = '[-]'; $color = 'Red' }
        'Detail'  { $prefix = '   '; $color = 'DarkGray' }
    }
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-IRToolHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Description,
        [string[]]$Technique
    )
    if ($script:IRQuiet) { return }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " IRToolKit :: $Name" -ForegroundColor White
    if ($Description) { Write-Host " $Description" -ForegroundColor Gray }
    if ($Technique) { Write-Host (" ATT&CK: " + ($Technique -join ', ')) -ForegroundColor Gray }
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

#endregion

#region ---------------------------------------------------------------- Event collection

function Get-IRWinEvent {
    <#
    .SYNOPSIS
        Wrapper around Get-WinEvent that handles ID chunking, "no events" conditions,
        multiple .evtx files, and remote hosts. Returns raw EventLogRecord objects.
    .PARAMETER LogName
        Live log/channel name (default Security). Ignored when -Path is used.
    .PARAMETER Path
        One or more .evtx files or directories containing .evtx files.
    .PARAMETER EventId
        Event IDs to retrieve. Automatically chunked (Get-WinEvent limits the ID list).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(ParameterSetName = 'Live')][string]$LogName = 'Security',
        [Parameter(ParameterSetName = 'Live')][string]$ComputerName,
        [Parameter(ParameterSetName = 'Live')][pscredential]$Credential,
        [Parameter(ParameterSetName = 'File', Mandatory)][string[]]$Path,
        [int[]]$EventId,
        [string]$ProviderName,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [long]$MaxEvents = 0
    )

    $hasStart = $PSBoundParameters.ContainsKey('StartTime')
    $hasEnd = $PSBoundParameters.ContainsKey('EndTime')

    # Resolve file list
    $files = @()
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        foreach ($p in $Path) {
            $resolved = $null
            try { $resolved = Resolve-Path -Path $p -ErrorAction Stop } catch { Write-IRStatus "Path not found: $p" -Level Error; continue }
            foreach ($r in $resolved) {
                $item = Get-Item -LiteralPath $r.Path
                if ($item.PSIsContainer) {
                    $files += Get-ChildItem -LiteralPath $item.FullName -Filter '*.evtx' -File | Select-Object -ExpandProperty FullName
                }
                else { $files += $item.FullName }
            }
        }
        if (-not $files) { Write-IRStatus 'No .evtx files to read.' -Level Warning; return }
    }

    # Chunk event IDs (Get-WinEvent FilterHashtable rejects long ID lists)
    $idChunks = @()
    if ($EventId -and $EventId.Count -gt 0) {
        $unique = @($EventId | Sort-Object -Unique)
        for ($i = 0; $i -lt $unique.Count; $i += 20) {
            $end = [Math]::Min($i + 19, $unique.Count - 1)
            $idChunks += , @($unique[$i..$end])
        }
    }
    else { $idChunks = @($null) }

    $targets = @()
    if ($PSCmdlet.ParameterSetName -eq 'File') { $targets = $files } else { $targets = @($LogName) }

    foreach ($target in $targets) {
        foreach ($chunk in $idChunks) {
            $fh = @{}
            if ($PSCmdlet.ParameterSetName -eq 'File') { $fh['Path'] = $target } else { $fh['LogName'] = $target }
            if ($chunk) { $fh['Id'] = $chunk }
            if ($ProviderName) { $fh['ProviderName'] = $ProviderName }
            if ($hasStart) { $fh['StartTime'] = $StartTime }
            if ($hasEnd) { $fh['EndTime'] = $EndTime }

            # SilentlyContinue with a LOCAL -ErrorVariable: this consumes the error record here so it
            # never propagates to a caller's -ErrorVariable (which would pollute a tool's error output).
            # We then inspect the captured record ourselves to emit a helpful warning. Using Stop/try-catch
            # or a bare SilentlyContinue would leak the record to the ancestor; -ErrorVariable contains it.
            $gwe = @{ FilterHashtable = $fh; ErrorAction = 'SilentlyContinue' }
            if ($MaxEvents -gt 0) { $gwe['MaxEvents'] = $MaxEvents }
            if ($PSCmdlet.ParameterSetName -eq 'Live') {
                if ($ComputerName) { $gwe['ComputerName'] = $ComputerName }
                if ($Credential) { $gwe['Credential'] = $Credential }
            }

            $desc = $target
            if ($chunk) { $desc += ' ids=' + ($chunk -join ',') }
            Write-Verbose "Get-WinEvent $desc"
            $gweErr = $null
            Get-WinEvent @gwe -ErrorVariable gweErr 2>$null
            foreach ($er in @($gweErr)) {
                $fq = [string]$er.FullyQualifiedErrorId
                $msg = [string]$er.Exception.Message
                if ($fq -like 'NoMatchingEventsFound*') { Write-Verbose "No events: $desc"; continue }
                if ($msg -match 'Access is denied|Attempted to perform an unauthorized operation') {
                    Write-Warning "Access denied reading $desc - run elevated (or as a member of Event Log Readers)."
                    continue
                }
                if ($msg -match 'The RPC server is unavailable') {
                    Write-Warning "Cannot reach $ComputerName (RPC unavailable). Check firewall 'Remote Event Log Management' rules."
                    continue
                }
                if ($fq -like 'NoMatchingLogsFound*' -or $msg -match 'There is not an event log') {
                    Write-Warning "Log/channel not found: $desc"
                    continue
                }
                Write-Warning ("Error reading {0}: {1}" -f $desc, $msg)
            }
        }
    }
}

function ConvertFrom-IRWinEvent {
    <#
    .SYNOPSIS
        Flattens an EventLogRecord into a PSCustomObject: base properties plus every
        EventData/UserData element as a top-level property (e.g. .TargetUserName).
    .PARAMETER IncludeMessage
        Also render the formatted message (slow - needs provider metadata).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord,
        [switch]$IncludeMessage
    )
    process {
        $o = [ordered]@{
            TimeCreated  = $EventRecord.TimeCreated
            EventId      = [int]$EventRecord.Id
            Computer     = $EventRecord.MachineName
            ProviderName = $EventRecord.ProviderName
            LogName      = $EventRecord.LogName
            RecordId     = $EventRecord.RecordId
            Level        = $EventRecord.Level
            Task         = $EventRecord.Task
            AuditResult  = $null
            ProcessIdSys = $EventRecord.ProcessId
            ActivityId   = $EventRecord.ActivityId
        }
        $kw = $EventRecord.Keywords
        if ($null -ne $kw) {
            if (($kw -band 0x20000000000000) -ne 0) { $o['AuditResult'] = 'Success' }
            elseif (($kw -band 0x10000000000000) -ne 0) { $o['AuditResult'] = 'Failure' }
        }

        $xml = $null
        try { $xml = [xml]$EventRecord.ToXml() } catch { Write-Verbose "ToXml failed for record $($EventRecord.RecordId): $($_.Exception.Message)" }
        if ($xml) {
            $ed = $xml.Event.EventData
            if ($ed) {
                $idx = 0
                foreach ($d in @($ed.ChildNodes)) {
                    $idx++
                    if ($d.LocalName -ne 'Data') {
                        # e.g. <Binary>
                        $o[$d.LocalName] = $d.InnerText
                        continue
                    }
                    $name = $null
                    if ($d.Attributes -and $d.Attributes['Name']) { $name = $d.Attributes['Name'].Value }
                    if (-not $name) { $name = "Data$idx" }
                    if ($o.Contains($name)) { $name = "EventData_$name" }
                    $o[$name] = $d.InnerText
                }
            }
            $ud = $xml.Event.UserData
            if ($ud) {
                foreach ($container in @($ud.ChildNodes)) {
                    foreach ($n in @($container.ChildNodes)) {
                        $name = $n.LocalName
                        if (-not $name) { continue }
                        if ($o.Contains($name)) { $name = "UserData_$name" }
                        $o[$name] = $n.InnerText
                    }
                }
            }
        }
        if ($IncludeMessage) {
            try { $o['Message'] = $EventRecord.FormatDescription() } catch { $o['Message'] = $null }
        }
        $obj = [pscustomobject]$o
        $obj.PSObject.TypeNames.Insert(0, 'IRToolKit.Event')
        $obj
    }
}

function Import-IREvents {
    <#
    .SYNOPSIS
        Loads previously exported / synthetic flattened events from JSON, CSV or CliXml and
        normalises TimeCreated to [datetime] and EventId to [int].
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = Resolve-Path -Path $Path -ErrorAction Stop
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($file in $resolved) {
        $ext = [IO.Path]::GetExtension($file.Path).ToLowerInvariant()
        $raw = $null
        switch ($ext) {
            '.json' { $raw = Get-Content -LiteralPath $file.Path -Raw -Encoding UTF8 | ConvertFrom-Json }
            '.csv'  { $raw = Import-Csv -LiteralPath $file.Path }
            '.xml'  { $raw = Import-Clixml -LiteralPath $file.Path }
            default { throw "Unsupported input file type '$ext' (use .json, .csv or .xml)" }
        }
        foreach ($r in @($raw)) {
            if ($null -eq $r) { continue }
            # JSON root may be { events: [...] }
            if ($r.PSObject.Properties['Events'] -and -not $r.PSObject.Properties['EventId']) {
                foreach ($e in @($r.Events)) { $all.Add((ConvertTo-IRNormalizedEvent $e)) }
            }
            else { $all.Add((ConvertTo-IRNormalizedEvent $r)) }
        }
    }
    $all.ToArray()
}

function ConvertTo-IRNormalizedEvent {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$InputObject)
    process {
        $o = $InputObject
        if ($o -is [hashtable] -or $o -is [System.Collections.Specialized.OrderedDictionary]) { $o = [pscustomobject]$o }
        $tc = $o.PSObject.Properties['TimeCreated']
        if ($tc -and $tc.Value -isnot [datetime]) {
            $parsed = ConvertTo-IRDateTime $tc.Value
            if ($null -ne $parsed) { $tc.Value = $parsed }
        }
        $eid = $o.PSObject.Properties['EventId']
        if ($eid -and $eid.Value -isnot [int]) {
            $tmp = 0
            if ([int]::TryParse([string]$eid.Value, [ref]$tmp)) { $eid.Value = $tmp }
        }
        elseif (-not $eid -and $o.PSObject.Properties['Id']) {
            $o | Add-Member -NotePropertyName EventId -NotePropertyValue ([int]$o.Id) -Force
        }
        if ($o.PSObject.TypeNames[0] -ne 'IRToolKit.Event') { $o.PSObject.TypeNames.Insert(0, 'IRToolKit.Event') }
        $o
    }
}

function ConvertTo-IRDateTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $s = [string]$Value
    if ($s -match '^\\?/Date\((-?\d+)\)\\?/$') {
        return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$matches[1]).LocalDateTime
    }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) {
        if ($dt.Kind -eq 'Utc') { return $dt.ToLocalTime() }
        return $dt
    }
    if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
    return $null
}

function Export-IREvents {
    <#
    .SYNOPSIS  Saves flattened events to JSON (ISO-8601 timestamps) so they can be re-imported anywhere.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Events,
        [Parameter(Mandatory)][string]$Path
    )
    begin { $buf = New-Object System.Collections.Generic.List[object] }
    process { foreach ($e in $Events) { $buf.Add($e) } }
    end {
        $out = foreach ($e in $buf) {
            $h = [ordered]@{}
            foreach ($p in $e.PSObject.Properties) {
                if ($p.Value -is [datetime]) { $h[$p.Name] = $p.Value.ToString('o') } else { $h[$p.Name] = $p.Value }
            }
            [pscustomobject]$h
        }
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        ConvertTo-Json -InputObject @($out) -Depth 6 | Out-File -LiteralPath $Path -Encoding UTF8
        Write-IRStatus "Exported $($buf.Count) events to $Path" -Level Success
    }
}

function New-IRSourceContext {
    <#
    .SYNOPSIS
        Builds the event-source context used by every tool from the tool's bound parameters.
        Modes: Live (local/remote log), File (.evtx), Object (pre-flattened events).
    .PARAMETER BoundParameters
        Pass $PSBoundParameters from the calling script.
    .PARAMETER InputObject
        Pre-flattened events collected from the pipeline by the calling script.
    .PARAMETER DefaultLookbackDays
        Lookback applied in Live mode when the caller did not pass -StartTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$BoundParameters,
        [object[]]$InputObject,
        [int]$DefaultLookbackDays = 7,
        [bool]$PipelineInput = $false
    )
    $ctx = [ordered]@{
        Mode         = 'Live'
        ComputerName = $null
        Credential   = $null
        Path         = @()
        Events       = $null
        StartTime    = $null
        EndTime      = $null
        MaxEvents    = 0
        Description  = ''
    }
    if ($BoundParameters.ContainsKey('ComputerName') -and $BoundParameters['ComputerName']) { $ctx.ComputerName = $BoundParameters['ComputerName'] }
    if ($BoundParameters.ContainsKey('Credential')) { $ctx.Credential = $BoundParameters['Credential'] }
    if ($BoundParameters.ContainsKey('MaxEvents')) { $ctx.MaxEvents = [long]$BoundParameters['MaxEvents'] }
    if ($BoundParameters.ContainsKey('StartTime')) { $ctx.StartTime = [datetime]$BoundParameters['StartTime'] }
    if ($BoundParameters.ContainsKey('EndTime')) { $ctx.EndTime = [datetime]$BoundParameters['EndTime'] }

    # Object mode is selected when the caller used -InputObject, piped anything in (even an empty
    # set from a filter that matched nothing - detected via $MyInvocation.ExpectingInput passed as
    # -PipelineInput), or supplied events directly. This prevents an empty pipeline from silently
    # falling back to scanning the live machine.
    $objectModeRequested = ($BoundParameters.ContainsKey('InputObject')) -or $PipelineInput -or ($InputObject -and $InputObject.Count -gt 0)
    if ($objectModeRequested) {
        $ctx.Mode = 'Object'
        if ($InputObject -and $InputObject.Count -gt 0) { $ctx.Events = @($InputObject | ConvertTo-IRNormalizedEvent) } else { $ctx.Events = @() }
        $ctx.Description = "$($ctx.Events.Count) pre-parsed events (pipeline / -InputObject)"
    }
    elseif ($BoundParameters.ContainsKey('InputPath') -and $BoundParameters['InputPath']) {
        $ctx.Mode = 'Object'
        $ctx.Events = @(Import-IREvents -Path $BoundParameters['InputPath'])
        $ctx.Description = "$($ctx.Events.Count) pre-parsed events from $($BoundParameters['InputPath'])"
    }
    elseif ($BoundParameters.ContainsKey('Path') -and $BoundParameters['Path']) {
        $ctx.Mode = 'File'
        $ctx.Path = @($BoundParameters['Path'])
        $ctx.Description = 'EVTX file(s): ' + ($ctx.Path -join ', ')
    }
    else {
        $ctx.Mode = 'Live'
        if (-not $ctx.StartTime -and $DefaultLookbackDays -gt 0) { $ctx.StartTime = (Get-Date).AddDays(-1 * $DefaultLookbackDays) }
        $host_ = $ctx.ComputerName
        if (-not $host_) { $host_ = $env:COMPUTERNAME + ' (local)' }
        $ctx.Description = "Live event log on $host_"
    }
    $o = [pscustomobject]$ctx
    $o.PSObject.TypeNames.Insert(0, 'IRToolKit.SourceContext')
    $o
}

function Get-IRSourceEvents {
    <#
    .SYNOPSIS
        Retrieves flattened events for a tool regardless of source mode.
    .PARAMETER LogName
        Channel to read in Live mode and to filter on (when the LogName property exists) in File/Object modes.
    .PARAMETER EventId
        Event IDs to retrieve.
    .PARAMETER ProviderName
        Optional provider filter (e.g. Microsoft-Windows-Sysmon).
    .PARAMETER NoLogNameFilter
        In File/Object mode do not filter by LogName (use when the channel name is unreliable).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [string]$LogName = 'Security',
        [int[]]$EventId,
        [string]$ProviderName,
        [switch]$IncludeMessage,
        [switch]$NoLogNameFilter
    )
    $result = $null
    switch ($Context.Mode) {
        'Object' {
            $events = $Context.Events
            if ($EventId) {
                $idSet = @{}; foreach ($i in $EventId) { $idSet[[int]$i] = $true }
                $events = @($events | Where-Object { $idSet.ContainsKey([int]$_.EventId) })
            }
            if ($ProviderName) {
                $events = @($events | Where-Object { -not $_.PSObject.Properties['ProviderName'] -or -not $_.ProviderName -or $_.ProviderName -eq $ProviderName })
            }
            if ($LogName -and -not $NoLogNameFilter) {
                $events = @($events | Where-Object { -not $_.PSObject.Properties['LogName'] -or -not $_.LogName -or $_.LogName -eq $LogName })
            }
            $result = $events
        }
        'File' {
            $p = @{ Path = $Context.Path }
            if ($EventId) { $p['EventId'] = $EventId }
            if ($ProviderName) { $p['ProviderName'] = $ProviderName }
            if ($Context.StartTime) { $p['StartTime'] = $Context.StartTime }
            if ($Context.EndTime) { $p['EndTime'] = $Context.EndTime }
            if ($Context.MaxEvents -gt 0) { $p['MaxEvents'] = $Context.MaxEvents }
            $events = @(Get-IRWinEvent @p | ConvertFrom-IRWinEvent -IncludeMessage:$IncludeMessage)
            if ($LogName -and -not $NoLogNameFilter) {
                $events = @($events | Where-Object { -not $_.LogName -or $_.LogName -eq $LogName })
            }
            $result = $events
        }
        default {
            $p = @{ LogName = $LogName }
            if ($EventId) { $p['EventId'] = $EventId }
            if ($ProviderName) { $p['ProviderName'] = $ProviderName }
            if ($Context.ComputerName) { $p['ComputerName'] = $Context.ComputerName }
            if ($Context.Credential) { $p['Credential'] = $Context.Credential }
            if ($Context.StartTime) { $p['StartTime'] = $Context.StartTime }
            if ($Context.EndTime) { $p['EndTime'] = $Context.EndTime }
            if ($Context.MaxEvents -gt 0) { $p['MaxEvents'] = $Context.MaxEvents }
            $result = @(Get-IRWinEvent @p | ConvertFrom-IRWinEvent -IncludeMessage:$IncludeMessage)
        }
    }
    # Apply time window in Object mode (Live/File already filtered by Get-WinEvent)
    if ($Context.Mode -eq 'Object' -and ($Context.StartTime -or $Context.EndTime)) {
        $result = @($result | Where-Object {
                $t = $_.TimeCreated
                (-not $Context.StartTime -or ($t -and $t -ge $Context.StartTime)) -and
                (-not $Context.EndTime -or ($t -and $t -le $Context.EndTime))
            })
    }
    Write-Verbose ("Get-IRSourceEvents {0} ids=[{1}] -> {2} events" -f $LogName, ($EventId -join ','), @($result).Count)
    @($result)
}

function Get-IRLogInfo {
    <#
    .SYNOPSIS  Returns size / record count / oldest and newest event time for a log (live only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [string]$ComputerName,
        [pscredential]$Credential
    )
    # Use -ErrorAction Ignore (NOT Stop or SilentlyContinue): only Ignore discards the error record
    # entirely. Stop and SilentlyContinue both still record it, so it leaks into a caller's
    # -ErrorVariable and pollutes the tool's error output. StrictMode is off, so .TimeCreated on a
    # null result is safe.
    $p = @{ ListLog = $LogName; ErrorAction = 'Ignore' }
    if ($ComputerName) { $p['ComputerName'] = $ComputerName }
    if ($Credential) { $p['Credential'] = $Credential }
    $log = Get-WinEvent @p
    if (-not $log) { Write-Verbose "Get-IRLogInfo: '$LogName' not available (missing or access denied)."; return $null }
    $oldest = $null; $newest = $null
    $q = @{ LogName = $LogName; MaxEvents = 1; ErrorAction = 'Ignore' }
    if ($ComputerName) { $q['ComputerName'] = $ComputerName }
    if ($Credential) { $q['Credential'] = $Credential }
    $oEvt = Get-WinEvent @q -Oldest; if ($oEvt) { $oldest = $oEvt.TimeCreated }
    $nEvt = Get-WinEvent @q; if ($nEvt) { $newest = $nEvt.TimeCreated }
    [pscustomobject]@{
        LogName           = $log.LogName
        IsEnabled         = $log.IsEnabled
        RecordCount       = $log.RecordCount
        FileSizeMB        = [Math]::Round(($log.FileSize / 1MB), 1)
        MaximumSizeMB     = [Math]::Round(($log.MaximumSizeInBytes / 1MB), 1)
        LogMode           = $log.LogMode
        OldestEvent       = $oldest
        NewestEvent       = $newest
        RetentionDays     = $(if ($oldest -and $newest) { [Math]::Round(($newest - $oldest).TotalDays, 1) } else { $null })
    }
}

#endregion

#region ---------------------------------------------------------------- Findings

function New-IRFinding {
    <#
    .SYNOPSIS  Creates a standardized finding object (PSTypeName IRToolKit.Finding).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description,
        [string]$Technique,
        [string]$TechniqueName,
        [ValidateSet('High', 'Medium', 'Low')][string]$Confidence = 'Medium',
        [string]$Account,
        [string]$SourceIp,
        [string]$SourceHost,
        [string]$Target,
        [string]$Computer,
        [datetime]$TimeCreated,
        [datetime]$LastSeen,
        [int[]]$EventIds,
        [int]$EventCount,
        [object[]]$Evidence,
        [string]$Recommendation,
        [hashtable]$Extra
    )
    if (-not $PSBoundParameters.ContainsKey('TimeCreated')) {
        if ($Evidence -and $Evidence.Count -gt 0 -and $Evidence[0].PSObject.Properties['TimeCreated']) {
            $times = @($Evidence | ForEach-Object { $_.TimeCreated } | Where-Object { $_ -is [datetime] } | Sort-Object)
            if ($times.Count -gt 0) { $TimeCreated = $times[0]; if (-not $PSBoundParameters.ContainsKey('LastSeen')) { $LastSeen = $times[-1] } }
        }
        if (-not $TimeCreated) { $TimeCreated = Get-Date }
    }
    if (-not $PSBoundParameters.ContainsKey('LastSeen') -and -not $LastSeen) { $LastSeen = $TimeCreated }
    if (-not $PSBoundParameters.ContainsKey('EventCount')) { $EventCount = @($Evidence).Count }
    if (-not $Computer -and $Evidence -and $Evidence.Count -gt 0 -and $Evidence[0].PSObject.Properties['Computer']) { $Computer = $Evidence[0].Computer }

    $f = [ordered]@{
        TimeCreated    = $TimeCreated
        LastSeen       = $LastSeen
        Severity       = $Severity
        Confidence     = $Confidence
        Tool           = $Tool
        Technique      = $Technique
        TechniqueName  = $TechniqueName
        Title          = $Title
        Account        = $Account
        SourceIp       = $SourceIp
        SourceHost     = $SourceHost
        Target         = $Target
        Computer       = $Computer
        EventIds       = $EventIds
        EventCount     = $EventCount
        Description    = $Description
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { if (-not $f.Contains($k)) { $f[$k] = $Extra[$k] } } }
    $obj = [pscustomobject]$f
    $obj.PSObject.TypeNames.Insert(0, 'IRToolKit.Finding')
    $obj
}

function Get-IRSeverityRank { param([string]$Severity) if ($script:IRSeverityRank.ContainsKey($Severity)) { $script:IRSeverityRank[$Severity] } else { 0 } }

function Write-IRFindingSummary {
    <#
    .SYNOPSIS  Prints a one-line-per-finding summary plus severity counts to the host.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [string]$Tool,
        [int]$MaxLines = 50
    )
    if ($script:IRQuiet) { return }
    $Findings = @($Findings | Where-Object { $_ })
    if ($Findings.Count -eq 0) {
        Write-Host "[+] $Tool`: no findings." -ForegroundColor Green
        return
    }
    $sorted = $Findings | Sort-Object @{ Expression = { Get-IRSeverityRank $_.Severity }; Descending = $true }, TimeCreated
    $counts = $Findings | Group-Object Severity | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host ("[!] {0}: {1} finding(s) [{2}]" -f $Tool, $Findings.Count, ($counts -join ', ')) -ForegroundColor Yellow
    $n = 0
    foreach ($f in $sorted) {
        $n++
        if ($n -gt $MaxLines) { Write-Host "    ... $($Findings.Count - $MaxLines) more (use -OutputPath or inspect the returned objects)" -ForegroundColor DarkGray; break }
        $color = 'Gray'
        switch ($f.Severity) { 'Critical' { $color = 'Magenta' } 'High' { $color = 'Red' } 'Medium' { $color = 'Yellow' } 'Low' { $color = 'Cyan' } }
        $who = $f.Account; if ($f.SourceIp) { $who += " from $($f.SourceIp)" }
        Write-Host ("    [{0,-13}] {1:yyyy-MM-dd HH:mm:ss}  {2}  {3}" -f $f.Severity, $f.TimeCreated, $f.Title, $who) -ForegroundColor $color
    }
}

function Export-IRFindings {
    <#
    .SYNOPSIS  Exports findings to CSV, JSON and/or HTML. Returns the paths written.
    .PARAMETER Path
        Output directory OR a file path. If a directory, files are named <Tool>-<timestamp>.<ext>.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Csv', 'Json', 'Html', 'All')][string]$Format = 'Json',
        [string]$Name = 'IRToolKit'
    )
    $Findings = @($Findings | Where-Object { $_ })
    $formats = @($Format); if ($Format -eq 'All') { $formats = @('Csv', 'Json', 'Html') }
    $isDir = (Test-Path -LiteralPath $Path -PathType Container) -or (-not [IO.Path]::HasExtension($Path))
    if ($isDir -and -not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $written = @()
    foreach ($fmt in $formats) {
        $ext = $fmt.ToLower()
        $file = $Path
        if ($isDir) { $file = Join-Path $Path ("{0}-{1}.{2}" -f $Name, $stamp, $ext) }
        elseif ($formats.Count -gt 1) { $file = [IO.Path]::ChangeExtension($Path, $ext) }
        switch ($fmt) {
            'Csv' {
                $flat = foreach ($f in $Findings) {
                    [pscustomobject]@{
                        TimeCreated = $f.TimeCreated; LastSeen = $f.LastSeen; Severity = $f.Severity; Confidence = $f.Confidence
                        Tool = $f.Tool; Technique = $f.Technique; TechniqueName = $f.TechniqueName; Title = $f.Title
                        Account = $f.Account; SourceIp = $f.SourceIp; SourceHost = $f.SourceHost; Target = $f.Target; Computer = $f.Computer
                        EventIds = ($f.EventIds -join ' '); EventCount = $f.EventCount; Description = $f.Description; Recommendation = $f.Recommendation
                    }
                }
                $flat | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
            }
            'Json' {
                $json = foreach ($f in $Findings) {
                    $h = [ordered]@{}
                    foreach ($p in $f.PSObject.Properties) {
                        if ($p.Name -eq 'Evidence') {
                            $h['Evidence'] = @(foreach ($e in @($p.Value)) {
                                    if ($null -eq $e) { continue }
                                    $eh = [ordered]@{}
                                    foreach ($ep in $e.PSObject.Properties) { if ($ep.Value -is [datetime]) { $eh[$ep.Name] = $ep.Value.ToString('o') } else { $eh[$ep.Name] = $ep.Value } }
                                    [pscustomobject]$eh
                                })
                        }
                        elseif ($p.Value -is [datetime]) { $h[$p.Name] = $p.Value.ToString('o') }
                        else { $h[$p.Name] = $p.Value }
                    }
                    [pscustomobject]$h
                }
                ConvertTo-Json -InputObject @($json) -Depth 8 | Out-File -LiteralPath $file -Encoding UTF8
            }
            'Html' { ConvertTo-IRHtmlReport -Findings $Findings -Title $Name | Out-File -LiteralPath $file -Encoding UTF8 }
        }
        $written += $file
        Write-IRStatus "Wrote $fmt report: $file" -Level Success
    }
    $written
}

function ConvertTo-IRHtmlReport {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [string]$Title = 'IRToolKit Report',
        [string[]]$Notes
    )
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    function enc($s) { if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $Findings = @($Findings | Where-Object { $_ } | Sort-Object @{ Expression = { Get-IRSeverityRank $_.Severity }; Descending = $true }, TimeCreated)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + (enc $Title) + '</title>')
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#fafafa;color:#222}h1{margin-bottom:4px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #ddd;padding:6px;vertical-align:top;font-size:13px}th{background:#333;color:#fff;text-align:left;position:sticky;top:0}tr.Critical td.sev{background:#6a0dad;color:#fff}tr.High td.sev{background:#c0392b;color:#fff}tr.Medium td.sev{background:#e67e22;color:#fff}tr.Low td.sev{background:#2980b9;color:#fff}tr.Informational td.sev{background:#7f8c8d;color:#fff}.summary span{display:inline-block;margin-right:14px;padding:4px 8px;border-radius:4px;background:#eee}details{margin:0}pre{white-space:pre-wrap;font-size:11px;background:#f4f4f4;padding:6px;max-height:300px;overflow:auto}</style></head><body>')
    [void]$sb.AppendLine('<h1>' + (enc $Title) + '</h1><div>Generated ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' on ' + (enc $env:COMPUTERNAME) + '</div>')
    $counts = $Findings | Group-Object Severity
    [void]$sb.Append('<p class="summary">Total: <b>' + $Findings.Count + '</b> ')
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Informational') {
        $c = ($counts | Where-Object Name -eq $sev).Count; if (-not $c) { $c = 0 }
        [void]$sb.Append("<span>$sev`: $c</span>")
    }
    [void]$sb.AppendLine('</p>')
    if ($Notes) { foreach ($n in $Notes) { [void]$sb.AppendLine('<p>' + (enc $n) + '</p>') } }
    [void]$sb.AppendLine('<table><tr><th>Severity</th><th>Time</th><th>Tool</th><th>Technique</th><th>Title</th><th>Account</th><th>Source</th><th>Target</th><th>Computer</th><th>Events</th><th>Description</th></tr>')
    foreach ($f in $Findings) {
        $src = $f.SourceIp; if ($f.SourceHost) { $src = "$src $($f.SourceHost)".Trim() }
        $ev = ''
        if ($f.Evidence) {
            $sample = @($f.Evidence | Select-Object -First 5 | ForEach-Object {
                    $e = $_; ($e.PSObject.Properties | Where-Object { $null -ne $_.Value -and "$($_.Value)" -ne '' -and $_.Name -notin 'Evidence' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                })
            $ev = '<details><summary>' + $f.EventCount + ' event(s)</summary><pre>' + (enc ($sample -join "`n`n")) + '</pre></details>'
        }
        [void]$sb.AppendLine('<tr class="' + $f.Severity + '"><td class="sev">' + (enc $f.Severity) + '<br/><small>' + (enc $f.Confidence) + '</small></td><td>' + $f.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '</td><td>' + (enc $f.Tool) + '</td><td>' + (enc $f.Technique) + '</td><td><b>' + (enc $f.Title) + '</b></td><td>' + (enc $f.Account) + '</td><td>' + (enc $src) + '</td><td>' + (enc $f.Target) + '</td><td>' + (enc $f.Computer) + '</td><td>' + ($f.EventIds -join ' ') + '<br/>' + $ev + '</td><td>' + (enc $f.Description) + '<br/><i>' + (enc $f.Recommendation) + '</i></td></tr>')
    }
    [void]$sb.AppendLine('</table></body></html>')
    $sb.ToString()
}

function Complete-IRTool {
    <#
    .SYNOPSIS
        Standard tool epilogue: prints the summary, exports if -OutputPath was given, returns findings.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][string]$Tool,
        [string]$OutputPath,
        [string]$Format = 'Json',
        [switch]$PassThru
    )
    $Findings = @($Findings | Where-Object { $_ })
    Write-IRFindingSummary -Findings $Findings -Tool $Tool
    if ($OutputPath) { Export-IRFindings -Findings $Findings -Path $OutputPath -Format $Format -Name $Tool | Out-Null }
    $Findings
}

#endregion

#region ---------------------------------------------------------------- Decoders

function ConvertTo-IRHexString {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if ($s -match '^0x[0-9a-f]+$') { return '0x' + ($s.Substring(2).TrimStart('0')); }
    $n = 0L
    if ([long]::TryParse($s, [ref]$n)) { return '0x' + $n.ToString('x') }
    return $s
}

function ConvertTo-IRInt {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [long]$Value }
    $s = ([string]$Value).Trim()
    if ($s -match '^0x([0-9a-fA-F]+)$') { return [Convert]::ToInt64($matches[1], 16) }
    $n = 0L
    if ([long]::TryParse($s, [ref]$n)) { return $n }
    return $null
}

function ConvertFrom-IRKerberosEncryptionType {
    param($Value)
    $k = ConvertTo-IRHexString $Value
    if ($k -eq '0x') { $k = '0x0' }
    if ($k -and $script:IRKerberosEncryptionTypes.ContainsKey($k)) { return "$($script:IRKerberosEncryptionTypes[$k]) ($k)" }
    return "Unknown ($Value)"
}

function Test-IRWeakKerberosEncryption {
    <# .SYNOPSIS Returns $true for RC4 or DES ticket encryption types. #>
    param($Value)
    $k = ConvertTo-IRHexString $Value
    return ($k -in '0x1', '0x3', '0x17', '0x18')
}

function ConvertFrom-IRKerberosStatus {
    param($Value)
    $k = ConvertTo-IRHexString $Value
    if ($k -eq '0x') { $k = '0x0' }
    if ($k -and $script:IRKerberosStatusCodes.ContainsKey($k)) { return "$($script:IRKerberosStatusCodes[$k]) [$k]" }
    return "Unknown [$Value]"
}

function ConvertFrom-IRPreAuthType {
    param($Value)
    $k = [string]$Value
    if ($script:IRKerberosPreAuthTypes.ContainsKey($k)) { return "$($script:IRKerberosPreAuthTypes[$k]) [$k]" }
    return "Unknown [$k]"
}

function ConvertFrom-IRLogonType {
    param($Value)
    $k = [string]$Value
    if ($script:IRLogonTypes.ContainsKey($k)) { return "$($script:IRLogonTypes[$k]) [$k]" }
    return "Unknown [$k]"
}

function ConvertFrom-IRNtStatus {
    param($Value)
    $k = ConvertTo-IRHexString $Value
    if ($k -eq '0x') { $k = '0x0' }
    if ($k -and $script:IRNtStatusCodes.ContainsKey($k)) { return "$($script:IRNtStatusCodes[$k]) [$k]" }
    return "Unknown [$Value]"
}

function ConvertFrom-IRTicketOptions {
    <# .SYNOPSIS Decodes the hex TicketOptions value of 4768/4769/4770 to flag names. #>
    param($Value)
    $n = ConvertTo-IRInt $Value
    if ($null -eq $n) { return @() }
    $flags = @()
    foreach ($entry in $script:IRTicketOptionBits.GetEnumerator()) {
        $mask = [long]1 -shl (31 - [int]$entry.Key)
        if (($n -band $mask) -ne 0) { $flags += $entry.Value }
    }
    $flags
}

function ConvertFrom-IRSamUac {
    <# .SYNOPSIS Decodes the hex OldUacValue/NewUacValue (SAM USER_* flags) of 4720/4738/4741/4742. #>
    param($Value)
    $n = ConvertTo-IRInt $Value
    if ($null -eq $n) { return @() }
    $flags = @()
    foreach ($entry in $script:IRSamUacFlags.GetEnumerator()) { if (($n -band [long]$entry.Key) -ne 0) { $flags += $entry.Value } }
    $flags
}

function ConvertFrom-IRLdapUac {
    <# .SYNOPSIS Decodes a decimal/hex LDAP userAccountControl value (5136 AttributeValue, AD queries). #>
    param($Value)
    $n = ConvertTo-IRInt $Value
    if ($null -eq $n) { return @() }
    $flags = @()
    foreach ($entry in $script:IRLdapUacFlags.GetEnumerator()) { if (($n -band [long]$entry.Key) -ne 0) { $flags += $entry.Value } }
    $flags
}

function Compare-IRSamUac {
    <# .SYNOPSIS Returns the SAM UAC flags added and removed between OldUacValue and NewUacValue. #>
    param($Old, $New)
    $o = @(ConvertFrom-IRSamUac $Old); $n = @(ConvertFrom-IRSamUac $New)
    [pscustomobject]@{
        Added   = @($n | Where-Object { $_ -notin $o })
        Removed = @($o | Where-Object { $_ -notin $n })
    }
}

function ConvertFrom-IRUacChangeString {
    <# .SYNOPSIS Translates the "%%2110" style UserAccountControl text of 4720/4738/4742 to readable flags. #>
    param($Value)
    if (-not $Value) { return @() }
    $out = @()
    foreach ($m in [regex]::Matches([string]$Value, '%%\d{4}')) {
        $code = $m.Value
        if ($script:IRUacChangeStrings.ContainsKey($code)) { $out += $script:IRUacChangeStrings[$code] } else { $out += $code }
    }
    if ($out.Count -eq 0 -and ([string]$Value).Trim() -ne '-' -and ([string]$Value).Trim() -ne '') {
        # Already rendered text (e.g. from Message) - split on tab/newline
        $out = @(([string]$Value) -split "[\r\n\t]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    $out
}

function ConvertFrom-IRDsAccessMask {
    <# .SYNOPSIS Decodes the hex AccessMask of 4662/4661/4670 (directory service objects). #>
    param($Value)
    $n = ConvertTo-IRInt $Value
    if ($null -eq $n) { return @() }
    $flags = @()
    foreach ($entry in $script:IRDsAccessMask.GetEnumerator()) { if (($n -band [long]$entry.Key) -ne 0) { $flags += $entry.Value } }
    $flags
}

function Get-IRGuidsFromText {
    <# .SYNOPSIS Extracts every GUID present in a string (e.g. the 4662 Properties field). #>
    param([string]$Text)
    if (-not $Text) { return @() }
    @([regex]::Matches($Text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
}

function Resolve-IRGuidName {
    <# .SYNOPSIS Maps a known right/attribute GUID to its name (replication rights, well-known attributes, or live schema). #>
    param([string]$Guid, [switch]$NoSchemaLookup)
    if (-not $Guid) { return $null }
    $g = $Guid.ToLowerInvariant().Trim('{}')
    if ($script:IRReplicationRightGuids.ContainsKey($g)) { return $script:IRReplicationRightGuids[$g] }
    if ($script:IRWellKnownGuids.ContainsKey($g)) { return $script:IRWellKnownGuids[$g] }
    if (-not $NoSchemaLookup) {
        $name = Resolve-IRSchemaGuid -Guid $g
        if ($name) { return $name }
    }
    return $g
}

function ConvertTo-IRIpAddress {
    <# .SYNOPSIS Normalises IpAddress fields (strips ::ffff:, handles '-', '::1'). #>
    param($Value)
    if ($null -eq $Value) { return '-' }
    $s = ([string]$Value).Trim()
    if ($s -eq '' -or $s -eq '-') { return '-' }
    if ($s -like '::ffff:*') { $s = $s.Substring(7) }
    if ($s -eq '::1') { return '127.0.0.1' }
    return $s
}

function Test-IRLocalIp {
    param($Value)
    $ip = ConvertTo-IRIpAddress $Value
    return ($ip -in '-', '127.0.0.1', '::1', 'localhost', '0.0.0.0', '::')
}

function Test-IRMachineAccount {
    <# .SYNOPSIS True when a name is a computer account (ends with '$'). Handles UPN (name@realm) and DOMAIN\name forms. #>
    param($Name)
    if (-not $Name) { return $false }
    $n = ([string]$Name).Trim()
    if ($n -match '^(.+)@[^@]+$') { $n = $matches[1] }   # strip UPN realm: WS-70$@CORP.LOCAL -> WS-70$
    if ($n -match '\\([^\\]+)$') { $n = $matches[1] }     # strip DOMAIN\: CORP\WS-70$ -> WS-70$
    return ($n.TrimEnd() -like '*$')
}

function Get-IRAccountKey {
    <# .SYNOPSIS Normalised DOMAIN\user key (lower-case, UPN converted) for grouping. #>
    param($User, $Domain)
    $u = [string]$User
    if ($u -match '^(.+)@(.+)$') { $u = $matches[1]; if (-not $Domain) { $Domain = $matches[2] } }
    if ($u -match '^(.+)\\(.+)$') { $Domain = $matches[1]; $u = $matches[2] }
    $d = [string]$Domain
    if ($d -and $d -ne '-') { return ("{0}\{1}" -f $d, $u).ToLowerInvariant() }
    return $u.ToLowerInvariant()
}

function Test-IRPrivilegedGroup {
    <# .SYNOPSIS Returns $true if a group SID or name is in the privileged list. #>
    param([string]$Sid, [string]$Name)
    if ($Sid) {
        $s = $Sid.Trim()
        if ($script:IRPrivilegedBuiltinSids.ContainsKey($s)) { return $true }
        if ($s -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') { if ($script:IRPrivilegedGroupRids.ContainsKey($matches[1])) { return $true } }
    }
    if ($Name) {
        $n = $Name.Trim()
        if ($n -match '^CN=([^,]+)') { $n = $matches[1] }
        if ($n -match '\\(.+)$') { $n = $matches[1] }
        foreach ($p in $script:IRPrivilegedGroupNames) { if ($n -ieq $p) { return $true } }
    }
    return $false
}

function Get-IRPrivilegedGroupName {
    param([string]$Sid, [string]$Name)
    if ($Sid) {
        $s = $Sid.Trim()
        if ($script:IRPrivilegedBuiltinSids.ContainsKey($s)) { return $script:IRPrivilegedBuiltinSids[$s] }
        if ($s -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and $script:IRPrivilegedGroupRids.ContainsKey($matches[1])) { return $script:IRPrivilegedGroupRids[$matches[1]] }
    }
    return $Name
}

function Get-IRReferenceTable {
    <# .SYNOPSIS Exposes the module reference tables to tools (read-only copies). #>
    param([Parameter(Mandatory)][ValidateSet('KerberosEncryptionTypes', 'KerberosStatusCodes', 'PreAuthTypes', 'LogonTypes', 'NtStatusCodes', 'SamUacFlags', 'LdapUacFlags', 'UacChangeStrings', 'DsAccessMask', 'ReplicationRightGuids', 'WellKnownGuids', 'PrivilegedGroupRids', 'PrivilegedBuiltinSids', 'PrivilegedGroupNames', 'SensitiveAttributes', 'KerberoastExcludedServices')][string]$Name)
    switch ($Name) {
        'KerberosEncryptionTypes'   { $script:IRKerberosEncryptionTypes.Clone() }
        'KerberosStatusCodes'       { $script:IRKerberosStatusCodes.Clone() }
        'PreAuthTypes'              { $script:IRKerberosPreAuthTypes.Clone() }
        'LogonTypes'                { $script:IRLogonTypes.Clone() }
        'NtStatusCodes'             { $script:IRNtStatusCodes.Clone() }
        'SamUacFlags'               { $script:IRSamUacFlags }
        'LdapUacFlags'              { $script:IRLdapUacFlags }
        'UacChangeStrings'          { $script:IRUacChangeStrings.Clone() }
        'DsAccessMask'              { $script:IRDsAccessMask }
        'ReplicationRightGuids'     { $script:IRReplicationRightGuids.Clone() }
        'WellKnownGuids'            { $script:IRWellKnownGuids.Clone() }
        'PrivilegedGroupRids'       { $script:IRPrivilegedGroupRids.Clone() }
        'PrivilegedBuiltinSids'     { $script:IRPrivilegedBuiltinSids.Clone() }
        'PrivilegedGroupNames'      { @($script:IRPrivilegedGroupNames) }
        'SensitiveAttributes'       { $script:IRSensitiveAttributes.Clone() }
        'KerberoastExcludedServices' { @($script:IRKerberoastExcludedServices) }
    }
}

#endregion

#region ---------------------------------------------------------------- Analysis helpers

function Find-IRBurst {
    <#
    .SYNOPSIS
        Sliding-window burst detector. Groups events by key, sorts by time and reports windows
        where the number of events (or distinct values of -DistinctProperty) reaches -Threshold.
    .EXAMPLE
        Find-IRBurst -Events $e -GroupBy TargetUserName,IpAddress -DistinctProperty ServiceName -WindowMinutes 10 -Threshold 5
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory)][string[]]$GroupBy,
        [string]$DistinctProperty,
        [double]$WindowMinutes = 10,
        [int]$Threshold = 10,
        [string]$TimeProperty = 'TimeCreated'
    )
    $Events = @($Events | Where-Object { $_ -and $_.$TimeProperty -is [datetime] })
    if ($Events.Count -eq 0) { return @() }
    $groups = @{}
    foreach ($e in $Events) {
        $keyParts = foreach ($g in $GroupBy) { $v = $e.$g; if ($null -eq $v) { '' } else { ([string]$v).ToLowerInvariant() } }
        $key = $keyParts -join '|'
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add($e)
    }
    $windowTicks = [TimeSpan]::FromMinutes($WindowMinutes).Ticks
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($key in $groups.Keys) {
        $list = @($groups[$key] | Sort-Object $TimeProperty)
        $n = $list.Count

        # Whole-group early-out: if the group can never reach the threshold, skip it in O(group).
        # This is the common benign case (a busy account below threshold) and keeps that case cheap.
        if ($DistinctProperty) {
            $allDistinct = @{}
            foreach ($e in $list) { $dv = $e.$DistinctProperty; if ($null -ne $dv) { $allDistinct[[string]$dv] = $true } }
            if ($allDistinct.Count -lt $Threshold) { continue }
        }
        elseif ($n -lt $Threshold) { continue }

        # Fixed-start, maximal-window burst detection with a forward-only j pointer and an incrementally
        # maintained distinct-count map. Each of i and j advances at most n times across the whole group,
        # so this is O(n) amortized per group (no per-start re-slice / re-unique). Emission is non-overlapping.
        $counts = @{}       # distinct value -> occurrences currently inside [i..j]
        $distinct = 0       # number of keys in $counts
        $i = 0
        $j = $i - 1
        while ($i -lt $n) {
            if ($j -lt $i) { $j = $i - 1; $counts = @{}; $distinct = 0 }
            $startTicks = $list[$i].$TimeProperty.Ticks
            while (($j + 1) -lt $n -and ($list[$j + 1].$TimeProperty.Ticks - $startTicks) -le $windowTicks) {
                $j++
                if ($DistinctProperty) {
                    $dv = $list[$j].$DistinctProperty
                    if ($null -ne $dv) { $dvk = [string]$dv; if ($counts.ContainsKey($dvk)) { $counts[$dvk]++ } else { $counts[$dvk] = 1; $distinct++ } }
                }
            }
            $count = if ($DistinctProperty) { $distinct } else { ($j - $i + 1) }
            if ($count -ge $Threshold) {
                $window = $list[$i..$j]
                $distinctValues = $null
                if ($DistinctProperty) { $distinctValues = @($window | ForEach-Object { $_.$DistinctProperty } | Where-Object { $null -ne $_ } | Select-Object -Unique) }
                $keyObj = [ordered]@{}
                for ($k = 0; $k -lt $GroupBy.Count; $k++) { $keyObj[$GroupBy[$k]] = $window[0].($GroupBy[$k]) }
                $results.Add([pscustomobject]@{
                        Key            = [pscustomobject]$keyObj
                        KeyString      = $key
                        WindowStart    = $window[0].$TimeProperty
                        WindowEnd      = $window[-1].$TimeProperty
                        EventCount     = $window.Count
                        DistinctCount  = $(if ($DistinctProperty) { $distinct } else { $window.Count })
                        DistinctValues = $distinctValues
                        Events         = $window
                    })
                # Jump past the emitted burst (non-overlapping) and reset the window state.
                $i = $j + 1; $j = $i - 1; $counts = @{}; $distinct = 0
            }
            else {
                # Not a burst from this start: drop list[i] from the window and advance i (j is retained).
                if ($DistinctProperty -and $j -ge $i) {
                    $dv = $list[$i].$DistinctProperty
                    if ($null -ne $dv) { $dvk = [string]$dv; if ($counts.ContainsKey($dvk)) { $counts[$dvk]--; if ($counts[$dvk] -le 0) { [void]$counts.Remove($dvk); $distinct-- } } }
                }
                $i++
            }
        }
    }
    $results.ToArray()
}

function Group-IRByKey {
    <# .SYNOPSIS Fast hashtable grouping; returns a hashtable key -> List[object]. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Events, [Parameter(Mandatory)][scriptblock]$KeyScript)
    $groups = @{}
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $key = [string](& $KeyScript $e)
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add($e)
    }
    $groups
}

function Test-IRPatternMatch {
    <# .SYNOPSIS Returns the first regex (from a list) that matches the text, or $null. #>
    param([string]$Text, [string[]]$Patterns)
    if (-not $Text) { return $null }
    foreach ($p in $Patterns) { if ($Text -match $p) { return $p } }
    return $null
}

function Get-IRFirst {
    <#
    .SYNOPSIS
        Returns the first N elements of a collection by slicing, never by piping to Select-Object -First.
    .DESCRIPTION
        In Windows PowerShell 5.1 `... | Select-Object -First N` emits an internal
        StopUpstreamCommandsException that can leak to the error stream when used on a plain array
        inside a function that is itself running in a pipeline. This helper slices instead, so it is
        safe to call anywhere. Always returns an array (possibly empty).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$InputObject, [int]$Count = 1)
    if ($null -eq $InputObject -or $InputObject.Count -eq 0 -or $Count -le 0) { return , @() }
    $n = [Math]::Min($Count, $InputObject.Count)
    , @($InputObject[0..($n - 1)])
}

#endregion

#region ---------------------------------------------------------------- Active Directory helpers (no RSAT required)

function Get-IRDomainControllers {
    <#
    .SYNOPSIS  Lists domain controllers (name, IP, site) via System.DirectoryServices; cached. Returns @() when not domain-joined.
    .PARAMETER Additional
        Extra DC names/IPs supplied by the analyst (e.g. when running offline against exported logs).
    #>
    [CmdletBinding()]
    param([string[]]$Additional, [switch]$Forest, [switch]$Refresh)
    if (-not $Refresh -and $null -ne $script:IRDomainControllerCache) { $list = $script:IRDomainControllerCache }
    else {
        $list = New-Object System.Collections.Generic.List[object]
        # Gate the live lookup on Test-IRAdAvailable. Calling GetCurrentDomain()/GetCurrentForest() on a
        # non-domain host throws a .NET method exception that Windows PowerShell 5.1 records into the
        # caller's -ErrorVariable even when caught here (2>$null / try-catch / $Error.Clear() do not
        # stop it). Test-IRAdAvailable is leak-free, so checking it first avoids the throw entirely.
        if (Test-IRAdAvailable) {
            try {
                if ($Forest) {
                    $f = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    foreach ($d in $f.Domains) { foreach ($dc in $d.DomainControllers) { $list.Add([pscustomobject]@{ Name = $dc.Name; IPAddress = $dc.IPAddress; Site = $dc.SiteName; Domain = $d.Name }) } }
                }
                else {
                    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    foreach ($dc in $d.DomainControllers) { $list.Add([pscustomobject]@{ Name = $dc.Name; IPAddress = $dc.IPAddress; Site = $dc.SiteName; Domain = $d.Name }) }
                }
            }
            catch { Write-Verbose "Get-IRDomainControllers: AD unreachable ($($_.Exception.Message))" }
        }
        else { Write-Verbose 'Get-IRDomainControllers: host is not domain-joined; returning supplied -Additional entries only.' }
        # Do not cache when only -Additional would be present; cache the discovered (AD) list.
        $script:IRDomainControllerCache = $list
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in $list) { $out.Add($x) }
    foreach ($a in @($Additional)) { if ($a) { $out.Add([pscustomobject]@{ Name = $a; IPAddress = $a; Site = $null; Domain = $null }) } }
    $out.ToArray()
}

function Get-IRDomainControllerLookup {
    <# .SYNOPSIS Hashtable of lower-case DC names (short + FQDN), IPs and machine accounts (NAME$) for fast membership tests. #>
    [CmdletBinding()]
    param([string[]]$Additional)
    $lookup = @{}
    foreach ($dc in @(Get-IRDomainControllers -Additional $Additional)) {
        if ($dc.Name) {
            $n = $dc.Name.ToLowerInvariant(); $lookup[$n] = $true
            $short = $n.Split('.')[0]; $lookup[$short] = $true; $lookup["$short`$"] = $true
        }
        if ($dc.IPAddress) { $lookup[([string]$dc.IPAddress).ToLowerInvariant()] = $true }
    }
    $lookup
}

function Test-IRDomainController {
    <# .SYNOPSIS True when a host name, IP or machine account refers to a known DC (uses lookup from Get-IRDomainControllerLookup). #>
    param([hashtable]$Lookup, $Value)
    if (-not $Lookup -or $Lookup.Count -eq 0 -or -not $Value) { return $false }
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -like '::ffff:*') { $v = $v.Substring(7) }
    if ($Lookup.ContainsKey($v)) { return $true }
    if ($Lookup.ContainsKey($v.TrimEnd('$'))) { return $true }
    if ($Lookup.ContainsKey($v.Split('.')[0])) { return $true }
    return $false
}

function Get-IRRootDse {
    try { return [ADSI]'LDAP://RootDSE' } catch { return $null }
}

function Resolve-IRSchemaGuid {
    <# .SYNOPSIS Resolves an attribute/class schemaIDGUID or extended-right GUID to its name via LDAP (cached, best-effort). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Guid)
    $g = $Guid.ToLowerInvariant().Trim('{}')
    if ($script:IRSchemaGuidCache.ContainsKey($g)) { return $script:IRSchemaGuidCache[$g] }
    $name = $null
    try {
        $root = Get-IRRootDse
        if ($root) {
            $bytes = ([guid]$g).ToByteArray()
            $hex = ($bytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
            $schemaNc = [string]$root.schemaNamingContext
            $configNc = [string]$root.configurationNamingContext
            $ds = New-Object System.DirectoryServices.DirectorySearcher
            $ds.SearchRoot = [ADSI]"LDAP://$schemaNc"
            $ds.Filter = "(schemaIDGUID=$hex)"
            $ds.PropertiesToLoad.Add('lDAPDisplayName') | Out-Null
            $r = $ds.FindOne()
            if ($r) { $name = [string]$r.Properties['ldapdisplayname'][0] }
            if (-not $name) {
                $ds2 = New-Object System.DirectoryServices.DirectorySearcher
                $ds2.SearchRoot = [ADSI]"LDAP://CN=Extended-Rights,$configNc"
                $ds2.Filter = "(rightsGuid=$g)"
                $ds2.PropertiesToLoad.Add('displayName') | Out-Null
                $r2 = $ds2.FindOne()
                if ($r2) { $name = [string]$r2.Properties['displayname'][0] }
            }
        }
    }
    catch { Write-Verbose "Resolve-IRSchemaGuid: $($_.Exception.Message)" }
    $script:IRSchemaGuidCache[$g] = $name
    $name
}

function Get-IRSchemaAttributeGuid {
    <# .SYNOPSIS Returns the schemaIDGUID (lower-case string) for an attribute lDAPDisplayName, or $null when AD is unavailable. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AttributeName)
    $key = "name:" + $AttributeName.ToLowerInvariant()
    if ($script:IRSchemaGuidCache.ContainsKey($key)) { return $script:IRSchemaGuidCache[$key] }
    $guid = $null
    try {
        $root = Get-IRRootDse
        if ($root) {
            $ds = New-Object System.DirectoryServices.DirectorySearcher
            $ds.SearchRoot = [ADSI]("LDAP://" + [string]$root.schemaNamingContext)
            $ds.Filter = "(lDAPDisplayName=$AttributeName)"
            $ds.PropertiesToLoad.Add('schemaIDGUID') | Out-Null
            $r = $ds.FindOne()
            if ($r -and $r.Properties['schemaidguid'].Count -gt 0) { $guid = ([guid][byte[]]$r.Properties['schemaidguid'][0]).ToString().ToLowerInvariant() }
        }
    }
    catch { Write-Verbose "Get-IRSchemaAttributeGuid: $($_.Exception.Message)" }
    $script:IRSchemaGuidCache[$key] = $guid
    $guid
}

function Get-IRAdObject {
    <#
    .SYNOPSIS  Looks up an AD object by sAMAccountName via DirectorySearcher (no RSAT). Returns $null if unavailable.
    .PARAMETER Properties  LDAP attributes to load.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [string[]]$Properties = @('distinguishedName', 'userAccountControl', 'servicePrincipalName', 'msDS-SupportedEncryptionTypes', 'memberOf', 'adminCount', 'objectClass', 'pwdLastSet', 'whenCreated')
    )
    try {
        $ds = New-Object System.DirectoryServices.DirectorySearcher
        $san = $SamAccountName -replace '([\\*()\0])', '\$1'
        $ds.Filter = "(sAMAccountName=$san)"
        foreach ($p in $Properties) { $ds.PropertiesToLoad.Add($p) | Out-Null }
        $r = $ds.FindOne()
        if (-not $r) { return $null }
        $o = [ordered]@{ SamAccountName = $SamAccountName }
        foreach ($p in $Properties) {
            $vals = $r.Properties[$p.ToLowerInvariant()]
            if ($vals.Count -eq 1) { $o[$p] = $vals[0] } elseif ($vals.Count -gt 1) { $o[$p] = @($vals) } else { $o[$p] = $null }
        }
        [pscustomobject]$o
    }
    catch { Write-Verbose "Get-IRAdObject: $($_.Exception.Message)"; return $null }
}

function Test-IRAdAvailable {
    try { $r = Get-IRRootDse; if ($r -and $r.defaultNamingContext) { return $true } } catch {}
    return $false
}

#endregion

#region ---------------------------------------------------------------- Audit policy

function Get-IRAuditPolicy {
    <# .SYNOPSIS Parses 'auditpol /get /category:*' into objects (Subcategory, Setting). Requires elevation on most hosts. #>
    [CmdletBinding()]
    param()
    $out = @()
    try { $raw = & auditpol.exe /get /category:* /r 2>$null } catch { return @() }
    if (-not $raw) { return @() }
    try {
        $csv = $raw | Where-Object { $_ -and $_ -notmatch '^\s*$' } | ConvertFrom-Csv
        foreach ($row in $csv) {
            $out += [pscustomobject]@{ Subcategory = $row.Subcategory; Guid = $row.'Subcategory GUID'; Setting = $row.'Inclusion Setting'; Exclusion = $row.'Exclusion Setting' }
        }
    }
    catch { Write-Verbose "Get-IRAuditPolicy: $($_.Exception.Message)" }
    $out
}

#endregion

# Load the default display format for findings / events (skipped when running inlined/standalone,
# where $PSScriptRoot is not set - formatting is cosmetic).
if ($PSScriptRoot) {
    $fmt = Join-Path $PSScriptRoot 'IRToolKit.Format.ps1xml'
    if (Test-Path -LiteralPath $fmt) { try { Update-FormatData -PrependPath $fmt -ErrorAction Stop } catch { Write-Verbose "Format data not loaded: $($_.Exception.Message)" } }
}

Export-ModuleMember -Function *-IR* -Variable @()
