. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ADCSAbuse.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ADCSAbuse.json'

# Full malicious sample. administrator@corp.local is flagged as a privileged UPN so the ESC1 SAN
# request escalates to Critical.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; PrivilegedUpn = @('administrator@corp.local') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1649').Count -eq $f.Count) 'all findings tagged T1649'

# Rule 1 - ESC1 SAN abuse is Critical and names both the requester (lowpriv) and the SAN (administrator).
$esc1 = @($f | Where-Object { $_.Title -like '*ESC1*' -and $_.Title -like '*SAN*' })
Assert-IR ($esc1.Count -ge 1) 'ESC1 SAN abuse detected'
Assert-IR (@($esc1 | Where-Object Severity -eq 'Critical').Count -ge 1) 'ESC1 SAN abuse escalated to Critical for privileged SAN'
Assert-IR (@($esc1 | Where-Object { $_.Account -like '*lowpriv*' -and ($_.Target -like '*administrator*' -or $_.Description -like '*administrator*') }).Count -ge 1) 'ESC1 finding names lowpriv requester and administrator SAN'

# Rule 2 - dangerous certificate-template modification (msPKI-Certificate-Name-Flag) is High.
$tmpl = @($f | Where-Object { $_.Title -like '*template modified*' })
Assert-IR ($tmpl.Count -ge 1) 'dangerous certificate template modification detected'
Assert-IR (@($tmpl | Where-Object { $_.Severity -eq 'High' -and $_.Description -like '*msPKI-Certificate-Name-Flag*' }).Count -ge 1) 'name-flag template change is High'
Assert-IR (@($tmpl | Where-Object { $_.Account -eq 'eviladmin' }).Count -ge 1) 'template change actor (eviladmin) captured'

# Rule 3 - certificate-logon impersonation anomaly is Critical and names the thumbprint, requester and auth user.
$certlogon = @($f | Where-Object { $_.EventIds -contains 4768 -and $_.EventIds -contains 4887 })
Assert-IR ($certlogon.Count -ge 1) 'certificate-logon anomaly detected'
Assert-IR (@($certlogon | Where-Object Severity -eq 'Critical').Count -ge 1) 'certificate-logon anomaly is Critical'
Assert-IR (@($certlogon | Where-Object { $_.Description -like '*ABC123*' -and $_.Description -like '*lowpriv*' -and $_.Account -eq 'administrator' }).Count -ge 1) 'cert ABC123 issued to lowpriv used as administrator'

# Rule 4 - altSecurityIdentities (ESC14) is High.
$altsec = @($f | Where-Object { $_.Title -like '*altSecurityIdentities*' })
Assert-IR ($altsec.Count -ge 1) 'altSecurityIdentities mapping detected'
Assert-IR (@($altsec | Where-Object { $_.Severity -eq 'High' -and $_.Account -eq 'eviluser' }).Count -ge 1) 'altSecurityIdentities change is High by eviluser'

# Rule 5 - tooling in a PowerShell script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'AD CS tooling script block detected'

# Rule 1b - certificate issued to lowpriv whose SAN names cfo@corp.local via the plain User template with no
# requester-supplied SAN (enrollment-agent on-behalf-of = ESC3 / ESC2) -> High.
$obo = @($f | Where-Object { $_.Title -like '*different identity than the requester*' })
Assert-IR ($obo.Count -eq 1 -and $obo[0].Severity -eq 'High' -and $obo[0].Account -like '*lowpriv*' -and $obo[0].Target -like '*cfo@corp.local*' -and $obo[0].Target -like '*ceo@corp.local*') 'enrollment-agent style issuance (lowpriv -> cfo + ceo) detected once as High'
Assert-IR (($obo[0].EventIds -contains 4887) -and $obo[0].Description -like '*1401*' -and $obo[0].Description -like '*1404*') 'ESC3 finding anchors on both 4887 requests'
Assert-IR (@($f | Where-Object { $_.Account -like '*WEB01*' }).Count -eq 0) 'machine certificate for its own dNSHostName (WEB01$) not flagged'
Assert-IR (@($f | Where-Object { $_.Title -like '*different identity*' -and $_.Account -like '*alice*' }).Count -eq 0) 'certificate whose SAN matches its requester (alice) not flagged'
$ka = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; KnownEnrollmentAgent = @('CORP\lowpriv') }
Assert-IR (@($ka.Findings | Where-Object { $_.Title -like '*different identity than the requester*' }).Count -eq 0 -and $ka.Errors.Count -eq 0) 'approved agent suppressed by -KnownEnrollmentAgent'

# Rule 6 - ESC7: CA Administrator + Certificate Manager granted to Everyone (4882) -> High.
$esc7 = @($f | Where-Object { $_.EventIds -contains 4882 })
Assert-IR ($esc7.Count -eq 1 -and $esc7[0].Severity -eq 'High' -and $esc7[0].Account -eq 'eviladmin') 'ESC7 broad CA permission grant detected as High, by eviladmin'
# ('[' is a wildcard class in -like, so compare the bracketed label with Contains.)
Assert-IR ($esc7[0].Target -eq 'Everyone [CA Administrator + Certificate Manager]' -and $esc7[0].Description.Contains('Everyone [CA Administrator + Certificate Manager]') -and -not $esc7[0].Target.Contains('Domain Admins')) 'ESC7 finding names the broad principal and the rights (Domain Admins not treated as broad)'

# Rule 7 - KDC 41 (SID mismatch) using thumbprint ABC123 issued to lowpriv -> Critical (correlated); KDC 39 whose
# certificate subject (CN=lowpriv) is not the account (administrator) -> Medium; bob's clean 39 stays silent.
$kdc41 = @($f | Where-Object { $_.EventIds -contains 41 })
Assert-IR ($kdc41.Count -eq 1 -and $kdc41[0].Severity -eq 'Critical' -and ($kdc41[0].EventIds -contains 4887) -and $kdc41[0].Description -like '*lowpriv*') 'KDC 41 correlated to an issuance for another requester is Critical'
$kdc39 = @($f | Where-Object { $_.EventIds -contains 39 })
Assert-IR ($kdc39.Count -eq 1 -and $kdc39[0].Severity -eq 'Medium' -and $kdc39[0].Account -eq 'administrator') 'KDC 39 with certificate subject != account is Medium; clean 39 (bob) silent'

# Benign activity must not be flagged.
Assert-IR (@($f | Where-Object { $_.Account -like '*alice*' }).Count -eq 0) 'benign normal issuance (alice) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -eq 'bob' }).Count -eq 0) 'benign smart-card PKINIT (bob) not flagged by default'
Assert-IR (@($f | Where-Object { $_.Account -like '*admin-maint*' }).Count -eq 0) "benign template 'revision' change not flagged"

# Without -FlagAllPkinit the uncorrelated smart-card logon must stay silent.
$noflag = @($f | Where-Object { $_.Title -like '*without correlating issuance*' })
Assert-IR ($noflag.Count -eq 0) 'uncorrelated PKINIT not reported without -FlagAllPkinit'

# Benign-only subset: drop every malicious actor/requester/tooling event.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        ($_.Requester -notlike '*lowpriv*') -and ($_.SubjectUserName -notlike '*evil*') -and
        ($_.TargetUserName -ne 'administrator') -and ($_.AccountName -ne 'administrator') -and ($_.EventId -ne 4104)
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; PrivilegedUpn = @('administrator@corp.local') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression (corpus, Rule 6): a 4882 that only grants Enroll / Read to Authenticated Users is silent; one that
# leaves CA Administrator with a named admin group (no broad principal) is a Low review item.
$acl = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:00:00Z'; EventId = 4882; Computer = 'CA01.corp.local'; LogName = 'Security'; SubjectUserName = 'pki-admin'; SubjectDomainName = 'CORP'; SecuritySettings = ' Allow(0x00000300) NT AUTHORITY\Authenticated Users Read Enroll Allow(0x00000200) CORP\Domain Computers Enroll' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:01:00Z'; EventId = 4882; Computer = 'CA01.corp.local'; LogName = 'Security'; SubjectUserName = 'pki-admin'; SubjectDomainName = 'CORP'; SecuritySettings = ' Allow(0x00000303) CORP\PKI Admins CA Administrator Certificate Manager Read Enroll Allow(0x00000300) NT AUTHORITY\Authenticated Users Read Enroll' }
)
$aclr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $acl; Quiet = $true }
Assert-IR ($aclr.Findings.Count -eq 1 -and $aclr.Findings[0].Severity -eq 'Low' -and $aclr.Findings[0].Target -like 'CORP\PKI Admins*' -and $aclr.Errors.Count -eq 0) 'Enroll-only 4882 silent; named-group CA Administrator grant is a Low review item'

# Regression (corpus, Rule 7): KDC 40 is Medium on its own; KDC 39 with a matching subject is silent; a KDC 41
# whose serial matches a live-schema 4887 (SerialNumber field) issued to someone else is Critical even when the
# certificate was issued weeks earlier (an exact serial match is not time-bounded); an event 41 with no
# certificate identity at all (e.g. Kernel-Power 41 in an unfiltered System export) and KDC 39s whose subject is
# the account's host name / naming-convention variant stay silent.
$kdcIn = @(
    [pscustomobject]@{ TimeCreated = '2026-09-01T13:00:00Z'; EventId = 4887; Computer = 'CA01.corp.local'; LogName = 'Security'; Requester = 'CORP\agent01'; Attributes = 'CertificateTemplate:User'; CertificateTemplate = 'User'; RequestId = '2001'; SerialNumber = '4a 00 00 00 11 22 33'; SubjectAlternativeName = 'Other Name: Principal Name=agent01@corp.local' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:05:00Z'; EventId = 41; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; AccountName = 'victim'; Subject = '@@@CN=agent01'; Issuer = 'corp-CA01-CA'; SerialNumber = '4A000000112233'; Thumbprint = 'FFEE' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:06:00Z'; EventId = 40; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; AccountName = 'carol'; Subject = 'CN=carol'; Issuer = 'corp-CA01-CA'; SerialNumber = '5B00'; Thumbprint = 'AABB' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:07:00Z'; EventId = 39; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; AccountName = 'dave'; Subject = 'CN=dave'; Issuer = 'corp-CA01-CA'; SerialNumber = '5C00'; Thumbprint = 'CCDD' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:08:00Z'; EventId = 39; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; AccountName = 'HOST01$'; Subject = 'CN=host01.corp.local'; Issuer = 'corp-CA01-CA'; SerialNumber = '5D00'; Thumbprint = 'DDEE' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:09:00Z'; EventId = 39; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; AccountName = 'jdoe'; Subject = 'CN=john.doe'; Issuer = 'corp-CA01-CA'; SerialNumber = '5E00'; Thumbprint = 'EEFF' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:10:00Z'; EventId = 41; Computer = 'DC01.corp.local'; LogName = 'System'; Level = 1 }
)
$kr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $kdcIn; Quiet = $true }
Assert-IR (@($kr.Findings | Where-Object { $_.EventIds -contains 41 -and $_.Severity -eq 'Critical' -and $_.Account -eq 'victim' }).Count -eq 1) 'KDC 41 correlated via the live SerialNumber field (spaces / case ignored, 29 days apart) is Critical'
Assert-IR (@($kr.Findings | Where-Object { $_.EventIds -contains 40 -and $_.Severity -eq 'Medium' -and $_.Account -eq 'carol' }).Count -eq 1) 'KDC 40 alone is Medium'
Assert-IR (@($kr.Findings | Where-Object { $_.Account -in @('dave', 'HOST01$', 'jdoe', '') }).Count -eq 0 -and $kr.Findings.Count -eq 2 -and $kr.Errors.Count -eq 0) 'clean / host-name / naming-convention KDC 39s and an identity-less 41 are silent; no stray errors'

# Regression (review, Rule 1b): a UPN prefix that differs from the sAMAccountName (jdoe / john.doe) and a multi-SAN
# web certificate that includes the requester's own host are NOT on-behalf-of; one lone mismatch per requester is
# rolled up into a single Medium review finding instead of a High per requester; -PrivilegedUpn escalates a pair.
$fp = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T14:00:00Z'; EventId = 4887; Computer = 'CA01'; LogName = 'Security'; Requester = 'CORP\jdoe'; Attributes = 'CertificateTemplate:User'; CertificateTemplate = 'User'; RequestId = '3001'; SubjectAlternativeName = 'Other Name: Principal Name=john.doe@corp.local'; SerialNumber = '3001' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T14:01:00Z'; EventId = 4887; Computer = 'CA01'; LogName = 'Security'; Requester = 'CORP\WEB02$'; Attributes = 'CertificateTemplate:WebServer'; CertificateTemplate = 'WebServer'; RequestId = '3002'; SubjectAlternativeName = 'DNS Name=www.corp.local, DNS Name=web02.corp.local'; SerialNumber = '3002' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T14:02:00Z'; EventId = 4887; Computer = 'CA01'; LogName = 'Security'; Requester = 'CORP\svc_enroll'; Attributes = 'CertificateTemplate:User'; CertificateTemplate = 'User'; RequestId = '3003'; SubjectAlternativeName = 'Other Name: Principal Name=mary@corp.local'; SerialNumber = '3003' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T14:03:00Z'; EventId = 4887; Computer = 'CA01'; LogName = 'Security'; Requester = 'CORP\pkiops'; Attributes = 'CertificateTemplate:WebServer'; CertificateTemplate = 'WebServer'; RequestId = '3004'; SubjectAlternativeName = 'DNS Name=intranet.corp.local'; SerialNumber = '3004' }
)
$fpr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $fp; Quiet = $true }
Assert-IR (@($fpr.Findings | Where-Object { $_.Account -like '*jdoe*' -or $_.Account -like '*WEB02*' -or $_.Description -like '*john.doe*' -or $_.Description -like '*web02*' }).Count -eq 0) 'UPN-prefix convention (jdoe / john.doe) and own-host multi-SAN web cert not flagged'
$roll = @($fpr.Findings | Where-Object { $_.Title -like '*one each*' })
Assert-IR ($roll.Count -eq 1 -and $roll[0].Severity -eq 'Medium' -and $roll[0].Description -like '*svc_enroll -> mary@corp.local*' -and $roll[0].Description -like '*pkiops -> intranet.corp.local*') 'lone mismatches (svc_enroll -> mary, pkiops -> intranet) rolled up into one Medium review finding'
Assert-IR ($fpr.Findings.Count -eq 1 -and $fpr.Errors.Count -eq 0) 'no per-requester High for lone mismatches; no stray errors'
$pv = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $fp; Quiet = $true; PrivilegedUpn = @('mary@corp.local') }
Assert-IR (@($pv.Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Account -like '*svc_enroll*' }).Count -eq 1) 'privileged identity in a lone mismatch escalates that requester to Critical'

Complete-IRTest
