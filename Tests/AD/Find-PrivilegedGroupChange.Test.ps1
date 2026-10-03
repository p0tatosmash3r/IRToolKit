. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-PrivilegedGroupChange.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-PrivilegedGroupChange.json'

# Full malicious sample.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 1) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1098').Count -eq $f.Count) 'all findings tagged T1098'

# Rule 1 - Domain Admins add is Critical and names both eviluser (member) and helpdeskguy (actor).
$da = @($f | Where-Object { $_.Title -eq 'Principal added to privileged group' -and $_.Target -like '*Domain Admins*' })
Assert-IR ($da.Count -ge 1) 'Domain Admins add detected'
Assert-IR (@($da | Where-Object Severity -eq 'Critical').Count -ge 1) 'Domain Admins add is Critical'
Assert-IR ($da[0].Account -like '*helpdeskguy*') 'Domain Admins add names the actor helpdeskguy'
Assert-IR ($da[0].Description -like '*eviluser*' -or $da[0].Target -like '*eviluser*') 'Domain Admins add names the member eviluser'
Assert-IR ($da[0].EventIds -contains 4728) 'Domain Admins add is event 4728'

# Rule 3 - Enterprise Admins stealth add/remove produces a High stealth finding ...
$stealth = @($f | Where-Object { $_.Title -like '*temporary elevation*' -and $_.Target -like '*Enterprise Admins*' })
Assert-IR ($stealth.Count -ge 1) 'EA stealth add-then-remove detected'
Assert-IR (@($stealth | Where-Object Severity -eq 'High').Count -ge 1) 'EA stealth finding is High severity'
Assert-IR ($stealth[0].EventIds -contains 4756 -and $stealth[0].EventIds -contains 4757) 'EA stealth finding correlates 4756 + 4757'
# ... AND the EA add itself is Critical.
$eaAdd = @($f | Where-Object { $_.Title -eq 'Principal added to privileged group' -and $_.Target -like '*Enterprise Admins*' })
Assert-IR ($eaAdd.Count -ge 1 -and @($eaAdd | Where-Object Severity -eq 'Critical').Count -ge 1) 'EA add is Critical'

# Rule 1 - built-in Administrators add (S-1-5-32-544) is Critical.
$admins = @($f | Where-Object { $_.Title -eq 'Principal added to privileged group' -and $_.Target -like 'Administrators <-*' })
Assert-IR ($admins.Count -ge 1 -and @($admins | Where-Object Severity -eq 'Critical').Count -ge 1) 'built-in Administrators add is Critical'
Assert-IR ($admins[0].EventIds -contains 4732) 'built-in Administrators add is event 4732'

# Rule 1 - DnsAdmins add (privileged by capability) is High, not Critical.
$dns = @($f | Where-Object { $_.Title -eq 'Principal added to privileged group' -and $_.Target -like '*DnsAdmins*' })
Assert-IR ($dns.Count -ge 1) 'DnsAdmins add detected'
Assert-IR ($dns[0].Severity -eq 'High') 'DnsAdmins add is High (capability group, not Critical)'

# Benign non-privileged group 'All Staff' changes must NOT be flagged.
Assert-IR (@($f | Where-Object { $_.Target -like '*All Staff*' -or $_.Description -like '*All Staff*' }).Count -eq 0) 'non-privileged All Staff changes not flagged'

# Benign-only subset (only the non-privileged 'All Staff' events) -> no findings, no errors.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.TargetUserName -eq 'All Staff' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Regression (real-log FP): IIS_IUSRS (S-1-5-32-568) is no longer treated as a privileged group - IIS setup
# routinely adds IUSR (S-1-5-17) to it. A real built-in privileged group (Administrators, 544) still fires.
$iis = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:00:00Z'; EventId = 4732; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'SYSTEM'; SubjectUserSid = 'S-1-5-18'; TargetUserName = 'IIS_IUSRS'; TargetSid = 'S-1-5-32-568'; MemberSid = 'S-1-5-17' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:01:00Z'; EventId = 4732; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; SubjectUserSid = 'S-1-5-21-1-2-3-1107'; TargetUserName = 'Administrators'; TargetSid = 'S-1-5-32-544'; MemberName = 'CN=rogue,CN=Users,DC=lab,DC=internal'; MemberSid = 'S-1-5-21-1-2-3-1200' }
)
$iisr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $iis; Quiet = $true }
Assert-IR (@($iisr.Findings | Where-Object { $_.Target -like '*IIS_IUSRS*' }).Count -eq 0) 'IIS_IUSRS membership change not flagged (not a privileged group)'
Assert-IR (@($iisr.Findings | Where-Object { $_.Target -like '*Administrators*' }).Count -eq 1) 'built-in Administrators add still flagged'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
