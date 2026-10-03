. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ADReconnaissance.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ADReconnaissance.json'

$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 4) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object { $_.Technique -in @('T1087.002', 'T1069.002', 'T1482', 'T1018') }).Count -eq $f.Count) 'all findings tagged a recon technique'

# RULE 1 - BloodHound-style LDAP filters (1644) from the attacker client -> High.
$ldap = @($f | Where-Object { $_.EventIds -contains 1644 -and $_.Title -like '*LDAP reconnaissance*' })
Assert-IR ($ldap.Count -ge 1) 'BloodHound LDAP filter recon detected'
Assert-IR ($ldap[0].Severity -eq 'High') 'LDAP recon-filter finding is High'
Assert-IR ($ldap[0].SourceIp -eq '10.10.20.66') 'LDAP recon client captured'

# RULE 2 - mass local-group enumeration (4799 burst) by 'collector' -> High.
$enum = @($f | Where-Object { $_.Title -like '*local-group*' -and $_.Account -eq 'collector' })
Assert-IR ($enum.Count -ge 1) 'mass local-group enumeration burst detected'
Assert-IR ($enum[0].Severity -eq 'High') 'enumeration burst is High'
Assert-IR ($enum[0].Technique -eq 'T1069.002') 'enumeration tagged T1069.002'

# RULE 3 - tooling.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'BloodHound/PowerView tooling script block detected'

# RULE 4 - recon processes: AdFind (High) and net group /domain (Medium).
$adfind = @($f | Where-Object { $_.EventIds -contains 4688 -and $_.Target -like '*AdFind*' })
Assert-IR ($adfind.Count -ge 1 -and $adfind[0].Severity -eq 'High') 'AdFind execution detected as High'
$netgrp = @($f | Where-Object { $_.EventIds -contains 4688 -and $_.Description -like '*Domain Admins*' })
Assert-IR ($netgrp.Count -ge 1 -and $netgrp[0].Severity -eq 'Medium') 'net group /domain detected as Medium'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.SourceIp -eq '10.10.20.5' }).Count -eq 0) 'single targeted LDAP lookup not flagged'
Assert-IR (@($f | Where-Object { $_.Account -eq 'SYSTEM' }).Count -eq 0) 'single SYSTEM group enumeration not flagged'
Assert-IR (@($f | Where-Object { $_.Description -like '*whoami*' }).Count -eq 0) 'benign whoami /groups not flagged'

# -ExcludeAccount suppresses the collector (RULE 2) and a scanner client (RULE 1).
$ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; ExcludeAccount = @('collector', '10.10.20.66') }
Assert-IR (@($ex.Findings | Where-Object { $_.Account -eq 'collector' }).Count -eq 0) 'enumeration burst suppressed by -ExcludeAccount'
Assert-IR (@($ex.Findings | Where-Object { $_.SourceIp -eq '10.10.20.66' }).Count -eq 0) 'LDAP recon client suppressed by -ExcludeAccount'

# Benign-only subset -> no findings (drop the attacker client, the collector burst, tooling, recon procs).
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.Client -notlike '10.10.20.66*' -and $_.SubjectUserName -ne 'collector' -and
        $_.SubjectUserName -ne 'eviluser' -and $_.EventId -ne 4104
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression (Major 1): RULE 4 must match the image LEAF, not substrings of the command line / path.
$ov = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:00:00Z'; EventId = 4688; Computer = 'WS1'; LogName = 'Security'; SubjectUserName = 'analyst'; NewProcessName = 'C:\Windows\System32\notepad.exe'; CommandLine = 'notepad.exe "C:\Reports\SharpHound-20260930.json"' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:01:00Z'; EventId = 4688; Computer = 'WS1'; LogName = 'Security'; SubjectUserName = 'analyst'; NewProcessName = 'C:\Backup\adfind\archive.exe'; CommandLine = 'archive.exe --daily' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:02:00Z'; EventId = 4688; Computer = 'WS1'; LogName = 'Security'; SubjectUserName = 'eviluser'; NewProcessName = 'C:\Temp\SharpHound.exe'; CommandLine = 'SharpHound.exe -c All' }
)
$ovr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $ov; Quiet = $true }
Assert-IR (@($ovr.Findings | Where-Object { $_.Description -like '*notepad*' -or $_.Description -like '*archive.exe*' }).Count -eq 0) 'opening recon OUTPUT / dir named adfind not flagged'
Assert-IR (@($ovr.Findings | Where-Object { $_.Target -like '*SharpHound.exe*' -and $_.Severity -eq 'High' }).Count -eq 1) 'real SharpHound.exe process still High'

# Regression (Major 2): blank-subject 4799 across distinct SIDs/hosts must NOT fabricate one burst.
$blank = @(0..24 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T16:10:00Z').AddSeconds($_).ToString('o'); EventId = 4799; Computer = ("H$_"); LogName = 'Security'; TargetUserName = 'Administrators'; SubjectUserName = ''; SubjectUserSid = ("S-1-5-21-$_-$_-$_-1000"); CallerProcessName = ("C:\p$_.exe") } })
$bl = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $blank; Quiet = $true }
Assert-IR (@($bl.Findings | Where-Object { $_.Title -like '*enumeration*' }).Count -eq 0) 'blank-subject 4799 across distinct principals does not fabricate a burst'

# Regression (Minor 2): SYSTEM / machine mass enumeration excluded by default, included on demand.
$sysmass = @(0..24 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T16:20:00Z').AddSeconds($_).ToString('o'); EventId = 4799; Computer = ("H$_"); LogName = 'Security'; TargetUserName = 'Administrators'; SubjectUserName = 'SYSTEM'; SubjectUserSid = 'S-1-5-18'; CallerProcessName = 'C:\Windows\System32\svchost.exe' } })
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $sysmass; Quiet = $true }).Findings | Where-Object { $_.Title -like '*enumeration*' }).Count -eq 0) 'SYSTEM mass enumeration excluded by default'
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $sysmass; Quiet = $true; IncludeMachineAndSystem = $true }).Findings | Where-Object { $_.Title -like '*enumeration*' }).Count -eq 1) 'SYSTEM mass enumeration included with -IncludeMachineAndSystem'

# Regression (Major 3): IPv6 client is preserved intact and excludable; [ipv6]:port strips correctly.
$v6 = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:30:00Z'; EventId = 1644; Computer = 'DC01'; LogName = 'Directory Service'; Client = 'fe80::dead:beef:1'; Filter = '(samAccountType=805306368)' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:30:05Z'; EventId = 1644; Computer = 'DC01'; LogName = 'Directory Service'; Client = '[fe80::dead:beef:2]:51000'; Filter = '(objectClass=trustedDomain)' }
)
$v6a = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $v6; Quiet = $true }
Assert-IR (@($v6a.Findings | Where-Object { $_.SourceIp -eq 'fe80::dead:beef:1' }).Count -eq 1) 'bare IPv6 client preserved intact'
Assert-IR (@($v6a.Findings | Where-Object { $_.SourceIp -eq 'fe80::dead:beef:2' }).Count -eq 1) 'bracketed IPv6 port stripped to the address'
$v6ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $v6; Quiet = $true; ExcludeAccount = @('fe80::dead:beef:1') }
Assert-IR (@($v6ex.Findings | Where-Object { $_.SourceIp -eq 'fe80::dead:beef:1' }).Count -eq 0) 'IPv6 client suppressed by -ExcludeAccount'

# Regression (Minor 1): RULE 1 honours -ExcludeAccount against the 1644 issuing account, not only the IP.
$lu = @([pscustomobject]@{ TimeCreated = '2026-09-30T16:40:00Z'; EventId = 1644; Computer = 'DC01'; LogName = 'Directory Service'; Client = '10.10.20.200'; User = 'CORP\NESSUS_SVC'; Filter = '(samAccountType=805306368)' })
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $lu; Quiet = $true }).Findings).Count -eq 1) '1644 recon fires without exclusion'
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $lu; Quiet = $true; ExcludeAccount = @('NESSUS_SVC') }).Findings).Count -eq 0) '1644 recon suppressed by -ExcludeAccount against the issuing account'

Complete-IRTest
