. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-SkeletonKey.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-SkeletonKey.json'
$dcs = @('DC01', 'DC02', 'DC03', 'DC04', 'DC05')

$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = $dcs }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1556.001').Count -eq $f.Count) 'all findings tagged T1556.001'

# RULE 1 - RC4 downgrade burst on DC01 (confirmed AES downgrades -> High; single-signal DC -> not escalated).
$burst = @($f | Where-Object { $_.Title -like '*RC4 encryption downgrade*' -and $_.Computer -eq 'DC01' })
Assert-IR ($burst.Count -eq 1) 'RC4 downgrade burst on DC01 detected'
Assert-IR ($burst[0].Severity -eq 'High') 'RC4 burst with confirmed AES downgrades is High'
Assert-IR ($burst[0].Confidence -eq 'High') 'RC4 burst confidence High when AES downgrade confirmed'
Assert-IR ($burst[0].EventIds -contains 4768) 'RC4 burst is event 4768'
Assert-IR ($burst[0].Description -like '*9 distinct*') 'machine / krbtgt / AES accounts excluded (exactly 9 distinct users)'

# RULE 4 - tooling in a 4104 script block on DC02 -> Critical (skeleton-specific signature).
$tool4104 = @($f | Where-Object { $_.EventIds -contains 4104 })
Assert-IR ($tool4104.Count -eq 1 -and $tool4104[0].Severity -eq 'Critical') 'skeleton-key tooling script block is Critical'

# CORRELATION - DC02 shows notable privilege use + tooling, so the 4673 finding is escalated to Critical.
$priv02 = @($f | Where-Object { $_.EventIds -contains 4673 -and $_.Computer -eq 'DC02' })
Assert-IR ($priv02.Count -eq 1) 'LSASS sensitive-privilege use on DC02 detected'
Assert-IR ($priv02[0].Severity -eq 'Critical') 'DC02 privilege finding escalated to Critical by correlation'
Assert-IR ($priv02[0].Description -like '*CORRELATION*') 'correlation note added to the escalated finding'

# RULE 1 single - AES-capable account issued RC4 on DC03 (single DC) -> Medium.
$single = @($f | Where-Object { $_.Title -like '*AES-capable account issued an RC4*' })
Assert-IR ($single.Count -eq 1 -and $single[0].Severity -eq 'Medium') 'single AES-capable RC4 downgrade is Medium'
Assert-IR ($single[0].Account -eq 'bob') 'single downgrade names the account'

# RULE 3 - known-bad driver install on DC04 -> High.
$drv = @($f | Where-Object { $_.Title -like '*driver installed*' -and $_.Computer -eq 'DC04' })
Assert-IR ($drv.Count -eq 1 -and $drv[0].Severity -eq 'High') 'known-bad driver install on DC04 is High'
Assert-IR ($drv[0].Target -eq 'mimidrv') 'driver finding names the service'

# RULE 2 standalone - a named EDR account using SeDebug from a normal path is a quiet Low feeder, not High.
$edr = @($f | Where-Object { $_.EventIds -contains 4673 -and $_.Account -eq 'edrsvc' })
Assert-IR ($edr.Count -eq 1 -and $edr[0].Severity -eq 'Low') 'benign EDR SeDebug is Low (correlation feeder), not High'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4673 -and $_.Computer -eq 'DC01' }).Count -eq 0) 'boot-time SYSTEM/lsass SeTcb (4673) excluded by default'
Assert-IR (@($f | Where-Object { $_.Target -eq 'MyApp' }).Count -eq 0) 'ordinary user-mode service install not flagged'
Assert-IR (@($f | Where-Object { $_.Computer -eq 'SOC-NAMING' }).Count -eq 0) 'naming a tool in a comment / hunt query / filename does not fire (even for crit signatures)'
Assert-IR (@($f | Where-Object { $_.Computer -eq 'WS-ADMIN' }).Count -eq 0) 'opening a tool output / plan file does not fire'

# -ExcludeAccount suppresses a known SeDebug tool account; strong signals survive.
$ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = $dcs; ExcludeAccount = @('edrsvc') }
Assert-IR (@($ex.Findings | Where-Object { $_.Account -eq 'edrsvc' }).Count -eq 0) 'edrsvc suppressed by -ExcludeAccount'
Assert-IR (@($ex.Findings | Where-Object { $_.Title -like '*RC4 encryption downgrade*' }).Count -eq 1) 'strong signals survive -ExcludeAccount of an unrelated account'

# -IncludeSystem surfaces the boot-time SYSTEM/lsass SeTcb that is hidden by default.
$incSys = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = $dcs; IncludeSystem = $true }
Assert-IR (@($incSys.Findings | Where-Object { $_.EventIds -contains 4673 -and $_.Computer -eq 'DC01' }).Count -eq 1) 'SYSTEM/lsass SeTcb surfaced with -IncludeSystem'

# Graceful degrade: no signature file -> RULE 4 disabled, behavioural rules still run, no errors.
$noSig = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = $dcs; SignatureFile = (Join-Path $PSScriptRoot 'no-such-signatures.json') }
Assert-IR ($noSig.Errors.Count -eq 0) 'missing signature file does not error'
Assert-IR (@($noSig.Findings | Where-Object { $_.EventIds -contains 4104 }).Count -eq 0) 'tooling rule disabled when signature file is absent'
Assert-IR (@($noSig.Findings | Where-Object { $_.Title -like '*RC4 encryption downgrade*' }).Count -eq 1) 'behavioural RC4 rule still runs without the signature file'

# Regression (R3-MAJOR): a MALFORMED signature file degrades silently - no stray error records.
$badSig = Join-Path ([IO.Path]::GetTempPath()) ("sk-bad-{0}.json" -f ([guid]::NewGuid().ToString('N')))
Set-Content -LiteralPath $badSig -Value '{ "tooling": [ {"category":"crit", "value": } BROKEN' -Encoding ASCII
try {
    $mal = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = $dcs; SignatureFile = $badSig }
    Assert-IR ($mal.Errors.Count -eq 0) 'malformed signature file degrades with zero stray error records'
    Assert-IR (@($mal.Findings | Where-Object { $_.EventIds -contains 4104 }).Count -eq 0) 'malformed signature file disables RULE 4'
    Assert-IR (@($mal.Findings | Where-Object { $_.Title -like '*RC4 encryption downgrade*' }).Count -eq 1) 'behavioural rules still run with a malformed signature file'
}
finally { Remove-Item -LiteralPath $badSig -Force -ErrorAction SilentlyContinue }

# Regression (R1-MAJOR): an RC4 burst with NO AES-downgrade evidence is Medium, not High.
$noaes = @(0..7 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T11:00:00Z').AddSeconds($_ * 20).ToString('o'); EventId = 4768; Computer = 'DCR1'; LogName = 'Security'; TargetUserName = ("legacy$_"); TargetDomainName = 'CORP'; TicketEncryptionType = '0x17'; Status = '0x0'; IpAddress = ("10.1.1.$_") } })
$rn = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $noaes; Quiet = $true }
$rnb = @($rn.Findings | Where-Object { $_.Title -like '*RC4 encryption downgrade*' })
Assert-IR ($rnb.Count -eq 1 -and $rnb[0].Severity -eq 'Medium') 'RC4 burst with no AES evidence is Medium (not High)'

# Regression (R2-MAJOR#1): an operator running as SYSTEM with SeDebug from a temp path is NOT excluded.
$sysop = @([pscustomobject]@{ TimeCreated = '2026-09-30T11:10:00Z'; EventId = 4673; Computer = 'DCR2'; LogName = 'Security'; SubjectUserName = 'SYSTEM'; SubjectUserSid = 'S-1-5-18'; PrivilegeList = 'SeDebugPrivilege'; ProcessName = 'C:\Windows\Temp\runner.exe'; Service = '-' })
$rs = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $sysop; Quiet = $true }
$rsf = @($rs.Findings | Where-Object { $_.EventIds -contains 4673 -and $_.Computer -eq 'DCR2' })
Assert-IR ($rsf.Count -eq 1 -and $rsf[0].Severity -eq 'High') 'SYSTEM+SeDebug from a temp path fires High (operator-as-SYSTEM not excluded)'

# Regression (R2-MAJOR#2): a benign service whose path merely contains "PowerShell" is not flagged.
$pwsh = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T11:20:00Z'; EventId = 7045; Computer = 'DCR3'; LogName = 'System'; ServiceName = 'VendorSvc'; ImagePath = 'C:\Program Files\PowerShell\7\supportsvc.exe'; ServiceType = 'user mode service'; StartType = 'auto start' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T11:21:00Z'; EventId = 4697; Computer = 'DCR3'; LogName = 'Security'; SubjectUserName = 'admin'; ServiceName = 'AcmePsToolkit'; ServiceFileName = 'C:\Program Files\Acme PowerShell Toolkit\acme.exe'; ServiceType = '0x10'; ServiceStartType = '2' }
)
$rp = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $pwsh; Quiet = $true; DomainController = @('DCR3') }
Assert-IR ($rp.Findings.Count -eq 0) 'services with "PowerShell" only in the path/name are not flagged'

# Regression (R3 minor): a clean-path signed driver on a DC is Medium, not a High firehose.
$cleandrv = @([pscustomobject]@{ TimeCreated = '2026-09-30T11:30:00Z'; EventId = 7045; Computer = 'DCR4'; LogName = 'System'; ServiceName = 'VendorNicFilter'; ImagePath = 'C:\Windows\System32\drivers\vnicflt.sys'; ServiceType = 'kernel mode driver'; StartType = 'boot start' })
$rc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $cleandrv; Quiet = $true; DomainController = @('DCR4') }
$rcf = @($rc.Findings | Where-Object { $_.Title -like '*driver installed*' })
Assert-IR ($rcf.Count -eq 1 -and $rcf[0].Severity -eq 'Medium') 'clean-path driver on a DC is Medium, not High'

# Regression (R5-BLOCKER): correlation ties signals on the same DC across name forms (short vs FQDN).
$nameform = @(0..7 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T12:00:00Z').AddSeconds($_ * 20).ToString('o'); EventId = 4768; Computer = 'DCR5'; LogName = 'Security'; TargetUserName = ("w$_"); TargetDomainName = 'CORP'; TicketEncryptionType = '0x17'; Status = '0x0'; IpAddress = ("10.2.2.$_") } })
$nameform += [pscustomobject]@{ TimeCreated = '2026-09-30T12:02:00Z'; EventId = 4673; Computer = 'DCR5.corp.local'; LogName = 'Security'; SubjectUserName = 'attacker'; SubjectUserSid = 'S-1-5-21-9-9-9-1111'; PrivilegeList = 'SeDebugPrivilege'; ProcessName = 'C:\Windows\Temp\x.exe'; Service = '-' }
$nf = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $nameform; Quiet = $true }
Assert-IR (@($nf.Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Description -like '*CORRELATION*' }).Count -eq 2) 'correlation ties RC4 (short name) + LSASS priv (FQDN) on the same DC'

# Regression (R6-MAJOR): a lone service/driver does NOT by itself make a DC hot (service excluded from the count).
$svcnocorr = @(0..7 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T13:00:00Z').AddSeconds($_ * 20).ToString('o'); EventId = 4768; Computer = 'DCR6'; LogName = 'Security'; TargetUserName = ("leg$_"); TargetDomainName = 'CORP'; TicketEncryptionType = '0x17'; Status = '0x0'; IpAddress = ("10.3.3.$_") } })
$svcnocorr += [pscustomobject]@{ TimeCreated = '2026-09-30T13:05:00Z'; EventId = 7045; Computer = 'DCR6'; LogName = 'System'; ServiceName = 'VendorDrv'; ImagePath = 'C:\Windows\System32\drivers\vdrv.sys'; ServiceType = 'kernel mode driver'; StartType = 'boot start' }
$sn = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $svcnocorr; Quiet = $true; DomainController = @('DCR6') }
Assert-IR (@($sn.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 0) 'RC4 + a lone driver (no priv/tool) is NOT escalated to Critical'
Assert-IR (@($sn.Findings | Where-Object { $_.Title -like '*RC4 encryption downgrade*' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'the no-AES RC4 burst stays Medium without correlation'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        ($_.EventId -eq 4768 -and $_.TargetUserName -in @('alice', 'WS-9$', 'krbtgt')) -or
        ($_.EventId -eq 4673 -and $_.SubjectUserName -eq 'DC01$') -or
        ($_.EventId -eq 7045 -and $_.ServiceName -eq 'MyApp') -or
        ($_.Computer -eq 'SOC-NAMING') -or ($_.Computer -eq 'WS-ADMIN')
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = $dcs }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Regression (real-log FP): Microsoft Defender's service in ProgramData\Windows Defender\Platform is NOT
# flagged (benign allowlist), while a non-Defender service under ProgramData still is (narrow exception).
$defender = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:00:00Z'; EventId = 7045; Computer = 'DC01'; LogName = 'System'; ServiceName = 'MDCoreSvc'; ImagePath = '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe"'; ServiceType = 'user mode service'; StartType = 'auto start' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:01:00Z'; EventId = 7045; Computer = 'DC01'; LogName = 'System'; ServiceName = 'Sketchy'; ImagePath = 'C:\ProgramData\Updater\svc.exe'; ServiceType = 'user mode service'; StartType = 'auto start' }
    # Evasion attempts that the TIGHTENED allowlist must still flag:
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:02:00Z'; EventId = 7045; Computer = 'DC01'; LogName = 'System'; ServiceName = 'EvilInDefenderDir'; ImagePath = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\evil.exe'; ServiceType = 'user mode service'; StartType = 'auto start' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:03:00Z'; EventId = 7045; Computer = 'DC01'; LogName = 'System'; ServiceName = 'DefenderSubstr'; ImagePath = 'C:\Windows\Temp\Microsoft\Windows Defender\Platform\x\payload.exe'; ServiceType = 'user mode service'; StartType = 'auto start' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:04:00Z'; EventId = 7045; Computer = 'DC01'; LogName = 'System'; ServiceName = 'DefenderTraversal'; ImagePath = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\..\..\..\..\Windows\Temp\x.exe'; ServiceType = 'user mode service'; StartType = 'auto start' }
)
$def = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $defender; Quiet = $true; DomainController = @('DC01') }
Assert-IR (@($def.Findings | Where-Object { $_.Target -eq 'MDCoreSvc' }).Count -eq 0) 'genuine Defender platform binary not flagged (benign allowlist)'
Assert-IR (@($def.Findings | Where-Object { $_.Target -eq 'Sketchy' }).Count -eq 1) 'a non-Defender ProgramData service is still flagged'
Assert-IR (@($def.Findings | Where-Object { $_.Target -eq 'EvilInDefenderDir' }).Count -eq 1) 'a non-Defender binary dropped IN the Defender folder is still flagged (allowlist is binary-specific)'
Assert-IR (@($def.Findings | Where-Object { $_.Target -eq 'DefenderSubstr' }).Count -eq 1) 'the Defender path embedded in a temp path (substring) is still flagged (anchored to drive root)'
Assert-IR (@($def.Findings | Where-Object { $_.Target -eq 'DefenderTraversal' }).Count -eq 1) 'a Defender path with ..\ traversal is still flagged'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
