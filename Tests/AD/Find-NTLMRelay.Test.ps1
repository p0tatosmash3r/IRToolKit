. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-NTLMRelay.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-NTLMRelay.json'

# Full malicious sample. DomainController lets RULE 1 recognise the relayed DC machine account.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1557.001').Count -eq $f.Count) 'all findings tagged T1557.001'

# RULE 1 - relayed DC machine account is Critical.
$dc = @($f | Where-Object { $_.Account -like 'DC01*' -and $_.Title -like '*Machine account NTLM*' })
Assert-IR ($dc.Count -ge 1) 'relayed DC machine account detected'
Assert-IR ($dc[0].Severity -eq 'Critical') 'relayed DC machine account is Critical'
Assert-IR ($dc[0].SourceIp -eq '10.10.20.66') 'relay source IP captured'

# RULE 1 - non-DC machine account is High (not Critical).
$srv = @($f | Where-Object { $_.Account -like 'FILESRV01*' -and $_.Title -like '*Machine account NTLM*' })
Assert-IR ($srv.Count -ge 1) 'relayed non-DC machine account detected'
Assert-IR ($srv[0].Severity -eq 'High') 'relayed non-DC machine account is High'

# RULE 2 - many accounts over NTLM from one source.
$farm = @($f | Where-Object { $_.Title -like '*Many accounts authenticated via NTLM*' -and $_.SourceIp -eq '10.10.20.66' })
Assert-IR ($farm.Count -ge 1) 'NTLM relay/harvest farm detected'
Assert-IR ($farm[0].Severity -eq 'High') 'relay farm is High'

# RULE 3 - 4776 validation spike from one workstation.
$harvest = @($f | Where-Object { $_.EventIds -contains 4776 })
Assert-IR ($harvest.Count -ge 1) '4776 validation spike detected'

# RULE 4 - NTLMv1 downgrade.
$v1 = @($f | Where-Object { $_.Title -like '*NTLMv1*' })
Assert-IR ($v1.Count -ge 1) 'NTLMv1 downgrade detected'
Assert-IR ($v1[0].Account -like 'legacysvc*') 'NTLMv1 finding names the account'

# RULE 5 - tooling in a PowerShell script block.
$tooling = @($f | Where-Object { $_.Title -like '*tooling*' -and $_.EventIds -contains 4104 })
Assert-IR ($tooling.Count -ge 1) 'Inveigh tooling script block detected'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Account -like 'alice*' }).Count -eq 0) 'Kerberos user logon (alice) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'WS-99*' }).Count -eq 0) 'Kerberos machine logon (WS-99$) not flagged'
Assert-IR (@($f | Where-Object { $_.SourceIp -eq '10.10.20.31' }).Count -eq 0) 'single benign NTLM user logon (bob) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'SYSTEM*' }).Count -eq 0) 'loopback/self NTLM logon not flagged'

# -ExcludeSource suppresses the burst rules for a known multi-user host.
$ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02'); ExcludeSource = @('10.10.20.66', 'KALI') }
Assert-IR (@($ex.Findings | Where-Object { $_.Title -like '*Many accounts authenticated via NTLM*' }).Count -eq 0) 'RULE2 suppressed by -ExcludeSource'
Assert-IR (@($ex.Findings | Where-Object { $_.EventIds -contains 4776 }).Count -eq 0) 'RULE3 suppressed by -ExcludeSource'
# The DC machine-account relay (RULE 1) is independent of -ExcludeSource and must still fire.
Assert-IR (@($ex.Findings | Where-Object { $_.Account -like 'DC01*' -and $_.Severity -eq 'Critical' }).Count -ge 1) 'RULE1 DC relay still fires despite -ExcludeSource'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.IpAddress -ne '10.10.20.66' -and $_.Workstation -ne 'KALI' -and $_.LmPackageName -ne 'NTLM V1' -and $_.EventId -ne 4104 })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression: DC relay escalation must survive UPN / DOMAIN\ TargetUserName forms (not just bare NAME$).
$upn = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:00:00Z'; EventId = 4624; Computer = 'DC02'; LogName = 'Security'; TargetUserName = 'DC01$@CORP.LOCAL'; TargetDomainName = 'CORP'; LogonType = '3'; AuthenticationPackageName = 'NTLM'; LmPackageName = 'NTLM V2'; WorkstationName = 'KALI'; IpAddress = '10.10.20.66' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:01:00Z'; EventId = 4624; Computer = 'DC02'; LogName = 'Security'; TargetUserName = 'CORP\DC02$'; TargetDomainName = 'CORP'; LogonType = '3'; AuthenticationPackageName = 'Negotiate'; LmPackageName = 'NTLM V2'; WorkstationName = 'KALI'; IpAddress = '10.10.20.66' }
)
$u = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $upn; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR (@($u.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 2) 'DC relay escalates to Critical for UPN and DOMAIN\ name forms'

# Regression: -ExcludeSource by workstation NAME suppresses the RULE 2 farm (not only by IP).
$farm = @(1..6 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T14:00:00Z').AddSeconds($_ * 20).ToString('o'); EventId = 4624; Computer = 'SRV'; LogName = 'Security'; TargetUserName = ('u' + $_); TargetDomainName = 'CORP'; LogonType = '3'; AuthenticationPackageName = 'NTLM'; LmPackageName = 'NTLM V2'; WorkstationName = 'SCCM01'; IpAddress = '10.10.30.50' } })
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $farm; Quiet = $true }).Findings).Count -ge 1) 'farm fires without exclusion'
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $farm; Quiet = $true; ExcludeSource = @('SCCM01') }).Findings).Count -eq 0) 'farm suppressed by -ExcludeSource workstation name'

# Regression: -ExcludeMachineAccount suppresses a confirmed-benign machine-account NTLM logon (RULE 1).
$mach = @([pscustomobject]@{ TimeCreated = '2026-09-30T15:00:00Z'; EventId = 4624; Computer = 'SRV'; LogName = 'Security'; TargetUserName = 'BACKUP01$'; TargetDomainName = 'CORP'; LogonType = '3'; AuthenticationPackageName = 'NTLM'; LmPackageName = 'NTLM V2'; WorkstationName = 'BACKUP01'; IpAddress = '10.10.40.10' })
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $mach; Quiet = $true }).Findings).Count -eq 1) 'benign machine NTLM fires by default'
Assert-IR (@((Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $mach; Quiet = $true; ExcludeMachineAccount = @('BACKUP01') }).Findings).Count -eq 0) 'machine NTLM suppressed by -ExcludeMachineAccount'

# Regression (NoADLookup wired): the DC list comes solely from -DomainController, so the run is
# equivalent to the baseline (DC relay escalation intact) and error-free.
$rNo = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02'); NoADLookup = $true }
Assert-IR ($rNo.Findings.Count -eq $f.Count -and $rNo.Errors.Count -eq 0) '-NoADLookup run matches the baseline and has no stray errors'
Assert-IR (@($rNo.Findings | Where-Object Severity -eq 'Critical').Count -eq @($f | Where-Object Severity -eq 'Critical').Count) '-NoADLookup keeps the DC-relay Critical escalation'

Complete-IRTest
