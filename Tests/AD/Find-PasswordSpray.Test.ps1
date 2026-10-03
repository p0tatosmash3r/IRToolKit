. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-PasswordSpray.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-PasswordSpray.json'

# Full malicious sample.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 3) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1110.003').Count -eq $f.Count) 'all findings tagged T1110.003'

# RULE 1 - classic NTLM (4625) spray from 10.10.20.66, High, >= 15 distinct accounts.
$spray66 = @($f | Where-Object { $_.SourceIp -eq '10.10.20.66' -and $_.Title -like 'Password spray*' })
Assert-IR ($spray66.Count -ge 1) 'RULE1 spray from 10.10.20.66 detected'
Assert-IR (@($spray66 | Where-Object Severity -eq 'High').Count -ge 1) 'RULE1 spray is High severity'
Assert-IR ($spray66[0].DistinctAccounts -ge 15) 'RULE1 spray counts >= 15 distinct accounts'

# RULE 2 - the spray succeeded, Critical, naming user07.
$succeeded = @($f | Where-Object { $_.Severity -eq 'Critical' -and $_.Title -like '*succeeded*' })
Assert-IR ($succeeded.Count -ge 1) 'RULE2 succeeded finding raised'
Assert-IR (@($succeeded | Where-Object { $_.Account -like 'user07*' }).Count -ge 1) 'RULE2 names compromised account user07'
Assert-IR ($succeeded[0].SourceIp -eq '10.10.20.66') 'RULE2 ties the success to the spray source'

# RULE 1 - Kerberos pre-auth (4771) spray from the second source 10.10.20.77, High.
$spray77 = @($f | Where-Object { $_.SourceIp -eq '10.10.20.77' })
Assert-IR ($spray77.Count -ge 1) 'RULE1 4771 spray from 10.10.20.77 detected'
Assert-IR (@($spray77 | Where-Object Severity -eq 'High').Count -ge 1) 'RULE1 4771 spray is High severity'

# Benign: a single account (bob) failing repeatedly is brute force / lockout, never spray.
Assert-IR (@($f | Where-Object { $_.Target -like '*bob*' }).Count -eq 0) 'single-account bob not flagged as spray'
Assert-IR (@($f | Where-Object { $_.SourceIp -like '*10.10.20.30*' }).Count -eq 0) "bob's source not flagged"

# Benign: a source below the distinct-account threshold is not flagged.
Assert-IR (@($f | Where-Object { $_.SourceIp -like '*10.10.20.31*' }).Count -eq 0) 'below-threshold source (10.10.20.31) not flagged'

# Benign-only subset (drop both attacker sources) must be clean and error-free.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.IpAddress -notlike '*10.10.20.66*' -and $_.IpAddress -ne '10.10.20.77'
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
