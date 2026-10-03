. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-Kerberoasting.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-Kerberoasting.json'

# Full malicious sample (AD lookups disabled so the test is deterministic offline).
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 2) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1558.003').Count -eq $f.Count) 'all findings tagged T1558.003'

# RC4 burst by jdoe should be High + weak-cipher.
$jdoe = @($f | Where-Object { $_.Account -like 'jdoe*' -and $_.Title -like '*RC4*' })
Assert-IR ($jdoe.Count -ge 1) 'jdoe RC4 burst detected'
Assert-IR (@($jdoe | Where-Object Severity -eq 'High').Count -ge 1) 'jdoe RC4 burst is High severity'
Assert-IR ($jdoe[0].SourceIp -eq '10.10.20.66') 'IPv4-mapped source IP normalised'

# AES opsec burst by mallory should be caught by the volume rule (High).
$mallory = @($f | Where-Object { $_.Account -like 'mallory*' })
Assert-IR ($mallory.Count -ge 1) 'mallory AES volume burst detected'
Assert-IR (@($mallory | Where-Object Severity -eq 'High').Count -ge 1) 'mallory burst is High severity'

# Benign activity must not be flagged.
Assert-IR (@($f | Where-Object { $_.Account -like 'bob*' }).Count -eq 0) 'single AES ticket (bob) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'WS-101*' }).Count -eq 0) 'machine->machine cifs ticket not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*krbtgt*' }).Count -eq 0) 'krbtgt ticket excluded'
Assert-IR (@($f | Where-Object { $_.Target -like '*WS-101$*' }).Count -eq 0) 'machine service account excluded'

# Legacy single RC4 request should surface as Medium (hygiene), not High.
$legacy = @($f | Where-Object { $_.Account -like 'legacyapp*' })
Assert-IR ($legacy.Count -eq 1 -and $legacy[0].Severity -eq 'Medium') 'single legacy RC4 request is Medium'

# PowerShell tooling script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'Kerberoast script block detected'

# Honeypot fires immediately and as Critical.
$hp = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true; HoneypotAccount = @('svc_legacy') }
Assert-IR (@($hp.Findings | Where-Object { $_.Title -like '*honeypot*' -and $_.Severity -eq 'Critical' }).Count -ge 1) 'honeypot request is Critical'

# Benign-only subset -> no findings. Keep only the genuinely benign events:
# bob (single AES), WS-101$ (machine->machine), alice/krbtgt, charlie (failure). Exclude the
# two attacker IPs, the lone-RC4 legacyapp (intentionally Medium) and the tooling script block.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.IpAddress -notlike '*10.10.20.66*' -and $_.IpAddress -ne '10.10.20.77' -and
        $_.EventId -ne 4104 -and $_.ServiceName -ne 'svc_legacy'
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; NoADLookup = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; NoADLookup = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
