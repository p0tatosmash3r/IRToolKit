. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ASREPRoasting.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ASREPRoasting.json'

# Full malicious sample (AD lookups disabled so the test is deterministic offline).
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 4) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1558.004').Count -eq $f.Count) 'all findings tagged T1558.004'

# Rule 1 - roast sweep: High, source IP normalised, lists the four target accounts.
$sweep = @($f | Where-Object { $_.Title -like '*sweep*' })
Assert-IR ($sweep.Count -eq 1) 'AS-REP roast sweep detected'
Assert-IR ($sweep[0].Severity -eq 'High') 'roast sweep is High severity'
Assert-IR ($sweep[0].SourceIp -eq '10.10.20.66') 'IPv4-mapped source IP normalised'
$sweepText = "$($sweep[0].Target) $($sweep[0].Description)"
Assert-IR ($sweepText -like '*svc_legacy1*' -and $sweepText -like '*svc_report*' -and $sweepText -like '*oldadmin*' -and $sweepText -like '*serviceacct*') 'roast sweep lists all four target accounts'

# Rule 2 - user enumeration: Medium.
$enum = @($f | Where-Object { $_.Title -like '*enumeration*' })
Assert-IR ($enum.Count -eq 1 -and $enum[0].Severity -eq 'Medium') 'user enumeration detected as Medium'

# Rule 5 - tooling script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'AS-REP roasting script block detected'

# Rule 1 - single AES no-preauth account is Medium (not High).
$aes = @($f | Where-Object { $_.Account -like 'svc_aesonly*' })
Assert-IR ($aes.Count -eq 1) 'single AES no-preauth account produces one finding'
Assert-IR ($aes[0].Severity -eq 'Medium') 'single AES no-preauth account is Medium'

# Benign activity must not be flagged.
Assert-IR (@($f | Where-Object { $_.Account -like 'alice*' }).Count -eq 0) 'PA-ENC-TIMESTAMP logon (alice) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'bob*' }).Count -eq 0) 'smart-card/PKINIT logon (bob) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'WS-50*' }).Count -eq 0) 'machine account WS-50$ not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'carol*' }).Count -eq 0) 'bad-password failure (carol) not flagged'

# Rule 3 - honeypot fires immediately as Critical.
$hp = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true; HoneypotAccount = @('svc_legacy1') }
Assert-IR (@($hp.Findings | Where-Object { $_.Title -like '*honeypot*' -and $_.Severity -eq 'Critical' }).Count -ge 1) 'honeypot no-preauth AS-REQ is Critical'
Assert-IR ($hp.Errors.Count -eq 0) 'honeypot run has no errors'

# Benign-only subset -> no findings. Keep only the genuinely benign events: alice (PreAuth 2),
# bob (PKINIT), WS-50$ (machine), carol (failure). Exclude the attacker IP, the 4104 tooling event
# and the intentionally-Medium svc_aesonly.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.IpAddress -notlike '*10.10.20.66*' -and
        $_.EventId -ne 4104 -and
        $_.TargetUserName -ne 'svc_aesonly'
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; NoADLookup = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; NoADLookup = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
