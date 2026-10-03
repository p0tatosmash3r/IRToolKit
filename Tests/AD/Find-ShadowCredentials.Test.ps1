. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ShadowCredentials.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ShadowCredentials.json'

# Full malicious sample (AD lookups disabled so the test is deterministic offline).
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 1) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1098.001').Count -eq $f.Count) 'all findings tagged T1098.001'

# RULE1 - key credential added to the CFO object by eviluser (actor != target) is High.
$cfo = @($f | Where-Object { $_.Account -like '*eviluser*' -and $_.Target -like '*CFO*' -and $_.Title -like '*added*' })
Assert-IR ($cfo.Count -ge 1) 'CFO key-credential add detected'
Assert-IR (@($cfo | Where-Object Severity -eq 'High').Count -ge 1) 'CFO add is High severity naming eviluser'

# RULE3 - the svc_target add correlates with the PKINIT TGT => Critical naming svc_target.
$pkinit = @($f | Where-Object { $_.Severity -eq 'Critical' -and $_.Title -like '*PKINIT*' -and ($_.Account -like '*svc_target*' -or $_.Target -like '*svc_target*') })
Assert-IR ($pkinit.Count -ge 1) 'correlated add-then-PKINIT on svc_target is Critical'

# RULE4 - tooling script block detected.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'Shadow Credentials tooling script block detected'

# Benign events must not be flagged.
Assert-IR (@($f | Where-Object { $_.Account -like '*alice*' -or $_.Target -like '*alice*' }).Count -eq 0) 'self-enrollment (alice) not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*bob*' }).Count -eq 0) 'unrelated-attribute change (displayName) not flagged'

# RULE1 escalation - the DC02 add becomes Critical only when DC02 is known to be a domain controller.
$dc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; NoADLookup = $true; DomainController = @('DC02') }
$dcAdd = @($dc.Findings | Where-Object { $_.Target -like '*DC02*' -and $_.Title -like '*added*' })
Assert-IR ($dc.Errors.Count -eq 0) 'DC run has no stray errors'
Assert-IR ($dcAdd.Count -ge 1 -and (@($dcAdd | Where-Object Severity -eq 'Critical').Count -ge 1)) 'DC02 key-credential add is Critical with -DomainController DC02'

# Benign-only subset -> no findings. Keep only the genuinely benign 5136 events (alice self-enroll, bob displayName).
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -eq 'alice' -or $_.SubjectUserName -eq 'helpdesk' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; NoADLookup = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; NoADLookup = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
