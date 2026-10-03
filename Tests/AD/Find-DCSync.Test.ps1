. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-DCSync.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-DCSync.json'

# Full sample WITH a DC list (DC02) and an approved replication account (MSOL) supplied.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC02'); KnownReplicationAccount = @('MSOL_a1b2c3') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 2) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1003.006').Count -eq $f.Count) 'all findings tagged T1003.006'

# DCSync by eviladmin -> Critical, mentions Get-Changes-All (full replication).
$evil = @($f | Where-Object { $_.Account -like '*eviladmin*' -and $_.EventIds -contains 4662 })
Assert-IR ($evil.Count -eq 1) 'DCSync by eviladmin detected (one grouped finding)'
Assert-IR ($evil[0].Severity -eq 'Critical') 'eviladmin DCSync is Critical'
Assert-IR ($evil[0].Description -like '*Get-Changes-All*') 'description mentions Get-Changes-All'
Assert-IR ($evil[0].Confidence -eq 'High') 'confidence High when DC list is supplied'
Assert-IR ($evil[0].EventCount -eq 2) 'two DCSync 4662 events grouped; ReadProperty-only 4662 not counted'

# Benign DC replication (DC02$) excluded by -DomainController DC02.
Assert-IR (@($f | Where-Object { $_.Account -like '*DC02*' }).Count -eq 0) 'DC02$ DC replication excluded with -DomainController'
# Approved sync account excluded by -KnownReplicationAccount.
Assert-IR (@($f | Where-Object { $_.Account -like '*MSOL*' }).Count -eq 0) 'MSOL replication account excluded'

# Tooling 4104 (mimikatz lsadump::dcsync) -> Critical.
$tooling = @($f | Where-Object { $_.EventIds -contains 4104 })
Assert-IR ($tooling.Count -ge 1) 'DCSync tooling script block detected'
Assert-IR ($tooling[0].Severity -eq 'Critical') 'tooling script block is Critical'

# Run WITHOUT -DomainController: eviladmin is still reported, but at Medium confidence with the note.
$n = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; KnownReplicationAccount = @('MSOL_a1b2c3') }
Assert-IR ($n.Errors.Count -eq 0) 'no-DC-list run has no errors'
$evilN = @($n.Findings | Where-Object { $_.Account -like '*eviladmin*' -and $_.EventIds -contains 4662 })
Assert-IR ($evilN.Count -ge 1) 'eviladmin reported even without a DC list'
Assert-IR ($evilN[0].Confidence -eq 'Medium') 'confidence lowered to Medium without a DC list'
Assert-IR ($evilN[0].Description -like '*DC exclusion could not be performed*') 'note about missing DC exclusion present'

# Benign-only subset (DC02$ + MSOL + ReadProperty eviladmin) with proper exclusions -> clean.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.EventId -eq 4662 -and ($_.SubjectUserName -eq 'DC02$' -or $_.SubjectUserName -eq 'MSOL_a1b2c3' -or ($_.SubjectUserName -eq 'eviladmin' -and $_.AccessMask -eq '0x10'))
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC02'); KnownReplicationAccount = @('MSOL_a1b2c3') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
