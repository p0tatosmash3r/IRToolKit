. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-DCShadow.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-DCShadow.json'

# Full malicious sample. DC02 is a known DC so its legitimate replication SPNs / rights are excluded.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 4) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1207').Count -eq $f.Count) 'all findings tagged T1207'

# RULE 1 - DRS/GC SPN added to the non-DC WS-ROGUE$ (4742) -> Critical.
$spn = @($f | Where-Object { $_.Target -like 'WS-ROGUE*' -and $_.Title -like '*SPN added to a non-DC*' })
Assert-IR ($spn.Count -ge 1) 'rogue DRS/GC SPN on WS-ROGUE$ detected'
Assert-IR ($spn[0].Severity -eq 'Critical') 'rogue SPN finding is Critical'
Assert-IR ($spn[0].Account -like 'eviladmin*') 'rogue SPN finding names the actor'

# RULE 1 via 5136 - DRS SPN added to WS-PRINT2 computer object -> Critical.
Assert-IR (@($f | Where-Object { $_.Target -like 'WS-PRINT2*' -and $_.Severity -eq 'Critical' }).Count -ge 1) 'DRS SPN via 5136 on WS-PRINT2 detected'

# RULE 2+3 - transient nTDSDSA (created then deleted 3.5 min later) -> Critical, correlates 5137+5141.
$ntds = @($f | Where-Object { $_.Title -like '*Transient nTDSDSA*' })
Assert-IR ($ntds.Count -ge 1) 'transient rogue nTDSDSA detected'
Assert-IR ($ntds[0].Severity -eq 'Critical') 'transient nTDSDSA is Critical'
Assert-IR (($ntds[0].EventIds -contains 5137) -and ($ntds[0].EventIds -contains 5141)) 'transient nTDSDSA correlates create (5137) and delete (5141)'

# RULE 4 - push/topology replication rights by the non-DC eviladmin (4662) -> High.
$push = @($f | Where-Object { $_.Title -like '*push/topology rights*' -and $_.Account -like 'eviladmin*' })
Assert-IR ($push.Count -ge 1) 'replication push rights by non-DC detected'
Assert-IR ($push[0].Severity -eq 'High') 'replication push rights finding is High'

# RULE 5 - DCShadow tooling in a script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'DCShadow tooling script block detected'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Target -like 'DC02*' -or $_.Account -like 'DC02*' }).Count -eq 0) 'legitimate DC (DC02$) replication SPNs/rights not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like 'WS-50*' }).Count -eq 0) 'ordinary computer SPNs (WS-50$) not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like 'WS-77*' }).Count -eq 0) 'benign HTTP SPN add (WS-77) not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*New Hire*' }).Count -eq 0) 'benign user object creation not flagged'

# Without a DC list, WS-ROGUE still fires but the finding carries the no-DC-list caveat.
$noDc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
Assert-IR (@($noDc.Findings | Where-Object { $_.Target -like 'WS-ROGUE*' }).Count -ge 1) 'rogue SPN still reported without a DC list'
Assert-IR ($noDc.Errors.Count -eq 0) 'no-DC-list run has no stray errors'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -ne 'eviladmin' -and $_.TargetUserName -ne 'WS-ROGUE$' -and $_.EventId -ne 4104 })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression: known-DC exclusion must survive DOMAIN\ and UPN forms of the account name (RULE 1 + RULE 4).
$dcForms = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T08:00:00Z'; EventId = 4742; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'CORP\DC02$'; SubjectUserName = 'CORP\DC02$'; ServicePrincipalNames = "GC/DC02.corp.local/corp.local`r`nE3514235-4B06-11D1-AB04-00C04FC2DCD2/g1/corp.local" }
    [pscustomobject]@{ TimeCreated = '2026-09-30T08:01:00Z'; EventId = 4742; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'DC02$@CORP.LOCAL'; SubjectUserName = 'DC02$@CORP.LOCAL'; ServicePrincipalNames = "GC/DC02.corp.local/corp.local`r`nE3514235-4B06-11D1-AB04-00C04FC2DCD2/g2/corp.local" }
    [pscustomobject]@{ TimeCreated = '2026-09-30T08:02:00Z'; EventId = 4662; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'CORP\DC02$'; ObjectName = 'DC=corp,DC=local'; OperationType = 'Control Access'; AccessMask = '0x100'; Properties = '{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}' }
)
$df = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $dcForms; Quiet = $true; DomainController = @('DC02') }
Assert-IR ($df.Findings.Count -eq 0) 'known DC in DOMAIN\ and UPN forms is excluded (RULE 1 + RULE 4)'
Assert-IR ($df.Errors.Count -eq 0) 'DC-form run has no stray errors'

# Regression: an nTDSDSA delete that shares a DN with a create but falls OUTSIDE the window still gets
# its own standalone finding (create High + delete Medium), not silently dropped.
$dn = 'CN=NTDS Settings,CN=WS-LATE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local'
$overWindow = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T10:00:00Z'; EventId = 5137; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'nTDSDSA'; ObjectDN = $dn }
    [pscustomobject]@{ TimeCreated = '2026-09-30T13:00:00Z'; EventId = 5141; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'nTDSDSA'; ObjectDN = $dn }
)
$ow = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $overWindow; Quiet = $true; DomainController = @('DC01') }
Assert-IR (@($ow.Findings | Where-Object { $_.Title -like '*created*' -and $_.Severity -eq 'High' }).Count -ge 1) 'nTDSDSA create outside window is standalone High'
Assert-IR (@($ow.Findings | Where-Object { $_.Title -like '*deleted*' -and $_.Severity -eq 'Medium' }).Count -ge 1) 'uncorrelated nTDSDSA delete still gets its standalone Medium finding'
Assert-IR (@($ow.Findings | Where-Object { $_.Title -like '*Transient*' }).Count -eq 0) 'create+delete outside window is NOT reported as transient'

Complete-IRTest
