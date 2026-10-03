. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-GoldenGMSA.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-GoldenGMSA.json'

# Full malicious sample. DC01/DC02 are known DCs so their KDS/gMSA reads are excluded.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 4) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1555').Count -eq $f.Count) 'all findings tagged T1555'

# RULE 1 - KDS root key read by non-DC eviladmin -> Critical.
$kds = @($f | Where-Object { $_.Title -like '*KDS root key*' })
Assert-IR ($kds.Count -ge 1) 'KDS root key read by non-DC detected'
Assert-IR ($kds[0].Severity -eq 'Critical') 'KDS root key theft is Critical'
Assert-IR ($kds[0].Account -eq 'eviladmin') 'KDS read finding names the actor'
# The DC01$ read of the same object must be excluded.
Assert-IR (@($kds | Where-Object { $_.Account -like 'DC01*' }).Count -eq 0) 'DC read of KDS root key excluded'

# RULE 2 - gMSA managed-password blob read by a USER account -> High.
$blob = @($f | Where-Object { $_.Title -like '*managed-password blob*' })
Assert-IR ($blob.Count -ge 1) 'gMSA managed-password blob read by a user detected'
Assert-IR ($blob[0].Severity -eq 'High') 'user gMSA blob read is High'
Assert-IR ($blob[0].Account -eq 'eviluser') 'blob read finding names the user'
# The machine-account (SQLSVC01$) read is NOT reported by default.
Assert-IR (@($f | Where-Object { $_.Account -like 'SQLSVC01*' }).Count -eq 0) 'machine-account gMSA blob read not flagged by default'

# RULE 3 - msDS-GroupMSAMembership addition -> High; the deletion is not flagged.
$mem = @($f | Where-Object { $_.Title -like '*retrieval principals*' })
Assert-IR ($mem.Count -eq 1) 'gMSA membership addition detected (deletion not flagged)'
Assert-IR ($mem[0].Severity -eq 'High') 'gMSA membership addition is High'

# RULE 4 - Golden gMSA tooling in a script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'Golden gMSA tooling script block detected'

# Benign unrelated 4662 (helpdesk reading a user object) not flagged.
Assert-IR (@($f | Where-Object { $_.Account -eq 'helpdesk' }).Count -eq 0) 'unrelated 4662 object access not flagged'

# -IncludeMachineReaders surfaces the machine read (Medium); -ExpectedGmsaReader suppresses it.
$incM = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02'); IncludeMachineReaders = $true }
Assert-IR (@($incM.Findings | Where-Object { $_.Account -like 'SQLSVC01*' -and $_.Severity -eq 'Medium' }).Count -ge 1) 'machine gMSA blob read surfaced (Medium) with -IncludeMachineReaders'
$expR = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02'); IncludeMachineReaders = $true; ExpectedGmsaReader = @('SQLSVC01$') }
Assert-IR (@($expR.Findings | Where-Object { $_.Account -like 'SQLSVC01*' }).Count -eq 0) 'known reader suppressed by -ExpectedGmsaReader'

# Regression: DC exclusion survives DOMAIN\ and UPN forms of the reader.
$dcForms = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T02:00:00Z'; EventId = 4662; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'CORP\DC02$'; ObjectName = 'CN=k,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local'; OperationType = 'Object Access'; AccessMask = '0x10'; Properties = 'All properties' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T02:01:00Z'; EventId = 4662; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'DC02$@CORP.LOCAL'; ObjectName = 'CN=k,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=corp,DC=local'; OperationType = 'Object Access'; AccessMask = '0x10'; Properties = 'All properties' }
)
$df = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $dcForms; Quiet = $true; DomainController = @('DC02') }
Assert-IR ($df.Findings.Count -eq 0) 'DC reader in DOMAIN\ and UPN forms excluded from KDS rule'

# Without a DC list, the KDS read still reports (Medium confidence) with a caveat.
$noDc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
Assert-IR (@($noDc.Findings | Where-Object { $_.Title -like '*KDS root key*' -and $_.Account -eq 'eviladmin' }).Count -ge 1) 'KDS read still reported without a DC list'
Assert-IR ($noDc.Errors.Count -eq 0) 'no-DC-list run has no stray errors'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -ne 'eviladmin' -and $_.SubjectUserName -ne 'eviluser' -and $_.EventId -ne 4104 })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression: RULE 4 must NOT fire on routine RSAT gMSA administration (dual-use strings are not signatures),
# but MUST fire on named offensive tooling.
$ps = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:00:00Z'; EventId = 4104; Computer = 'DC01'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'Get-ADServiceAccount -Identity svc_sql -Properties msDS-ManagedPassword' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:01:00Z'; EventId = 4104; Computer = 'DC01'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'Get-KdsRootKey | Format-List' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T16:02:00Z'; EventId = 4104; Computer = 'WS1'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'Import-Module GoldenGMSA; Get-GoldenGMSAPassword -Sid S-1-5-21-1-2-3-2500' }
)
$pr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $ps; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR (@($pr.Findings | Where-Object { $_.Description -like '*Get-ADServiceAccount*' -or $_.Description -like '*Get-KdsRootKey*' }).Count -eq 0) 'routine RSAT gMSA admin (Get-ADServiceAccount / Get-KdsRootKey) not flagged'
Assert-IR (@($pr.Findings | Where-Object { $_.EventIds -contains 4104 }).Count -eq 1) 'only the named GoldenGMSA tooling fires RULE 4'

Complete-IRTest
