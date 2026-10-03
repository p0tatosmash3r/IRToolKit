. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ADCSAbuse.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ADCSAbuse.json'

# Full malicious sample. administrator@corp.local is flagged as a privileged UPN so the ESC1 SAN
# request escalates to Critical.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; PrivilegedUpn = @('administrator@corp.local') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1649').Count -eq $f.Count) 'all findings tagged T1649'

# Rule 1 - ESC1 SAN abuse is Critical and names both the requester (lowpriv) and the SAN (administrator).
$esc1 = @($f | Where-Object { $_.Title -like '*ESC1*' -and $_.Title -like '*SAN*' })
Assert-IR ($esc1.Count -ge 1) 'ESC1 SAN abuse detected'
Assert-IR (@($esc1 | Where-Object Severity -eq 'Critical').Count -ge 1) 'ESC1 SAN abuse escalated to Critical for privileged SAN'
Assert-IR (@($esc1 | Where-Object { $_.Account -like '*lowpriv*' -and ($_.Target -like '*administrator*' -or $_.Description -like '*administrator*') }).Count -ge 1) 'ESC1 finding names lowpriv requester and administrator SAN'

# Rule 2 - dangerous certificate-template modification (msPKI-Certificate-Name-Flag) is High.
$tmpl = @($f | Where-Object { $_.Title -like '*template modified*' })
Assert-IR ($tmpl.Count -ge 1) 'dangerous certificate template modification detected'
Assert-IR (@($tmpl | Where-Object { $_.Severity -eq 'High' -and $_.Description -like '*msPKI-Certificate-Name-Flag*' }).Count -ge 1) 'name-flag template change is High'
Assert-IR (@($tmpl | Where-Object { $_.Account -eq 'eviladmin' }).Count -ge 1) 'template change actor (eviladmin) captured'

# Rule 3 - certificate-logon impersonation anomaly is Critical and names the thumbprint, requester and auth user.
$certlogon = @($f | Where-Object { $_.EventIds -contains 4768 -and $_.EventIds -contains 4887 })
Assert-IR ($certlogon.Count -ge 1) 'certificate-logon anomaly detected'
Assert-IR (@($certlogon | Where-Object Severity -eq 'Critical').Count -ge 1) 'certificate-logon anomaly is Critical'
Assert-IR (@($certlogon | Where-Object { $_.Description -like '*ABC123*' -and $_.Description -like '*lowpriv*' -and $_.Account -eq 'administrator' }).Count -ge 1) 'cert ABC123 issued to lowpriv used as administrator'

# Rule 4 - altSecurityIdentities (ESC14) is High.
$altsec = @($f | Where-Object { $_.Title -like '*altSecurityIdentities*' })
Assert-IR ($altsec.Count -ge 1) 'altSecurityIdentities mapping detected'
Assert-IR (@($altsec | Where-Object { $_.Severity -eq 'High' -and $_.Account -eq 'eviluser' }).Count -ge 1) 'altSecurityIdentities change is High by eviluser'

# Rule 5 - tooling in a PowerShell script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'AD CS tooling script block detected'

# Benign activity must not be flagged.
Assert-IR (@($f | Where-Object { $_.Account -like '*alice*' }).Count -eq 0) 'benign normal issuance (alice) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -eq 'bob' }).Count -eq 0) 'benign smart-card PKINIT (bob) not flagged by default'
Assert-IR (@($f | Where-Object { $_.Account -like '*admin-maint*' }).Count -eq 0) "benign template 'revision' change not flagged"

# Without -FlagAllPkinit the uncorrelated smart-card logon must stay silent.
$noflag = @($f | Where-Object { $_.Title -like '*without correlating issuance*' })
Assert-IR ($noflag.Count -eq 0) 'uncorrelated PKINIT not reported without -FlagAllPkinit'

# Benign-only subset: drop every malicious actor/requester/tooling event.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        ($_.Requester -notlike '*lowpriv*') -and ($_.SubjectUserName -notlike '*evil*') -and
        ($_.TargetUserName -ne 'administrator') -and ($_.EventId -ne 4104)
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; PrivilegedUpn = @('administrator@corp.local') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
