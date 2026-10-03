. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-DelegationAbuse.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-DelegationAbuse.json'

# Full malicious sample. -DomainController makes DC01/DC02 recognisable offline so the DC-specific
# escalations (Rule 1 Critical on DC02, Rule 4 delegation to a DC SPN) can fire.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -eq 5) 'malicious sample produces exactly the five expected findings'
Assert-IR (@($f | Where-Object { $_.Technique }).Count -eq $f.Count) 'every finding carries an ATT&CK technique'

# Rule 1 - RBCD write on a member server. High, names FILESRV01 and eviluser.
$rbcdFs = @($f | Where-Object { $_.Title -like '*RBCD*' -and $_.Target -like '*FILESRV01*' })
Assert-IR ($rbcdFs.Count -eq 1) 'RBCD write on FILESRV01 detected'
Assert-IR ($rbcdFs[0].Severity -eq 'High') 'RBCD on a non-DC is High'
Assert-IR ($rbcdFs[0].Account -like '*eviluser*') 'RBCD finding names the actor eviluser'

# Rule 1 - RBCD write on DC02 is Critical because -DomainController recognised it as a DC.
$rbcdDc = @($f | Where-Object { $_.Title -like '*RBCD*' -and $_.Target -like '*DC02*' })
Assert-IR ($rbcdDc.Count -eq 1) 'RBCD write on DC02 detected'
Assert-IR ($rbcdDc[0].Severity -eq 'Critical') 'RBCD on a DC is Critical with -DomainController'

# Rule 2 - unconstrained delegation enabled on WEBSRV02$.
$unc = @($f | Where-Object { $_.Title -like '*nconstrained*' -and $_.Target -like '*WEBSRV02$*' })
Assert-IR ($unc.Count -eq 1) 'unconstrained delegation on WEBSRV02$ detected'
Assert-IR ($unc[0].Severity -eq 'High') 'unconstrained delegation is High'

# Rule 3 - constrained delegation with protocol transition on svc_app.
$pt = @($f | Where-Object { $_.Target -like '*svc_app*' })
Assert-IR ($pt.Count -eq 1) 'constrained delegation on svc_app detected'
Assert-IR ($pt[0].Severity -eq 'High' -and $pt[0].Title -like '*protocol transition*') 'protocol transition change is High'

# Rule 4 - constrained delegation to a DC SPN (ldap/DC01) on svc_bad.
$dcspn = @($f | Where-Object { $_.Target -like '*svc_bad*' })
Assert-IR ($dcspn.Count -eq 1) 'delegation to DC SPN on svc_bad detected'
Assert-IR ($dcspn[0].Severity -eq 'High' -and $dcspn[0].Target -like '*ldap/DC01*') 'delegation to a DC SPN is High'

# Benign events must never fire.
Assert-IR (@($f | Where-Object { $_.Target -like '*MEMBERSRV05*' }).Count -eq 0) 'benign computer change (Old==New UAC) not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*jsmith*' }).Count -eq 0) 'benign description change not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*normaluser*' }).Count -eq 0) "benign Don't Expire Password change not flagged"

# Without -DomainController the DC escalations cannot be applied: DC02 RBCD stays High.
$rNoDc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$dc02NoDc = @($rNoDc.Findings | Where-Object { $_.Title -like '*RBCD*' -and $_.Target -like '*DC02*' })
Assert-IR ($dc02NoDc.Count -eq 1 -and $dc02NoDc[0].Severity -eq 'High') 'RBCD on DC02 is only High without -DomainController'
Assert-IR ($rNoDc.Errors.Count -eq 0) 'run without -DomainController has no errors'

# Benign-only subset (everything not touched by eviluser / eviladmin) -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -ne 'eviluser' -and $_.SubjectUserName -ne 'eviladmin' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
