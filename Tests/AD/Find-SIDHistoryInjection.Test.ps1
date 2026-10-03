. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-SIDHistoryInjection.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-SIDHistoryInjection.json'

$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1134.005').Count -eq $f.Count) 'all findings tagged T1134.005'

# RULE 1 - 4765 injecting Domain Admins (512) into eviluser -> Critical.
$inj = @($f | Where-Object { $_.Account -eq 'eviluser' -and $_.EventIds -contains 4765 })
Assert-IR ($inj.Count -ge 1) '4765 privileged SID injection detected'
Assert-IR ($inj[0].Severity -eq 'Critical') 'privileged SID injection is Critical'
Assert-IR ($inj[0].Target -like '*512*' -and $inj[0].Target -like '*Domain Admins*') 'injected SID resolved to Domain Admins'

# RULE 2 - 5136 sIDHistory write of Enterprise Admins (519) -> Critical; the %%14675 delete is not flagged.
$five136 = @($f | Where-Object { $_.Account -eq 'svc_backdoor' -and $_.EventIds -contains 5136 })
Assert-IR ($five136.Count -ge 1) '5136 sIDHistory write detected'
Assert-IR ($five136[0].Severity -eq 'Critical') '5136 privileged sIDHistory write is Critical'
Assert-IR (@($f | Where-Object { $_.Account -eq 'olddupe' }).Count -eq 0) 'sIDHistory Value-Deleted (5136 %%14675) not flagged'

# RULE 3 - 4766 failed privileged attempt -> High.
$fail = @($f | Where-Object { $_.EventIds -contains 4766 })
Assert-IR ($fail.Count -ge 1) '4766 failed injection attempt detected'
Assert-IR ($fail[0].Severity -eq 'High') 'failed privileged attempt is High'

# RULE 4 - 4738 account change carrying the Administrator SID (RID 500) -> Critical.
$r4 = @($f | Where-Object { $_.Account -eq 'svc_legacy' -and $_.EventIds -contains 4738 })
Assert-IR ($r4.Count -ge 1) '4738 SidHistory-field injection detected'
Assert-IR ($r4[0].Severity -eq 'Critical') 'RID 500 (Administrator) injection is Critical'

# RULE 5 - tooling.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'SID-history tooling script block detected'

# Non-privileged migration addition -> one aggregated High (not Critical); account listed in Target.
$mig = @($f | Where-Object { $_.Target -like '*migrated1*' -and $_.Severity -eq 'High' })
Assert-IR ($mig.Count -eq 1) 'non-privileged migration sIDHistory is one aggregated High'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Account -eq 'normaluser' }).Count -eq 0) 'account change with empty SidHistory not flagged'
Assert-IR (@($f | Where-Object { $_.Account -eq 'someuser' }).Count -eq 0) 'unrelated attribute change not flagged'

# -KnownMigrationSid suppresses the migration addition (prefix match) but privileged stays Critical.
$km = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; KnownMigrationSid = @('S-1-5-21-999-888-777') }
Assert-IR (@($km.Findings | Where-Object { $_.Target -like '*migrated1*' }).Count -eq 0) 'known migration SID suppressed by -KnownMigrationSid'
Assert-IR (@($km.Findings | Where-Object { $_.Account -eq 'eviluser' -and $_.Severity -eq 'Critical' }).Count -ge 1) 'privileged injection still Critical despite -KnownMigrationSid'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -ne 'eviladmin' -and $_.SubjectUserName -ne 'admin' -and $_.EventId -ne 4104 -and $_.TargetUserName -ne 'migrated1' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression (Issue 1): the ACTOR's SID in a rendered 4765 Message must NOT be treated as the injected SID.
# A legit non-privileged migration performed by the built-in Administrator (Subject SID ...-500 in the
# message) must be High, not Critical, and the actor SID must not appear as the injected target.
$leak = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T09:00:00Z'; EventId = 4765; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'migratedX'; TargetSid = 'S-1-5-21-111-222-333-1400'; SourceSid = 'S-1-5-21-999-888-777-1106'; SubjectUserName = 'Administrator'; SubjectUserSid = 'S-1-5-21-111-222-333-500'; Message = 'SID History was added to an account. Subject: Security ID: S-1-5-21-111-222-333-500 Account Name: Administrator. Target Account: migratedX. Source Account: Security ID: S-1-5-21-999-888-777-1106' }
)
$lk = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $leak; Quiet = $true }
Assert-IR (@($lk.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 0) 'actor Administrator SID in message does not cause a false Critical'
Assert-IR (@($lk.Findings | Where-Object { $_.Target -like '*-500*' }).Count -eq 0) 'actor SID not reported as the injected SID'
Assert-IR (@($lk.Findings | Where-Object { $_.Severity -eq 'High' }).Count -eq 1) 'legit non-priv migration by Administrator is a single High'

# Regression (Issue 2): a bulk non-privileged migration aggregates to ONE High, not one per account.
$bulk = @(0..9 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-20T09:00:00Z').AddSeconds($_).ToString('o'); EventId = 4765; Computer = 'DC01'; LogName = 'Security'; TargetUserName = ("mig$_"); TargetSid = ("S-1-5-21-111-222-333-{0}" -f (3000 + $_)); SourceSid = ("S-1-5-21-999-888-777-{0}" -f (2000 + $_)); SubjectUserName = 'admt_svc' } })
$bk = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $bulk; Quiet = $true }
Assert-IR (@($bk.Findings | Where-Object { $_.Severity -eq 'High' }).Count -eq 1) '10-account bulk migration aggregates to one High finding'

Complete-IRTest
