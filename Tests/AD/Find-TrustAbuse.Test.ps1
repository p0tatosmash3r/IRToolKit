. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-TrustAbuse.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-TrustAbuse.json'

$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 11) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object { $_.Technique -in @('T1484.002', 'T1134.005') }).Count -eq $f.Count) 'all findings tagged a trust-abuse technique'

# RULE 1a (5136 precise transition): external-trust QUARANTINED cleared -> SID filtering disabled -> High.
$sidoff = @($f | Where-Object { $_.Title -like '*Dangerous trust configuration*' -and $_.Target -eq 'ext.example' })
Assert-IR ($sidoff.Count -eq 1 -and $sidoff[0].Severity -eq 'High') 'external-trust SID-filtering-disable is High'
Assert-IR ($sidoff[0].Technique -eq 'T1134.005') 'SID-filtering-disable tagged T1134.005 (SID-history enabler)'
Assert-IR ($sidoff[0].Confidence -eq 'High') 'confirmed 5136 transition is High confidence'

# RULE 1a: TREAT_AS_EXTERNAL set on a forest trust -> Critical.
$tae = @($f | Where-Object { $_.Title -like '*Dangerous trust configuration*' -and $_.Target -eq 'partner.example' -and $_.Severity -eq 'Critical' })
Assert-IR ($tae.Count -eq 1) 'treat-as-external on a forest trust is Critical'
Assert-IR ($tae[0].Description -like '*TREAT_AS_EXTERNAL*') 'finding names the treat-as-external change'

# RULE 1a: msDS-SupportedEncryptionTypes AES->RC4 downgrade -> Medium.
$rc4 = @($f | Where-Object { $_.Title -like '*encryption downgraded to RC4*' })
Assert-IR ($rc4.Count -eq 1 -and $rc4[0].Severity -eq 'Medium') 'trust key AES->RC4 downgrade is Medium'

# RULE 1b (4716, new state only): SidFilteringEnabled=Disabled -> High.
$m4716 = @($f | Where-Object { $_.EventIds -contains 4716 -and $_.Target -eq 'legacy.example' })
Assert-IR ($m4716.Count -eq 1 -and $m4716[0].Severity -eq 'High') '4716 modification leaving SID filtering disabled is High'

# RULE 2: new trust with SID filtering disabled -> High.
$newtrust = @($f | Where-Object { $_.Title -like '*New domain/forest trust created*' })
Assert-IR ($newtrust.Count -eq 1 -and $newtrust[0].Target -eq 'rogue.attacker') 'new trust detected'
Assert-IR ($newtrust[0].Severity -eq 'High') 'new trust with SID filtering disabled is High'

# RULE 3: trust removed -> Medium; forest TLN entry added -> Medium.
$removed = @($f | Where-Object { $_.Title -like '*trust removed*' -and $_.Target -eq 'old.example' })
Assert-IR ($removed.Count -eq 1 -and $removed[0].Severity -eq 'Medium') 'trust removal is Medium'
$tln = @($f | Where-Object { $_.Title -like '*name-suffix routing entry added*' })
Assert-IR ($tln.Count -eq 1 -and $tln[0].Severity -eq 'Medium') 'forest-trust routing entry addition is Medium'

# RULE 4: netdom /enablesidhistory and .NET SetSidFilteringStatus -> High (exactly those two commands).
$cmd = @($f | Where-Object { $_.Title -like '*Trust-modifying command executed*' })
Assert-IR ($cmd.Count -eq 2) 'exactly the two dangerous trust commands fire (netdom /verify does not)'
Assert-IR (@($cmd | Where-Object { $_.Description -like '*enablesidhistory*' -and $_.Severity -eq 'High' -and $_.Technique -eq 'T1134.005' }).Count -eq 1) 'netdom /enablesidhistory:Yes is High and tagged T1134.005'
Assert-IR (@($cmd | Where-Object { $_.Description -like '*SetSidFilteringStatus*' -and $_.Severity -eq 'High' }).Count -eq 1) '.NET SetSidFilteringStatus is High'

# RULE 5: offensive trust-key tooling (exactly the two real invocations; naming does not fire).
$toolf = @($f | Where-Object { $_.Title -like '*Trust-key / credential tool*' })
Assert-IR ($toolf.Count -eq 2) 'exactly the two offensive-tool invocations fire (naming a tool in a filename does not)'
Assert-IR (@($toolf | Where-Object { $_.EventIds -contains 4104 -and $_.Severity -eq 'Critical' }).Count -eq 1) 'Mimikatz lsadump::trust is Critical'
Assert-IR (@($toolf | Where-Object { $_.EventIds -contains 4688 -and $_.Target -eq 'rubeus' -and $_.Severity -eq 'High' }).Count -eq 1) 'Rubeus execution is High'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Target -eq 'autoreset.example' }).Count -eq 0) 'ANONYMOUS-LOGON trust auto-reset excluded by default'
Assert-IR (@($f | Where-Object { $_.Target -eq 'corp-child.example' }).Count -eq 0) 'benign within-forest attribute change not flagged'
Assert-IR (@($f | Where-Object { $_.Computer -eq 'WS-ADMIN' }).Count -eq 0) 'naming a tool / netdom /verify does not fire'

# -ExcludeAccount suppresses a known trust admin; eviladmin strong signals survive.
$ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; ExcludeAccount = @('trustadmin') }
Assert-IR (@($ex.Findings | Where-Object { $_.Target -eq 'migrate.example' }).Count -eq 0) 'trust admin change suppressed by -ExcludeAccount'
Assert-IR (@($ex.Findings | Where-Object { $_.Target -eq 'partner.example' -and $_.Severity -eq 'Critical' }).Count -eq 1) 'strong signals survive -ExcludeAccount of an unrelated admin'

# -IncludeAnonymousResets surfaces the ANONYMOUS-LOGON modification hidden by default.
$inc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; IncludeAnonymousResets = $true }
Assert-IR (@($inc.Findings | Where-Object { $_.Target -eq 'autoreset.example' }).Count -eq 1) 'ANONYMOUS-LOGON modification surfaced with -IncludeAnonymousResets'

# Graceful degrade: no signature file -> RULE 5 (offensive tooling) disabled, other rules still run, no errors.
$noSig = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; SignatureFile = (Join-Path $PSScriptRoot 'no-such-signatures.json') }
Assert-IR ($noSig.Errors.Count -eq 0) 'missing signature file does not error'
Assert-IR (@($noSig.Findings | Where-Object { $_.Title -like '*Trust-key / credential tool*' }).Count -eq 0) 'offensive-tooling rule disabled when signature file is absent'
Assert-IR (@($noSig.Findings | Where-Object { $_.Title -like '*Trust-modifying command executed*' }).Count -eq 2) 'inline netdom/.NET command rule still runs without the signature file'

# Regression: a MALFORMED signature file degrades silently (isolated-runspace parse) - zero stray errors.
$badSig = Join-Path ([IO.Path]::GetTempPath()) ("ta-bad-{0}.json" -f ([guid]::NewGuid().ToString('N')))
Set-Content -LiteralPath $badSig -Value '{ "tooling": [ {"category":"crit", "value": } OOPS' -Encoding ASCII
try {
    $mal = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; SignatureFile = $badSig }
    Assert-IR ($mal.Errors.Count -eq 0) 'malformed signature file degrades with zero stray error records'
    Assert-IR (@($mal.Findings | Where-Object { $_.Title -like '*Trust-key / credential tool*' }).Count -eq 0) 'malformed signature file disables RULE 5'
}
finally { Remove-Item -LiteralPath $badSig -Force -ErrorAction SilentlyContinue }

# Regression: Value-Added-only trustAttributes (no Deleted pair / no OpCorrelationID) flags the dangerous end-state.
$addonly = @([pscustomobject]@{ TimeCreated = '2026-09-30T11:00:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=fabric.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '72'; OperationType = '%%14674' })
$ao = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $addonly; Quiet = $true }
$aof = @($ao.Findings | Where-Object { $_.Target -eq 'fabric.example' })
Assert-IR ($aof.Count -eq 1 -and $aof[0].Severity -eq 'Critical') 'added-only treat-as-external end-state flags Critical'
Assert-IR ($aof[0].Confidence -eq 'Medium') 'added-only (no old value) is Medium confidence (transition not confirmed)'

# Regression (direction correctness): ADDING the QUARANTINED bit (enabling SID filtering) is NOT flagged.
$enable = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T11:10:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'trustadmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=good.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '1'; OperationType = '%%14675'; OpCorrelationID = 'g1' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T11:10:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'trustadmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=good.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '5'; OperationType = '%%14674'; OpCorrelationID = 'g1' }
)
$en = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $enable; Quiet = $true }
Assert-IR (@($en.Findings | Where-Object { $_.Target -eq 'good.example' }).Count -eq 0) 'enabling SID filtering (adding QUARANTINED) is not flagged'

# Regression: netdom /quarantine:Yes (re-enabling) is NOT flagged; only the dangerous flags are.
$safecmd = @([pscustomobject]@{ TimeCreated = '2026-09-30T11:20:00Z'; EventId = 4688; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'trustadmin'; NewProcessName = 'C:\Windows\System32\netdom.exe'; CommandLine = 'netdom trust corp.local /Domain:partner.example /quarantine:Yes' })
$sc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $safecmd; Quiet = $true }
Assert-IR ($sc.Findings.Count -eq 0) 'netdom /quarantine:Yes (re-enabling SID filtering) is not flagged'

# Regression (decode): the old->new flag names are decoded correctly (GetEnumerator, not positional index).
Assert-IR ($sidoff[0].Description -like '*QUARANTINED_DOMAIN*') 'decoded context names the QUARANTINED_DOMAIN bit (decode fixed)'
Assert-IR ($tae[0].Description -like '*FOREST_TRANSITIVE*' -and $tae[0].Description -like '*TREAT_AS_EXTERNAL*') 'decoded context names FOREST_TRANSITIVE and TREAT_AS_EXTERNAL'

# Regression: a lone Value-Deleted trustAttributes (no resulting value) is NOT a confirmed transition.
$delonly = @([pscustomobject]@{ TimeCreated = '2026-09-30T12:00:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=del.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '5'; OperationType = '%%14675'; OpCorrelationID = 'd1' })
$do = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $delonly; Quiet = $true }
Assert-IR (@($do.Findings | Where-Object { $_.Target -eq 'del.example' }).Count -eq 0) 'deleted-only trustAttributes (no new value) does not fabricate a confirmed SID-filtering-disable'

# Regression: a non-trustedDomain object carrying a trustAttributes-named value is not treated as a trust.
$notrust = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:10:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'user'; ObjectDN = 'CN=weird,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '1'; OperationType = '%%14675'; OpCorrelationID = 'w1' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:10:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'user'; ObjectDN = 'CN=weird,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '0'; OperationType = '%%14674'; OpCorrelationID = 'w1' }
)
$nt = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $notrust; Quiet = $true }
Assert-IR (@($nt.Findings | Where-Object { $_.Target -eq 'weird' }).Count -eq 0) 'non-trustedDomain object with a trustAttributes-named value is not flagged'

# Regression: an out-of-Int64 attribute value is parsed without leaking a stray error record.
$huge = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:20:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=huge.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '99999999999999999999999999'; OperationType = '%%14675'; OpCorrelationID = 'h1' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T12:20:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviladmin'; ObjectClass = 'trustedDomain'; ObjectDN = 'CN=huge.example,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'trustAttributes'; AttributeValue = '0xFFFFFFFFFFFFFFFFFF'; OperationType = '%%14674'; OpCorrelationID = 'h1' }
)
$hg = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $huge; Quiet = $true }
Assert-IR ($hg.Errors.Count -eq 0) 'out-of-Int64 attribute value parsed without a stray error record'

# Regression: a real netdom /enablesidhistory:yes (not commented) still fires High.
$realnetdom = @([pscustomobject]@{ TimeCreated = '2026-09-30T12:30:00Z'; EventId = 4104; Computer = 'DC01'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'netdom trust corp.local /Domain:partner.example /enablesidhistory:yes' })
$rnd = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $realnetdom; Quiet = $true }
Assert-IR (@($rnd.Findings | Where-Object { $_.Title -like '*Trust-modifying command executed*' -and $_.Severity -eq 'High' }).Count -eq 1) 'real (uncommented) netdom /enablesidhistory:yes still fires High'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
