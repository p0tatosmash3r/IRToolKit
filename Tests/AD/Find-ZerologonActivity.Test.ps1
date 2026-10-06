. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-ZerologonActivity.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-ZerologonActivity.json'

# Full malicious sample. DC01/DC02 are known DCs so DC-targeted resets/channels escalate to Critical.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02') }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 5) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1210').Count -eq $f.Count) 'all findings tagged T1210'

# RULE 1 - DC machine-account password changed by ANONYMOUS LOGON -> Critical.
$reset = @($f | Where-Object { $_.Target -eq 'DC01$' -and $_.Title -like '*ANONYMOUS LOGON*' })
Assert-IR ($reset.Count -ge 1) 'anonymous DC machine-password change detected'
Assert-IR ($reset[0].Severity -eq 'Critical') 'anonymous DC machine-password change is Critical'
Assert-IR ($reset[0].Account -eq 'ANONYMOUS LOGON') 'reset finding attributes ANONYMOUS LOGON'

# RULE 1 - non-DC machine reset by ANONYMOUS LOGON -> High (not Critical).
$wsReset = @($f | Where-Object { $_.Target -eq 'WS-50$' -and $_.Title -like '*ANONYMOUS LOGON*' })
Assert-IR ($wsReset.Count -ge 1) 'anonymous non-DC machine-password change detected'
Assert-IR ($wsReset[0].Severity -eq 'High') 'anonymous non-DC machine-password change is High'

# RULE 2 - 5829 allowed vulnerable channel for a DC account -> Critical; 5827 denied for NAS01$ -> High.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 5829 }).Count -ge 1) '5829 allowed-vulnerable Netlogon detected'
Assert-IR (@($f | Where-Object { $_.EventIds -contains 5829 -and $_.Severity -eq 'Critical' }).Count -ge 1) '5829 for a DC account is Critical'
$denied = @($f | Where-Object { $_.EventIds -contains 5827 })
Assert-IR ($denied.Count -ge 1) '5827 denied-vulnerable Netlogon detected'

# RULE 3 - burst of 5805 Netlogon failures for DC01$ -> High.
$burst = @($f | Where-Object { $_.EventIds -contains 5805 })
Assert-IR ($burst.Count -ge 1) '5805 Netlogon failure burst detected'
Assert-IR ($burst[0].Severity -eq 'High') '5805 burst is High'

# RULE 4 - Zerologon tooling in a script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'Zerologon tooling script block detected'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Target -eq 'WS-77$' }).Count -eq 0) 'normal helpdesk machine change not flagged'
Assert-IR (@($f | Where-Object { $_.Title -like '*ANONYMOUS LOGON*' -and $_.Evidence.SubjectUserName -eq 'DC01$' }).Count -eq 0) 'self machine-password rotation not flagged'

# Without a DC list the anonymous reset still fires (as High) with a caveat, and no stray errors.
$noDc = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
Assert-IR (@($noDc.Findings | Where-Object { $_.Target -eq 'DC01$' -and $_.Title -like '*ANONYMOUS LOGON*' }).Count -ge 1) 'anonymous reset still reported without a DC list'
Assert-IR ($noDc.Errors.Count -eq 0) 'no-DC-list run has no stray errors'

# Benign-only subset (authenticated/self machine changes only) -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.EventId -eq 4742 -and $_.SubjectUserName -ne 'ANONYMOUS LOGON' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression: 5805 failures with NO parseable account, from many different hosts, must NOT sum into one
# fabricated single-account burst (they are excluded from the burst rule).
$base = [datetime]'2026-09-30T14:20:00Z'
$unparsed = @(0..24 | ForEach-Object { [pscustomobject]@{ TimeCreated = $base.AddSeconds($_ * 10).ToString('o'); EventId = 5805; Computer = ("WS-$_.corp.local"); LogName = 'System'; ProviderName = 'NETLOGON'; Message = 'The session setup failed to authenticate.' } })
$up = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $unparsed; Quiet = $true; DomainController = @('DC01') }
Assert-IR (@($up.Findings | Where-Object { $_.EventIds -contains 5805 }).Count -eq 0) '5805 events with no parseable account do not fabricate a burst'
Assert-IR ($up.Errors.Count -eq 0) 'unparseable-5805 run has no stray errors'

# Regression: many identical 582x events for one device collapse to ONE finding (grouped), not N.
$nas = @(0..29 | ForEach-Object { [pscustomobject]@{ TimeCreated = $base.AddSeconds($_ * 5).ToString('o'); EventId = 5829; Computer = 'DC01.corp.local'; LogName = 'System'; ProviderName = 'NETLOGON'; Message = 'The Netlogon service allowed a vulnerable Netlogon secure channel connection. Machine SamAccountName: NAS01$ Account Type: Machine Account' } })
$n = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $nas; Quiet = $true; DomainController = @('DC01', 'DC02') }
Assert-IR (@($n.Findings | Where-Object { $_.EventIds -contains 5829 }).Count -eq 1) '30 identical 5829 events collapse to one finding'
Assert-IR ($n.Errors.Count -eq 0) 'grouped-5829 run has no stray errors'

# Regression (NoADLookup wired): the DC list comes solely from -DomainController, so the run is
# equivalent to the baseline (DC escalation intact) and error-free.
$rNo = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; DomainController = @('DC01', 'DC02'); NoADLookup = $true }
Assert-IR ($rNo.Findings.Count -eq $f.Count -and $rNo.Errors.Count -eq 0) '-NoADLookup run matches the baseline and has no stray errors'
Assert-IR (@($rNo.Findings | Where-Object Severity -eq 'Critical').Count -eq @($f | Where-Object Severity -eq 'Critical').Count) '-NoADLookup keeps the DC-based Critical escalations'

Complete-IRTest
