. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-KerberosTicketAnomaly.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-KerberosTicketAnomaly.json'

# Full malicious sample. ExpectedDomain lets RULE 5 (realm mismatch) evaluate.
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; ExpectedDomain = 'CORP.LOCAL' }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 6) 'malicious sample produces the expected findings'
Assert-IR (@($f | Where-Object { $_.Technique -in @('T1558.001', 'T1558.002', 'T1550.003') }).Count -eq $f.Count) 'every finding carries a ticket-forging technique'

# RULE 2 - svcpuppet silver ticket / pass-the-ticket (TGS with no preceding TGT).
$silver = @($f | Where-Object { $_.Account -like '*svcpuppet*' -and $_.Technique -eq 'T1558.002' })
Assert-IR ($silver.Count -ge 1) 'svcpuppet silver/PTT (no preceding TGT) detected'
Assert-IR (@($silver | Where-Object Severity -eq 'High').Count -ge 1) 'svcpuppet silver/PTT is High severity'
Assert-IR ($silver[0].SourceIp -eq '10.10.20.66') 'IPv4-mapped source IP normalised'
Assert-IR ($silver[0].Confidence -eq 'High') 'svcpuppet confidence raised to High by attacker-IP combo'

# RULE 1 - administrator RC4 encryption downgrade (Golden Ticket artifact).
$dg = @($f | Where-Object { $_.Account -like 'administrator*' -and $_.Title -like '*downgrade*' })
Assert-IR ($dg.Count -ge 1) 'administrator RC4 encryption downgrade detected'
Assert-IR (@($dg | Where-Object Severity -eq 'High').Count -ge 1) 'RC4 downgrade is High severity'
Assert-IR ($dg[0].Technique -eq 'T1558.001') 'downgrade tagged as Golden Ticket (T1558.001)'

# RULE 4 - krbtgt account authenticating as a client -> Critical.
$krb = @($f | Where-Object { $_.Account -like 'krbtgt*' -and $_.Severity -eq 'Critical' })
Assert-IR ($krb.Count -ge 1) 'krbtgt-as-client usage is Critical'

# RULE 5 - forged ticket with mismatched / blank realm (phantom @ CORP.EVIL).
$realm = @($f | Where-Object { $_.Title -like '*realm*' })
Assert-IR ($realm.Count -ge 1) 'mismatched realm (RULE 5) detected'

# RULE 6 - mimikatz golden-ticket tooling in a PowerShell script block.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'ticket-forging 4104 script block detected'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Account -like 'alice*' }).Count -eq 0) 'benign alice (TGT then TGS) not flagged'
Assert-IR (@($f | Where-Object { $_.Account -like 'WS-70*' }).Count -eq 0) 'machine account WS-70$ not flagged by RULE 2'
Assert-IR (@($f | Where-Object { $_.Account -like 'bob*' }).Count -eq 0) 'cross-realm referral (bob) not flagged as silver'

# Benign-only subset -> no findings. Drop everything from the attacker IP and the tooling event.
$benign = @(Import-IREvents -Path $sample | Where-Object {
        $_.IpAddress -notlike '*10.10.20.66*' -and $_.EventId -ne 4104
    })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true; ExpectedDomain = 'CORP.LOCAL' }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true; ExpectedDomain = 'CORP.LOCAL' }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

Complete-IRTest
