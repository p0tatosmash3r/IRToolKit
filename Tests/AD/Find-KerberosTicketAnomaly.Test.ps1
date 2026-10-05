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

# RULE 7 - lower-case realm in the 4769 client principal (ghost@corp.local) -> High, Golden Ticket.
$lc = @($f | Where-Object { $_.Title -like '*realm is not upper case*' })
Assert-IR ($lc.Count -eq 1 -and $lc[0].Account -eq 'ghost@corp.local') 'lower-case realm forged-ticket artefact (RULE 7) detected once, for ghost'
Assert-IR ($lc[0].Severity -eq 'High' -and $lc[0].Technique -eq 'T1558.001' -and $lc[0].SourceIp -eq '10.10.20.66') 'RULE 7 finding is High / Golden Ticket with the normalised source IP'
Assert-IR (@($f | Where-Object { $_.Account -like 'ghost*' -and $_.Technique -eq 'T1558.002' -and $_.Severity -eq 'High' }).Count -ge 1) 'RULE 7 source IP corroborates the TGS-without-TGT finding for ghost'

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

# Regression (corpus, RULE 7): mixed-case realm fires; a principal without '@' and a lower-case 4768 do not.
$rc = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T10:00:00Z'; EventId = 4769; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'mixed@Corp.Local'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'cifs/fs01.corp.local'; TicketEncryptionType = '0x12'; Status = '0x0'; IpAddress = '10.10.20.90' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T10:00:01Z'; EventId = 4769; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'norealm'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'cifs/fs01.corp.local'; TicketEncryptionType = '0x12'; Status = '0x0'; IpAddress = '10.10.20.91' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T10:00:02Z'; EventId = 4768; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'lower@corp.local'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'krbtgt'; TicketEncryptionType = '0x12'; PreAuthType = '2'; Status = '0x0'; IpAddress = '10.10.20.92' }
)
$rcr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $rc; Quiet = $true }
$rcf = @($rcr.Findings | Where-Object { $_.Title -like '*realm is not upper case*' })
Assert-IR ($rcf.Count -eq 1 -and $rcf[0].Account -eq 'mixed@Corp.Local') 'mixed-case realm fires RULE 7 exactly once; no-realm 4769 and lower-case 4768 do not'
Assert-IR ($rcf[0].Severity -eq 'Medium' -and $rcf[0].Confidence -eq 'Low' -and $rcf[0].Description -like '*case-normalised*') 'with no upper-case realm in the dataset a single hit is reported Medium/Low with a caveat'
Assert-IR ($rcr.Errors.Count -eq 0) 'RULE 7 regression input has no stray errors'

# Regression (real log, RULE 1 overpass-the-hash): a principal whose only TGTs are RC4 (lowercase realm) but
# whose service tickets are AES must fire the downgrade rule even with NO AES TGT; a principal that is RC4
# everywhere (TGT and TGS) must NOT (no AES evidence = cannot assert a downgrade offline).
$otph = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:49:00Z'; EventId = 4768; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'svc_sql@CORP.LOCAL'; TargetDomainName = 'corp.local'; ServiceName = 'krbtgt'; TicketEncryptionType = '0x17'; TicketOptions = '0x40800010'; PreAuthType = '2'; Status = '0x0'; IpAddress = '10.10.20.66' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:50:00Z'; EventId = 4768; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'svc_sql@CORP.LOCAL'; TargetDomainName = 'corp.local'; ServiceName = 'krbtgt'; TicketEncryptionType = '0x17'; TicketOptions = '0x40800010'; PreAuthType = '2'; Status = '0x0'; IpAddress = '10.10.20.66' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:51:00Z'; EventId = 4769; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'svc_sql@CORP.LOCAL'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'cifs/fs01.corp.local'; TicketEncryptionType = '0x12'; Status = '0x0'; IpAddress = '10.10.20.66' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:52:00Z'; EventId = 4769; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'svc_sql@CORP.LOCAL'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'host/dc01.corp.local'; TicketEncryptionType = '0x12'; Status = '0x0'; IpAddress = '10.10.20.66' }
    # control: rc4only is RC4 on both TGT and TGS (no AES anywhere) - not assertable as a downgrade offline.
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:53:00Z'; EventId = 4768; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'rc4only@CORP.LOCAL'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'krbtgt'; TicketEncryptionType = '0x17'; TicketOptions = '0x40810010'; PreAuthType = '2'; Status = '0x0'; IpAddress = '10.10.20.9' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T23:54:00Z'; EventId = 4769; Computer = 'DC01'; LogName = 'Security'; TargetUserName = 'rc4only@CORP.LOCAL'; TargetDomainName = 'CORP.LOCAL'; ServiceName = 'cifs/fs01.corp.local'; TicketEncryptionType = '0x17'; Status = '0x0'; IpAddress = '10.10.20.9' }
)
$ot = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $otph; Quiet = $true }
$otf = @($ot.Findings | Where-Object { $_.Title -like '*overpass-the-hash*' })
Assert-IR ($otf.Count -eq 1 -and $otf[0].Account -like 'svc_sql*' -and $otf[0].Severity -eq 'High') 'overpass-the-hash: RC4 TGT + AES service tickets (no AES TGT) fires the downgrade rule once, High'
Assert-IR (($otf[0].EventIds -contains 4768) -and ($otf[0].EventIds -contains 4769) -and $otf[0].Description -like "*realm is written 'corp.local'*") 'overpass finding cites both 4768/4769 and the lowercase TGT realm'
Assert-IR (@($ot.Findings | Where-Object { $_.Account -like 'rc4only*' }).Count -eq 0) 'RC4-everywhere principal (no AES evidence) is not flagged as a downgrade'
Assert-IR ($ot.Errors.Count -eq 0) 'overpass-the-hash regression input has no stray errors'
# RULE 3 must emit at most ONE forwardable+renewable context finding per principal, not one per RC4 TGT.
Assert-IR (@($ot.Findings | Where-Object { $_.Title -like '*forwardable + renewable*' -and $_.Account -like 'svc_sql*' }).Count -le 1) 'forwardable+renewable context is emitted at most once per principal (no per-TGT flood)'

# Regression (review, RULE 7): a case-normalised export (every realm lower-cased, no upper-case realm anywhere)
# must NOT produce one Golden Ticket finding per user - one Informational note instead.
$norm = @(1..6 | ForEach-Object { [pscustomobject]@{ TimeCreated = ([datetime]'2026-09-30T11:00:00Z').AddSeconds($_).ToString('o'); EventId = 4769; Computer = 'dc01'; LogName = 'Security'; TargetUserName = "user$($_)@corp.local"; TargetDomainName = 'corp.local'; ServiceName = 'cifs/fs01.corp.local'; TicketEncryptionType = '0x12'; Status = '0x0'; IpAddress = "10.10.30.$($_)" } })
$nr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $norm; Quiet = $true }
Assert-IR (@($nr.Findings | Where-Object { $_.Title -like '*realm is not upper case*' }).Count -eq 0) 'case-normalised export does not fire RULE 7 per principal'
Assert-IR (@($nr.Findings | Where-Object { $_.Title -like '*case-normalised*' -and $_.Severity -eq 'Informational' }).Count -eq 1 -and $nr.Errors.Count -eq 0) 'case-normalised export yields one Informational note, error-free'

Complete-IRTest
