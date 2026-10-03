. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-GPOAbuse.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-GPOAbuse.json'

$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true }
$f = $r.Findings
Assert-IR ($r.Errors.Count -eq 0) 'runs without errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'emits only finding objects'
Assert-IR ($f.Count -ge 6) 'malicious sample produces findings'
Assert-IR (@($f | Where-Object Technique -eq 'T1484.001').Count -eq $f.Count) 'all findings tagged T1484.001'

# RULE 1 - code-executing CSE added to a GPO -> Critical.
$cse = @($f | Where-Object { $_.Title -like '*client-side extension*' })
Assert-IR ($cse.Count -ge 1) 'GPO CSE change detected'
Assert-IR ($cse[0].Severity -eq 'Critical') 'code-executing CSE add is Critical'
Assert-IR ($cse[0].Description -like '*Scheduled Tasks*') 'scheduled-tasks CSE named in finding'

# RULE 1 - GPO ACL change -> High.
$acl = @($f | Where-Object { $_.Title -like '*security descriptor*' })
Assert-IR ($acl.Count -ge 1 -and $acl[0].Severity -eq 'High') 'GPO ACL change is High'

# RULE 2 - gPLink on the Domain Controllers OU -> High.
$link = @($f | Where-Object { $_.Title -like '*gPLink*sensitive*' -and $_.Target -like '*Domain Controllers*' })
Assert-IR ($link.Count -ge 1 -and $link[0].Severity -eq 'High') 'gPLink to the DC OU is High'

# RULE 3 - new GPO -> Medium.
$newgpo = @($f | Where-Object { $_.Title -like '*New Group Policy Object*' })
Assert-IR ($newgpo.Count -ge 1 -and $newgpo[0].Severity -eq 'Medium') 'new GPO is Medium'

# RULE 4 - SYSVOL ScheduledTasks.xml write -> High.
$sysvol = @($f | Where-Object { $_.Title -like '*SYSVOL policy file*' })
Assert-IR ($sysvol.Count -ge 1 -and $sysvol[0].Severity -eq 'High') 'SYSVOL GPT write is High'
Assert-IR ($sysvol[0].Target -like '*ScheduledTasks.xml*') 'SYSVOL finding names the written file'

# RULE 5 - tooling in 4104 and 4688.
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4104 }).Count -ge 1) 'GPO-abuse tooling script block detected'
Assert-IR (@($f | Where-Object { $_.EventIds -contains 4688 -and $_.Target -like '*SharpGPOAbuse*' }).Count -ge 1) 'SharpGPOAbuse process detected'

# Benign activity must never fire.
Assert-IR (@($f | Where-Object { $_.Target -like '*jdoe*' }).Count -eq 0) 'non-GPO attribute change not flagged'
Assert-IR (@($f | Where-Object { $_.Target -like '*Registry.pol*' }).Count -eq 0) 'SYSVOL Registry.pol READ not flagged'

# Routine edits by a GPO admin: Medium findings present by default...
Assert-IR (@($f | Where-Object { $_.Account -eq 'gpoadmin' }).Count -ge 1) 'routine GPO admin edits reported by default'
# ...and suppressed with -ExcludeAccount, while eviluser's strong signals are untouched.
$ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; ExcludeAccount = @('gpoadmin') }
Assert-IR (@($ex.Findings | Where-Object { $_.Account -eq 'gpoadmin' }).Count -eq 0) 'routine GPO admin edits suppressed by -ExcludeAccount'
Assert-IR (@($ex.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -ge 1) 'strong signals survive -ExcludeAccount'

# Strong signals are never suppressed even if the acting account is excluded.
$exE = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputPath = $sample; Quiet = $true; ExcludeAccount = @('eviluser') }
Assert-IR (@($exE.Findings | Where-Object { $_.Title -like '*client-side extension*' }).Count -ge 1) 'CSE add still fires despite excluded actor'
Assert-IR (@($exE.Findings | Where-Object { $_.Title -like '*gPLink*sensitive*' }).Count -ge 1) 'DC-OU link still fires despite excluded actor'
Assert-IR (@($exE.Findings | Where-Object { $_.Title -like '*SYSVOL policy file*' }).Count -ge 1) 'SYSVOL write still fires despite excluded actor'

# Benign-only subset -> no findings.
$benign = @(Import-IREvents -Path $sample | Where-Object { $_.SubjectUserName -eq 'helpdesk' -or $_.SubjectUserName -eq 'wsuser' })
$b = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $benign; Quiet = $true }
Assert-IR ($b.Findings.Count -eq 0) 'benign-only subset is clean'
Assert-IR ($b.Errors.Count -eq 0) 'benign-only subset has no stray errors'

# Empty input.
$e = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = @(); Quiet = $true }
Assert-IR ($e.Findings.Count -eq 0 -and $e.Errors.Count -eq 0) 'empty input is clean and error-free'

# Regression (Major 1): RULE 5 must fire on an INVOCATION, never on a tool NAME in a file arg / search string.
$r5 = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T17:00:00Z'; EventId = 4104; Computer = 'WS1'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'Get-Content C:\reports\SharpGPOAbuse-output.txt' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T17:01:00Z'; EventId = 4104; Computer = 'WS1'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'findstr /i New-GPOImmediateTask C:\detections\gpo-rules.txt' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T17:02:00Z'; EventId = 4688; Computer = 'WS1'; LogName = 'Security'; SubjectUserName = 'analyst'; NewProcessName = 'C:\Windows\System32\notepad.exe'; CommandLine = 'notepad.exe "C:\loot\SharpGPOAbuse-notes.txt"' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T17:03:00Z'; EventId = 4104; Computer = 'WS1'; LogName = 'Microsoft-Windows-PowerShell/Operational'; ScriptBlockText = 'New-GPOImmediateTask -TaskName pwn -GPODisplayName ''Default Domain Policy''' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T17:04:00Z'; EventId = 4688; Computer = 'WS1'; LogName = 'Security'; SubjectUserName = 'eviluser'; NewProcessName = 'C:\Python39\python.exe'; CommandLine = 'python.exe pygpoabuse.py corp.local/eviluser -gpo-id abc' }
)
$r5r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r5; Quiet = $true }
Assert-IR (@($r5r.Findings | Where-Object { $_.Description -like '*output.txt*' -or $_.Description -like '*gpo-rules.txt*' -or $_.Description -like '*notes.txt*' }).Count -eq 0) 'naming a GPO-abuse tool (output / rule / search string) does not fire'
Assert-IR (@($r5r.Findings | Where-Object { $_.EventIds -contains 4104 -and $_.Description -like '*New-GPOImmediateTask*' }).Count -eq 1) 'real New-GPOImmediateTask invocation still fires'
Assert-IR (@($r5r.Findings | Where-Object { $_.EventIds -contains 4688 -and $_.Account -eq 'eviluser' }).Count -eq 1) 'real pygpoabuse.py invocation still fires'

# Regression (Major 2 + Minor 5): GptTmpl.inf / Registry.pol writes are Medium & suppressible; code files stay High.
$r4 = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:00:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'gpoadmin'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\Policies\{AAA}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'; AccessList = '%%4417'; AccessMask = '0x2' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:01:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'gpoadmin'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\Policies\{AAA}\Machine\Registry.pol'; AccessList = ''; AccessMask = '0x2' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:02:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviluser'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\Policies\{AAA}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml'; AccessList = ''; AccessMask = '0x2' }
)
$r4r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r4; Quiet = $true }
Assert-IR (@($r4r.Findings | Where-Object { $_.Target -like '*GptTmpl.inf*' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'GptTmpl.inf write by an admin is Medium'
Assert-IR (@($r4r.Findings | Where-Object { $_.Target -like '*Registry.pol*' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'Registry.pol write (hex-mask only) is Medium and decoded as a write'
Assert-IR (@($r4r.Findings | Where-Object { $_.Target -like '*ScheduledTasks.xml*' -and $_.Severity -eq 'High' }).Count -eq 1) 'ScheduledTasks.xml write (hex-mask only) stays High'
$r4ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r4; Quiet = $true; ExcludeAccount = @('gpoadmin', 'eviluser') }
Assert-IR (@($r4ex.Findings | Where-Object { $_.Target -like '*GptTmpl.inf*' -or $_.Target -like '*Registry.pol*' }).Count -eq 0) 'routine policy-file writes suppressed by -ExcludeAccount'
Assert-IR (@($r4ex.Findings | Where-Object { $_.Target -like '*ScheduledTasks.xml*' -and $_.Severity -eq 'High' }).Count -eq 1) 'code-file write never suppressed by -ExcludeAccount'

# Regression (Minor 6): the legacy NETLOGON \scripts\ share is not under \Policies\ and must not fire;
# a real GPO startup script under \Policies\...\Scripts\ does.
$rp = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:10:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviluser'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\scripts\logon.bat'; AccessList = '%%4417'; AccessMask = '0x2' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:11:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviluser'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\Policies\{AAA}\Machine\Scripts\Startup\evil.bat'; AccessList = '%%4417'; AccessMask = '0x2' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T18:12:00Z'; EventId = 5145; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'wsuser'; ShareName = '\\*\SYSVOL'; RelativeTargetName = 'corp.local\Policies\{AAA}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'; AccessList = '%%4416'; AccessMask = '0x1' }
)
$rpr = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $rp; Quiet = $true }
Assert-IR (@($rpr.Findings | Where-Object { $_.Target -like '*logon.bat*' }).Count -eq 0) 'NETLOGON \scripts\ share (not under \Policies\) not flagged'
Assert-IR (@($rpr.Findings | Where-Object { $_.Target -like '*evil.bat*' -and $_.Severity -eq 'High' }).Count -eq 1) 'GPO startup script under \Policies\...\Scripts\ is High'
Assert-IR (@($rpr.Findings | Where-Object { $_.Target -like '*GptTmpl.inf*' }).Count -eq 0) 'GptTmpl.inf READ (0x1, no write bit) not flagged'

# Regression (Major 3 + Minor 7): a non-code CSE edit is Medium & suppressible; code-CSE on gPCUser... is Critical and names the attribute.
$r1 = @(
    [pscustomobject]@{ TimeCreated = '2026-09-30T19:00:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'gpoadmin'; ObjectClass = 'groupPolicyContainer'; ObjectDN = 'CN={BBB},CN=Policies,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'gPCMachineExtensionNames'; AttributeValue = '[{00000000-0000-0000-0000-000000000000}{35378EAC-683F-11D2-A89A-00C04FBBCFA2}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}]'; OperationType = '%%14674' }
    [pscustomobject]@{ TimeCreated = '2026-09-30T19:01:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviluser'; ObjectClass = 'groupPolicyContainer'; ObjectDN = 'CN={CCC},CN=Policies,CN=System,DC=corp,DC=local'; AttributeLDAPDisplayName = 'gPCUserExtensionNames'; AttributeValue = '[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'; OperationType = '%%14674' }
)
$r1r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r1; Quiet = $true }
Assert-IR (@($r1r.Findings | Where-Object { $_.Account -eq 'gpoadmin' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'non-code CSE edit is Medium'
Assert-IR (@($r1r.Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.Title -like '*gPCUserExtensionNames*' }).Count -eq 1) 'code CSE on gPCUserExtensionNames is Critical and names the attribute'
$r1ex = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r1; Quiet = $true; ExcludeAccount = @('gpoadmin', 'eviluser') }
Assert-IR (@($r1ex.Findings | Where-Object { $_.Account -eq 'gpoadmin' }).Count -eq 0) 'non-code CSE edit suppressed by -ExcludeAccount'
Assert-IR (@($r1ex.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count -eq 1) 'code CSE add never suppressed by -ExcludeAccount'

# Regression (Minor 4): a cleared gPLink on the domain root is High and described as a removal, not an application.
$r2 = @([pscustomobject]@{ TimeCreated = '2026-09-30T19:10:00Z'; EventId = 5136; Computer = 'DC01'; LogName = 'Security'; SubjectUserName = 'eviluser'; ObjectClass = 'domainDNS'; ObjectDN = 'DC=corp,DC=local'; AttributeLDAPDisplayName = 'gPLink'; AttributeValue = ''; OperationType = '%%14675' })
$r2r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ InputObject = $r2; Quiet = $true }
Assert-IR (@($r2r.Findings | Where-Object { $_.Title -like '*sensitive*' -and $_.Severity -eq 'High' }).Count -eq 1) 'cleared gPLink on domain root is High'
Assert-IR (@($r2r.Findings | Where-Object { $_.Description -like '*removed*' -and $_.Description -notlike '*applies the linked*' }).Count -eq 1) 'cleared gPLink described as a removal, not an application'

Complete-IRTest
