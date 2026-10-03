<#
.SYNOPSIS
    Detects Group Policy abuse (malicious GPO edits, links and SYSVOL template tampering) from Windows
    Security and PowerShell event logs.

.DESCRIPTION
    An attacker with write access to a Group Policy Object - or who can create and link one - can push a
    change to every computer or user the GPO applies to: an immediate scheduled task (code execution),
    a logon/startup script, Restricted Groups membership (adding themselves to local Administrators), or
    user-rights assignments. Tools: SharpGPOAbuse, New-GPOImmediateTask, PowerGPOAbuse, pyGPOAbuse.

    A GPO has two halves: the Group Policy Container (GPC) in AD (CN={GUID},CN=Policies,CN=System,...,
    objectClass groupPolicyContainer) and the Group Policy Template (GPT) files in SYSVOL
    (\\domain\SYSVOL\domain\Policies\{GUID}\ ... GptTmpl.inf, ScheduledTasks.xml, scripts). It is linked to
    a scope (domain / OU / site) via the gPLink attribute. This tool watches all three.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 - a Group Policy Container was modified (5136 on a groupPolicyContainer):
          - gPCMachineExtensionNames / gPCUserExtensionNames changed: Critical when a code-executing CSE
            GUID (scheduled tasks / scripts) is added; otherwise Medium (enabling a non-code settings
            category is routine authoring, suppressed for -ExcludeAccount GPO admins).
          - nTSecurityDescriptor changed (the GPO's ACL - e.g. granting an attacker write) -> High.
          - any other attribute (versionNumber, gPCFileSysPath, displayName, flags) -> Medium routine edit
            (suppressed for -ExcludeAccount GPO admins).
      * RULE 2 - a gPLink was changed (5136 gPLink on an OU / domain): High when the linked scope is the
        Domain Controllers OU or the domain root (pushes/removes the GPO to DCs / everyone), else Medium.
      * RULE 3 - a new Group Policy Container was created (5137) -> Medium (an attacker-created GPO to link).
      * RULE 4 - SYSVOL GPT tampering (5145 detailed file share, or 4663 file access) writing a policy file
        under \Policies\{GUID}\. Code / privilege vectors (ScheduledTasks.xml, scripts.ini / psscripts.ini,
        a Scripts\ folder file) -> High (the GPT-side write SharpGPOAbuse / pyGPOAbuse perform). GptTmpl.inf
        / Registry.pol are rewritten on nearly every GPO save -> Medium (suppressed for -ExcludeAccount).
      * RULE 5 - GPO-abuse tooling INVOKED in a PowerShell script block (4104) or a process (4688):
        SharpGPOAbuse, New-GPOImmediateTask, PowerGPOAbuse, pyGPOAbuse -> High. Merely naming a tool
        (opening its output or a detection rule) does not fire.

    Required audit policy / log sources (domain controllers):
      * DS Access > Audit Directory Service Changes = Success (SACL on the Policies container / OUs) -> 5136 / 5137.
      * Object Access > Audit Detailed File Share = Success (or a SACL on SYSVOL) -> 5145; File System -> 4663.
      * Audit Process Creation (with command line) -> 4688; PowerShell Script Block Logging -> 4104.

    Known false positives:
      * Administrators edit GPOs routinely - every edit bumps versionNumber and can touch
        gPCMachineExtensionNames. The strong signals (code-executing CSE added, GPO ACL changed, link to the
        DC OU / domain root, SYSVOL task/script write, named tooling) are the attack indicators; routine
        attribute edits are Medium and can be suppressed for known GPO admins via -ExcludeAccount. Confirm
        GPO changes against change control.

.PARAMETER ComputerName
    Remote computer to read the live logs from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders) to analyse offline.
.PARAMETER InputObject
    Pre-flattened IRToolKit event objects via the pipeline.
.PARAMETER InputPath
    JSON / CSV / CliXml file of pre-flattened events.
.PARAMETER StartTime
    Only analyse events at or after this time (live mode defaults to the last 7 days).
.PARAMETER EndTime
    Only analyse events at or before this time.
.PARAMETER MaxEvents
    Cap on events read per event-ID batch (0 = unlimited).
.PARAMETER OutputPath
    Directory or file to write results to.
.PARAMETER Format
    Export format: Csv, Json, Html or All (default Json).
.PARAMETER Quiet
    Suppress console status output.
.PARAMETER ExcludeAccount
    Known GPO administrators / management service accounts. Their ROUTINE GPO edits (RULE 1 Medium, RULE 2
    Medium links, RULE 3 new GPOs) are suppressed; the strong signals (CSE add, ACL change, DC/domain link,
    SYSVOL task/script write, tooling) are NEVER suppressed, so a compromised admin is still caught.

.EXAMPLE
    .\Find-GPOAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeAccount gpoadmin,CORP\gpo_svc
    Hunt GPO abuse in an exported DC Security log, suppressing routine edits by known GPO admins.

.EXAMPLE
    .\Find-GPOAbuse.ps1 -StartTime (Get-Date).AddDays(-14) -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1484.001 (Domain Policy Modification: Group Policy Modification)
    Events : 5136, 5137, 5145, 4663 (Security), 4688, 4104 (PowerShell Operational)
    Part of IRToolKit.
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Live')][string]$ComputerName,
    [Parameter(ParameterSetName = 'Live')][pscredential]$Credential,
    [Parameter(ParameterSetName = 'File', Mandatory)][string[]]$Path,
    [Parameter(ParameterSetName = 'Object', Mandatory, ValueFromPipeline)][AllowEmptyCollection()][object[]]$InputObject,
    [Parameter(ParameterSetName = 'ObjectFile', Mandatory)][string]$InputPath,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [int]$MaxEvents = 0,
    [string]$OutputPath,
    [ValidateSet('Csv', 'Json', 'Html', 'All')][string]$Format = 'Json',
    [switch]$Quiet,

    [string[]]$ExcludeAccount
)

begin {
    $irModule = $null; $irDir = $PSScriptRoot
    for ($i = 0; $i -lt 5 -and $irDir; $i++) {
        $candidate = Join-Path $irDir 'Common\IRToolKit.Common.psm1'
        if (Test-Path -LiteralPath $candidate) { $irModule = $candidate; break }
        $irDir = Split-Path -Parent $irDir
    }
    if (-not $irModule) { throw "IRToolKit.Common.psm1 not found above $PSScriptRoot. Keep the folder structure intact." }
    Import-Module $irModule -Force
    $toolName = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    if (-not $toolName) { $toolName = 'Find-GPOAbuse' }
    $technique = 'T1484.001'; $techniqueName = 'Group Policy Modification'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $excludeSet = @{}
    foreach ($x in @($ExcludeAccount)) {
        if ($x) {
            $xb = [string]$x
            if ($xb -match '^(.+)@[^@]+$') { $xb = $matches[1] }
            if ($xb -match '\\([^\\]+)$') { $xb = $matches[1] }
            $excludeSet[$xb.Trim().ToLowerInvariant().TrimEnd('$')] = $true
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Group Policy abuse (malicious GPO edits / links / SYSVOL tampering)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # Client-side-extension GUIDs that cause a GPO to execute code when added to gPC*ExtensionNames.
    $codeCseGuids = @{
        'aadced64-746c-4633-a97c-d61349046527' = 'Scheduled Tasks (immediate task - code execution)'
        '42b5faae-6536-11d2-ae5a-0000f87571e3' = 'Scripts (logon/startup - code execution)'
        'cdeafc3d-948d-49dd-ab12-e578ba4af7aa' = 'TCPIP / scheduled task CSE'
    }
    # Code / privilege-delivery GPT files -> High, never suppressed (the actual SharpGPOAbuse vectors).
    $gptCodeFiles = 'scheduledtasks\.xml', 'scripts\.ini', 'psscripts\.ini', '\\scripts\\'
    # Policy files written on nearly every routine GPO save -> Medium, suppressible for known admins.
    $gptPolicyFiles = 'gpttmpl\.inf', 'registry\.pol'

    # GPO-abuse tool / cmdlet detection that does NOT fire on merely NAMING a tool (opening its output,
    # a detection rule, or this tool's own source). Binary/script tools must be INVOKED (not a -output.txt
    # filename argument); PowerView/PowerGPOAbuse functions must be at a command position, not an argument
    # passed to e.g. findstr.
    function Get-GpoToolHit {
        param([string]$Text)
        if (-not $Text) { return $null }
        if ($Text -match '(?i)(?<![\w-])(SharpGPOAbuse|pygpoabuse|PowerGPOAbuse)(\.exe|\.py)?(?=$|[\s"''|);])') { return $matches[1] }
        if ($Text -match '(?im)(?:^|[\n;&{(="''|])\s*(?:\$\w+\s*=\s*)?(New-GPOImmediateTask|Invoke-GPOImmediateTask|Set-GPOImmediateTask|Add-GPOGroupMember)\b') { return $matches[1] }
        return $null
    }

    function Test-GpoExcluded {
        param([string]$Actor)
        if ($excludeSet.Count -eq 0) { return $false }
        $a = ([string]$Actor).Trim().ToLowerInvariant()
        if (-not $a) { return $false }
        if ($excludeSet.ContainsKey($a.TrimEnd('$'))) { return $true }
        if ($a -match '\\([^\\]+)$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        if ($a -match '^(.+)@[^@]+$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        return $false
    }
    function Test-IsGpcObject {
        param($Evt)
        $cls = [string]$Evt.ObjectClass
        $dn = [string]$Evt.ObjectDN
        if ($cls -match '(?i)groupPolicyContainer') { return $true }
        if ($dn -match '(?i)CN=Policies,CN=System') { return $true }
        return $false
    }
    function Test-IROpAdded {
        param($Op)
        $o = [string]$Op
        return -not ($o -match '14675' -or $o -match 'Value Deleted')
    }

    $dirMods = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136)
    Write-IRStatus "Loaded $($dirMods.Count) 5136 event(s)" -Level Detail

    foreach ($e in $dirMods) {
        $attr = [string]$e.AttributeLDAPDisplayName
        if (-not $attr) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $objDn = [string]$e.ObjectDN
        $val = [string]$e.AttributeValue

        # ---- RULE 2: gPLink change on an OU / domain ----
        if ($attr -ieq 'gPLink') {
            $isDcOu = ($objDn -match '(?i)OU=Domain Controllers')
            $isDomainRoot = ($objDn -match '^(?i)DC=')   # DN begins with DC= => the domain head object
            $isCleared = (-not $val.Trim()) -or (-not (Test-IROpAdded $e.OperationType))  # link removed / value deleted
            if ($isDcOu -or $isDomainRoot) {
                $scope = if ($isDcOu) { 'the Domain Controllers OU' } else { 'the domain root' }
                if ($isCleared) {
                    $desc = ("{0} removed a GPO link (gPLink) from {1} (5136). Removing a link from {2} stops the GPO applying there - which can silently disable a security baseline across the most sensitive systems." -f $actor, $objDn, $scope)
                } else {
                    $desc = ("{0} changed the gPLink on {1} (5136), which applies the linked GPO(s) to {2}. Linking a GPO to the DC OU or domain root pushes its settings to the most sensitive systems - a common GPO-abuse escalation. New value: {3}" -f $actor, $objDn, $scope, $val)
                }
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'GPO link (gPLink) changed on a sensitive scope' `
                            -Description $desc `
                            -Account $actor -Target $objDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm the link change was authorised. If not, restore/remove it, and inspect the linked GPO(s) for malicious scheduled tasks / scripts / Restricted Groups settings.'))
            }
            elseif (-not (Test-GpoExcluded $actor)) {
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'GPO link (gPLink) changed' `
                            -Description ("{0} changed the gPLink on {1}. A new GPO link changes which policy applies to that scope; confirm it is an authorised change." -f $actor, $objDn) `
                            -Account $actor -Target $objDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm the link change was authorised and the linked GPO is expected.'))
            }
            continue
        }

        if (-not (Test-IsGpcObject $e)) { continue }
        if (-not (Test-IROpAdded $e.OperationType)) { continue }
        $gpoCn = $objDn; if ($gpoCn -match '^\s*CN=([^,]+)') { $gpoCn = $matches[1].Trim() }

        # ---- RULE 1: GPO container attribute changes ----
        if ($attr -imatch '^gPC(Machine|User)ExtensionNames$') {
            $guids = @(Get-IRGuidsFromText $val)
            $codeHits = @($guids | Where-Object { $codeCseGuids.ContainsKey($_) })
            if ($codeHits.Count -gt 0) {
                # A code-executing CSE was added -> the attack indicator. Always fired, never suppressed.
                $note = ' A code-executing client-side extension was added: ' + (($codeHits | ForEach-Object { $codeCseGuids[$_] }) -join ', ') + '. The GPO will now run that on every machine in scope.'
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title ("GPO client-side extension list changed ({0})" -f $attr) `
                            -Description ("{0} changed {1} on GPO '{2}'. Adding a client-side extension makes the GPO process a new policy type (scheduled tasks, scripts, registry) on targets - the mechanism SharpGPOAbuse / New-GPOImmediateTask use to push code.{3} Value: {4}" -f $actor, $attr, $gpoCn, $note, $val) `
                            -Account $actor -Target $gpoCn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm the GPO edit was authorised. If not, inspect the GPO''s SYSVOL folder for ScheduledTasks.xml / scripts and remove them, unlink the GPO, and treat targets in scope as potentially compromised.'))
                continue
            }
            # No code-executing CSE: enabling a new (non-code) settings category rewrites the CSE list on
            # normal GPO authoring -> Medium, suppressible for known GPO admins.
            if (Test-GpoExcluded $actor) { continue }
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                        -Technique $technique -TechniqueName $techniqueName -Title ("GPO client-side extension list changed ({0})" -f $attr) `
                        -Description ("{0} changed {1} on GPO '{2}'. This enables a new policy type on targets; no code-executing (scheduled-task / script) client-side extension was added, so it is likely routine GPO authoring - confirm against change control. Value: {3}" -f $actor, $attr, $gpoCn, $val) `
                        -Account $actor -Target $gpoCn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the GPO edit was authorised. Correlate with SYSVOL writes and ACL changes on the same GPO.'))
            continue
        }
        if ($attr -ieq 'nTSecurityDescriptor') {
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'GPO security descriptor (ACL) changed' `
                        -Description ("{0} changed the security descriptor (ACL) of GPO '{1}'. Granting write/edit rights on a GPO lets a principal push policy to every system in its scope - a GPO-takeover step." -f $actor, $gpoCn) `
                        -Account $actor -Target $gpoCn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the delegation change was authorised. If not, restore the GPO ACL, identify who was granted write, and review the GPO contents.'))
            continue
        }
        # Routine GPO attribute edit (versionNumber, gPCFileSysPath, displayName, flags, ...).
        if (Test-GpoExcluded $actor) { continue }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Group Policy Object modified' `
                    -Description ("{0} modified GPO '{1}' (attribute {2}). GPO edits are routine for administrators but also the vehicle for policy-based attacks; confirm against change control." -f $actor, $gpoCn, $attr) `
                    -Account $actor -Target $gpoCn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the GPO change was authorised. Correlate with SYSVOL writes and CSE / ACL changes on the same GPO.'))
    }

    # ---- RULE 3: new Group Policy Container created (5137) ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5137)) {
        if (-not (Test-IsGpcObject $e)) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        if (Test-GpoExcluded $actor) { continue }
        $objDn = [string]$e.ObjectDN
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'New Group Policy Object created' `
                    -Description ("{0} created a new Group Policy Container ({1}). Attackers create a GPO they control and then link it to a scope; on its own a new GPO is also routine administration." -f $actor, $objDn) `
                    -Account $actor -Target $objDn -Computer $e.Computer -EventIds 5137 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the GPO was created by an authorised admin. Watch for it being linked (gPLink) and for scheduled-task / script content in its SYSVOL folder.'))
    }

    # ---- RULE 4: SYSVOL GPT tampering (5145 detailed file share / 4663 file access) ----
    # GPO template files always live under ...\Policies\{GUID}\... in SYSVOL. Requiring \policies\ in the
    # path keeps the legacy NETLOGON \scripts\ share (SYSVOL\<domain>\scripts\) from matching the script
    # pattern. Code/privilege files (ScheduledTasks.xml, scripts) are High and never suppressed; the policy
    # files written on nearly every GPO save (GptTmpl.inf, Registry.pol) are Medium and suppressible.
    function Test-GptWrite {
        param([string]$PathText, [string]$AccessText, [string]$AccessMask)
        if (-not $PathText) { return $null }
        $p = $PathText.ToLowerInvariant()
        if ($p -notmatch '\\policies\\') { return $null }
        $fileHit = $null; $cat = $null
        foreach ($f in $gptCodeFiles) { if ($p -match $f) { $fileHit = $f; $cat = 'Code'; break } }
        if (-not $fileHit) { foreach ($f in $gptPolicyFiles) { if ($p -match $f) { $fileHit = $f; $cat = 'Policy'; break } } }
        if (-not $fileHit) { return $null }
        # Write vs read: match the access-right text, or decode the numeric AccessMask (a write logged with
        # only the hex mask, no %% text, would otherwise be missed). Write-ish bits: FILE_WRITE_DATA 0x2,
        # FILE_APPEND_DATA 0x4, FILE_WRITE_EA 0x10, FILE_WRITE_ATTRIBUTES 0x100, DELETE 0x10000,
        # WRITE_DAC 0x40000, WRITE_OWNER 0x80000, GENERIC_WRITE 0x40000000, GENERIC_ALL 0x10000000.
        $isWrite = $false
        $a = ([string]$AccessText).ToLowerInvariant()
        if ($a -match 'write|append|%%4417|%%4418|%%4424|create|delete') { $isWrite = $true }
        if (-not $isWrite) {
            $mask = 0L; $mt = ([string]$AccessMask).Trim()
            if ($mt -match '^0x[0-9a-fA-F]+$') { try { $mask = [Convert]::ToInt64($mt, 16) } catch { $mask = 0L } }
            elseif ($mt -match '^\d+$') { try { $mask = [int64]$mt } catch { $mask = 0L } }
            $writeBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
            if (($mask -band $writeBits) -ne 0) { $isWrite = $true }
        }
        if (-not $isWrite) { return $null }
        return [pscustomobject]@{ File = $fileHit; Category = $cat }
    }
    function Add-GptWriteFinding {
        param($Result, [string]$Actor, $Evt, [string]$TargetText, [string]$SourceIpText, [int]$EventId)
        $isCode = ($Result.Category -eq 'Code')
        if (-not $isCode -and (Test-GpoExcluded $Actor)) { return }  # routine policy-file save by a known GPO admin
        $sev = 'Medium'; if ($isCode) { $sev = 'High' }
        $src = ''; if ($SourceIpText) { $src = " from $SourceIpText" }
        if ($isCode) {
            $desc = ("{0} wrote a code/privilege Group Policy template file under SYSVOL\\Policies{1} (event {2}): {3}. Writing ScheduledTasks.xml or a startup/logon script into a GPO's SYSVOL folder is how SharpGPOAbuse / pyGPOAbuse deliver code or privilege changes to every system in scope." -f $Actor, $src, $EventId, $TargetText)
            $rec = 'Inspect the written file (an immediate scheduled task, startup script, or Restricted Groups entry). Remove malicious content, unlink/disable the GPO, and treat targets in scope as compromised.'
        } else {
            $desc = ("{0} wrote a Group Policy template file under SYSVOL\\Policies{1} (event {2}): {3}. GptTmpl.inf / Registry.pol are rewritten on nearly every GPO save, so this is likely routine - but confirm it against change control and review the setting that changed." -f $Actor, $src, $EventId, $TargetText)
            $rec = 'Confirm the GPO edit was authorised. Compare the file against the previous version to see which security setting / registry value changed.'
        }
        $ev = @{ Tool = $toolName; Severity = $sev; Confidence = 'Medium'; Technique = $technique; TechniqueName = $techniqueName
            Title = 'GPO SYSVOL policy file written (GPT tampering)'; Description = $desc; Account = $Actor; Target = $TargetText
            Computer = $Evt.Computer; EventIds = $EventId; Evidence = (Get-IRFirst @($Evt) 200); Recommendation = $rec }
        if ($SourceIpText) { $ev['SourceIp'] = $SourceIpText }
        $findings.Add((New-IRFinding @ev))
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5145)) {
        $rel = ([string]$e.ShareName) + '\' + ([string]$e.RelativeTargetName)
        $res = Test-GptWrite -PathText $rel -AccessText ([string]$e.AccessList) -AccessMask ([string]$e.AccessMask)
        if (-not $res) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        Add-GptWriteFinding -Result $res -Actor $actor -Evt $e -TargetText ([string]$e.RelativeTargetName) -SourceIpText (ConvertTo-IRIpAddress $e.IpAddress) -EventId 5145
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4663)) {
        $res = Test-GptWrite -PathText ([string]$e.ObjectName) -AccessText ([string]$e.AccessList) -AccessMask ([string]$e.AccessMask)
        if (-not $res) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        Add-GptWriteFinding -Result $res -Actor $actor -Evt $e -TargetText ([string]$e.ObjectName) -SourceIpText '' -EventId 4663
    }

    # ---- RULE 5: GPO-abuse tooling in PowerShell (4104) and processes (4688) ----
    # Get-GpoToolHit only fires on an actual INVOCATION, never on a tool name that appears as a file
    # argument (e.g. notepad SharpGPOAbuse-notes.txt) or a search string (findstr /i New-GPOImmediateTask ...).
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)) {
        $text = [string]$e.ScriptBlockText
        if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
        if (-not $text) { continue }
        $hit = Get-GpoToolHit $text
        if ($hit) {
            $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'GPO-abuse tooling in PowerShell script block' `
                        -Description ("PowerShell script block on {0} matched GPO-abuse signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                        -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Identify the user and process. Correlate with 5136 GPO edits, gPLink changes and SYSVOL writes in the same window.'))
        }
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4688)) {
        $img = [string]$e.NewProcessName
        $cmd = [string]$e.CommandLine
        $leaf = (($img -split '[\\/]')[-1]).ToLowerInvariant()
        $hit = $null
        if ($leaf -eq 'sharpgpoabuse.exe' -or $leaf -eq 'pygpoabuse.exe') { $hit = $leaf }
        else { $hit = Get-GpoToolHit $cmd }   # invocation-anchored: tool as a named file arg does not match
        if (-not $hit) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'GPO-abuse tool executed' `
                    -Description ("{0} ran a GPO-abuse tool on {1}: {2}. Command: {3}" -f $actor, $e.Computer, $hit, $(if ($cmd) { $cmd } else { $img })) `
                    -Account $actor -Target $hit -Computer $e.Computer -EventIds 4688 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm whether authorised. Correlate with GPO edits (5136), gPLink changes and SYSVOL writes from the same host and window.'))
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
