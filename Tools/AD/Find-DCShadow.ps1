<#
.SYNOPSIS
    Detects DCShadow - rogue domain controller registration - from Windows Security event logs.

.DESCRIPTION
    DCShadow (mimikatz lsadump::dcshadow) lets an attacker who already holds high privilege push
    malicious changes into Active Directory through the REPLICATION channel instead of a normal LDAP
    write, so the change (SID history, group membership, primaryGroupID, a backdoor ACL, etc.) appears
    on every DC without a corresponding 4662/5136 "normal" modification on a real DC. To do it the
    attacker briefly turns an attacker-controlled machine into a transient DC:
      1. registers it as a DC by creating an nTDSDSA object ("NTDS Settings") under the Configuration
         partition (CN=Sites,CN=Configuration,...);
      2. adds two SPNs to the computer so real DCs will authenticate to it for replication: a Global
         Catalog SPN (GC/...) and the Directory Replication Service SPN carrying the DRSUAPI RPC
         interface GUID E3514235-4B06-11D1-AB04-00C04FC2DCD2;
      3. triggers replication (DsReplicaAdd / push);
      4. tears the nTDSDSA object and SPNs back down to clean up - so the rogue DC exists only for
         seconds to minutes.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 (Critical) - the DRS replication SPN (interface GUID E3514235-...) or a GC/ SPN is added
        to a computer that is NOT an established domain controller (4742 ServicePrincipalNames, or 5136
        Value-Added on servicePrincipalName). Registering replication capability on a non-DC is the
        defining DCShadow setup step.
      * RULE 2 (High; Critical when paired with RULE 3) - an nTDSDSA object is created (5137) under the
        Configuration/Sites partition - a new domain controller registered in the directory.
      * RULE 3 (Medium/Medium) - an nTDSDSA object is deleted (5141). On its own it is the teardown of
        a DC; correlated with a RULE 2 creation of the same object within -CorrelationMinutes it is the
        transient "appear then vanish" rogue DC that is DCShadow's signature - the delete is then folded
        into the RULE 2 creation finding, which escalates to Critical.
      * RULE 4 (High) - replication PUSH / topology rights used by a non-DC principal (4662 Properties
        containing DS-Replication-Synchronize, DS-Replication-Manage-Topology, or DS-Install-Replica).
        This is the push side of replication, distinct from the read rights Find-DCSync looks for.
      * RULE 5 (High) - DCShadow tooling in a PowerShell script block (4104): the dcshadow module name
        and the DRS replication call names (full signature set in the RULE 5 list in the body).

    Required audit policy / log sources (on domain controllers):
      * DS Access > Audit Directory Service Changes = Success  -> 5137 / 5141 (object create/delete) and
        5136 (attribute changes); needs a SACL on the Configuration naming context for the nTDSDSA events.
      * Account Management > Audit Computer Account Management = Success -> 4742.
      * DS Access > Audit Directory Service Access = Success (with SACL) -> 4662.
      * Optional: PowerShell Script Block Logging (4104) for RULE 5.

    Known false positives:
      * A LEGITIMATE domain controller promotion (dcpromo / Install-ADDSDomainController) performs the
        exact same steps - creates an nTDSDSA object and adds the GC and DRS SPNs. A real, planned new DC
        will therefore trip RULE 1 and RULE 2. Pass existing DCs to -DomainController so they are not
        reflagged, and confirm any new DC is an authorised promotion (then add it to -DomainController).
        The transient create+delete correlation (RULE 2+3) is the pattern a real promotion will NOT show.
      * Demoting a DC legitimately deletes its nTDSDSA object (RULE 3). Confirm against change control.

.PARAMETER ComputerName
    Remote computer to read the live Security log from (default: local machine).
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
.PARAMETER NoADLookup
    Skip live Active Directory DC discovery; only -DomainController entries are used to recognise DCs.
.PARAMETER DomainController
    Existing domain controller names / IPs. Consulted by RULE 1 (an SPN target that is a known DC is
    legitimate) and RULE 4 (a known-DC 4662 subject is excluded); RULE 2/3 do not use it. Offline, this
    supplies the whole DC list.
.PARAMETER CorrelationMinutes
    Window (minutes) in which an nTDSDSA create (5137) followed by a delete (5141) of the same object is
    treated as a transient rogue DC and escalated to Critical (default 60).

.EXAMPLE
    .\Find-DCShadow.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController DC01,DC02
    Hunt rogue-DC registration across two DC logs offline.

.EXAMPLE
    .\Find-DCShadow.ps1 -StartTime (Get-Date).AddDays(-3) -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1207 (Rogue Domain Controller)
    Events : 4742, 5136, 5137, 5141, 4662 (Security), 4104 (PowerShell Operational)
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
    [switch]$NoADLookup,
    [string[]]$DomainController,

    [int]$CorrelationMinutes = 60
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
    if (-not $toolName) { $toolName = 'Find-DCShadow' }
    $technique = 'T1207'; $techniqueName = 'Rogue Domain Controller (DCShadow)'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'DCShadow / rogue domain controller registration' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # DRSUAPI RPC interface GUID - the marker of the Directory Replication Service SPN that DCShadow adds.
    $drsGuid = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2'
    # Replication PUSH / topology rights (the push side; Find-DCSync owns the read side).
    $pushRightGuids = @{
        '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
        '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
        '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    }

    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController -NoDiscovery:$NoADLookup
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - cannot exclude legitimate DCs; RULE 4 confidence drops to Medium and findings carry a caveat.' -Level Detail }

    function Get-DnLeaf {
        param([string]$Dn)
        if (-not $Dn) { return $null }
        if ($Dn -match '^\s*CN=([^,]+)') { return $matches[1].Trim() }
        return $Dn.Trim()
    }

    function Test-IROpAdded {
        # 5136 OperationType: an add unless explicitly a delete (%%14675 / Value Deleted).
        param($Op)
        $o = [string]$Op
        if ($o -match '14675' -or $o -match 'Value Deleted') { return $false }
        return $true
    }

    function Get-DCSBareName {
        # Normalise NAME$@REALM / DOMAIN\NAME$ to the bare account before a DC-lookup test. Test-IRDomainController
        # itself handles the trailing '$' and FQDN, but not the UPN realm or DOMAIN\ prefix (CONVENTIONS).
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@[^@]+$') { $u = $matches[1] }
        if ($u -match '\\([^\\]+)$') { $u = $matches[1] }
        return $u.Trim()
    }

    # ---- RULE 1: DRS / GC SPN added to a non-DC computer (rogue DC registration) ----
    # Source A: 4742 computer account changed (ServicePrincipalNames carries the full current SPN list).
    $acctEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4742)
    # Source B: 5136 Value-Added on servicePrincipalName.
    $spn5136 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136 | Where-Object { ([string]$_.AttributeLDAPDisplayName) -ieq 'servicePrincipalName' })
    Write-IRStatus "Loaded $($acctEvents.Count) 4742 and $($spn5136.Count) servicePrincipalName 5136 event(s)" -Level Detail

    function Test-SpnTextDcShadow {
        # Returns a result object when the SPN text carries the DRS interface GUID or a GC/ SPN.
        param([string]$Text)
        $t = [string]$Text
        if (-not $t) { return $null }
        $tl = $t.ToLowerInvariant()
        $hasDrs = $tl -match [regex]::Escape($drsGuid)
        $hasGc = ($tl -match '(?m)(^|[\s,;])gc/')
        if (-not $hasDrs -and -not $hasGc) { return $null }
        $kinds = @(); if ($hasDrs) { $kinds += 'DRS replication SPN (E3514235-... DRSUAPI)' }; if ($hasGc) { $kinds += 'Global Catalog SPN (GC/)' }
        [pscustomobject]@{ HasDrs = $hasDrs; HasGc = $hasGc; Kinds = $kinds }
    }

    function Add-DcShadowSpnFinding {
        param($Evt, [string]$TargetName, [string]$Actor, $SpnResult, [int]$EventId)
        $isDc = $false
        if ($dcLookup.Count -gt 0) { $isDc = (Test-IRDomainController -Lookup $dcLookup -Value (Get-DCSBareName $TargetName)) }
        if ($isDc) { return }   # an established DC legitimately holds these SPNs
        $conf = 'High'
        $caveat = ''
        if ($SpnResult.HasDrs) { $conf = 'High' }
        if ($dcLookup.Count -eq 0) { $caveat = ' No DC list was supplied, so a legitimate DC could not be excluded; supply -DomainController to confirm.' }
        $actorTxt = $Actor; if (-not $actorTxt) { $actorTxt = '-' }
        $desc = ("The replication SPN(s) [{0}] were added to computer object '{1}' by {2}. These SPNs make other DCs treat the host as a domain controller for replication - the registration step of a rogue DC (DCShadow), or a (less likely) unplanned DC promotion. The host is not in the known-DC list.{3}" -f `
                ($SpnResult.Kinds -join ', '), $TargetName, $actorTxt, $caveat)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Replication (DRS/GC) SPN added to a non-DC computer (rogue DC registration)' `
                    -Description $desc -Account $actorTxt -Target $TargetName -Computer $Evt.Computer `
                    -EventIds $EventId -Evidence (Get-IRFirst @($Evt) 200) `
                    -Recommendation 'Confirm whether this host is an authorised new domain controller. If not, this is DCShadow: remove the SPNs and the nTDSDSA object, treat the actor and source host as compromised, hunt for replicated changes (sIDHistory, group membership, ACLs) pushed in the same window, and review who holds replication / DS-Install-Replica rights.'))
    }

    foreach ($e in $acctEvents) {
        $r = Test-SpnTextDcShadow ([string]$e.ServicePrincipalNames)
        if (-not $r) { continue }
        Add-DcShadowSpnFinding -Evt $e -TargetName ([string]$e.TargetUserName) -Actor ([string]$e.SubjectUserName) -SpnResult $r -EventId 4742
    }
    foreach ($e in $spn5136) {
        if (-not (Test-IROpAdded $e.OperationType)) { continue }
        $r = Test-SpnTextDcShadow ([string]$e.AttributeValue)
        if (-not $r) { continue }
        Add-DcShadowSpnFinding -Evt $e -TargetName (Get-DnLeaf ([string]$e.ObjectDN)) -Actor ([string]$e.SubjectUserName) -SpnResult $r -EventId 5136
    }

    # ---- RULE 2 / RULE 3: nTDSDSA object created (5137) / deleted (5141) ----
    $created = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5137)
    $deleted = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5141)
    Write-IRStatus "Loaded $($created.Count) 5137 and $($deleted.Count) 5141 event(s)" -Level Detail

    function Test-IsNtdsdsaObject {
        param($Evt)
        $cls = [string]$Evt.ObjectClass
        $dn = [string]$Evt.ObjectDN
        if ($cls -and $cls -match '(?i)nTDSDSA') { return $true }
        if ($dn -and ($dn -match '(?i)CN=NTDS Settings' -or ($dn -match '(?i)CN=Sites,CN=Configuration' -and $dn -match '(?i)CN=Servers'))) { return $true }
        return $false
    }

    # Index deletions by object DN for the transient-correlation check.
    $delByDn = @{}
    foreach ($e in $deleted) {
        if (-not (Test-IsNtdsdsaObject $e)) { continue }
        $k = ([string]$e.ObjectDN).ToLowerInvariant()
        if (-not $delByDn.ContainsKey($k)) { $delByDn[$k] = New-Object System.Collections.Generic.List[object] }
        $delByDn[$k].Add($e)
    }

    # DNs whose create+delete were actually correlated as a transient pair (so the delete is already
    # reported with the create). A delete that merely shares a DN with a create but was NOT correlated
    # (outside the window, or a null create time) is NOT in here, so it still gets its standalone finding.
    $pairedDns = @{}
    foreach ($e in $created) {
        if (-not (Test-IsNtdsdsaObject $e)) { continue }
        $dn = [string]$e.ObjectDN
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        # Transient correlation: a matching delete within the window => appear-then-vanish rogue DC.
        $transient = $null
        if ($delByDn.ContainsKey($dn.ToLowerInvariant())) {
            foreach ($d in $delByDn[$dn.ToLowerInvariant()]) {
                if (($e.TimeCreated -is [datetime]) -and ($d.TimeCreated -is [datetime])) {
                    $mins = ($d.TimeCreated - $e.TimeCreated).TotalMinutes
                    if ($mins -ge 0 -and $mins -le $CorrelationMinutes) { $transient = $d; break }
                }
            }
        }
        if ($transient) { $pairedDns[$dn.ToLowerInvariant()] = $true }
        $sev = 'High'; $conf = 'High'; $title = 'nTDSDSA object created (new domain controller registered)'
        $extra = ''
        if ($transient) {
            $sev = 'Critical'
            $title = 'Transient nTDSDSA object (rogue DC appeared then was removed - DCShadow)'
            $gap = [Math]::Round((($transient.TimeCreated - $e.TimeCreated).TotalMinutes), 1)
            $extra = (" The object was DELETED {0} min later (event 5141), i.e. the DC existed only transiently - the defining DCShadow pattern, not a normal promotion." -f $gap)
        }
        $desc = ("An nTDSDSA object ('{0}') was created under the Configuration partition by {1}, registering a new domain controller in the directory.{2} A rogue nTDSDSA lets an attacker push replicated changes that bypass normal change auditing (DCShadow)." -f $dn, $actor, $extra)
        $ev = @($e); if ($transient) { $ev += $transient }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title $title `
                    -Description $desc -Account $actor -Target $dn -Computer $e.Computer `
                    -EventIds (@($ev | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)) -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Confirm against change control whether a DC was being promoted. If not, this is a rogue DC (DCShadow): remove it, treat the actor/source as compromised, and hunt for the changes it replicated (sIDHistory, group membership, ACL/primaryGroupID edits) in the surrounding window.'))
    }

    # Standalone nTDSDSA deletions not paired with a create we saw -> DC demotion or DCShadow cleanup.
    foreach ($e in $deleted) {
        if (-not (Test-IsNtdsdsaObject $e)) { continue }
        $dn = [string]$e.ObjectDN
        if ($pairedDns.ContainsKey($dn.ToLowerInvariant())) { continue }   # already reported with its create (transient pair)
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $desc = ("An nTDSDSA object ('{0}') was deleted by {1}. This is either a legitimate DC demotion or the cleanup phase of a DCShadow rogue DC whose creation is not in this dataset." -f $dn, $actor)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'nTDSDSA object deleted (DC demotion or DCShadow cleanup)' `
                    -Description $desc -Account $actor -Target $dn -Computer $e.Computer `
                    -EventIds 5141 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm against change control whether a DC was demoted. If not, hunt for a matching nTDSDSA creation and replicated changes just before this time (DCShadow cleanup).'))
    }

    # ---- RULE 4: replication PUSH / topology rights used by a non-DC (4662) ----
    $ds = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4662)
    foreach ($e in $ds) {
        $guids = @(Get-IRGuidsFromText ([string]$e.Properties))
        if ($guids.Count -eq 0) { continue }
        $hits = @($guids | Where-Object { $pushRightGuids.ContainsKey($_) })
        if ($hits.Count -eq 0) { continue }
        $subject = [string]$e.SubjectUserName
        if (-not $subject) { continue }
        if ($dcLookup.Count -gt 0 -and (Test-IRDomainController -Lookup $dcLookup -Value (Get-DCSBareName $subject))) { continue }   # real DC replicating
        $rightNames = @($hits | ForEach-Object { $pushRightGuids[$_] })
        $conf = 'Medium'; if ($dcLookup.Count -gt 0) { $conf = 'High' }
        $caveat = ''; if ($dcLookup.Count -eq 0) { $caveat = ' No DC list supplied, so a legitimate DC could not be excluded; supply -DomainController.' }
        $desc = ("{0} exercised replication push/topology right(s) [{1}] on {2} (event 4662). These are the write/topology side of replication used to push changes or register replication - abnormal for a non-DC principal and consistent with DCShadow.{3}" -f `
                $subject, ($rightNames -join ', '), ([string]$e.ObjectName), $caveat)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Replication push/topology rights used by a non-DC' `
                    -Description $desc -Account $subject -Target ([string]$e.ObjectName) -Computer $e.Computer `
                    -EventIds 4662 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the principal is an authorised DC. If not, treat as DCShadow / replication abuse: investigate the source host and restrict replication rights on the naming contexts to domain controllers only.'))
    }

    # ---- RULE 5: DCShadow tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'lsadump::dcshadow', 'dcshadow', 'DsReplicaAdd', 'DsAddEntry', 'Invoke-Mimikatz', 'mimikatz'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'DCShadow tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched DCShadow signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this. Correlate with nTDSDSA create/delete, replication-SPN additions, and 4662 replication rights from the same host and window.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
