<#
.SYNOPSIS
    Detects DCSync (directory replication) credential theft from Windows Security and PowerShell logs.

.DESCRIPTION
    DCSync abuses Active Directory replication. A security principal that holds the
    DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights can ask a domain
    controller to replicate secrets - including every account's password hash and the krbtgt key -
    by issuing the MS-DRSR DsGetNCChanges call. Tools such as mimikatz "lsadump::dcsync" and Impacket
    secretsdump perform exactly this. Because replication is a normal DC-to-DC operation, the abuse is
    only distinguishable by the identity of the requester: a legitimate request comes from a domain
    controller, a malicious one comes from a user or a non-DC machine account.

    Detection logic:
      * Source: Security event 4662 (Audit Directory Service Access - operations on objects) logged on
        the DC. The key fields are SubjectUserName / SubjectUserSid / SubjectDomainName (who asked),
        ObjectName (the object replicated - the domain head for a full DCSync), AccessMask, and
        Properties (the list of control-access right / attribute GUIDs that were exercised).
      * Rule 1 - DCSync by a non-DC: a 4662 whose Properties field contains one or more of the
        replication right GUIDs
          1131f6aa-9c07-11d1-f79f-00c04fc2dcd2  DS-Replication-Get-Changes
          1131f6ad-9c07-11d1-f79f-00c04fc2dcd2  DS-Replication-Get-Changes-All
          89e95b76-444d-4c62-991a-0facbeda640c  DS-Replication-Get-Changes-In-Filtered-Set
        where the SubjectUserName is NOT a known domain controller (name / machine account) and is NOT
        an analyst-approved replication service account. Reported as Critical. If Get-Changes-All was
        requested the finding notes that all domain secrets (hashes + krbtgt) can be replicated.
      * Rule 3 - DCSync tooling in PowerShell: a 4104 script block containing DCSync tool signatures
        (dcsync, lsadump, DsGetNCChanges, secretsdump, Invoke-DCSync, Get-ADReplAccount).

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > DS Access > Audit Directory Service Access = Success, PLUS a SACL
        that audits the replication rights on the domain head (domainDNS object). Without the SACL the
        4662 events are never written.
      * Optional: PowerShell Script Block Logging (4104) for Rule 3.

    Known false positives:
      * Domain controllers replicate constantly and legitimately generate 4662 with these GUIDs, so
        DC subjects MUST be excluded. Supply -DomainController with the DC names when running offline
        (not domain joined) - otherwise DC exclusion cannot be performed and the finding is lowered to
        Medium confidence with an explicit note.
      * Azure AD Connect / directory-sync service accounts (typically MSOL_ * ) legitimately hold
        Get-Changes and Get-Changes-All. Pass known good accounts via -KnownReplicationAccount to
        suppress them. Read-only DCs use Get-Changes-In-Filtered-Set as part of normal operation.

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
    Skip live Active Directory look-ups. This tool performs no per-object AD enrichment; the switch
    only prevents implicit live discovery of the domain controllers, in which case DC exclusion relies
    solely on the names supplied through -DomainController.
.PARAMETER DomainController
    DC names / IPs used to recognise legitimate domain-controller replication (and to exclude it).
    Supply these when running offline / not domain joined so that DC-to-DC replication is not flagged.
.PARAMETER KnownReplicationAccount
    Service accounts that legitimately hold replication rights (e.g. Azure AD Connect MSOL_ accounts).
    4662 replication events from these subjects are not reported.

.EXAMPLE
    .\Find-DCSync.ps1 -DomainController DC01,DC02
    Analyse the local DC Security log for the last 7 days, excluding replication by DC01 and DC02.

.EXAMPLE
    .\Find-DCSync.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -KnownReplicationAccount MSOL_a1b2c3 -OutputPath C:\Evidence\Out -Format All

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} | ConvertFrom-IRWinEvent | .\Find-DCSync.ps1 -DomainController DC01

.NOTES
    ATT&CK : T1003.006 (OS Credential Dumping: DCSync)
    Events : 4662 (Security - Directory Service Access), 4104 (PowerShell Operational)
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

    [string[]]$KnownReplicationAccount
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
    if (-not $toolName) { $toolName = 'Find-DCSync' }
    $technique = 'T1003.006'; $techniqueName = 'DCSync'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]

    # The three replication extended rights whose presence in a 4662 Properties field indicates DCSync.
    $dcSyncTriggerGuids = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = $true
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = $true
        '89e95b76-444d-4c62-991a-0facbeda640c' = $true
    }
    $getChangesAllGuid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    $knownReplSet = @{}
    foreach ($a in @($KnownReplicationAccount)) { if ($a) { $knownReplSet[$a.ToLowerInvariant().TrimEnd('$')] = $true } }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'DCSync (directory replication of domain secrets by a non-DC)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # Build the domain-controller exclusion lookup. Only perform live DC discovery when AD is actually
    # reachable and -NoADLookup was not set; otherwise trust only the analyst-supplied -DomainController
    # names (this keeps the tool error-free when run offline / not domain joined).
    $dcLookup = $null
    if ((-not $NoADLookup) -and (Test-IRAdAvailable)) {
        $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController
    }
    else {
        $dcLookup = @{}
        foreach ($d in @($DomainController)) {
            if (-not $d) { continue }
            $n = ([string]$d).ToLowerInvariant()
            $dcLookup[$n] = $true
            $short = $n.Split('.')[0]
            $dcLookup[$short] = $true
            $dcLookup["$short`$"] = $true
        }
    }
    $dcListAvailable = ($dcLookup -and $dcLookup.Count -gt 0)
    if (-not $dcListAvailable) {
        Write-IRStatus 'No domain-controller list available - DC replication cannot be excluded. Supply -DomainController for accurate results.' -Level Warning
    }

    # ---- Rule 1: directory-replication (DCSync) 4662 by a non-domain-controller ---------------------
    $ds = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4662)
    Write-IRStatus "Loaded $($ds.Count) 4662 event(s)" -Level Detail

    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($e in $ds) {
        $propText = ''
        $pp = $e.PSObject.Properties['Properties']
        if ($pp) { $propText = [string]$pp.Value }
        if (-not $propText -and $e.PSObject.Properties['Message']) { $propText = [string]$e.Message }
        if (-not $propText) { continue }

        $guids = @(Get-IRGuidsFromText $propText)
        if ($guids.Count -eq 0) { continue }
        $hits = @($guids | Where-Object { $dcSyncTriggerGuids.ContainsKey($_) })
        if ($hits.Count -eq 0) { continue }                                  # no replication right -> not DCSync

        $subject = [string]$e.SubjectUserName
        if (-not $subject) { continue }
        if (Test-IRDomainController -Lookup $dcLookup -Value $subject) { continue }  # legitimate DC replication
        $subjKey = $subject.ToLowerInvariant().TrimEnd('$')
        if ($knownReplSet.ContainsKey($subjKey)) { continue }                        # approved sync account

        $e | Add-Member -NotePropertyName _TriggerGuids -NotePropertyValue $hits -Force
        $candidates.Add($e)
    }
    Write-IRStatus "$($candidates.Count) replication 4662 event(s) from non-DC subject(s) after filtering" -Level Detail

    $conf = 'High'
    if (-not $dcListAvailable) { $conf = 'Medium' }

    foreach ($g in ($candidates.ToArray() | Group-Object { Get-IRAccountKey $_.SubjectUserName $_.SubjectDomainName })) {
        $ev = @($g.Group)
        $subject = [string]$ev[0].SubjectUserName
        $domain = [string]$ev[0].SubjectDomainName
        $who = $subject
        if ($domain -and $domain -ne '-') { $who = "$domain\$subject" }
        $target = [string]$ev[0].ObjectName
        $computer = [string]$ev[0].Computer

        # Union of the replication rights actually exercised, resolved to readable names.
        $rg = New-Object System.Collections.Generic.List[string]
        foreach ($x in $ev) { foreach ($gu in @($x._TriggerGuids)) { if ($gu -and ($rg -notcontains $gu)) { $rg.Add($gu) } } }
        $rightNames = @($rg | ForEach-Object { Resolve-IRGuidName $_ -NoSchemaLookup })
        $hasAll = ($rg -contains $getChangesAllGuid)
        $amask = [string]$ev[0].AccessMask
        $amaskFlags = @(ConvertFrom-IRDsAccessMask $amask)

        $desc = "{0} requested Active Directory replication of '{1}' on {2} via extended right(s): {3}. {4} directory-service-access event(s) (4662); AccessMask {5} [{6}]." -f `
            $who, $target, $computer, ($rightNames -join ', '), $ev.Count, $amask, ($amaskFlags -join ', ')
        if ($hasAll) {
            $desc += ' DS-Replication-Get-Changes-All was requested - this replicates all domain secrets including every password hash and the krbtgt key (full DCSync).'
        }
        else {
            $desc += ' Only partial replication right(s) were seen, which is still abnormal for a non-DC principal.'
        }
        if (-not $dcListAvailable) {
            $desc += ' DC exclusion could not be performed (no DC list available); supply -DomainController to filter.'
        }

        # Entra / Azure AD Connect sync accounts (MSOL_<hex>, AAD_<hex>, the AAD Connect gMSA, or an
        # account literally named ADSync / AADConnect) legitimately hold Get-Changes rights. Their name is
        # environment-specific so they cannot be excluded by default, but we can RECOGNISE the well-known
        # pattern and down-rank from Critical to Low with a confirm note, rather than alarm on first run.
        # Pass the real account via -KnownReplicationAccount to suppress entirely.
        $sev = 'Critical'; $title = 'DCSync directory replication by non-DC account'
        $subjKeyLower = $subject.ToLowerInvariant().TrimEnd('$')
        if ($subjKeyLower -match '^(msol_[0-9a-f]+|aad_[0-9a-f]+|aadconnect|adsync|sync_[0-9a-f]+)$' -or $subject -match '(?i)aad.?connect') {
            $sev = 'Low'
            $title = 'Directory replication by a likely Azure AD Connect / sync account (confirm)'
            $desc += ' The subject name matches the Azure AD Connect / Entra sync pattern (e.g. MSOL_*), which legitimately replicates directory changes. Confirm this is your sync account; if it is, add it to -KnownReplicationAccount to suppress. If it is NOT your sync account, an attacker may be masquerading as one - treat as Critical.'
        }

        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title $title `
                    -Description $desc -Account $subject -Target $target -Computer $computer `
                    -EventIds 4662 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Confirm whether this principal is an authorised domain controller or an approved replication service (e.g. Azure AD Connect). If not, treat as domain-wide credential compromise: reset the krbtgt password twice, rotate privileged and service-account credentials, and investigate the source host for mimikatz / secretsdump. Restrict DS-Replication-Get-Changes* rights on the domain head to domain controllers only.'))
    }

    # ---- Rule 3: DCSync tooling in PowerShell script blocks (4104) ----------------------------------
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'dcsync', 'lsadump', 'DsGetNCChanges', 'secretsdump', 'Invoke-DCSync', 'Get-ADReplAccount', 'DCSync'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'DCSync tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched DCSync signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence @($e) `
                            -Recommendation 'Identify the user and process that ran this script block. Correlate with 4662 replication events from the same host and treat the host as compromised.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
