<#
.SYNOPSIS
    Detects SID History injection - a privileged SID planted in an account's sIDHistory - from Windows
    Security and PowerShell event logs.

.DESCRIPTION
    sIDHistory is a legitimate attribute used during domain migration: a migrated account carries its
    old-domain SID so it keeps access. Attackers abuse it by injecting a PRIVILEGED SID (Domain Admins
    512, Enterprise Admins 519, Schema Admins 518, the domain Administrator 500, builtin Administrators
    S-1-5-32-544, etc.) into the sIDHistory of an account they control. The account then inherits all the
    access of that SID, invisibly - it is NOT a listed member of the group, so group-membership audits
    miss it. It is a stealthy privilege-escalation and persistence primitive (mimikatz sid::add,
    DSInternals Add-ADDBSidHistory, or pushed via DCShadow).

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 (Critical/High) - SID History was added to an account (Security 4765). Critical when any
        added SID is privileged (the injection attack); High otherwise (a bare sIDHistory addition is
        abnormal outside a controlled migration).
      * RULE 2 (Critical/High) - sIDHistory attribute written (Security 5136, Value Added on sIDHistory).
        Same privileged-vs-not severity split; this is the authoritative attribute-level signal.
      * RULE 3 (Medium) - a SID History addition ATTEMPT failed (Security 4766).
      * RULE 4 (Critical/High) - a user/computer account change (4738/4742) whose SidHistory field now
        carries a SID value (fallback where 4765/5136 are not audited).
      * RULE 5 (High) - SID-history injection tooling in a PowerShell script block (4104): mimikatz
        sid::add / sid::patch, DSInternals Add-ADDBSidHistory, Invoke-Mimikatz.

    A privileged SID is one whose RID is a privileged group RID (512/518/519/520/...), the domain
    Administrator (RID 500), or a built-in privileged SID (S-1-5-32-544, ...).

    Required audit policy / log sources (domain controllers):
      * Account Management > Audit User Account Management = Success -> 4765 / 4766 / 4738.
      * DS Access > Audit Directory Service Changes = Success (SACL) -> 5136 on sIDHistory.
      * Optional: PowerShell Script Block Logging (4104) for RULE 5.
      NOTE: 4765/4766 require "Audit SAM" / account-management SID-history auditing and are not on by
      default; the 5136 sIDHistory path needs a SACL. Enable at least one for coverage.

    Known false positives:
      * A genuine domain migration (ADMT) adds sIDHistory in bulk - but those SIDs come from the SOURCE
        domain (a different domain SID) and are ordinary user RIDs, so they surface at High, not Critical.
        Add known source-domain SIDs to -KnownMigrationSid to suppress them. A PRIVILEGED SID in
        sIDHistory is essentially never a legitimate migration artefact and stays Critical regardless.

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
.PARAMETER KnownMigrationSid
    SIDs (exact) or domain-SID prefixes (e.g. S-1-5-21-1111-2222-3333) known to be legitimate migration
    source SIDs. A non-privileged sIDHistory addition matching one is suppressed; privileged SIDs are
    always reported.

.EXAMPLE
    .\Find-SIDHistoryInjection.ps1 -Path C:\Evidence\DC01-Security.evtx
    Hunt SID History injection in an exported DC Security log.

.EXAMPLE
    .\Find-SIDHistoryInjection.ps1 -StartTime (Get-Date).AddDays(-30) -KnownMigrationSid S-1-5-21-9-8-7 -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1134.005 (Access Token Manipulation: SID-History Injection)
    Events : 4765, 4766, 4738, 4742, 5136 (Security), 4104 (PowerShell Operational)
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

    [string[]]$KnownMigrationSid
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
    if (-not $toolName) { $toolName = 'Find-SIDHistoryInjection' }
    $technique = 'T1134.005'; $techniqueName = 'SID-History Injection'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $migrationSet = @{}
    foreach ($s in @($KnownMigrationSid)) { if ($s) { $migrationSet[([string]$s).Trim().ToUpperInvariant()] = $true } }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'SID History injection (privileged SID planted in sIDHistory)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    function Get-IRSidsFromText {
        param([string]$Text)
        if (-not $Text) { return @() }
        @([regex]::Matches($Text, '(?i)S-1-\d+(?:-\d+)+') | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
    }
    function Get-SidDomainPrefix {
        param([string]$Sid)
        if ($Sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { return $matches[1] }
        if ($Sid -match '^(.*)-\d+$') { return $matches[1] }
        return $Sid
    }
    # Extract the ADDED SID(s) from an event, preferring the structured SID fields and only falling back
    # to the rendered Message when none are present. Always excludes the account's own SID (TargetSid) and
    # the ACTOR's SID (SubjectUserSid) - both appear in a real 4765/4766 Message and must not be mistaken
    # for an injected SID (otherwise a change made by the built-in Administrator reads as a RID-500 injection).
    function Get-SidHistoryAdded {
        param($Evt, [string[]]$Fields)
        $sids = New-Object System.Collections.Generic.List[string]
        foreach ($p in $Fields) { if ($Evt.PSObject.Properties[$p] -and $Evt.$p) { foreach ($s in (Get-IRSidsFromText ([string]$Evt.$p))) { $sids.Add($s) } } }
        if ($sids.Count -eq 0) { foreach ($s in (Get-IRSidsFromText ([string]$Evt.Message))) { $sids.Add($s) } }
        $exclude = @{}
        foreach ($ex in @([string]$Evt.TargetSid, [string]$Evt.SubjectUserSid)) { $u = $ex.Trim().ToUpperInvariant(); if ($u) { $exclude[$u] = $true } }
        @($sids | Select-Object -Unique | Where-Object { $_ -and -not $exclude.ContainsKey($_) })
    }
    function Test-PrivilegedSid {
        param([string]$Sid)
        if (-not $Sid) { return $false }
        if (Test-IRPrivilegedGroup -Sid $Sid) { return $true }
        if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-500$') { return $true }   # domain Administrator
        return $false
    }
    function Resolve-SidLabel {
        param([string]$Sid)
        $n = Get-IRPrivilegedGroupName -Sid $Sid
        if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-500$') { $n = 'Administrator (RID 500)' }
        if ($n -and $n -ne $Sid) { return "$Sid ($n)" }
        return $Sid
    }
    function Test-IsMigrationSid {
        param([string]$Sid)
        if ($migrationSet.Count -eq 0) { return $false }
        $u = ([string]$Sid).ToUpperInvariant()
        if ($migrationSet.ContainsKey($u)) { return $true }
        foreach ($k in $migrationSet.Keys) { if ($u.StartsWith($k)) { return $true } }   # domain-SID prefix
        return $false
    }

    # A PRIVILEGED sIDHistory addition is emitted immediately as a per-event Critical. A NON-privileged
    # addition is accumulated and rolled up (grouped by actor + source-domain prefix) into a single High
    # finding at the end, so a bulk legitimate migration is one finding with a count, not one per account.
    $nonPrivAdds = New-Object System.Collections.Generic.List[object]

    function Add-SidHistoryFinding {
        param($Evt, [string]$Account, [string]$Actor, [string[]]$Sids, [int]$EventId, [string]$Via)
        $sids = @($Sids | Where-Object { $_ })
        if ($sids.Count -eq 0) { return }
        $actorTxt = $Actor; if (-not $actorTxt) { $actorTxt = '-' }
        $priv = @($sids | Where-Object { Test-PrivilegedSid $_ })
        if ($priv.Count -gt 0) {
            $privLabels = @($priv | ForEach-Object { Resolve-SidLabel $_ })
            $desc = ("A PRIVILEGED SID was added to the sIDHistory of account '{0}' ({1}, event {2}) by {3}. Injected privileged SID(s): {4}. This grants '{0}' that privileged access invisibly (it is not a listed group member) - SID History injection." -f `
                    $Account, $Via, $EventId, $actorTxt, ($privLabels -join ', '))
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Privileged SID injected into sIDHistory' `
                        -Description $desc -Account $Account -Target (($priv | ForEach-Object { Resolve-SidLabel $_ }) -join ', ') -Computer $Evt.Computer `
                        -EventIds $EventId -Evidence (Get-IRFirst @($Evt) 200) `
                        -Recommendation 'Treat as privilege escalation / persistence. Clear the injected SID from the account sIDHistory (Set-ADUser -Remove / ntdsutil), reset and investigate the account, and review how the actor obtained the ability to write sIDHistory (DsAddSidHistory privilege, DCShadow, or offline ntds.dit edit).'))
            return
        }
        # Non-privileged: suppress only when ALL added SIDs are known-migration; otherwise accumulate.
        $nonMig = @($sids | Where-Object { -not (Test-IsMigrationSid $_) })
        if ($nonMig.Count -eq 0) { return }
        $nonPrivAdds.Add([pscustomobject]@{ Account = $Account; Actor = $actorTxt; Sids = $sids; EventId = $EventId; Evt = $Evt; Prefix = (Get-SidDomainPrefix $sids[0]) })
    }

    # ---- RULE 1: 4765 SID History was added ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4765 -IncludeMessage)) {
        $added = @(Get-SidHistoryAdded -Evt $e -Fields @('SourceSid', 'SidList', 'SidHistory', 'NewSid'))
        Add-SidHistoryFinding -Evt $e -Account ([string]$e.TargetUserName) -Actor ([string]$e.SubjectUserName) -Sids $added -EventId 4765 -Via '4765 SID History added'
    }

    # ---- RULE 2: 5136 sIDHistory attribute Value Added ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136 | Where-Object { ([string]$_.AttributeLDAPDisplayName) -ieq 'sIDHistory' })) {
        $op = [string]$e.OperationType
        if ($op -match '14675' -or $op -match 'Value Deleted') { continue }
        $account = [string]$e.ObjectDN; if ($account -match '^\s*CN=([^,]+)') { $account = $matches[1].Trim() }
        $added = @(Get-IRSidsFromText ([string]$e.AttributeValue))
        Add-SidHistoryFinding -Evt $e -Account $account -Actor ([string]$e.SubjectUserName) -Sids $added -EventId 5136 -Via '5136 sIDHistory attribute write'
    }

    # ---- RULE 3: 4766 failed attempt to add SID History ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4766 -IncludeMessage)) {
        $account = [string]$e.TargetUserName
        $added = @(Get-SidHistoryAdded -Evt $e -Fields @('SourceSid', 'SidList', 'SidHistory'))
        if ($added.Count -eq 0) { continue }
        $labels = @($added | ForEach-Object { Resolve-SidLabel $_ })
        $hasPriv = @($added | Where-Object { Test-PrivilegedSid $_ }).Count -gt 0
        $sev = if ($hasPriv) { 'High' } else { 'Medium' }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Failed attempt to add SID History (4766)' `
                    -Description ("A SID History addition to account '{0}' FAILED (event 4766), attempted by {1}. SID(s): {2}. A failed attempt still indicates someone tried to inject SID history{3}." -f $account, ([string]$e.SubjectUserName), (($labels -join ', ')), $(if ($hasPriv) { ' with a PRIVILEGED SID' } else { '' })) `
                    -Account $account -Target ($labels -join ', ') -Computer $e.Computer `
                    -EventIds 4766 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Investigate the actor and source host; a failed injection attempt often precedes a successful one via another path (DCShadow, offline ntds.dit).'))
    }

    # ---- RULE 4: 4738 / 4742 account change carrying a SidHistory value (fallback) ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4738, 4742)) {
        if (-not ($e.PSObject.Properties['SidHistory'])) { continue }
        $raw = [string]$e.SidHistory
        if (-not $raw -or $raw.Trim() -eq '-' -or $raw.Trim() -eq '') { continue }
        $added = @(Get-IRSidsFromText $raw)
        if ($added.Count -eq 0) { continue }
        Add-SidHistoryFinding -Evt $e -Account ([string]$e.TargetUserName) -Actor ([string]$e.SubjectUserName) -Sids $added -EventId ([int]$e.EventId) -Via "$([int]$e.EventId) account change SidHistory field"
    }

    # ---- Aggregate the accumulated NON-privileged sIDHistory additions ----
    # One High finding per (actor, source-domain prefix) so a bulk legitimate migration is a single
    # counted finding instead of one per account.
    foreach ($g in ($nonPrivAdds | Group-Object { "$($_.Actor)|$($_.Prefix)" })) {
        $items = @($g.Group)
        $accts = @($items | ForEach-Object { $_.Account } | Where-Object { $_ } | Select-Object -Unique)
        $sidsAll = @($items | ForEach-Object { $_.Sids } | Select-Object -Unique)
        $actor = [string]$items[0].Actor
        $prefix = [string]$items[0].Prefix
        $eids = @($items | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)
        $acctList = (Get-IRFirst $accts 15) -join ', '
        $more = if ($accts.Count -gt 15) { " (+$($accts.Count - 15) more)" } else { '' }
        $desc = ("sIDHistory was added to {0} account(s) from source domain '{1}' by {2} ({3} event(s)). None of the added SIDs is privileged, which is consistent with an authorised domain migration - but a sIDHistory addition outside a controlled migration is abnormal. Accounts: {4}{5}. SIDs: {6}." -f `
                $accts.Count, $prefix, $actor, $items.Count, $acctList, $more, ((Get-IRFirst $sidsAll 10) -join ', '))
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'sIDHistory added (non-privileged - confirm authorised migration)' `
                    -Description $desc -Account $actor -Target $acctList -Computer $items[0].Evt.Computer `
                    -EventIds $eids -Evidence (Get-IRFirst (@($items | ForEach-Object { $_.Evt })) 200) `
                    -Recommendation 'Confirm an authorised migration added these SIDs (add the legitimate source-domain SID prefix to -KnownMigrationSid to suppress). If there was no migration, this is SID History injection: clear the sIDHistory values and investigate the actor.'))
    }

    # ---- RULE 5: SID-history injection tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Add-ADDBSidHistory', 'sid::add', 'sid::patch', 'Invoke-Mimikatz', 'mimikatz', 'Set-ADDBAccountPassword'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'SID History injection tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched SID-history injection signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process. Correlate with 4765 / 5136 sIDHistory additions on the DCs in the same window, and inspect sIDHistory across privileged-adjacent accounts.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
