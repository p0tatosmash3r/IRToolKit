<#
.SYNOPSIS
    Detects additions to (and removals from) privileged Active Directory groups in Windows
    Security event logs, including the stealth "temporary elevation" add-then-remove pattern.

.DESCRIPTION
    Adding an attacker-controlled principal to a privileged group (Domain Admins, Enterprise
    Admins, Schema Admins, the built-in Administrators group, DnsAdmins, Backup Operators,
    Account/Server/Print Operators, Group Policy Creator Owners, etc.) is one of the most direct
    privilege-escalation and persistence actions in a domain. On domain controllers these changes
    are recorded as Security "group membership change" audit events. A careful attacker often
    adds the account, performs a privileged action, then removes it again within minutes to limit
    the exposure window - a pattern that is itself a strong signal.

    Detection logic (each rule emits one IRToolKit.Finding):
      * Source: Security group-membership-change events on DCs.
          - Member added:   4728 (global), 4756 (universal), 4732 (local / built-in).
          - Member removed: 4729 (global), 4757 (universal), 4733 (local / built-in).
        Related group-lifecycle events (4727/4731/4754 created, 4735/4737/4755 changed, 4764
        type-changed) are documented here for the analyst but are not scored by this tool.
      * Pre-filter: only changes whose TARGET group is privileged, decided by
        Test-IRPrivilegedGroup on the group SID (well-known built-in SID or domain RID) OR the
        group name (capability groups such as DnsAdmins whose RID is domain-specific).
      * Rule 1 - privileged group ADD (High, or Critical for the domain-crown groups
        Domain Admins / Enterprise Admins / Schema Admins / built-in Administrators, identified
        by RID 512 / 519 / 518 or SID S-1-5-32-544). Reports who (SubjectUserName) added whom
        (MemberName DN / MemberSid) to which group.
      * Rule 2 - privileged group REMOVE (Medium). Attackers remove accounts to undo temporary
        elevation or to evict legitimate administrators.
      * Rule 3 - stealth add-then-remove (High; Informational/Low when BOTH the add and remove actors
        are in -KnownAdmin - the PAM / just-in-time elevation case). The same member is added to AND
        removed from the same privileged group within -StealthWindowMinutes (default 30), correlated on
        (group, member). This "temporary elevation" is a strong attacker signature.
      * Rule 4 - actor anomaly (an annotation on the Rule 1 finding, not a separate finding). When
        -KnownAdmin is supplied, adds performed by a subject that is NOT in that list are called
        out in the Rule 1 description; otherwise the actor is simply noted for the analyst.
      * Rule 5 - capability groups (DnsAdmins, Backup Operators, Account/Server/Print Operators,
        Group Policy Creator Owners, ...) are privileged-by-capability rather than by RID. They
        are matched by the module's privileged-group NAME list, so the Rule 1 finding already covers
        them (High, not Critical); no separate finding is emitted.

    This tool is self-contained: all privileged-group decisions come from the module's static
    reference tables (Test-IRPrivilegedGroup / Get-IRPrivilegedGroupName /
    Get-IRReferenceTable). It performs NO live Active Directory queries, so it is safe to run
    offline against exported logs. -NoADLookup / -DomainController are accepted for parity with
    the rest of the kit and have no effect here.

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > Account Management > Audit Security Group Management = Success
        (produces 4728/4729/4732/4733/4756/4757).

    Known false positives:
      * Legitimate administrator onboarding and role changes, help-desk staff adding users to
        operator groups, and IAM / provisioning automation all produce ADD events. Validate the
        actor, the member and whether a change-control record exists before escalating. A planned
        maintenance window that grants then revokes access can resemble the Rule 3 stealth
        pattern - confirm it was authorised.

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
    Accepted for interface parity with other IRToolKit tools. This detection uses only the static
    privileged-group reference tables and performs no live AD look-ups, so the switch has no effect.
.PARAMETER DomainController
    Accepted for interface parity. Not used by this tool (no DC-to-DC exclusion is performed).
.PARAMETER StealthWindowMinutes
    Maximum minutes between a privileged-group ADD and a matching REMOVE of the same member for the
    Rule 3 stealth "temporary elevation" finding to fire (default 30).
.PARAMETER KnownAdmin
    Account names (sAMAccountName or DOMAIN\user) expected to legitimately manage privileged group
    membership. When supplied, Rule 1 calls out any ADD performed by a subject that is not in this
    list (Rule 4 actor anomaly).

.EXAMPLE
    .\Find-PrivilegedGroupChange.ps1 -StartTime (Get-Date).AddDays(-14)
    Analyse the local DC Security log for privileged group changes over the last 14 days.

.EXAMPLE
    .\Find-PrivilegedGroupChange.ps1 -Path C:\Evidence\DC01-Security.evtx -KnownAdmin 'dom_admin1','tier0svc' -OutputPath C:\Evidence\Out -Format All
    Analyse an exported log, flag adds by anyone outside the known-admin list, and export all report formats.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4728,4732,4756,4729,4733,4757} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Find-PrivilegedGroupChange.ps1 -StealthWindowMinutes 15

.NOTES
    ATT&CK : T1098 (Account Manipulation), T1078.002 (Valid Accounts: Domain Accounts)
    Events : 4728 / 4756 / 4732 (member added), 4729 / 4757 / 4733 (member removed) - Security.
             Related group-lifecycle events 4727/4731/4754/4735/4737/4755/4764 are not scored.
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

    [int]$StealthWindowMinutes = 30,
    [string[]]$KnownAdmin
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
    if (-not $toolName) { $toolName = 'Find-PrivilegedGroupChange' }
    $technique = 'T1098'; $techniqueName = 'Account Manipulation'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $knownAdminSet = @{}
    foreach ($a in @($KnownAdmin)) {
        if ($a) {
            $knownAdminSet[(Get-IRAccountKey $a $null)] = $true
            $knownAdminSet[$a.ToLowerInvariant().TrimEnd('$')] = $true
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Privileged group membership changes (add / remove / stealth temporary elevation)' -Technique @('T1098', 'T1078.002')
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # ------------------------------------------------------------------ helpers
    function Get-PGCScope {
        param([int]$Id)
        if ($Id -eq 4728 -or $Id -eq 4729) { return 'global' }
        if ($Id -eq 4756 -or $Id -eq 4757) { return 'universal' }
        if ($Id -eq 4732 -or $Id -eq 4733) { return 'local/built-in' }
        return 'security-enabled'
    }

    function Get-PGCMemberCn {
        # Extract the CN for display but keep the DN in the event/evidence.
        param([string]$MemberName, [string]$MemberSid)
        $n = [string]$MemberName
        if ($n -and $n.Trim() -ne '' -and $n.Trim() -ne '-') {
            $n = $n.Trim()
            if ($n -match '^CN=([^,]+)') { return $matches[1] }
            if ($n -match '\\(.+)$') { return $matches[1] }
            return $n
        }
        $s = [string]$MemberSid
        if ($s -and $s.Trim() -ne '' -and $s.Trim() -ne '-') { return $s.Trim() }
        return '(unknown member)'
    }

    function Get-PGCMemberDetail {
        param($Event)
        $member = $Event._MemberCn
        $memberDn = [string]$Event.MemberName
        $memberSid = [string]$Event.MemberSid
        $extra = @()
        if ($memberDn -and $memberDn.Trim() -ne '' -and $memberDn.Trim() -ne '-' -and $memberDn.Trim() -ne $member) { $extra += "DN $($memberDn.Trim())" }
        if ($memberSid -and $memberSid.Trim() -ne '' -and $memberSid.Trim() -ne '-') { $extra += "SID $($memberSid.Trim())" }
        if ($extra.Count -gt 0) { return "$member (" + ($extra -join '; ') + ")" }
        return $member
    }

    function Get-PGCActorDetail {
        param($Event)
        $actor = [string]$Event.SubjectUserName
        if (-not $actor) { $actor = '(unknown actor)' }
        $sid = [string]$Event.SubjectUserSid
        $dom = [string]$Event.SubjectDomainName
        $full = $actor
        if ($dom -and $dom.Trim() -ne '' -and $dom.Trim() -ne '-') { $full = "$($dom.Trim())\$actor" }
        if ($sid -and $sid.Trim() -ne '' -and $sid.Trim() -ne '-') { $full += " (SID $($sid.Trim()))" }
        return $full
    }

    function Test-PGCCriticalGroup {
        # Domain-crown groups: Domain Admins (512), Schema Admins (518), Enterprise Admins (519),
        # or the built-in Administrators group (S-1-5-32-544).
        param([string]$Sid, [string]$Name)
        if ($Sid) {
            $s = $Sid.Trim()
            if ($s -eq 'S-1-5-32-544') { return $true }
            if ($s -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') { if ($matches[1] -in '512', '518', '519') { return $true } }
        }
        if ($Name) {
            $n = $Name.Trim()
            if ($n -match '^CN=([^,]+)') { $n = $matches[1] }
            if ($n -match '\\(.+)$') { $n = $matches[1] }
            foreach ($c in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') { if ($n -ieq $c) { return $true } }
        }
        return $false
    }

    # ------------------------------------------------------------------ load + filter
    $addIds = @(4728, 4732, 4756)
    $removeIds = @(4729, 4733, 4757)
    $addSet = @{}; foreach ($x in $addIds) { $addSet[[int]$x] = $true }

    $events = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId ($addIds + $removeIds))
    Write-IRStatus "Loaded $($events.Count) group-membership change event(s)" -Level Detail

    $priv = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        $groupName = [string]$e.TargetUserName
        $groupSid = [string]$e.TargetSid
        if (-not (Test-IRPrivilegedGroup -Sid $groupSid -Name $groupName)) { continue }

        $isAdd = $addSet.ContainsKey([int]$e.EventId)
        $resolvedName = Get-IRPrivilegedGroupName -Sid $groupSid -Name $groupName
        if (-not $resolvedName) { $resolvedName = $groupName }
        $memberCn = Get-PGCMemberCn -MemberName ([string]$e.MemberName) -MemberSid ([string]$e.MemberSid)

        $groupKey = $groupSid
        if (-not $groupKey -or $groupKey.Trim() -eq '' -or $groupKey.Trim() -eq '-') { $groupKey = $resolvedName }
        $groupKey = ([string]$groupKey).ToLowerInvariant()
        $memberKey = [string]$e.MemberSid
        if (-not $memberKey -or $memberKey.Trim() -eq '' -or $memberKey.Trim() -eq '-') { $memberKey = [string]$e.MemberName }
        if (-not $memberKey -or $memberKey.Trim() -eq '' -or $memberKey.Trim() -eq '-') { $memberKey = $memberCn }
        $memberKey = ([string]$memberKey).ToLowerInvariant()

        $e | Add-Member -NotePropertyName _IsAdd -NotePropertyValue $isAdd -Force
        $e | Add-Member -NotePropertyName _GroupName -NotePropertyValue $resolvedName -Force
        $e | Add-Member -NotePropertyName _GroupKey -NotePropertyValue $groupKey -Force
        $e | Add-Member -NotePropertyName _MemberKey -NotePropertyValue $memberKey -Force
        $e | Add-Member -NotePropertyName _MemberCn -NotePropertyValue $memberCn -Force
        $e | Add-Member -NotePropertyName _IsCritical -NotePropertyValue (Test-PGCCriticalGroup -Sid $groupSid -Name $resolvedName) -Force
        $priv.Add($e)
    }
    Write-IRStatus "$($priv.Count) privileged-group change event(s) after filtering" -Level Detail

    # ------------------------------------------------------------------ Rule 1 - privileged ADD (+ Rule 4 actor anomaly)
    foreach ($e in @($priv | Where-Object { $_._IsAdd })) {
        $actor = [string]$e.SubjectUserName
        $actorKey = Get-IRAccountKey $actor $e.SubjectDomainName
        $scope = Get-PGCScope ([int]$e.EventId)
        $sev = 'High'; if ($e._IsCritical) { $sev = 'Critical' }

        $desc = "{0} added {1} to privileged group '{2}'" -f (Get-PGCActorDetail $e), (Get-PGCMemberDetail $e), $e._GroupName
        if ([string]$e.TargetSid) { $desc += " (group SID $([string]$e.TargetSid))" }
        $desc += " via event $([int]$e.EventId) ($scope group)."
        if ($e._IsCritical) { $desc += " This group confers domain-level control; treat as a likely privilege-escalation or persistence action." }
        else { $desc += " This group is privileged by capability; its membership must be tightly controlled." }

        if ($knownAdminSet.Count -gt 0) {
            $known = $knownAdminSet.ContainsKey($actorKey) -or ($actor -and $knownAdminSet.ContainsKey($actor.ToLowerInvariant().TrimEnd('$')))
            if (-not $known) { $desc += " Actor '$actor' is NOT in the supplied known-admin list - unexpected principal performing a privileged-group change (Rule 4)." }
            else { $desc += " Actor '$actor' is in the supplied known-admin list - confirm the change was authorised." }
        }
        else { $desc += " Actor to verify: '$actor'." }

        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'High' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Principal added to privileged group' `
                    -Description $desc -Account $actor `
                    -Target ("{0} <- {1}" -f $e._GroupName, $e._MemberCn) -Computer $e.Computer `
                    -EventIds ([int]$e.EventId) -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the change against change control. If unauthorised, remove the principal, reset the affected and actor credentials, and investigate the actor account and source host for compromise.'))
    }

    # ------------------------------------------------------------------ Rule 2 - privileged REMOVE
    foreach ($e in @($priv | Where-Object { -not $_._IsAdd })) {
        $actor = [string]$e.SubjectUserName
        $scope = Get-PGCScope ([int]$e.EventId)
        $desc = "{0} removed {1} from privileged group '{2}' via event {3} ({4} group). Attackers remove accounts to undo temporary elevation or to evict legitimate administrators; verify this removal was expected." -f `
            (Get-PGCActorDetail $e), (Get-PGCMemberDetail $e), $e._GroupName, [int]$e.EventId, $scope
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Principal removed from privileged group' `
                    -Description $desc -Account $actor `
                    -Target ("{0} -> {1}" -f $e._GroupName, $e._MemberCn) -Computer $e.Computer `
                    -EventIds ([int]$e.EventId) -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the removal was expected. Correlate with a preceding add of the same member (possible temporary elevation) and with the actions taken while the member was in the group.'))
    }

    # ------------------------------------------------------------------ Rule 3 - stealth add-then-remove (temporary elevation)
    $byMember = Group-IRByKey -Events $priv.ToArray() -KeyScript { param($x) "$($x._GroupKey)|$($x._MemberKey)" }
    foreach ($key in $byMember.Keys) {
        $grp = @($byMember[$key] | Sort-Object TimeCreated)
        $adds = @($grp | Where-Object { $_._IsAdd })
        $removes = @($grp | Where-Object { -not $_._IsAdd })
        if ($adds.Count -eq 0 -or $removes.Count -eq 0) { continue }
        foreach ($add in $adds) {
            if ($add.TimeCreated -isnot [datetime]) { continue }
            $match = $null
            foreach ($rem in $removes) {
                if ($rem.TimeCreated -isnot [datetime]) { continue }
                $delta = ($rem.TimeCreated - $add.TimeCreated).TotalMinutes
                if ($delta -ge 0 -and $delta -le $StealthWindowMinutes) { $match = $rem; break }
            }
            if ($match) {
                $mins = [Math]::Round((($match.TimeCreated - $add.TimeCreated).TotalMinutes), 1)
                $addActor = [string]$add.SubjectUserName
                $remActor = [string]$match.SubjectUserName
                # A PAM / PIM / just-in-time system legitimately adds then removes membership within the
                # window. When BOTH the add and the remove actor are known-admin / automation accounts
                # (-KnownAdmin), this is expected elevation: down-rank to Informational instead of High.
                $sev = 'High'; $conf = 'Medium'; $jitNote = ''
                if ($knownAdminSet.Count -gt 0) {
                    $addKnown = $knownAdminSet.ContainsKey((Get-IRAccountKey $addActor $add.SubjectDomainName)) -or ($addActor -and $knownAdminSet.ContainsKey($addActor.ToLowerInvariant().TrimEnd('$')))
                    $remKnown = $knownAdminSet.ContainsKey((Get-IRAccountKey $remActor $match.SubjectDomainName)) -or ($remActor -and $knownAdminSet.ContainsKey($remActor.ToLowerInvariant().TrimEnd('$')))
                    if ($addKnown -and $remKnown) { $sev = 'Informational'; $conf = 'Low'; $jitNote = ' Both the add and remove were performed by known-admin / automation accounts (-KnownAdmin), consistent with a PAM / just-in-time elevation workflow; shown as context.' }
                }
                $desc = ("{0} was added to privileged group '{1}' by {2} and removed {3} min later by {4} (within the {5}-min stealth window). This temporary-elevation pattern strongly suggests an attacker granting rights, acting, then cleaning up.{6}" -f `
                    (Get-PGCMemberDetail $add), $add._GroupName, (Get-PGCActorDetail $add), $mins, $remActor, $StealthWindowMinutes, $jitNote)
                $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Rapid add-then-remove from privileged group (temporary elevation)' `
                            -Description $desc -Account $addActor `
                            -Target ("{0} <- {1}" -f $add._GroupName, $add._MemberCn) -Computer $add.Computer `
                            -EventIds @([int]$add.EventId, [int]$match.EventId) -Evidence (Get-IRFirst @($add, $match) 200) `
                            -Recommendation 'Treat the actor account and source host as suspect. Review every action taken during the elevation window (DCSync, backups, GPO edits, credential dumps) and reset affected credentials.'))
                break
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
