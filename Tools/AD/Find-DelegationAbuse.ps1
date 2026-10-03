<#
.SYNOPSIS
    Detects Kerberos delegation abuse (unconstrained, constrained / S4U, and resource-based
    constrained delegation) from Windows Security event logs.

.DESCRIPTION
    Kerberos delegation lets a service impersonate a user to a back-end service. Three variants are
    routinely abused by attackers to escalate privilege and move laterally:

      * Unconstrained delegation - an account carrying TRUSTED_FOR_DELEGATION (userAccountControl
        0x80000 / SAM flag 0x2000) caches the TGT of every user that authenticates to it, so whoever
        controls that account can replay those TGTs. Setting the flag on a non-DC computer or user is
        a classic foothold for TGT theft.
      * Constrained delegation (S4U) - msDS-AllowedToDelegateTo lists the SPNs a principal may
        delegate to. Adding targets (especially together with protocol transition,
        TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION / SAM flag 0x40000) lets the account request tickets
        for arbitrary users to those services (S4U2Self + S4U2Proxy).
      * Resource-Based Constrained Delegation (RBCD) - writing
        msDS-AllowedToActOnBehalfOfOtherIdentity (a security descriptor) on a target object lets a
        controlled account impersonate any user to that target. A very common modern privilege
        escalation, frequently chained with a written-back machine account.

    Detection logic:
      * Source A: Security 4742 (computer account changed) and 4738 (user account changed). Decodes
        OldUacValue/NewUacValue (Compare-IRSamUac) and the %%21xx UserAccountControl change text, and
        reads the AllowedToDelegateTo (msDS-AllowedToDelegateTo) list.
      * Source B: Security 5136 (directory object modified) - the authoritative, attribute-level
        source for msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), msDS-AllowedToDelegateTo and
        userAccountControl changes (OperationType %%14674 = Value Added, %%14675 = Value Deleted).
      * Rule 1 (RBCD write) - 5136 Value-Added of msDS-AllowedToActOnBehalfOfOtherIdentity. High, or
        Critical when the modified object is a known Domain Controller (-DomainController).
      * Rule 2 (unconstrained) - 4742/4738 adding TRUSTED_FOR_DELEGATION (or %%2104), or a 5136
        userAccountControl Value-Added decoding to TRUSTED_FOR_DELEGATION. High.
      * Rule 3 (constrained / protocol transition) - 4742/4738 or 5136 that set/add
        msDS-AllowedToDelegateTo, or that add TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (or %%2114).
        High when protocol transition is enabled, otherwise Medium.
      * Rule 4 (sensitive-SPN delegation) - a constrained-delegation target list that includes an SPN
        (ldap/ host/ cifs/ http/) on a known Domain Controller raises Rule 3 to High.

    Required audit policy / log sources (all on the DC):
      * Advanced Audit Policy > DS Access > Audit Directory Service Changes = Success (event 5136,
        and the audited objects need a SACL auditing Write Property / Write Members).
      * Advanced Audit Policy > Account Management > Audit Computer Account Management = Success (4742).
      * Advanced Audit Policy > Account Management > Audit User Account Management = Success (4738).

    Known false positives:
      * 4738/4742 report the full current msDS-AllowedToDelegateTo value on every account change, not a
        diff, so an unrelated change to an account that already has constrained delegation can surface
        here. The 5136 attribute-level events are the authoritative confirmation of an actual add.
      * Legitimate delegation onboarding (a new front-end service, a gMSA) sets these attributes too.
        Validate the actor (SubjectUserName) and the modified object before escalating.

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
    Skip live Active Directory discovery of domain controllers; rely only on -DomainController. Live
    discovery is attempted only when AD is reachable, so this is already a no-op when run offline.
.PARAMETER DomainController
    Extra DC names / IPs so DC-targeted RBCD (Rule 1) and delegation to a DC SPN (Rule 4) can be
    recognised when running offline / not domain joined. Test-IRDomainController returns $false when
    the lookup is empty, so without this parameter those escalations cannot be applied and the finding
    stays at its base severity.

.EXAMPLE
    .\Find-DelegationAbuse.ps1 -DomainController DC01,DC02
    Analyse the local DC Security log for the last 7 days, recognising DC01/DC02 as domain controllers.

.EXAMPLE
    .\Find-DelegationAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01 -OutputPath C:\Evidence\Out -Format All
    Analyse an exported Security log offline and write CSV/JSON/HTML reports.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136,4742,4738} | ConvertFrom-IRWinEvent | .\Find-DelegationAbuse.ps1 -DomainController DC01
    Pipe pre-collected events into the tool.

.NOTES
    ATT&CK : T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting / delegation TGT theft),
             T1134 (Access Token Manipulation - delegation impersonation / RBCD),
             T1484 (Domain Policy Modification - directory object / security descriptor changes)
    Events : 5136, 4742, 4738 (Security)
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
    [string[]]$DomainController
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
    if (-not $toolName) { $toolName = 'Find-DelegationAbuse' }
    $technique = @('T1558.003', 'T1134', 'T1484')
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Kerberos delegation abuse (unconstrained / constrained / RBCD)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # Build the domain-controller lookup. Only perform live DC discovery when AD is actually reachable
    # and -NoADLookup was not set; otherwise trust only the analyst-supplied -DomainController names
    # (this keeps the tool error-free when run offline / not domain joined).
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
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied); DC-specific escalations (Rule 1 Critical, Rule 4) cannot be applied.' -Level Detail }

    # ---- helpers -------------------------------------------------------------------------------
    function Get-IRDnLeaf {
        # Returns the first CN= value of a distinguishedName, else the raw string.
        param([string]$Dn)
        if (-not $Dn) { return $null }
        if ($Dn -match '^\s*CN=([^,]+)') { return $matches[1].Trim() }
        return $Dn.Trim()
    }

    function Get-IRDelegationSpnList {
        # Splits an AllowedToDelegateTo field (multi-line list or '-') into SPN strings.
        param($Value)
        $raw = [string]$Value
        if (-not $raw) { return @() }
        if ($raw.Trim() -eq '-' -or $raw.Trim() -eq '') { return @() }
        @($raw -split "[\r\n\t]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '-' })
    }

    function Test-IRDelegationToDc {
        # True when any delegation target SPN points at a known DC (ldap/ host/ cifs/ http/).
        param([string[]]$Spns, [hashtable]$Lookup)
        if (-not $Lookup -or $Lookup.Count -eq 0) { return $false }
        foreach ($spn in @($Spns)) {
            if (-not $spn) { continue }
            $parts = $spn -split '/'
            if ($parts.Count -lt 2) { continue }
            $svcClass = $parts[0].ToLowerInvariant()
            if ($svcClass -notin @('ldap', 'host', 'cifs', 'http')) { continue }
            $hostPart = $parts[1]
            if ($hostPart -match '^([^:]+)') { $hostPart = $matches[1] }
            if (Test-IRDomainController -Lookup $Lookup -Value $hostPart) { return $true }
        }
        return $false
    }

    function Test-IROperationAdded {
        # 5136 OperationType: treat as an add unless it is explicitly a delete (%%14675 / Value Deleted).
        param($OperationType)
        $op = [string]$OperationType
        if ($op -match '14675' -or $op -match 'Value Deleted') { return $false }
        return $true
    }

    # ---- Source B: 5136 directory object modifications ----------------------------------------
    $dirEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136)
    Write-IRStatus "Loaded $($dirEvents.Count) 5136 event(s)" -Level Detail
    foreach ($e in $dirEvents) {
        $attr = [string]$e.AttributeLDAPDisplayName
        if (-not $attr) { continue }
        if (-not (Test-IROperationAdded $e.OperationType)) { continue }
        $actor = [string]$e.SubjectUserName
        if (-not $actor) { $actor = '-' }
        $objDn = [string]$e.ObjectDN
        $objLeaf = Get-IRDnLeaf $objDn

        if ($attr -ieq 'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            # Rule 1 - RBCD write.
            $isDc = Test-IRDomainController -Lookup $dcLookup -Value $objLeaf
            $sev = 'High'; if ($isDc) { $sev = 'Critical' }
            $dcNote = ''
            if ($isDc) { $dcNote = ' The modified object is a known Domain Controller - control of this DC is at stake.' }
            elseif ($dcLookup.Count -eq 0) { $dcNote = ' (DC status of the target could not be checked; supply -DomainController to escalate DC targets to Critical.)' }
            $desc = ("{0} wrote msDS-AllowedToActOnBehalfOfOtherIdentity on {1}, configuring resource-based constrained delegation (RBCD). A security-descriptor value was added ({2}), letting the principal(s) named in it impersonate any user to that object.{3}" -f `
                    $actor, $objDn, ([string]$e.AttributeValue), $dcNote)
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'High' `
                        -Technique 'T1134' -TechniqueName 'Access Token Manipulation (Resource-Based Constrained Delegation)' `
                        -Title 'Resource-based constrained delegation (RBCD) configured' `
                        -Description $desc -Account $actor -Target $objDn -Computer $e.Computer `
                        -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the write was authorised. If not, clear msDS-AllowedToActOnBehalfOfOtherIdentity on the target, treat the actor and any account referenced in the descriptor as compromised, and review who holds write access to the target object.'))
            continue
        }

        if ($attr -ieq 'userAccountControl') {
            # Rule 2 - unconstrained delegation via a userAccountControl value add.
            $ldapFlags = @(ConvertFrom-IRLdapUac $e.AttributeValue)
            if ($ldapFlags -contains 'TRUSTED_FOR_DELEGATION') {
                $desc = ("{0} set userAccountControl on {1} to a value that enables unconstrained delegation (TRUSTED_FOR_DELEGATION). The account will cache the Kerberos TGT of every user that authenticates to it; on a non-DC this is dangerous and enables TGT theft. Decoded flags: {2}." -f `
                        $actor, $objDn, ($ldapFlags -join ', '))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique 'T1558.003' -TechniqueName 'Steal or Forge Kerberos Tickets (Unconstrained Delegation)' `
                            -Title 'Unconstrained delegation enabled' `
                            -Description $desc -Account $actor -Target $objDn -Computer $e.Computer `
                            -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Remove TRUSTED_FOR_DELEGATION unless the host is a DC that must have it. Add privileged accounts to Protected Users / mark them sensitive and not delegable, and investigate the actor.'))
            }
            # Rule 3 - constrained delegation with protocol transition (S4U2Self) via a userAccountControl
            # value add. The LDAP decoder names this flag TRUSTED_TO_AUTH_FOR_DELEGATION.
            if ($ldapFlags -contains 'TRUSTED_TO_AUTH_FOR_DELEGATION') {
                $desc = ("{0} set userAccountControl on {1} to enable protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION). With constrained delegation configured, the account can obtain a service ticket for ANY user to its delegation targets via S4U2Self, even without that user authenticating - a common privilege-escalation primitive. Decoded flags: {2}." -f `
                        $actor, $objDn, ($ldapFlags -join ', '))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique 'T1134' -TechniqueName 'Access Token Manipulation (Constrained Delegation / Protocol Transition)' `
                            -Title 'Protocol transition enabled (constrained delegation / S4U2Self)' `
                            -Description $desc -Account $actor -Target $objDn -Computer $e.Computer `
                            -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm protocol transition is required. Prefer constrained delegation without protocol transition (use any authentication protocol = off), and investigate the actor.'))
            }
            continue
        }

        if ($attr -ieq 'msDS-AllowedToDelegateTo') {
            # Rule 3 / Rule 4 - constrained delegation target added (5136 is authoritative).
            $spns = @([string]$e.AttributeValue | Where-Object { $_ -and $_.Trim() -ne '-' })
            $toDc = Test-IRDelegationToDc -Spns $spns -Lookup $dcLookup
            $sev = 'Medium'; $conf = 'Medium'; $dcNote = ''
            if ($toDc) {
                $sev = 'High'; $conf = 'High'
                $dcNote = ' At least one target SPN resolves to a Domain Controller (e.g. ldap/host/cifs/http on a DC), which effectively grants delegation to the directory itself.'
            }
            $desc = ("{0} added a constrained-delegation target (msDS-AllowedToDelegateTo) on {1}: {2}. The account can request service tickets for other users to the listed SPN(s) via S4U.{3}" -f `
                    $actor, $objDn, ($spns -join ', '), $dcNote)
            $title = 'Constrained delegation target added'
            if ($toDc) { $title = 'Constrained delegation to sensitive (DC) SPN' }
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                        -Technique 'T1134' -TechniqueName 'Access Token Manipulation (Constrained Delegation)' `
                        -Title $title `
                        -Description $desc -Account $actor -Target (($objLeaf + ' -> ' + ($spns -join ', ')).Trim()) -Computer $e.Computer `
                        -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the delegation target is expected. Remove unexpected SPNs from msDS-AllowedToDelegateTo, never allow delegation to DC SPNs, and investigate the actor.'))
            continue
        }
    }

    # ---- Source A: 4742 / 4738 account changes ------------------------------------------------
    $acctEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4742, 4738)
    Write-IRStatus "Loaded $($acctEvents.Count) 4742/4738 event(s)" -Level Detail
    foreach ($e in $acctEvents) {
        $obj = [string]$e.TargetUserName
        $actor = [string]$e.SubjectUserName
        if (-not $actor) { $actor = '-' }
        $cmp = Compare-IRSamUac $e.OldUacValue $e.NewUacValue
        $added = @($cmp.Added)
        $uacText = [string]$e.UserAccountControl

        $unconstrained = ($added -contains 'TRUSTED_FOR_DELEGATION') -or ($uacText -match '%%2104') -or ($uacText -match "Trusted For Delegation' - Enabled")
        $protocolTransition = ($added -contains 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION') -or ($uacText -match '%%2114') -or ($uacText -match "Trusted To Authenticate For Delegation' - Enabled")
        $spns = @(Get-IRDelegationSpnList $e.AllowedToDelegateTo)

        if ($unconstrained) {
            # Rule 2 - unconstrained delegation enabled.
            $desc = ("{0} enabled unconstrained delegation on {1} (TRUSTED_FOR_DELEGATION added, old={2} new={3}). The account will cache the Kerberos TGT of every user that authenticates to it; on a non-DC computer or a user account this is dangerous and enables TGT theft / impersonation." -f `
                    $actor, $obj, (ConvertTo-IRHexString $e.OldUacValue), (ConvertTo-IRHexString $e.NewUacValue))
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                        -Technique 'T1558.003' -TechniqueName 'Steal or Forge Kerberos Tickets (Unconstrained Delegation)' `
                        -Title 'Unconstrained delegation enabled' `
                        -Description $desc -Account $actor -Target $obj -Computer $e.Computer `
                        -EventIds ([int]$e.EventId) -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Remove TRUSTED_FOR_DELEGATION unless the host is a DC that must have it. Add privileged accounts to Protected Users / mark them sensitive and not delegable, and investigate the actor.'))
        }

        if ($spns.Count -gt 0 -or $protocolTransition) {
            # Rule 3 / Rule 4 - constrained delegation / protocol transition change.
            $toDc = Test-IRDelegationToDc -Spns $spns -Lookup $dcLookup
            $sev = 'Medium'; $conf = 'Medium'
            if ($protocolTransition -or $toDc) { $sev = 'High'; $conf = 'High' }
            $ptNote = ''
            if ($protocolTransition) { $ptNote = ' Protocol transition (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION / S4U2Self) is enabled, so the account can obtain tickets for arbitrary users without their involvement.' }
            $dcNote = ''
            if ($toDc) { $dcNote = ' At least one target SPN resolves to a Domain Controller, effectively granting delegation to the directory.' }
            $tgtList = '-'; if ($spns.Count -gt 0) { $tgtList = ($spns -join ', ') }
            $desc = ("{0} changed constrained delegation on {1}. Targets (msDS-AllowedToDelegateTo): {2}.{3}{4}" -f `
                    $actor, $obj, $tgtList, $ptNote, $dcNote)
            $title = 'Constrained delegation target set'
            if ($protocolTransition) { $title = 'Constrained delegation with protocol transition enabled' }
            elseif ($toDc) { $title = 'Constrained delegation to sensitive (DC) SPN' }
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                        -Technique 'T1134' -TechniqueName 'Access Token Manipulation (Constrained Delegation / Protocol Transition)' `
                        -Title $title `
                        -Description $desc -Account $actor -Target (($obj + ' -> ' + $tgtList).Trim()) -Computer $e.Computer `
                        -EventIds ([int]$e.EventId) -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the delegation change is expected (4738/4742 shows the full current list, not a diff - corroborate with 5136). Remove unexpected SPNs, disable protocol transition where not required, never delegate to DC SPNs, and investigate the actor.'))
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
