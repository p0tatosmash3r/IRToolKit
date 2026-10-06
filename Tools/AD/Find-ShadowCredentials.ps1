<#
.SYNOPSIS
    Detects Shadow Credentials (msDS-KeyCredentialLink abuse) from Windows Security and PowerShell logs.

.DESCRIPTION
    Shadow Credentials is an account-takeover technique that abuses the msDS-KeyCredentialLink
    attribute of a user or computer object. That attribute stores KeyCredentials - certificate /
    public-key pairs usable for Kerberos PKINIT (the same mechanism behind Windows Hello for
    Business and FIDO2). An attacker who holds write access to a target object (e.g. GenericWrite,
    WriteProperty, or an ACL misconfiguration) writes their own KeyCredential into
    msDS-KeyCredentialLink, then authenticates to the KDC via PKINIT to obtain a TGT for the target
    - and, via UnPAC-the-hash, the target's NTLM hash - without ever changing the account password.
    Tooling: Whisker, pyWhisker, ntlmrelayx --shadow-credentials, Set-ADComputer -KeyCredentialLink,
    Add-ADComputerKeyCredential / certipy shadow.

    Detection logic (each rule emits its own finding):
      * Rule 1 - key credential ADDED (Security 5136, AttributeLDAPDisplayName = msDS-KeyCredentialLink,
        OperationType = Value Added %%14674). The actor is SubjectUserName, the target object is
        ObjectDN. Reported High/High when the actor is NOT the same principal as the target (someone
        writing a key onto SOMEONE ELSE'S object = takeover). Escalated to Critical when the target
        object is a domain controller. Self-service enrollment (actor CN == target CN, the normal
        Windows Hello / FIDO2 path) is suppressed by default (-SelfEnrollmentIsBenign).
      * Rule 2 - key credential REMOVED (5136, OperationType = Value Deleted %%14675) by a principal
        other than the target. Reported Medium (attacker cleanup such as 'Whisker remove', or routine
        administration).
      * Rule 3 - add-then-PKINIT correlation. A Rule 1 add on target T by actor A followed within
        -PkinitWindowMinutes by a successful PKINIT TGT request (Security 4768, PreAuthType 16 or 17)
        for T is a strong takeover signal (fresh certificate credential used immediately) and is
        reported Critical.
      * Rule 4 - PowerShell script-block signatures (4104) for Shadow Credentials tooling. Reported Medium.

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > DS Access > Audit Directory Service Changes = Success -> 5136
        (and SACL auditing of Write on the relevant objects / msDS-KeyCredentialLink).
      * DC: Account Logon > Audit Kerberos Authentication Service = Success -> 4768 (Rule 3).
      * Optional: PowerShell Script Block Logging (4104) for Rule 4.

    Known false positives:
      * Windows Hello for Business and FIDO2 security-key enrollment legitimately write
        msDS-KeyCredentialLink on the user's OWN object (actor == target). Azure AD / Entra hybrid
        join and the ADFS / NGC (ngccredprov) service accounts also write it. The actor-not-equal-to-
        target heuristic plus the self-enrollment exclusion is the key discriminator; it is a
        HEURISTIC comparison of SubjectUserName against the CN of ObjectDN and can misclassify when
        the SubjectUserName does not match the object's CN (e.g. an enrollment service). Validate the
        actor, the target and the source host before escalating.

.PARAMETER ComputerName
    Remote computer to read the live event log from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders of .evtx) to analyse offline.
.PARAMETER InputObject
    Pre-flattened IRToolKit event objects (from Get-IRSourceEvents / Import-IREvents) via the pipeline.
.PARAMETER InputPath
    JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents).
.PARAMETER StartTime
    Only analyse events at or after this time. Live mode defaults to the last 7 days.
.PARAMETER EndTime
    Only analyse events at or before this time.
.PARAMETER MaxEvents
    Cap on events read per event-ID batch (0 = unlimited).
.PARAMETER OutputPath
    Directory or file to write results to. When a directory is given the file is named <Tool>-<timestamp>.<ext>.
.PARAMETER Format
    Export format: Csv, Json, Html or All (default Json).
.PARAMETER Quiet
    Suppress console status output. Findings are still returned as objects.
.PARAMETER NoADLookup
    Skip live Active Directory look-ups even when the host is domain joined.
.PARAMETER DomainController
    Extra domain controller names / IPs to treat as DCs. Used to recognise when the key credential
    was written onto a DC object (escalates Rule 1 to Critical) when running offline.
.PARAMETER PkinitWindowMinutes
    Maximum minutes between a key-credential add and a subsequent PKINIT TGT request for the same
    target to correlate them as a takeover (Rule 3). Default 60.
.PARAMETER SelfEnrollmentIsBenign
    When $true (default) a key-credential add whose actor (SubjectUserName) matches the target CN is
    treated as benign self-service enrollment (Windows Hello / FIDO2) and suppressed from Rule 1 and
    Rule 3. Set to $false to surface every add (self-enrollment adds are then reported Informational).

.EXAMPLE
    .\Find-ShadowCredentials.ps1 -StartTime (Get-Date).AddDays(-14)
    Analyse the local DC Security + PowerShell logs for the last 14 days.

.EXAMPLE
    .\Find-ShadowCredentials.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01,DC02 -OutputPath C:\Evidence\Out -Format All
    Analyse an exported log offline, treating DC01/DC02 as domain controllers, and write all report formats.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Find-ShadowCredentials.ps1

.NOTES
    ATT&CK : T1098.001 (Account Manipulation: Additional Cloud/AD Credentials - Key Credential / Shadow Credentials); findings carry T1098.001. Related parent behaviour: T1556 (Modify Authentication Process)
    Events : 5136 (Security - directory object modified), 4768 (Security - Kerberos TGT request / PKINIT), 4104 (PowerShell Operational)
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

    [int]$PkinitWindowMinutes = 60,
    [bool]$SelfEnrollmentIsBenign = $true
)

begin {
    # Locate Common\IRToolKit.Common.psm1 by walking up from the script folder (works from Tools\<Phase>\, Templates\, or a copied tree)
    $irModule = $null; $irDir = $PSScriptRoot
    for ($i = 0; $i -lt 5 -and $irDir; $i++) {
        $candidate = Join-Path $irDir 'Common\IRToolKit.Common.psm1'
        if (Test-Path -LiteralPath $candidate) { $irModule = $candidate; break }
        $irDir = Split-Path -Parent $irDir
    }
    if (-not $irModule) { throw "IRToolKit.Common.psm1 not found above $PSScriptRoot. Keep the folder structure intact." }
    Import-Module $irModule -Force
    $toolName = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    if (-not $toolName) { $toolName = 'Find-ShadowCredentials' }
    $technique = 'T1098.001'; $techniqueName = 'Additional Credentials: Key Credential (Shadow Credentials)'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Shadow Credentials (msDS-KeyCredentialLink abuse)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $keyCredAttr = 'msDS-KeyCredentialLink'

    # Normalise a principal / object name to a comparable key: strip UPN suffix, NetBIOS domain
    # prefix, a trailing '$' (machine accounts) and lower-case it. Used for the (heuristic) actor vs
    # target comparison and for correlating 4768 target names with 5136 object CNs.
    function Get-SCPrincipalKey {
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@(.+)$') { $u = $matches[1] }
        if ($u -match '^(.+)\\(.+)$') { $u = $matches[2] }
        return $u.Trim().TrimEnd('$').ToLowerInvariant()
    }
    function Get-SCObjectCn {
        param($Dn)
        $d = [string]$Dn
        if ($d -match '^\s*CN=([^,]+)') { return $matches[1].Trim() }
        return $d
    }

    # Build the DC lookup for the DC-target escalation. The analyst-supplied -DomainController names
    # are always honoured (offline use), and live auto-discovery is only attempted when Active
    # Directory is reachable and -NoADLookup was not set (guarding the read-only AD look-up per the
    # kit conventions; this also avoids the not-domain-joined discovery exception offline).
    $dcLookup = @{}
    foreach ($dc in @($DomainController)) {
        if (-not $dc) { continue }
        $n = ([string]$dc).Trim().ToLowerInvariant()
        if (-not $n) { continue }
        $dcLookup[$n] = $true
        $short = $n.Split('.')[0]; $dcLookup[$short] = $true; $dcLookup["$short`$"] = $true
    }
    if ((-not $NoADLookup) -and (Test-IRAdAvailable)) {
        foreach ($k in (Get-IRDomainControllerLookup).Keys) { $dcLookup[$k] = $true }
    }
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - DC-target escalation is disabled.' -Level Detail }

    # ---- Source A: directory object modifications (5136) ----
    $mods = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136)
    Write-IRStatus "Loaded $($mods.Count) 5136 event(s)" -Level Detail

    # Keep only msDS-KeyCredentialLink changes.
    $keyMods = @($mods | Where-Object { ([string]$_.AttributeLDAPDisplayName) -ieq $keyCredAttr })
    Write-IRStatus "$($keyMods.Count) msDS-KeyCredentialLink change(s)" -Level Detail

    # Suspicious adds (actor != target) tracked for the PKINIT correlation.
    $suspiciousAdds = New-Object System.Collections.Generic.List[object]

    foreach ($e in $keyMods) {
        $opType = [string]$e.OperationType
        $isAdd = ($opType -like '*14674*')
        $isDel = ($opType -like '*14675*')
        if (-not $isAdd -and -not $isDel) { continue }

        $objectDn = [string]$e.ObjectDN
        $actorRaw = [string]$e.SubjectUserName
        if (-not $objectDn -and -not $actorRaw) { continue }   # malformed 5136 with no target and no actor
        $objectClass = [string]$e.ObjectClass
        if (-not $objectClass) { $objectClass = 'object' }
        $targetCn = Get-SCObjectCn $objectDn
        $actor = [string]$e.SubjectUserName
        $actorKey = Get-SCPrincipalKey $actor
        $targetKey = Get-SCPrincipalKey $targetCn
        $isSelf = ($actorKey -ne '' -and $actorKey -eq $targetKey)
        $isDcTarget = (Test-IRDomainController -Lookup $dcLookup -Value $targetCn) -or (Test-IRDomainController -Lookup $dcLookup -Value $objectDn)

        if ($isAdd) {
            if ($isSelf) {
                if ($SelfEnrollmentIsBenign) { continue }   # benign self-service WHfB / FIDO2 enrollment
                # Switch turned off: surface self-enrollment as context only.
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'Low' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Self-service key credential enrollment' `
                            -Description ("{0} added a key credential ({1}) to its OWN {2} object {3}. Actor CN matches target CN, consistent with Windows Hello for Business / FIDO2 self-enrollment (benign). Shown because -SelfEnrollmentIsBenign was disabled." -f $actor, $keyCredAttr, $objectClass, $objectDn) `
                            -Account $actor -Target $objectDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Normally benign. Confirm the account genuinely enrolled a Windows Hello / FIDO2 credential.'))
                continue
            }

            # Self/other is inferred by comparing the actor's sAMAccountName to the object CN. For USER
            # objects the CN is normally the DISPLAY NAME ("Alice Smith"), not the sAMAccountName ("alice"),
            # so a CN containing whitespace cannot be reliably compared to the actor offline. In that case
            # (non-computer, non-DC target) down-rank to Informational so a normal Windows Hello rollout is
            # not flagged High - but still track the add for the PKINIT correlation, which escalates a true
            # follow-on takeover to Critical regardless.
            $cnLooksLikeDisplayName = ($targetCn -match '\s') -and ($objectClass -notlike '*computer*')
            if ($cnLooksLikeDisplayName -and -not $isDcTarget) {
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'Low' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Key credential added (self vs other undetermined)' `
                            -Description ("{0} added a key credential ({1}) to {2} object {3}. The target CN is a display name, not a sAMAccountName, so this cannot be reliably distinguished from self-service Windows Hello / FIDO2 enrollment offline. Confirm whether the actor owns this object; if not, this is a Shadow Credentials takeover." -f $actor, $keyCredAttr, $objectClass, $objectDn) `
                            -Account $actor -Target $objectDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm whether the actor is the owner of the target object (resolve the object sAMAccountName). If the actor is a different principal, treat the target as compromised and clear its msDS-KeyCredentialLink.'))
                $suspiciousAdds.Add([pscustomobject]@{
                        TargetKey = $targetKey; TargetCn = $targetCn; ObjectDn = $objectDn; ObjectClass = $objectClass
                        Actor = $actor; AddTime = $e.TimeCreated; AddEvent = $e; IsDcTarget = $isDcTarget
                    })
                continue
            }

            $sev = 'High'
            $takeoverNote = ("Actor '{0}' differs from target '{1}', which is characteristic of a Shadow Credentials takeover rather than self-service Windows Hello / FIDO2 enrollment (which writes the actor's OWN object)." -f $actor, $targetCn)
            if ($isDcTarget) {
                $sev = 'Critical'
                $takeoverNote += ' The target object is a DOMAIN CONTROLLER - abuse of a DC key credential enables full domain compromise.'
            }
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Shadow credential (key credential) added to another principal' `
                        -Description ("{0} added a key credential ({1}) to {2} object {3}. {4}" -f $actor, $keyCredAttr, $objectClass, $objectDn, $takeoverNote) `
                        -Account $actor -Target $objectDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Verify whether the actor is authorised to write msDS-KeyCredentialLink on the target. If not, treat the target as compromised: inspect/clear its msDS-KeyCredentialLink (KeyCredentials), reset the account, and audit write permissions (GenericWrite / WriteProperty / WriteDacl) on the object.'))

            $suspiciousAdds.Add([pscustomobject]@{
                    TargetKey = $targetKey; TargetCn = $targetCn; ObjectDn = $objectDn; ObjectClass = $objectClass
                    Actor = $actor; AddTime = $e.TimeCreated; AddEvent = $e; IsDcTarget = $isDcTarget
                })
        }
        elseif ($isDel) {
            if ($isSelf) { continue }   # removing one's own key is routine
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Shadow credential (key credential) removed from another principal' `
                        -Description ("{0} removed a key credential ({1}, Value Deleted) from {2} object {3}. May be attacker cleanup (e.g. 'Whisker remove' after a takeover) or legitimate administration." -f $actor, $keyCredAttr, $objectClass, $objectDn) `
                        -Account $actor -Target $objectDn -Computer $e.Computer -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Correlate with a preceding key-credential add on the same object and any PKINIT logons for it. Confirm the removal was expected.'))
        }
    }

    # ---- Rule 3: correlate a suspicious add with a subsequent PKINIT TGT request (4768) ----
    if ($suspiciousAdds.Count -gt 0) {
        $tgt = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
        Write-IRStatus "Loaded $($tgt.Count) 4768 event(s) for PKINIT correlation" -Level Detail

        # Index successful PKINIT (PreAuthType 16/17) TGT requests by normalised target name.
        $pkinitByTarget = @{}
        foreach ($t in $tgt) {
            $pre = [string]$t.PreAuthType
            if ($pre -ne '16' -and $pre -ne '17') { continue }
            $statusHex = ConvertTo-IRHexString $t.Status
            if ($statusHex -and $statusHex -ne '0x0' -and $statusHex -ne '0x') { continue }   # successes only
            $k = Get-SCPrincipalKey $t.TargetUserName
            if (-not $k) { continue }
            if (-not $pkinitByTarget.ContainsKey($k)) { $pkinitByTarget[$k] = New-Object System.Collections.Generic.List[object] }
            $pkinitByTarget[$k].Add($t)
        }

        $windowTicks = [TimeSpan]::FromMinutes($PkinitWindowMinutes).Ticks
        foreach ($add in $suspiciousAdds) {
            if (-not $pkinitByTarget.ContainsKey($add.TargetKey)) { continue }
            if ($add.AddTime -isnot [datetime]) { continue }
            foreach ($pk in $pkinitByTarget[$add.TargetKey]) {
                if ($pk.TimeCreated -isnot [datetime]) { continue }
                $delta = $pk.TimeCreated.Ticks - $add.AddTime.Ticks
                if ($delta -lt 0 -or $delta -gt $windowTicks) { continue }
                $mins = [Math]::Round(($pk.TimeCreated - $add.AddTime).TotalMinutes, 1)
                $ip = ConvertTo-IRIpAddress $pk.IpAddress
                $preDecoded = ConvertFrom-IRPreAuthType $pk.PreAuthType
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Shadow credential add followed by PKINIT logon (account takeover)' `
                            -Description ("A key credential was added to {0} ({1}) by {2} at {3:yyyy-MM-dd HH:mm:ss}, then a PKINIT TGT was requested for {0} from {4} at {5:yyyy-MM-dd HH:mm:ss} ({6} min later). PreAuth: {7}. This add-then-PKINIT sequence is a strong Shadow Credentials takeover signal (certificate credential used immediately; enables UnPAC-the-hash)." -f $add.TargetCn, $add.ObjectDn, $add.Actor, $add.AddTime, $ip, $pk.TimeCreated, $mins, $preDecoded) `
                            -Account $add.TargetCn -SourceIp $ip -Target $add.ObjectDn -Computer $pk.Computer -EventIds @(5136, 4768) `
                            -Evidence (Get-IRFirst @($add.AddEvent, $pk) 200) `
                            -Recommendation 'Treat the target account as compromised. Clear the attacker key credential from msDS-KeyCredentialLink, reset the account (twice for krbtgt-adjacent or DC targets), isolate the PKINIT source host, and hunt for UnPAC-the-hash / ticket reuse.'))
                break   # one correlation finding per add is enough
            }
        }
    }

    # ---- Rule 4: PowerShell script-block tooling signatures (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Whisker', 'pyWhisker', 'msDS-KeyCredentialLink', 'KeyCredential', 'Set-ADComputer.*KeyCredential', 'Add-ADComputerKeyCredential', 'shadowcred'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Shadow Credentials tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched Shadow Credentials signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this script block. Correlate with 5136 msDS-KeyCredentialLink writes and 4768 PKINIT logons from the same host / timeframe.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
