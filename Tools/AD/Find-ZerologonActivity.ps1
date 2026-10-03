<#
.SYNOPSIS
    Detects Zerologon (CVE-2020-1472) activity and exposure from Windows Security, System (Netlogon),
    and PowerShell event logs.

.DESCRIPTION
    CVE-2020-1472 ("Zerologon") is a flaw in the Netlogon secure-channel cryptography that lets an
    unauthenticated attacker with network access to a domain controller impersonate a machine account
    and set that account's password to EMPTY in AD - most damagingly the DC's own computer account,
    which yields domain compromise. This tool looks for the forensic artefacts the attack and the
    Microsoft hardening leave behind; it does NOT test or exploit anything.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 (Critical) - a COMPUTER account's password was changed by ANONYMOUS LOGON (Security 4742,
        SubjectUserName "ANONYMOUS LOGON" / SubjectUserSid S-1-5-7). Machine-account passwords are rotated
        by the machine itself over an authenticated channel, never anonymously; an anonymous machine
        password change is the Zerologon reset signature. Critical when the target is a domain controller,
        High otherwise.
      * RULE 2 (High/Medium) - the August-2020+ Netlogon hardening events in the System log (source
        NETLOGON): 5827/5828 (a vulnerable Netlogon connection from a machine/trust account was DENIED),
        5829 (a vulnerable connection was ALLOWED - enforcement not on), 5830/5831 (allowed by the
        group-policy exception list). 5829 in particular means a non-secure Netlogon channel was permitted.
      * RULE 3 (Medium; High on a burst) - a burst of Netlogon session-setup authentication FAILURES
        (System 5805) for a machine account from around the same time, consistent with the repeated
        attempts the exploit makes before it succeeds.
      * RULE 4 (High) - Zerologon tooling in a PowerShell script block (4104): zerologon, CVE-2020-1472,
        NetrServerPasswordSet2, NetrServerAuthenticate3, Invoke-Zerologon.

    Required log sources:
      * Security log (domain controllers): Audit Computer Account Management = Success -> 4742.
      * System log (domain controllers), source NETLOGON -> 5805 and 5827-5831. PULL THE SYSTEM LOG, not
        just Security - the hardening/vulnerable-channel events live there. The 5827-5831 events only
        exist on hosts with the August 2020 (or later) Netlogon update installed.
      * Optional: PowerShell Script Block Logging (4104) for RULE 4.

    Known false positives:
      * Legitimate but old / non-Windows devices (some NAS, appliances, printers, older Samba, pre-2020
        Windows) use the vulnerable Netlogon channel and will raise 5827/5828 (denied) or 5829 (allowed).
        Identify the machine account named in the event and confirm it is a known legacy device before
        discounting; a DC machine account appearing there is never a legacy-device false positive.
      * RULE 1 (anonymous machine-password change) has essentially no benign cause and should be treated
        as a true positive until proven otherwise.

.PARAMETER ComputerName
    Remote computer to read the live logs from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders) to analyse offline (include the System log).
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
    Skip live Active Directory look-ups.
.PARAMETER DomainController
    Domain controller names / IPs. A DC machine account whose password is reset anonymously is escalated
    to Critical; offline, this also supplies the DC list.
.PARAMETER FailureBurstThreshold
    Number of Netlogon auth failures (5805) for one machine account within the window to raise RULE 3 to
    High (default 20).
.PARAMETER WindowMinutes
    Sliding window length in minutes for the failure-burst rule (default 10).

.EXAMPLE
    .\Find-ZerologonActivity.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC01-System.evtx -DomainController DC01,DC02
    Hunt Zerologon artefacts across an exported DC Security + System log offline.

.EXAMPLE
    .\Find-ZerologonActivity.ps1 -StartTime (Get-Date).AddDays(-30) -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1210 (Exploitation of Remote Services); CVE-2020-1472 (Zerologon)
    Events : 4742 (Security); 5805, 5827, 5828, 5829, 5830, 5831 (System / NETLOGON); 4104 (PowerShell)
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

    [int]$FailureBurstThreshold = 20,
    [int]$WindowMinutes = 10
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
    if (-not $toolName) { $toolName = 'Find-ZerologonActivity' }
    $technique = 'T1210'; $techniqueName = 'Zerologon (CVE-2020-1472)'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Zerologon (CVE-2020-1472) activity and exposure' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - DC escalation uses a name heuristic only.' -Level Detail }

    function Get-ZLBareName {
        # NAME$@REALM / DOMAIN\NAME$ -> bare account for the DC-lookup test.
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@[^@]+$') { $u = $matches[1] }
        if ($u -match '\\([^\\]+)$') { $u = $matches[1] }
        return $u.Trim()
    }
    function Test-ZLAnonymous {
        param($Subject, $SubjectSid)
        $s = ([string]$Subject).Trim()
        $sid = ([string]$SubjectSid).Trim()
        if ($s -match '(?i)^ANONYMOUS LOGON$') { return $true }
        if ($sid -eq 'S-1-5-7') { return $true }
        return $false
    }
    function Get-ZLAccountFromEvent {
        # Pull a machine account name from a Netlogon 582x/5805 event via named fields or the message text.
        param($Evt)
        foreach ($p in @('SamAccountName', 'MachineAccount', 'Account', 'AccountName', 'TargetUserName', 'ComputerName', 'ClientMachineName')) {
            if ($Evt.PSObject.Properties[$p] -and $Evt.$p) { return [string]$Evt.$p }
        }
        $msg = [string]$Evt.Message
        if ($msg) {
            if ($msg -match '(?im)(?:SamAccountName|machine account|account(?:\s+name)?|computer)\s*[:=]?\s*([A-Za-z0-9_.-]+\$)') { return $matches[1] }
            if ($msg -match '([A-Za-z0-9_.-]+\$)') { return $matches[1] }
        }
        return $null
    }

    # ---- RULE 1: machine-account password changed by ANONYMOUS LOGON (4742) ----
    $acctEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4742)
    Write-IRStatus "Loaded $($acctEvents.Count) 4742 event(s)" -Level Detail
    foreach ($e in $acctEvents) {
        $target = [string]$e.TargetUserName
        if (-not $target) { continue }
        if (-not (Test-IRMachineAccount $target)) { continue }                 # computer accounts only
        if (-not (Test-ZLAnonymous $e.SubjectUserName $e.SubjectUserSid)) { continue }
        $bare = Get-ZLBareName $target
        $isDc = $false
        if ($dcLookup.Count -gt 0) { $isDc = (Test-IRDomainController -Lookup $dcLookup -Value $bare) }
        if (-not $isDc) {
            # Heuristic fallback when no DC list: a DC machine name usually matches the DC naming of the
            # host that logged it, but we cannot be sure - keep High and note the limitation.
        }
        $sev = if ($isDc) { 'Critical' } else { 'High' }
        $dcNote = if ($isDc) { ' The target is a DOMAIN CONTROLLER - this is the full-compromise Zerologon case.' } else { ' The target is a computer account; a Zerologon reset of any machine account is a foothold.' }
        if ($dcLookup.Count -eq 0) { $dcNote += ' No DC list supplied; pass -DomainController to confirm whether the target is a DC (would raise this to Critical).' }
        $desc = ("Computer account '{0}' had its password changed by ANONYMOUS LOGON (event 4742) on {1}. Machine accounts never rotate their password over an anonymous channel - this is the Zerologon (CVE-2020-1472) password-reset signature.{2}" -f `
                $target, $e.Computer, $dcNote)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'High' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Machine-account password changed by ANONYMOUS LOGON (Zerologon reset)' `
                    -Description $desc -Account 'ANONYMOUS LOGON' -Target $target -Computer $e.Computer `
                    -EventIds 4742 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Treat the domain as compromised if the target is a DC. Immediately reset the affected machine-account password TWICE (the computer object, and if a DC also run the standard krbtgt double-reset and restore the DC machine password via reset-machine-account procedures), apply the latest Netlogon update and enforce secure-channel enforcement mode, and hunt for follow-on DCSync / domain-admin activity from the same window.'))
    }

    # ---- RULE 2: Netlogon hardening events 5827-5831 (System / NETLOGON) ----
    # -NoLogNameFilter: these IDs are NETLOGON-specific, so read them even if a SIEM export relabelled
    # the channel. Group by (event-id, account) so one chatty legacy device yields one finding, not N.
    $hardening = @(Get-IRSourceEvents -Context $ctx -LogName 'System' -EventId 5827, 5828, 5829, 5830, 5831 -IncludeMessage -NoLogNameFilter)
    Write-IRStatus "Loaded $($hardening.Count) Netlogon 5827-5831 event(s)" -Level Detail
    foreach ($e in $hardening) {
        $acct = Get-ZLAccountFromEvent $e
        $e | Add-Member -NotePropertyName _AcctName -NotePropertyValue $(if ($acct) { $acct } else { '(account not parsed)' }) -Force
        $e | Add-Member -NotePropertyName _AcctKey -NotePropertyValue $(if ($acct) { (Get-ZLBareName $acct).ToLowerInvariant() } else { '(unparsed)' }) -Force
    }
    foreach ($g in ($hardening | Group-Object { "$([int]$_.EventId)|$($_._AcctKey)|$($_.Computer)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $id = [int]$ev[0].EventId
        $acctTxt = [string]$ev[0]._AcctName
        $acct = if ($ev[0]._AcctKey -ne '(unparsed)') { $acctTxt } else { $null }
        $isDc = $false
        if ($acct -and $dcLookup.Count -gt 0) { $isDc = (Test-IRDomainController -Lookup $dcLookup -Value (Get-ZLBareName $acct)) }
        $countNote = if ($ev.Count -gt 1) { (" ({0} such events)" -f $ev.Count) } else { '' }
        switch ($id) {
            { $_ -in 5827, 5828 } {
                $sev = if ($isDc) { 'Critical' } else { 'High' }
                $title = 'Vulnerable Netlogon secure-channel connection DENIED (5827/5828)'
                $body = ("A vulnerable (CVE-2020-1472) Netlogon secure-channel connection from {0} was denied by the DC (event {1}){2}. The hardening blocked it - but it shows a vulnerable client, or an exploitation attempt, reaching the DC." -f $acctTxt, $id, $countNote)
            }
            5829 {
                $sev = if ($isDc) { 'Critical' } else { 'High' }
                $title = 'Vulnerable Netlogon secure-channel connection ALLOWED (5829)'
                $body = ("A vulnerable (CVE-2020-1472) Netlogon secure-channel connection from {0} was ALLOWED (event 5829){1} - enforcement mode is not on, so the DC accepted a non-secure channel. This is both exposure and a usable channel for the attack." -f $acctTxt, $countNote)
            }
            default {
                $sev = 'Medium'
                $title = 'Vulnerable Netlogon connection allowed by group-policy exception (5830/5831)'
                $body = ("A vulnerable Netlogon connection from {0} was allowed by the group-policy exception list (event {1}){2}. Confirm the exception is still required." -f $acctTxt, $id, $countNote)
            }
        }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title $title `
                    -Description $body -Account $acctTxt -Target $acctTxt -Computer $ev[0].Computer `
                    -EventIds $id -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Identify the machine account named in the event. If it is a known legacy / non-Windows device, update or isolate it; if it is unexpected (especially a DC account), treat as Zerologon activity. Move all DCs to Netlogon enforcement mode so vulnerable channels are refused.'))
    }

    # ---- RULE 3: burst of Netlogon auth failures (System 5805) ----
    # The 5805 account lives only in the rendered Message. Events whose account cannot be parsed are
    # EXCLUDED from the burst: attributing a "single-account brute" requires knowing the account, and
    # lumping unparseable failures from many different hosts under one bucket fabricates a false burst
    # (this also means that offline, where the NETLOGON message may not render, RULE 3 simply does not
    # fire rather than mis-fire). -NoLogNameFilter keeps it robust to a relabelled export.
    $fail = @(Get-IRSourceEvents -Context $ctx -LogName 'System' -EventId 5805 -IncludeMessage -NoLogNameFilter)
    Write-IRStatus "Loaded $($fail.Count) Netlogon 5805 event(s)" -Level Detail
    $failNorm = New-Object System.Collections.Generic.List[object]
    $unparsed5805 = 0
    foreach ($e in $fail) {
        $acct = Get-ZLAccountFromEvent $e
        if (-not $acct) { $unparsed5805++; continue }   # cannot attribute to one account -> not burstable
        $e | Add-Member -NotePropertyName _AcctKey -NotePropertyValue ((Get-ZLBareName $acct).ToLowerInvariant()) -Force
        $e | Add-Member -NotePropertyName _AcctName -NotePropertyValue $acct -Force
        $failNorm.Add($e)
    }
    if ($unparsed5805 -gt 0) { Write-IRStatus "$unparsed5805 of $($fail.Count) 5805 event(s) had no parseable account (message not rendered?) and were excluded from the burst rule." -Level Detail }
    foreach ($b in @(Find-IRBurst -Events $failNorm.ToArray() -GroupBy '_AcctKey', 'Computer' -WindowMinutes $WindowMinutes -Threshold $FailureBurstThreshold)) {
        $acctName = [string]$b.Events[0]._AcctName
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Burst of Netlogon authentication failures (possible Zerologon brute)' `
                    -Description ("{0} Netlogon session-setup failures (event 5805) for machine account {1} within {2} min on {3}. A rapid burst of secure-channel auth failures for one machine account is consistent with the repeated attempts the Zerologon exploit makes before it succeeds." -f $b.EventCount, $acctName, $mins, $b.Events[0].Computer) `
                    -Account $acctName -Target $acctName -Computer $b.Events[0].Computer `
                    -EventIds 5805 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Check whether a machine password change (4742) or a 5827-5831 event for the same account follows the burst. If the account is a DC, treat as Zerologon and respond immediately. A broken secure channel on a legacy host can also cause 5805 - confirm the source.'))
    }

    # ---- RULE 4: Zerologon tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'zerologon', 'CVE-2020-1472', 'NetrServerPasswordSet2', 'NetrServerAuthenticate3', 'Invoke-Zerologon', 'set_empty_pw', 'reinstall_original_pw'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Zerologon tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched Zerologon signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this, and correlate with 4742 anonymous machine-password changes and 5805/5827-5831 Netlogon events on the DCs in the same window.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
