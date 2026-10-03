<#
.SYNOPSIS
    Detects Kerberoasting from Windows Security and PowerShell event logs.

.DESCRIPTION
    Kerberoasting abuses the fact that any authenticated principal can request a Kerberos service
    ticket (TGS) for any account that has a servicePrincipalName. When the service runs under a
    *user* account, the ticket is encrypted with that account's password-derived key, so an attacker
    can request the ticket, extract it, and crack the password offline. RC4 (etype 0x17) tickets are
    the easiest to crack, so tooling (Rubeus, Invoke-Kerberoast, GetUserSPNs) typically requests RC4
    even when the account supports AES, which is itself a detectable downgrade.

    Detection logic:
      * Source: Security event 4769 (Kerberos Service Ticket Operations, Success auditing) on DCs.
      * Pre-filter: successful requests (Status 0x0) for service accounts that are user accounts
        (ServiceName does not end with '$'), excluding krbtgt / kadmin and self-requests.
      * Rule 1 - weak-cipher burst: >= RC4Threshold distinct user service accounts requested with
        RC4/DES by one requester+IP within WindowMinutes. A single RC4 request is reported as Medium.
      * Rule 2 - volume burst: >= Threshold distinct user service accounts requested (any cipher) by
        one requester+IP within WindowMinutes (catches AES / opsec-aware roasting).
      * Rule 3 - machine-account requester asking for RC4 user-service tickets (unusual).
      * Rule 4 - honeypot: any 4769 for a -HoneypotAccount fires immediately.
      * Rule 5 - PowerShell 4104 script blocks containing Kerberoast tooling signatures.
      * Optional AD context: flags accounts that are AES-capable but received an RC4 ticket
        (encryption downgrade) and whether the service account is adminCount=1.

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > Account Logon > Audit Kerberos Service Ticket Operations = Success.
      * Optional: PowerShell Script Block Logging (4104) for Rule 5.

    Known false positives:
      * Legacy applications and some SQL / SharePoint / Exchange components legitimately request many
        service tickets, occasionally over RC4. Vulnerability scanners and account-discovery tools can
        mimic a burst. Validate the requester and the source host before escalating. A single Medium
        RC4 finding for a known legacy app is expected; the burst rules are the stronger signal.
      * Busy monitoring / management accounts (SCCM, SCOM, vCenter) can request many distinct service
        tickets every poll cycle and trip the volume rule. Add validated accounts to -ExcludeRequester.

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
    Skip live Active Directory look-ups.
.PARAMETER DomainController
    Extra DC names / IPs (used to recognise machine-account requesters offline).
.PARAMETER Threshold
    Distinct user service accounts (any cipher) in a window to raise the volume rule (default 10).
.PARAMETER RC4Threshold
    Distinct user service accounts requested with RC4/DES in a window to raise the weak-cipher rule (default 3).
.PARAMETER WindowMinutes
    Sliding window length in minutes for the burst rules (default 10).
.PARAMETER HoneypotAccount
    Service account names that must never be legitimately roasted; any ticket request fires a Critical finding.
.PARAMETER ExcludeRequester
    Known-good requester accounts (e.g. SCCM / SCOM / vCenter service accounts) to skip entirely, so their
    legitimate high-volume service-ticket activity does not trip the burst rules. Matched on the bare name.
.PARAMETER IncludeMachineRequesters
    Also evaluate the weak-cipher burst rule for machine-account requesters (the volume rule already
    evaluates machine requesters by default; machine weak requests otherwise surface via Rule 3).

.EXAMPLE
    .\Find-Kerberoasting.ps1 -StartTime (Get-Date).AddDays(-14)
    Analyse the local DC Security log for the last 14 days.

.EXAMPLE
    .\Find-Kerberoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -HoneypotAccount svc_decoy -OutputPath C:\Evidence\Out -Format All

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} | ConvertFrom-IRWinEvent | .\Find-Kerberoasting.ps1

.NOTES
    ATT&CK : T1558.003 (Kerberoasting)
    Events : 4769 (Security), 4104 (PowerShell Operational)
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

    [int]$Threshold = 10,
    [int]$RC4Threshold = 3,
    [int]$WindowMinutes = 10,
    [string[]]$HoneypotAccount,
    [string[]]$ExcludeRequester,
    [switch]$IncludeMachineRequesters
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
    if (-not $toolName) { $toolName = 'Find-Kerberoasting' }
    $technique = 'T1558.003'; $techniqueName = 'Kerberoasting'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $honeypotSet = @{}
    foreach ($h in @($HoneypotAccount)) { if ($h) { $honeypotSet[$h.ToLowerInvariant().TrimEnd('$')] = $true } }
    $excludeRequesterSet = @{}
    foreach ($x in @($ExcludeRequester)) {
        if ($x) { $xb = [string]$x; if ($xb -match '^(.+)@') { $xb = $matches[1] }; $excludeRequesterSet[$xb.ToLowerInvariant().TrimEnd('$')] = $true }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Kerberoasting (TGS requests for user service accounts)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $tgs = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4769)
    Write-IRStatus "Loaded $($tgs.Count) 4769 event(s)" -Level Detail

    $adAvailable = (-not $NoADLookup) -and (Test-IRAdAvailable)
    if ($adAvailable) { Write-IRStatus 'Active Directory reachable - service accounts will be enriched.' -Level Detail }
    $adCache = @{}
    $excluded = @(Get-IRReferenceTable KerberoastExcludedServices)

    # Normalise and pre-filter the 4769 set once.
    $roastable = New-Object System.Collections.Generic.List[object]
    $honeypotHits = New-Object System.Collections.Generic.List[object]
    foreach ($e in $tgs) {
        $svc = [string]$e.ServiceName
        if (-not $svc) { continue }
        $svcKey = $svc.ToLowerInvariant().TrimEnd('$')

        # Honeypot: match on the service account the ticket is for, regardless of status.
        if ($honeypotSet.Count -gt 0 -and $honeypotSet.ContainsKey($svcKey)) { $honeypotHits.Add($e); continue }

        $status = ConvertTo-IRHexString $e.Status
        if ($status -and $status -ne '0x0' -and $status -ne '0x') { continue }   # successes only
        if (Test-IRMachineAccount $svc) { continue }                             # service is a computer account
        if ($svcKey -in $excluded) { continue }                                  # krbtgt / kadmin (exact)
        # Cross-realm referral TGS (ServiceName 'krbtgt/REALM' or 'kadmin/...') is a referral, not a
        # roastable user service account. Native 4769 carries ServiceSid -502, but normalised JSON/CSV
        # pipelines often drop it, so also exclude by name prefix.
        if ($svcKey -like 'krbtgt/*' -or $svcKey -like 'kadmin/*') { continue }
        $svcSid = [string]$e.ServiceSid
        if ($svcSid -match '-502$') { continue }                                 # krbtgt by SID

        # Drop self-requests (user requesting a ticket to their own SPN).
        $reqUser = ([string]$e.TargetUserName)
        $reqBare = $reqUser; if ($reqBare -match '^(.+)@') { $reqBare = $matches[1] }
        if ($reqBare -and $reqBare.ToLowerInvariant().TrimEnd('$') -eq $svcKey) { continue }

        # Analyst-supplied allow-list of known-good requesters (busy service / monitoring accounts that
        # legitimately pull many service tickets, e.g. SCCM/SCOM/vCenter). Matched on the bare name.
        if ($excludeRequesterSet.Count -gt 0 -and $excludeRequesterSet.ContainsKey($reqBare.ToLowerInvariant().TrimEnd('$'))) { continue }

        $ip = ConvertTo-IRIpAddress $e.IpAddress
        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
        $e | Add-Member -NotePropertyName _ReqKey -NotePropertyValue (Get-IRAccountKey $reqUser $e.TargetDomainName) -Force
        $e | Add-Member -NotePropertyName _Weak -NotePropertyValue (Test-IRWeakKerberosEncryption $e.TicketEncryptionType) -Force
        $e | Add-Member -NotePropertyName _ReqIsMachine -NotePropertyValue (Test-IRMachineAccount $reqUser) -Force
        $roastable.Add($e)
    }
    Write-IRStatus "$($roastable.Count) candidate service-ticket request(s) after filtering" -Level Detail

    function Get-KServiceAccountNote {
        param([string]$ServiceName, [bool]$TicketWasWeak)
        if (-not $adAvailable) { return $null }
        $key = $ServiceName.ToLowerInvariant()
        if (-not $adCache.ContainsKey($key)) { $adCache[$key] = Get-IRAdObject -SamAccountName $ServiceName }
        $o = $adCache[$key]
        if (-not $o) { return $null }
        $notes = @()
        if ($o.adminCount -and [string]$o.adminCount -eq '1') { $notes += 'adminCount=1 (privileged/protected service account)' }
        $enc = $o.'msDS-SupportedEncryptionTypes'
        if ($null -ne $enc) {
            $encN = ConvertTo-IRInt $enc
            $aesCapable = ($null -ne $encN -and ($encN -band 0x18) -ne 0)
            if ($aesCapable -and $TicketWasWeak) { $notes += 'account is AES-capable but an RC4 ticket was issued (encryption downgrade)' }
        }
        if ($notes.Count -gt 0) { return ($notes -join '; ') }
        return $null
    }

    function Add-KBurstFinding {
        param($Burst, [string]$Severity, [string]$Confidence, [string]$Kind, [bool]$WeakOnly)
        $services = @($Burst.DistinctValues | Where-Object { $_ })
        if (-not $services -or $services.Count -eq 0) { $services = @($Burst.Events | ForEach-Object { $_.ServiceName } | Select-Object -Unique) }
        $encTypes = @($Burst.Events | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
        $reqUser = [string]$Burst.Events[0].TargetUserName
        $mins = [Math]::Round(($Burst.WindowEnd - $Burst.WindowStart).TotalMinutes, 1)
        $adNotes = New-Object System.Collections.Generic.List[string]
        if ($adAvailable) {
            foreach ($s in (Get-IRFirst $services 25)) {
                $weakForSvc = [bool](@($Burst.Events | Where-Object { $_.ServiceName -eq $s -and $_._Weak }).Count -gt 0)
                $n = Get-KServiceAccountNote -ServiceName $s -TicketWasWeak $weakForSvc
                if ($n) { $adNotes.Add("$s`: $n") }
            }
        }
        if ($adNotes.Count -gt 0 -and $Confidence -ne 'High') { $Confidence = 'High' }
        $desc = "{0} requested {1} distinct user service-account ticket(s) from {2} within {3} min. Encryption: {4}. Services: {5}." -f `
            $reqUser, $services.Count, $Burst.Events[0]._SourceIp, $mins, ($encTypes -join ', '), ((Get-IRFirst $services 10) -join ', ')
        if ($services.Count -gt 10) { $desc += " (+$($services.Count - 10) more)" }
        if ($adNotes.Count -gt 0) { $desc += ' AD context: ' + ((Get-IRFirst @($adNotes) 8) -join ' | ') + '.' }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $Severity -Confidence $Confidence `
                    -Technique $technique -TechniqueName $techniqueName -Title $Kind `
                    -Description $desc -Account $reqUser -SourceIp $Burst.Events[0]._SourceIp `
                    -Target ((Get-IRFirst $services 25) -join ', ') -Computer $Burst.Events[0].Computer `
                    -EventIds 4769 -Evidence (Get-IRFirst $Burst.Events 200) `
                    -Recommendation 'Confirm the requester should enumerate service tickets. Reset/rotate the exposed service-account passwords, move them to (g)MSA where possible, and review for weak passwords. Investigate the source host for offline cracking tooling.'))
    }

    # Honeypot rule (Rule 4) - one finding per requester+IP.
    if ($honeypotHits.Count -gt 0) {
        foreach ($g in ($honeypotHits | Group-Object { "$($_.TargetUserName)|$(ConvertTo-IRIpAddress $_.IpAddress)" })) {
            $ev = @($g.Group)
            $svcs = @($ev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Service ticket requested for honeypot account' `
                        -Description ("{0} requested a Kerberos ticket for honeypot service account(s) {1} from {2}. Honeypot accounts have no legitimate use." -f $ev[0].TargetUserName, ($svcs -join ', '), (ConvertTo-IRIpAddress $ev[0].IpAddress)) `
                        -Account $ev[0].TargetUserName -SourceIp (ConvertTo-IRIpAddress $ev[0].IpAddress) -Target ($svcs -join ', ') `
                        -Computer $ev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $ev 200) `
                        -Recommendation 'Treat the requesting account and source host as compromised. Isolate and investigate immediately.'))
        }
    }

    # Split requesters by machine vs user.
    $userReq = @($roastable | Where-Object { -not $_._ReqIsMachine })
    $machineReq = @($roastable | Where-Object { $_._ReqIsMachine })

    # Volume rule evaluates ALL requesters, user AND machine. The candidate pool already contains only
    # requests for *user* service accounts (machine services were filtered out), so a machine account
    # (SYSTEM / scheduled task / PsExec -s) pulling many user service tickets with AES is a real roast
    # that would otherwise hide from the default. The weak-cipher burst stays user-only because machine
    # weak requests have their own dedicated Rule 3 (set -IncludeMachineRequesters to fold them in here).
    $volumePool = $roastable
    $weakPool = @($userReq | Where-Object { $_._Weak })
    if ($IncludeMachineRequesters) { $weakPool = @($roastable | Where-Object { $_._Weak }) }

    # Rule 2 - volume burst (any cipher).
    $volumeKeys = @{}
    foreach ($b in @(Find-IRBurst -Events $volumePool -GroupBy '_ReqKey', '_SourceIp' -DistinctProperty 'ServiceName' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        Add-KBurstFinding -Burst $b -Severity 'High' -Confidence 'Medium' -Kind 'Kerberoasting burst (many service accounts)' -WeakOnly:$false
        $volumeKeys["$($b.KeyString)|$($b.WindowStart.Ticks)"] = $true
    }

    # Rule 1 - weak-cipher burst.
    $weakBurstReqKeys = @{}
    foreach ($b in @(Find-IRBurst -Events $weakPool -GroupBy '_ReqKey', '_SourceIp' -DistinctProperty 'ServiceName' -WindowMinutes $WindowMinutes -Threshold $RC4Threshold)) {
        Add-KBurstFinding -Burst $b -Severity 'High' -Confidence 'High' -Kind 'Kerberoasting burst (weak RC4/DES tickets)' -WeakOnly:$true
        foreach ($ev in $b.Events) { $weakBurstReqKeys["$($ev._ReqKey)|$($ev._SourceIp)"] = $true }
    }

    # Single weak-cipher requests that were not part of a weak burst -> Medium (hygiene / low-volume roast).
    $singleWeak = @($weakPool | Where-Object { -not $weakBurstReqKeys.ContainsKey("$($_._ReqKey)|$($_._SourceIp)") })
    foreach ($g in ($singleWeak | Group-Object { "$($_._ReqKey)|$($_._SourceIp)" })) {
        $ev = @($g.Group)
        $svcs = @($ev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
        $enc = @($ev | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
        $adNote = ''
        if ($adAvailable) {
            $n = Get-KServiceAccountNote -ServiceName $svcs[0] -TicketWasWeak $true
            if ($n) { $adNote = " AD context: $($svcs[0]): $n." }
        }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Weak-cipher service ticket request (RC4/DES)' `
                    -Description ("{0} requested {1} RC4/DES service ticket(s) for {2} from {3}. Encryption: {4}. Low volume, but RC4 tickets are crackable offline.{5}" -f $ev[0].TargetUserName, $ev.Count, ($svcs -join ', '), $ev[0]._SourceIp, ($enc -join ', '), $adNote) `
                    -Account $ev[0].TargetUserName -SourceIp $ev[0]._SourceIp -Target ($svcs -join ', ') `
                    -Computer $ev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Verify the service account still needs RC4. Move to AES / gMSA and ensure a strong password. Confirm the request is expected from this source.'))
    }

    # Rule 3 - machine-account requester asking for RC4 user-service tickets.
    $machineWeak = @($machineReq | Where-Object { $_._Weak })
    foreach ($g in ($machineWeak | Group-Object { "$($_._ReqKey)|$($_._SourceIp)" })) {
        $ev = @($g.Group)
        $svcs = @($ev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Machine account requested RC4 user-service tickets' `
                    -Description ("Machine account {0} requested RC4/DES ticket(s) for user service account(s) {1} from {2}. Machine accounts rarely roast user services; may indicate a compromised host running tooling under SYSTEM." -f $ev[0].TargetUserName, ((Get-IRFirst $svcs 10) -join ', '), $ev[0]._SourceIp) `
                    -Account $ev[0].TargetUserName -SourceIp $ev[0]._SourceIp -Target ((Get-IRFirst $svcs 25) -join ', ') `
                    -Computer $ev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Investigate the source host for process running as SYSTEM issuing service-ticket requests (Rubeus, Invoke-Kerberoast).'))
    }

    # Rule 5 - PowerShell script block signatures.
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'KerberosRequestorSecurityToken', 'Invoke-Kerberoast', 'Get-DomainSPNTicket', 'Request-SPNTicket', 'GetUserSPNs', 'Rubeus', 'kerberoast', 'Add-Type.+IdentityModel'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Kerberoasting tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched Kerberoast signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence @($e) `
                            -Recommendation 'Identify the user and process that ran this script block. Correlate with 4769 bursts from the same host.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
