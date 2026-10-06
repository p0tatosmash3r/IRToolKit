<#
.SYNOPSIS
    Detects AS-REP Roasting from Windows Security and PowerShell event logs.

.DESCRIPTION
    AS-REP Roasting abuses accounts that are configured with "Do not require Kerberos
    pre-authentication" (the LDAP userAccountControl flag DONT_REQ_PREAUTH / 0x400000). For such
    an account, any unauthenticated principal can send a Kerberos AS-REQ and the KDC returns an
    AS-REP whose encrypted portion is derived from the account's password. The attacker captures
    that AS-REP and cracks the password offline. Tooling includes Rubeus (asreproast),
    PowerSploit / Empire (Invoke-ASREPRoast, Get-ASREPHash) and Impacket (GetNPUsers.py). RC4
    (etype 0x17) AS-REPs are the easiest to crack, so most tooling prefers RC4.

    Detection logic:
      * Source: Security event 4768 (Kerberos Authentication Service / AS-REQ, Success AND Failure
        auditing) on domain controllers.
      * Pre-filter: machine accounts (TargetUserName ending with '$') are ignored for the roast
        rules; IpAddress is normalised with ConvertTo-IRIpAddress; local / loopback addresses are
        excluded from burst grouping (but a single roastable host is still reported).
      * Rule 1 - no-preauth success: a 4768 with PreAuthType exactly 0 AND Status 0x0 for a
        non-machine account means the KDC issued a ticket without pre-authentication, so the
        account genuinely does not require pre-auth (roastable). RC4/DES tickets are High/High;
        AES tickets are Medium/Medium (confidence rises to High when a live AD lookup confirms
        DONT_REQ_PREAUTH on the account). When >= Threshold distinct accounts are
        roasted from one IP within WindowMinutes it is reported as a High "roast sweep".
        PreAuthType 15/16/17 (PKINIT / smart card) and PreAuthType 2 (PA-ENC-TIMESTAMP) are never
        flagged - only PreAuthType exactly 0.
      * Rule 2 - user enumeration: >= EnumThreshold distinct non-existent TargetUserNames from one
        IP within the window (Status 0x6, KDC_ERR_C_PRINCIPAL_UNKNOWN) - consistent with a GetNPUsers
        username sweep that precedes a roast (Medium/Medium).
      * Rule 3 - honeypot: any no-preauth AS-REQ (PreAuthType 0) for a -HoneypotAccount is Critical.
      * Rule 4 - optional AD context: for each flagged account (when AD is reachable and -NoADLookup
        was not supplied) the account's userAccountControl is read and, if DONT_REQ_PREAUTH is set,
        the finding is confirmed roastable and confidence is raised to High.
      * Rule 5 - PowerShell 4104 script blocks containing AS-REP roasting tooling signatures.

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service =
        Success and Failure (Failure is required for the Rule 2 enumeration signal).
      * Optional: PowerShell Script Block Logging (4104) for Rule 5.

    Known false positives:
      * A few legacy or appliance accounts are legitimately configured without pre-authentication;
        a single no-preauth success for such an account is expected and is reported at Medium (AES)
        or High (RC4) so the analyst can confirm the configuration. The burst / sweep and enumeration
        rules are the stronger signals. Smart-card (PKINIT) logons use PreAuthType 15/16/17 and are
        never flagged.

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
    Skip live Active Directory look-ups (Rule 4).
.PARAMETER Threshold
    Distinct no-preauth accounts from one IP within the window to raise the roast-sweep rule (default 3).
    A couple of legitimately pre-auth-disabled accounts authenticating through a shared egress / NAT IP
    should not look like a sweep, so the default requires at least three distinct accounts.
.PARAMETER WindowMinutes
    Sliding window length in minutes for the burst rules (default 10).
.PARAMETER EnumThreshold
    Distinct non-existent accounts (Status 0x6) from one IP within the window to raise the
    user-enumeration rule (default 10).
.PARAMETER HoneypotAccount
    Account names that must never be legitimately roasted; any no-preauth AS-REQ fires a Critical finding.

.EXAMPLE
    .\Find-ASREPRoasting.ps1 -StartTime (Get-Date).AddDays(-14)
    Analyse the local DC Security log for the last 14 days.

.EXAMPLE
    .\Find-ASREPRoasting.ps1 -Path C:\Evidence\DC01-Security.evtx -HoneypotAccount svc_decoy -OutputPath C:\Evidence\Out -Format All

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -ErrorAction Ignore | ConvertFrom-IRWinEvent | .\Find-ASREPRoasting.ps1

.NOTES
    ATT&CK : T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)
    Events : 4768 (Security), 4104 (PowerShell Operational)
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

    [int]$Threshold = 3,
    [int]$WindowMinutes = 10,
    [int]$EnumThreshold = 10,
    [string[]]$HoneypotAccount
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
    if (-not $toolName) { $toolName = 'Find-ASREPRoasting' }
    $technique = 'T1558.004'; $techniqueName = 'AS-REP Roasting'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $honeypotSet = @{}
    foreach ($h in @($HoneypotAccount)) { if ($h) { $honeypotSet[$h.ToLowerInvariant().TrimEnd('$')] = $true } }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'AS-REP Roasting (AS-REQ for accounts without Kerberos pre-authentication)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $asreq = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
    Write-IRStatus "Loaded $($asreq.Count) 4768 event(s)" -Level Detail

    $adAvailable = (-not $NoADLookup) -and (Test-IRAdAvailable)
    if ($adAvailable) { Write-IRStatus 'Active Directory reachable - flagged accounts will be checked for DONT_REQ_PREAUTH.' -Level Detail }
    $adCache = @{}

    # Decode the account's userAccountControl to confirm DONT_REQ_PREAUTH (Rule 4). Returns $null when AD is off.
    function Get-IRPreauthAdNote {
        param([string]$Account)
        if (-not $adAvailable) { return $null }
        $sam = [string]$Account
        if ($sam -match '^(.+)@') { $sam = $matches[1] }
        if ($sam -match '\\(.+)$') { $sam = $matches[1] }
        if (-not $sam) { return $null }
        $key = $sam.ToLowerInvariant()
        if (-not $adCache.ContainsKey($key)) { $adCache[$key] = Get-IRAdObject -SamAccountName $sam }
        $o = $adCache[$key]
        if (-not $o -or $null -eq $o.userAccountControl) { return $null }
        $flags = @(ConvertFrom-IRLdapUac $o.userAccountControl)
        if ($flags -contains 'DONT_REQ_PREAUTH') { return 'account is configured DONT_REQ_PREAUTH (confirmed roastable)' }
        return $null
    }

    # Bucket the 4768 set once: honeypot hits, Rule 1 no-preauth successes, Rule 2 unknown-principal failures.
    $noPreauth = New-Object System.Collections.Generic.List[object]
    $enumFail = New-Object System.Collections.Generic.List[object]
    $honeypotHits = New-Object System.Collections.Generic.List[object]
    foreach ($e in $asreq) {
        $user = [string]$e.TargetUserName
        $preAuth = ([string]$e.PreAuthType).Trim()
        $statusHex = ConvertTo-IRHexString $e.Status
        $isSuccess = ($statusHex -eq '0x0' -or $statusHex -eq '0x')
        $ip = ConvertTo-IRIpAddress $e.IpAddress

        # Rule 3 - honeypot: any no-preauth AS-REQ for a decoy account, regardless of status.
        if ($honeypotSet.Count -gt 0 -and $preAuth -eq '0') {
            $uKey = $user
            if ($uKey -match '^(.+)@') { $uKey = $matches[1] }
            if ($uKey -match '\\(.+)$') { $uKey = $matches[1] }
            $uKey = $uKey.ToLowerInvariant().TrimEnd('$')
            if ($honeypotSet.ContainsKey($uKey)) {
                $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
                $honeypotHits.Add($e)
                continue
            }
        }

        # Rule 2 feed - non-existent principal (user enumeration), failures only.
        if ($statusHex -eq '0x6') {
            $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
            $enumFail.Add($e)
            continue
        }

        # Rule 1 feed - successful AS-REQ with no pre-authentication for a real (non-machine) account.
        if ($preAuth -ne '0') { continue }               # only PreAuthType exactly 0 (not 2 / 15 / 16 / 17)
        if (-not $isSuccess) { continue }                 # a successful ticket proves pre-auth is not required
        if (Test-IRMachineAccount $user) { continue }     # machine accounts are out of scope

        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
        $e | Add-Member -NotePropertyName _Weak -NotePropertyValue (Test-IRWeakKerberosEncryption $e.TicketEncryptionType) -Force
        $e | Add-Member -NotePropertyName _InSweep -NotePropertyValue $false -Force
        $noPreauth.Add($e)
    }
    Write-IRStatus "$($noPreauth.Count) no-preauth success event(s), $($enumFail.Count) unknown-principal failure(s)" -Level Detail

    # Rule 3 - honeypot (one finding per account+IP).
    if ($honeypotHits.Count -gt 0) {
        foreach ($g in ($honeypotHits | Group-Object { "$([string]$_.TargetUserName)|$($_._SourceIp)" })) {
            $ev = @($g.Group)
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'AS-REQ for honeypot account (no pre-authentication)' `
                        -Description ("An AS-REQ with no Kerberos pre-authentication ({0}) was seen for honeypot account '{1}' from {2}. Honeypot accounts have no legitimate use; any AS-REP roast attempt against one indicates an active attacker." -f (ConvertFrom-IRPreAuthType '0'), $ev[0].TargetUserName, $ev[0]._SourceIp) `
                        -Account $ev[0].TargetUserName -SourceIp $ev[0]._SourceIp -Target $ev[0].TargetUserName `
                        -Computer $ev[0].Computer -EventIds 4768 -Evidence (Get-IRFirst $ev 200) `
                        -Recommendation 'Treat the source host as compromised. Isolate it, hunt for AS-REP cracking tooling, and reset any exposed account passwords.'))
        }
    }

    # Rule 1 - roast sweep (>= Threshold distinct accounts from one IP within the window).
    $burstPool = @($noPreauth | Where-Object { -not (Test-IRLocalIp $_._SourceIp) })
    foreach ($b in @(Find-IRBurst -Events $burstPool -GroupBy '_SourceIp' -DistinctProperty 'TargetUserName' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        foreach ($ev in $b.Events) { $ev._InSweep = $true }
        $users = @($b.DistinctValues | Where-Object { $_ })
        if (-not $users -or $users.Count -eq 0) { $users = @($b.Events | ForEach-Object { $_.TargetUserName } | Select-Object -Unique) }
        $anyWeak = [bool](@($b.Events | Where-Object { $_._Weak }).Count -gt 0)
        $encTypes = @($b.Events | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $conf = 'Medium'; if ($anyWeak) { $conf = 'High' }
        $desc = "{0} distinct account(s) received an AS-REP with no pre-authentication ({1}) from {2} within {3} min - an AS-REP roasting sweep. Encryption: {4}. Accounts: {5}." -f `
            $users.Count, (ConvertFrom-IRPreAuthType '0'), $b.Events[0]._SourceIp, $mins, ($encTypes -join ', '), ((Get-IRFirst $users 20) -join ', ')
        if ($users.Count -gt 20) { $desc += " (+$($users.Count - 20) more)" }
        if ($adAvailable) {
            $adNotes = New-Object System.Collections.Generic.List[string]
            foreach ($u in (Get-IRFirst $users 25)) { $n = Get-IRPreauthAdNote -Account $u; if ($n) { $adNotes.Add("$u`: $n") } }
            if ($adNotes.Count -gt 0) { $desc += ' AD context: ' + ((Get-IRFirst @($adNotes) 8) -join ' | ') + '.'; $conf = 'High' }
        }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'AS-REP roasting sweep (multiple accounts without pre-auth)' `
                    -Description $desc -Account ((Get-IRFirst $users 20) -join ', ') -SourceIp $b.Events[0]._SourceIp `
                    -Target ((Get-IRFirst $users 25) -join ', ') -Computer $b.Events[0].Computer `
                    -EventIds 4768 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Confirm whether these accounts should have pre-authentication disabled; clear DONT_REQ_PREAUTH where it is not required and rotate their passwords. Investigate the source host for AS-REP cracking tooling.'))
    }

    # Rule 1 - single no-preauth account(s) not part of a sweep (grouped per account + IP).
    $singles = @($noPreauth | Where-Object { -not $_._InSweep })
    foreach ($g in ($singles | Group-Object { "$($_._SourceIp)|$(([string]$_.TargetUserName).ToLowerInvariant())" })) {
        $ev = @($g.Group)
        $user = [string]$ev[0].TargetUserName
        $anyWeak = [bool](@($ev | Where-Object { $_._Weak }).Count -gt 0)
        $enc = @($ev | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
        if ($anyWeak) { $sev = 'High'; $conf = 'High'; $crack = 'The RC4/DES AS-REP is trivially crackable offline.' }
        else { $sev = 'Medium'; $conf = 'Medium'; $crack = 'The AES AS-REP is still crackable offline given a weak password.' }
        $desc = "Account '{0}' received {1} AS-REP(s) with no pre-authentication ({2}) from {3}. Encryption: {4}. A successful AS-REQ with PreAuthType 0 means the account does not require Kerberos pre-authentication and is AS-REP roastable. {5}" -f `
            $user, $ev.Count, (ConvertFrom-IRPreAuthType '0'), $ev[0]._SourceIp, ($enc -join ', '), $crack
        if ($adAvailable) { $n = Get-IRPreauthAdNote -Account $user; if ($n) { $desc += " AD context: $n."; $conf = 'High' } }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Account without Kerberos pre-authentication (AS-REP roastable)' `
                    -Description $desc -Account $user -SourceIp $ev[0]._SourceIp -Target $user `
                    -Computer $ev[0].Computer -EventIds 4768 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Verify the account legitimately needs DONT_REQ_PREAUTH; if not, clear the flag and reset the password. Ensure the account has a long, random password.'))
    }

    # Rule 2 - user enumeration burst (unknown principals, Status 0x6).
    $enumPool = @($enumFail | Where-Object { -not (Test-IRLocalIp $_._SourceIp) })
    foreach ($b in @(Find-IRBurst -Events $enumPool -GroupBy '_SourceIp' -DistinctProperty 'TargetUserName' -WindowMinutes $WindowMinutes -Threshold $EnumThreshold)) {
        $users = @($b.DistinctValues | Where-Object { $_ })
        if (-not $users -or $users.Count -eq 0) { $users = @($b.Events | ForEach-Object { $_.TargetUserName } | Select-Object -Unique) }
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $desc = "{0} distinct non-existent account name(s) were queried from {1} within {2} min ({3}) - consistent with Kerberos username enumeration (e.g. Impacket GetNPUsers) that typically precedes an AS-REP roast. Examples: {4}." -f `
            $users.Count, $b.Events[0]._SourceIp, $mins, (ConvertFrom-IRKerberosStatus '0x6'), ((Get-IRFirst $users 15) -join ', ')
        if ($users.Count -gt 15) { $desc += " (+$($users.Count - 15) more)" }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Kerberos user enumeration (unknown principals)' `
                    -Description $desc -SourceIp $b.Events[0]._SourceIp `
                    -Target ((Get-IRFirst $users 25) -join ', ') -Computer $b.Events[0].Computer `
                    -EventIds 4768 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Investigate the source host. Kerberos name enumeration from a workstation or non-admin host often precedes AS-REP roasting or password spraying.'))
    }

    # Rule 5 - PowerShell script-block signatures.
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Rubeus', 'asreproast', 'Invoke-ASREPRoast', 'Get-ASREPHash', 'GetNPUsers', 'ASREP'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'AS-REP roasting tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched AS-REP roasting signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence @($e) `
                            -Recommendation 'Identify the user and process that ran this script block and correlate with 4768 no-preauth events from the same host.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
