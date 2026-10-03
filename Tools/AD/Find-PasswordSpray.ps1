<#
.SYNOPSIS
    Detects Active Directory password spraying from Windows Security event logs.

.DESCRIPTION
    Password spraying (ATT&CK T1110.003) is a brute-force variant in which an attacker tries one or
    a few passwords against MANY distinct accounts, rather than many passwords against one account, so
    that no single account crosses its lockout threshold. The tell-tale signature is a burst of
    authentication FAILURES for a large number of DISTINCT target accounts originating from a single
    source in a short window, frequently followed by a single successful logon once a weak password is
    guessed.

    Log sources:
      * Security 4625 - failed logon (NTLM / local). The precise reason is in SubStatus (decoded with
        ConvertFrom-IRNtStatus); 0xc000006a (wrong password) and 0xc0000064 (no such user) are typical.
      * Security 4771 - Kerberos pre-authentication failed (logged on the DC). Status 0x18
        (KDC_ERR_PREAUTH_FAILED - bad password) is the spray signal; only 0x18 failures are counted.
      * Security 4768 - Kerberos AS-REQ. Status 0x18 failures are treated like 4771; Status 0x0
        successes feed the "spray succeeded" correlation.
      * Security 4624 - successful logon, used only to correlate a success back to a sprayed account.

    Detection logic (each rule emits its own finding):
      * RULE 1 (High/High) - classic spray: failures are grouped by source (source IP, or WorkstationName
        when the IP is local/'-'); Find-IRBurst counts DISTINCT target accounts in a sliding window
        (-WindowMinutes). >= -Threshold distinct accounts from one source is a spray. Distinct-account
        counting means a single account failing many times (brute force / lockout) is NOT flagged.
      * RULE 4 is folded into RULE 1: when a single source sprays >= -HugeThreshold distinct accounts the
        same High/High finding is raised with an escalated "large-scale spray / enumeration" title, so the
        obvious case is always reported without emitting a duplicate finding for the same window.
      * RULE 2 (Critical/High) - spray succeeded: if the SAME source has a 4624 (or 4768) SUCCESS for one
        of the sprayed accounts within -SuccessWindowMinutes of a RULE 1 burst ending, a Critical finding
        names the likely-compromised account.
      * RULE 3 (Medium/Medium) - distributed / low-and-slow: when NO single source crosses the threshold
        but, per target domain and across ALL sources, >= -Threshold distinct accounts each fail only
        once or twice within the longer -SlowWindowMinutes window (a spray spread across hosts to stay
        under per-source thresholds). Lower confidence by design.

    Required audit policy / log sources:
      * DC and member servers: Advanced Audit Policy > Logon/Logoff > Audit Logon = Success and Failure
        (4624 / 4625); Account Logon > Audit Kerberos Authentication Service = Failure (4771 / 4768).

    Known false positives:
      * A misconfigured service or application with stale credentials can fail for several accounts from
        one host; a vulnerability scanner or a shared kiosk can mimic a small spray. A single account
        failing many times is lockout / targeted brute force, not spray, and is intentionally excluded.
        The RULE 3 distributed heuristic is deliberately low confidence - confirm the sources.

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
.PARAMETER Threshold
    Distinct target accounts failing from one source within the window to raise a spray (default 10).
.PARAMETER WindowMinutes
    Sliding window length in minutes for the classic per-source spray rule (default 30).
.PARAMETER SuccessWindowMinutes
    Minutes after a spray burst within which a success for a sprayed account is treated as a likely
    compromise (default 60).
.PARAMETER SlowWindowMinutes
    Sliding window length in minutes for the distributed / low-and-slow rule (default 120).
.PARAMETER HugeThreshold
    Distinct accounts from one source that always mark an obvious large-scale spray / enumeration (default 50).
.PARAMETER ExcludeSource
    Source IPs and/or workstation names to ignore - known VPN / RADIUS / Exchange / NAT concentrators and
    auth proxies through which many users (and some failures) legitimately arrive from one apparent source.
    Matching is case-insensitive against the source IP and the workstation name.
.PARAMETER IncludeAllFailureReasons
    By default the 4625 (NTLM/interactive) path counts only spray-relevant failures - bad password
    (0xc000006a) and unknown user (0xc0000064) - so lockout, expired-password, disabled and logon-hours
    storms do not inflate the distinct-account count. Pass this switch to count every 4625 failure reason.

.EXAMPLE
    .\Find-PasswordSpray.ps1 -StartTime (Get-Date).AddDays(-3)
    Analyse the local DC Security log for the last 3 days.

.EXAMPLE
    .\Find-PasswordSpray.ps1 -Path C:\Evidence\DC01-Security.evtx -Threshold 8 -OutputPath C:\Evidence\Out -Format All
    Analyse an exported log with a lower spray threshold and write CSV/JSON/HTML reports.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4771,4768,4624} | ConvertFrom-IRWinEvent | .\Find-PasswordSpray.ps1
    Pipe pre-collected events straight into the tool.

.NOTES
    ATT&CK : T1110.003 (Brute Force: Password Spraying)
    Events : 4625, 4771, 4768 (failures), 4624 / 4768 (successes - correlation) - all Security channel
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

    [int]$Threshold = 10,
    [int]$WindowMinutes = 30,
    [int]$SuccessWindowMinutes = 60,
    [int]$SlowWindowMinutes = 120,
    [int]$HugeThreshold = 50,
    [string[]]$ExcludeSource,
    [switch]$IncludeAllFailureReasons
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
    if (-not $toolName) { $toolName = 'Find-PasswordSpray' }
    $technique = 'T1110.003'; $techniqueName = 'Brute Force: Password Spraying'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Password spraying (many accounts failing from one source)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # ---------------------------------------------------------------- Load the event sources.
    $ev4625 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4625)
    $ev4771 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4771)
    $ev4768 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
    $ev4624 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4624)
    Write-IRStatus ("Loaded {0} 4625, {1} 4771, {2} 4768, {3} 4624 event(s)" -f $ev4625.Count, $ev4771.Count, $ev4768.Count, $ev4624.Count) -Level Detail

    # ---------------------------------------------------------------- Normalise into a failure pool.
    # Local helper: compute a grouping key that is the source IP, or the workstation when the IP is local/'-'.
    function Get-SpraySourceKey {
        param([string]$Ip, [string]$Workstation)
        if ((Test-IRLocalIp $Ip) -and $Workstation -and $Workstation -ne '-') { return 'ws:' + $Workstation.ToLowerInvariant() }
        return $Ip
    }

    # Source allow-list (known gateways/concentrators) - normalised IPs and lowercased workstation tokens.
    $excludeSet = @{}
    foreach ($x in @($ExcludeSource)) { if ($x) { $excludeSet[([string]$x).Trim().ToLowerInvariant()] = $true; $excludeSet[(ConvertTo-IRIpAddress $x).ToLowerInvariant()] = $true } }
    function Test-SprayExcluded {
        param([string]$Ip, [string]$Workstation, [string]$Key)
        if ($excludeSet.Count -eq 0) { return $false }
        foreach ($v in @($Ip, $Workstation, $Key)) { if ($v -and $excludeSet.ContainsKey(([string]$v).Trim().ToLowerInvariant())) { return $true } }
        if ($Key -and ($Key -like 'ws:*') -and $excludeSet.ContainsKey($Key.Substring(3))) { return $true }
        return $false
    }
    # Spray-relevant 4625 SubStatus codes (bad password, unknown user). Others are lockout/expired/etc noise.
    $sprayFailSubStatus = @{ '0xc000006a' = $true; '0xc0000064' = $true }

    $failures = New-Object System.Collections.Generic.List[object]

    foreach ($e in $ev4625) {
        if (-not $IncludeAllFailureReasons) {
            $sub = ConvertTo-IRHexString $e.SubStatus
            $st = ConvertTo-IRHexString $e.Status
            # Keep the failure only if either Status or SubStatus is a spray-relevant reason. When both are
            # absent/zero (some logs omit SubStatus), fall back to keeping it so we do not silently drop data.
            $hasReason = ($sub -and $sub -ne '0x0' -and $sub -ne '0x') -or ($st -and $st -ne '0x0' -and $st -ne '0x')
            if ($hasReason -and -not ($sprayFailSubStatus.ContainsKey([string]$sub) -or $sprayFailSubStatus.ContainsKey([string]$st))) { continue }
        }
        $ip = ConvertTo-IRIpAddress $e.IpAddress
        $ws = [string]$e.WorkstationName
        $srcKey = Get-SpraySourceKey -Ip $ip -Workstation $ws
        if (Test-SprayExcluded -Ip $ip -Workstation $ws -Key $srcKey) { continue }
        $tu = [string]$e.TargetUserName
        $td = [string]$e.TargetDomainName
        $su = [string]$e.SubjectUserName; if (-not $su) { $su = '-' }
        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
        $e | Add-Member -NotePropertyName _SourceKey -NotePropertyValue (Get-SpraySourceKey -Ip $ip -Workstation $ws) -Force
        $e | Add-Member -NotePropertyName _SourceHost -NotePropertyValue $ws -Force
        $e | Add-Member -NotePropertyName _TargetDisplay -NotePropertyValue $tu -Force
        $e | Add-Member -NotePropertyName _TargetKey -NotePropertyValue (Get-IRAccountKey $tu $td) -Force
        $e | Add-Member -NotePropertyName _TargetDomainKey -NotePropertyValue $(if ($td) { $td.ToLowerInvariant() } else { '-' }) -Force
        $e | Add-Member -NotePropertyName _Subject -NotePropertyValue $su -Force
        $e | Add-Member -NotePropertyName _Reason -NotePropertyValue (ConvertFrom-IRNtStatus $e.SubStatus) -Force
        $failures.Add($e)
    }

    # 4771 / 4768 share Kerberos failure handling; only bad-password (Status 0x18) is the spray signal.
    $kerbFailSets = @(, $ev4771) + @(, $ev4768)
    foreach ($set in $kerbFailSets) {
        foreach ($e in @($set)) {
            $status = ConvertTo-IRHexString $e.Status
            if ($status -ne '0x18') { continue }
            $ip = ConvertTo-IRIpAddress $e.IpAddress
            $srcKey = Get-SpraySourceKey -Ip $ip -Workstation $null
            if (Test-SprayExcluded -Ip $ip -Workstation $null -Key $srcKey) { continue }
            $tu = [string]$e.TargetUserName
            $td = [string]$e.TargetDomainName
            $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
            $e | Add-Member -NotePropertyName _SourceKey -NotePropertyValue $srcKey -Force
            $e | Add-Member -NotePropertyName _SourceHost -NotePropertyValue '' -Force
            $e | Add-Member -NotePropertyName _TargetDisplay -NotePropertyValue $tu -Force
            $e | Add-Member -NotePropertyName _TargetKey -NotePropertyValue (Get-IRAccountKey $tu $td) -Force
            $e | Add-Member -NotePropertyName _TargetDomainKey -NotePropertyValue $(if ($td) { $td.ToLowerInvariant() } else { '-' }) -Force
            $e | Add-Member -NotePropertyName _Subject -NotePropertyValue '-' -Force
            $e | Add-Member -NotePropertyName _Reason -NotePropertyValue (ConvertFrom-IRKerberosStatus $e.Status) -Force
            $failures.Add($e)
        }
    }
    Write-IRStatus "$($failures.Count) authentication failure(s) after normalisation" -Level Detail

    # ---------------------------------------------------------------- Normalise the success pool (for RULE 2).
    $successes = New-Object System.Collections.Generic.List[object]
    foreach ($e in $ev4624) {
        $ip = ConvertTo-IRIpAddress $e.IpAddress
        $ws = [string]$e.WorkstationName
        $tu = [string]$e.TargetUserName
        $td = [string]$e.TargetDomainName
        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
        $e | Add-Member -NotePropertyName _SourceKey -NotePropertyValue (Get-SpraySourceKey -Ip $ip -Workstation $ws) -Force
        $e | Add-Member -NotePropertyName _TargetDisplay -NotePropertyValue $tu -Force
        $e | Add-Member -NotePropertyName _TargetKey -NotePropertyValue (Get-IRAccountKey $tu $td) -Force
        $successes.Add($e)
    }
    foreach ($e in $ev4768) {
        $status = ConvertTo-IRHexString $e.Status
        if ($status -and $status -ne '0x0' -and $status -ne '0x') { continue }   # successes only
        $ip = ConvertTo-IRIpAddress $e.IpAddress
        $tu = [string]$e.TargetUserName
        $td = [string]$e.TargetDomainName
        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue $ip -Force
        $e | Add-Member -NotePropertyName _SourceKey -NotePropertyValue (Get-SpraySourceKey -Ip $ip -Workstation $null) -Force
        $e | Add-Member -NotePropertyName _TargetDisplay -NotePropertyValue $tu -Force
        $e | Add-Member -NotePropertyName _TargetKey -NotePropertyValue (Get-IRAccountKey $tu $td) -Force
        $successes.Add($e)
    }

    # ---------------------------------------------------------------- RULE 1 (+ RULE 4 escalation) and RULE 2.
    $compromisedSeen = @{}
    $bursts = @(Find-IRBurst -Events $failures.ToArray() -GroupBy '_SourceKey' -DistinctProperty '_TargetKey' -WindowMinutes $WindowMinutes -Threshold $Threshold)
    foreach ($b in $bursts) {
        foreach ($ev in $b.Events) { $ev | Add-Member -NotePropertyName _InBurst -NotePropertyValue $true -Force }

        $distinctAccts = @($b.Events | ForEach-Object { $_._TargetDisplay } | Select-Object -Unique)
        $distinctCount = [int]$b.DistinctCount
        $srcIp = [string]$b.Events[0]._SourceIp
        $srcHost = [string]$b.Events[0]._SourceHost
        $subj = [string]$b.Events[0]._Subject; if (-not $subj) { $subj = '-' }
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $eids = @($b.Events | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)
        $reasonGroups = @($b.Events | Group-Object _Reason | Sort-Object Count -Descending)
        $domReason = 'unknown'; if ($reasonGroups.Count -gt 0) { $domReason = [string]$reasonGroups[0].Name }
        $srcLabel = $srcIp; if ($srcHost) { $srcLabel = "$srcIp ($srcHost)" }

        $title = 'Password spray (many accounts failing from one source)'
        $severity = 'High'; $confidence = 'High'
        if ($distinctCount -ge $HugeThreshold) { $title = 'Large-scale password spray / account enumeration' }

        $desc = "{0} distinct target account(s) failed authentication from {1} within {2} min (threshold {3}). Dominant failure reason: {4}. Event IDs: {5}. Sample accounts: {6}." -f `
            $distinctCount, $srcLabel, $mins, $Threshold, $domReason, ($eids -join ', '), ((Get-IRFirst $distinctAccts 15) -join ', ')
        if ($distinctCount -gt 15) { $desc += " (+$($distinctCount - 15) more)" }

        $findings.Add((New-IRFinding -Tool $toolName -Severity $severity -Confidence $confidence `
                    -Technique $technique -TechniqueName $techniqueName -Title $title `
                    -Description $desc -Account $subj -SourceIp $srcIp -SourceHost $srcHost `
                    -Target ((Get-IRFirst $distinctAccts 50) -join ', ') -Computer $b.Events[0].Computer `
                    -EventIds $eids -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Confirm whether this source should authenticate as many accounts. Triage/block the source, verify the lockout policy, and check whether any sprayed account subsequently logged on successfully (possible compromise).' `
                    -Extra @{ DistinctAccounts = $distinctCount; WindowMinutes = $mins }))

        # RULE 2 - correlate a success for a sprayed account from the same source shortly after the burst.
        $burstKey = [string]$b.Events[0]._SourceKey
        $sprayed = @{}
        foreach ($tk in @($b.DistinctValues)) { if ($tk) { $sprayed[[string]$tk] = $true } }
        $winStart = $b.WindowStart
        $winEnd = $b.WindowEnd.AddMinutes($SuccessWindowMinutes)
        foreach ($s in $successes) {
            if (($s._SourceKey -ieq $burstKey) -and $sprayed.ContainsKey([string]$s._TargetKey) -and `
                ($s.TimeCreated -ge $winStart) -and ($s.TimeCreated -le $winEnd)) {
                $ckey = "$burstKey|$($s._TargetKey)"
                if ($compromisedSeen.ContainsKey($ckey)) { continue }
                $compromisedSeen[$ckey] = $true
                $acct = [string]$s._TargetDisplay
                $lt = ConvertFrom-IRLogonType $s.LogonType
                $cdesc = "Account '{0}' logged on successfully (event {1}, logon type {2}) from {3} at {4:yyyy-MM-dd HH:mm:ss}, within {5} min of a password-spray burst from the same source. The spray likely succeeded; treat this account as compromised." -f `
                    $acct, [int]$s.EventId, $lt, $srcLabel, $s.TimeCreated, $SuccessWindowMinutes
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Password spray likely succeeded' `
                            -Description $cdesc -Account $acct -SourceIp $srcIp -SourceHost $srcHost `
                            -Target $acct -Computer $s.Computer -EventIds @([int]$s.EventId) `
                            -Evidence (Get-IRFirst (@($b.Events) + @($s)) 200) `
                            -Recommendation 'Disable or reset the named account immediately, investigate the source host, and hunt for post-authentication activity (lateral movement, data access) from this source.'))
            }
        }
    }

    # ---------------------------------------------------------------- RULE 3 - distributed / low-and-slow.
    # Failures not already explained by a per-source burst, counted by DISTINCT account across all sources.
    # We deliberately count distinct accounts (not raw failures), so a single account failing many times
    # (brute force / a stale credential) only contributes 1 and cannot trigger this rule on its own - while
    # an attacker spraying 3+ passwords per account across many hosts is still caught (the earlier design
    # dropped any account with >2 failures, letting that common cadence evade detection entirely).
    $remaining = @($failures.ToArray() | Where-Object { -not ($_.PSObject.Properties['_InBurst'] -and $_._InBurst) })
    if ($remaining.Count -gt 0) {
        $slowEvents = New-Object System.Collections.Generic.List[object]
        foreach ($x in $remaining) { $slowEvents.Add($x) }
        if ($slowEvents.Count -gt 0) {
            $slowBursts = @(Find-IRBurst -Events $slowEvents.ToArray() -GroupBy '_TargetDomainKey' -DistinctProperty '_TargetKey' -WindowMinutes $SlowWindowMinutes -Threshold $Threshold)
            foreach ($b in $slowBursts) {
                $distinctAccts = @($b.Events | ForEach-Object { $_._TargetDisplay } | Select-Object -Unique)
                $srcs = @($b.Events | ForEach-Object { $_._SourceIp } | Select-Object -Unique)
                $dom = [string]$b.Events[0]._TargetDomainKey
                $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
                $eids = @($b.Events | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)
                $desc = "{0} distinct account(s) in domain '{1}' failed authentication across {2} distinct source(s) within {3} min, with no single source crossing the per-source threshold. This matches a distributed / low-and-slow password spray spread across hosts to stay under per-source thresholds (lower confidence). Sources: {4}. Sample accounts: {5}." -f `
                    $b.DistinctCount, $dom, $srcs.Count, $mins, ((Get-IRFirst $srcs 10) -join ', '), ((Get-IRFirst $distinctAccts 15) -join ', ')
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Possible distributed / low-and-slow password spray' `
                            -Description $desc -Account '-' -SourceIp ((Get-IRFirst $srcs 5) -join ', ') `
                            -Target ((Get-IRFirst $distinctAccts 50) -join ', ') -Computer $b.Events[0].Computer `
                            -EventIds $eids -Evidence (Get-IRFirst $b.Events 200) `
                            -Recommendation 'Correlate the listed sources - a shared infrastructure or proxy may indicate one actor. Verify the accounts, review the lockout policy, and check for any subsequent success from these sources.' `
                            -Extra @{ DistinctAccounts = [int]$b.DistinctCount }))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
