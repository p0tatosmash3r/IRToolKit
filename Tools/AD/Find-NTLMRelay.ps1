<#
.SYNOPSIS
    Detects NTLM relay and credential-coercion activity from Windows Security and PowerShell event logs.

.DESCRIPTION
    An NTLM relay attack captures or coerces a victim's NTLM authentication and forwards (relays) it to a
    target service, authenticating AS the victim without ever knowing the password. The relay is driven
    from an attacker host (Impacket ntlmrelayx, Responder, Inveigh, MultiRelay) and the victim is often a
    computer account coerced via PetitPotam / PrinterBug / Coercer / SpoolSample. The high-value variant
    coerces a domain controller or server machine account and relays it to LDAP (for RBCD / DCSync rights)
    or to AD CS web enrollment (ESC8) for a certificate - a path to full domain compromise.

    The attack is largely network-level, so the clean, log-based signals on the relayed-to host (DC / server
    / CA) are:
      * RULE 1 - a COMPUTER account performing an NTLM network logon (4624/4625, LogonType 3, package NTLM).
        Machines authenticate with Kerberos to domain resources; an NTLM logon by a machine account is the
        signature of a coerced machine whose authentication was relayed. Critical when the machine is a
        domain controller (relay of a DC = domain compromise), otherwise High.
      * RULE 2 - one source authenticating via NTLM as MANY distinct accounts in a short window (a relay /
        Responder host replaying many captured identities). Burst by source.
      * RULE 3 - an NTLM credential-validation spike (4776) from one workstation for many distinct accounts
        (Responder / relay harvesting, seen on the DC). 4776 carries no source IP, only the workstation name.
      * RULE 4 - NTLMv1 network logons (LmPackageName "NTLM V1" / "LM"), a downgrade that is trivially
        relayable and crackable; High when the downgraded principal is a machine / DC account.
      * RULE 5 - relay / coercion tooling in PowerShell script blocks (4104): Inveigh, ntlmrelayx,
        Responder, PetitPotam and related coercion / relay tool names (full signature set in the RULE 5
        list in the body).

    Required audit policy / log sources:
      * Audit Logon (Success, Failure) -> 4624 / 4625 on the relayed-to hosts (DCs, servers, CA).
      * Audit Credential Validation (Success, Failure) -> 4776 on the domain controllers.
      * Optional: PowerShell Script Block Logging (4104) for RULE 5.

    Known false positives:
      * NTLM is still used legitimately: accessing a share or service by IP address (rather than name)
        forces NTLM, and some backup agents, clustering, SCCM, scanners and legacy / appliance devices use
        NTLM. Those are usually USER or specific service accounts - a COMPUTER-account NTLM logon (RULE 1) is
        the much stronger signal. A Terminal Server / Citrix / VPN / NAT egress can authenticate as many
        accounts from one source and trip RULE 2/3; add such hosts to -ExcludeSource. Treat RULE 2/3 as
        leads to corroborate, and RULE 1 (especially a DC) and RULE 5 as the high-confidence signals.
      * Some environments do have a few computer accounts that legitimately use NTLM (backup, clustering,
        appliances). Each produces one RULE 1 finding per source; tune out confirmed-benign ones with
        -ExcludeMachineAccount after verifying them. A machine authenticating from its own routable IP is
        still reported (the tool cannot know each machine's own address offline).

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
    Domain controller names / IPs. Used to recognise a relayed DC machine account (RULE 1 -> Critical) and,
    offline, to supply the DC list when the host is not domain joined.
.PARAMETER Threshold
    Distinct accounts from one source (RULE 2) or one workstation (RULE 3) within the window to raise a
    relay / harvest burst (default 5).
.PARAMETER WindowMinutes
    Sliding window length in minutes for the burst rules (default 10).
.PARAMETER ExcludeSource
    Source IPs / workstation names to ignore for the burst rules (RULE 2 farm, RULE 3 4776 spike) - known
    Terminal Server / Citrix / VPN / NAT concentrators through which many accounts legitimately
    authenticate from one apparent source. Matched against the source IP and the workstation name. This
    does NOT suppress RULE 1 (machine-account NTLM), so it can never silently hide a relayed DC.
.PARAMETER ExcludeMachineAccount
    Computer accounts whose NTLM network logon is confirmed benign (e.g. a backup / clustering / appliance
    computer account that legitimately uses NTLM) and should be suppressed from RULE 1. Matched on the bare
    machine name (with or without a trailing '$', UPN, or DOMAIN\ prefix).
.PARAMETER PrivilegedAccount
    Account names (users or machines) whose relayed NTLM logon should be escalated to Critical. An
    NTLMv1 downgrade (RULE 4) involving such an account is raised to High as well.

.EXAMPLE
    .\Find-NTLMRelay.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC02-Security.evtx -DomainController DC01,DC02
    Hunt relayed machine-account logons and NTLM harvesting across two DC logs offline.

.EXAMPLE
    .\Find-NTLMRelay.ps1 -StartTime (Get-Date).AddDays(-2) -ExcludeSource 10.0.0.50 -OutputPath C:\Evidence\Out -Format All
    Analyse the local live log for the last two days, ignoring a known Terminal Server at 10.0.0.50.

.NOTES
    ATT&CK : T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)
    Events : 4624, 4625, 4776 (Security), 4104 (PowerShell Operational)
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

    [int]$Threshold = 5,
    [int]$WindowMinutes = 10,
    [string[]]$ExcludeSource,
    [string[]]$ExcludeMachineAccount,
    [string[]]$PrivilegedAccount
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
    if (-not $toolName) { $toolName = 'Find-NTLMRelay' }
    $technique = 'T1557.001'; $techniqueName = 'NTLM Relay / SMB Relay'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $excludeSet = @{}
    foreach ($x in @($ExcludeSource)) { if ($x) { $excludeSet[([string]$x).Trim().ToLowerInvariant()] = $true; $excludeSet[(ConvertTo-IRIpAddress $x).ToLowerInvariant()] = $true } }
    # Bare-name normaliser (NAME$@REALM / DOMAIN\NAME$ -> name$) for account comparisons.
    function Get-NtlmBareName {
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@[^@]+$') { $u = $matches[1] }
        if ($u -match '\\([^\\]+)$') { $u = $matches[1] }
        return $u.Trim().ToLowerInvariant().TrimEnd('$')
    }
    $privSet = @{}
    foreach ($p in @($PrivilegedAccount)) { if ($p) { $k = Get-NtlmBareName $p; if ($k) { $privSet[$k] = $true } } }
    $excludeMachineSet = @{}
    foreach ($m in @($ExcludeMachineAccount)) { if ($m) { $k = Get-NtlmBareName $m; if ($k) { $excludeMachineSet[$k] = $true } } }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'NTLM relay / credential coercion (relayed machine accounts, NTLM harvesting, downgrade, tooling)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController -NoDiscovery:$NoADLookup
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - DC relay escalation (RULE 1 Critical) is limited.' -Level Detail }

    $ev4624 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4624)
    $ev4625 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4625)
    $ev4776 = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4776)
    Write-IRStatus ("Loaded {0} 4624, {1} 4625, {2} 4776 event(s)" -f $ev4624.Count, $ev4625.Count, $ev4776.Count) -Level Detail

    # Local helpers.
    function Test-IsNtlmLogon {
        param($Evt)
        $ap = ([string]$Evt.AuthenticationPackageName).Trim()
        $lm = ([string]$Evt.LmPackageName).Trim()
        if ($ap -match '(?i)ntlm') { return $true }
        if ($ap -match '(?i)negotiate' -and $lm -match '(?i)ntlm|^lm$') { return $true }
        return $false
    }
    function Test-IsNtlmV1 {
        param($Evt)
        $lm = ([string]$Evt.LmPackageName).Trim()
        return ($lm -match '(?i)ntlm\s*v1' -or $lm -ieq 'lm')
    }
    function Get-RelaySourceKey {
        param([string]$Ip, [string]$Workstation)
        if ((Test-IRLocalIp $Ip) -and $Workstation -and $Workstation -ne '-') { return 'ws:' + $Workstation.ToLowerInvariant() }
        return $Ip
    }

    # Normalise 4624 + 4625 network NTLM logons into one pool.
    $ntlmLogons = New-Object System.Collections.Generic.List[object]
    foreach ($e in (@($ev4624) + @($ev4625))) {
        if (([string]$e.LogonType) -ne '3') { continue }         # network logons only
        if (-not (Test-IsNtlmLogon $e)) { continue }
        $tu = [string]$e.TargetUserName
        if (-not $tu -or $tu -eq '-') { continue }
        if ($tu -match '(?i)^ANONYMOUS LOGON$') { continue }
        $ip = ConvertTo-IRIpAddress $e.IpAddress
        $ws = [string]$e.WorkstationName
        # One Add-Member call (a hashtable of note properties) instead of eight - cheaper per event.
        $e | Add-Member -Force -NotePropertyMembers @{
            _SourceIp      = $ip
            _SourceKey     = (Get-RelaySourceKey -Ip $ip -Workstation $ws)
            _SourceHost    = $ws
            _TargetKey     = (Get-IRAccountKey $tu $e.TargetDomainName)
            _TargetDisplay = $tu
            _IsMachine     = (Test-IRMachineAccount $tu)
            _IsV1          = (Test-IsNtlmV1 $e)
        }
        $ntlmLogons.Add($e)
    }
    Write-IRStatus "$($ntlmLogons.Count) NTLM network logon(s) after normalisation" -Level Detail

    # ---- RULE 1: machine-account NTLM network logon (coerced-machine relay) ----
    # Skip only true loopback self-logons (keep a missing/'-' source IP, which a coerced logon may lack),
    # and honour -ExcludeMachineAccount for confirmed-benign machine accounts. RULE 1 is deliberately NOT
    # affected by -ExcludeSource: that list tunes out multi-user gateways for the burst rules, and must not
    # silently suppress the headline DC-relay Critical.
    $machineLogons = @($ntlmLogons | Where-Object {
            $_._IsMachine -and
            -not ((Test-IRLocalIp $_._SourceIp) -and ([string]$_._SourceIp) -ne '-') -and
            -not $excludeMachineSet.ContainsKey((Get-NtlmBareName $_._TargetDisplay))
        })
    foreach ($g in ($machineLogons | Group-Object { "$($_._TargetKey)|$($_._SourceKey)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $machine = [string]$ev[0]._TargetDisplay
        $machineBare = Get-NtlmBareName $machine
        $src = [string]$ev[0]._SourceIp; $srcHost = [string]$ev[0]._SourceHost
        $srcLabel = $src; if ($srcHost) { $srcLabel = "$src ($srcHost)" }
        $isDc = Test-IRDomainController -Lookup $dcLookup -Value $machineBare
        $isPriv = $privSet.ContainsKey($machineBare)
        $sev = 'High'; $conf = 'Medium'; $note = ''
        if ($isDc) { $sev = 'Critical'; $conf = 'High'; $note = ' The machine is a DOMAIN CONTROLLER - a relayed DC authentication (e.g. PetitPotam -> LDAP/AD CS) can grant domain-wide control (RBCD, DCSync rights, or an ESC8 certificate).' }
        elseif ($isPriv) { $sev = 'Critical'; $conf = 'High'; $note = ' The machine account is on the privileged list.' }
        $pkg = [string]$ev[0].AuthenticationPackageName; $lm = [string]$ev[0].LmPackageName
        $desc = ("Computer account '{0}' performed {1} NTLM network logon(s) (package {2} / {3}) from {4}. Machine accounts authenticate to domain resources with Kerberos; an inbound NTLM logon by a computer account is characteristic of a coerced machine (PetitPotam / PrinterBug / Coercer) whose authentication was relayed.{5}" -f `
                $machine, $ev.Count, $pkg, $lm, $srcLabel, $note)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Machine account NTLM network logon (possible relayed / coerced authentication)' `
                    -Description $desc -Account $machine -SourceIp $src -SourceHost $srcHost -Target ([string]$ev[0].Computer) `
                    -Computer $ev[0].Computer -EventIds (@($ev | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)) -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Confirm whether this machine legitimately uses NTLM (rare). If not, hunt for coercion (PetitPotam/PrinterBug) and a relay host at the source, check for resulting RBCD / shadow-credential / certificate changes on this object, and enforce SMB and LDAP signing plus Extended Protection for Authentication (EPA).'))
    }

    # ---- RULE 2: one source authenticating via NTLM as many distinct accounts (relay / harvest farm) ----
    # Exclude by source IP, source key, AND workstation name (-ExcludeSource may name a multi-user host
    # whose logons carry a routable IP, so the IP-only check would miss a name-based exclusion).
    $burstPool = @($ntlmLogons | Where-Object {
            -not $excludeSet.ContainsKey([string]$_._SourceIp) -and
            -not $excludeSet.ContainsKey([string]$_._SourceKey) -and
            -not ($_._SourceHost -and $excludeSet.ContainsKey(([string]$_._SourceHost).ToLowerInvariant())) -and
            -not (Test-IRLocalIp $_._SourceIp)
        })
    foreach ($b in @(Find-IRBurst -Events $burstPool -GroupBy '_SourceKey' -DistinctProperty '_TargetKey' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        $accts = @($b.Events | ForEach-Object { $_._TargetDisplay } | Select-Object -Unique)
        $machineCount = @($b.Events | Where-Object { $_._IsMachine } | ForEach-Object { $_._TargetDisplay } | Select-Object -Unique).Count
        $src = [string]$b.Events[0]._SourceIp; $srcHost = [string]$b.Events[0]._SourceHost
        $srcLabel = $src; if ($srcHost) { $srcLabel = "$src ($srcHost)" }
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $desc = ("{0} distinct account(s) authenticated via NTLM from {1} within {2} min ({3} of them computer accounts). A single source authenticating as many identities over NTLM is consistent with an NTLM relay / Responder host replaying captured credentials. Accounts: {4}." -f `
                $b.DistinctCount, $srcLabel, $mins, $machineCount, ((Get-IRFirst $accts 15) -join ', '))
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Many accounts authenticated via NTLM from one source (possible relay / harvesting)' `
                    -Description $desc -Account '-' -SourceIp $src -SourceHost $srcHost `
                    -Target ((Get-IRFirst $accts 50) -join ', ') -Computer $b.Events[0].Computer `
                    -EventIds (@($b.Events | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)) -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Confirm whether this source is a legitimate multi-user host (Terminal Server / VPN / proxy - if so add it to -ExcludeSource). Otherwise treat it as a relay host: isolate it, and enforce SMB/LDAP signing and EPA so relayed authentication is rejected.'))
    }

    # ---- RULE 3: NTLM credential-validation spike from one workstation (4776 - Responder / relay harvesting) ----
    $valPool = New-Object System.Collections.Generic.List[object]
    foreach ($e in $ev4776) {
        $tu = [string]$e.TargetUserName
        if (-not $tu -or $tu -eq '-') { continue }
        $wsName = [string]$e.Workstation
        if (-not $wsName) { $wsName = '-' }
        if ($excludeSet.ContainsKey($wsName.ToLowerInvariant())) { continue }
        $e | Add-Member -NotePropertyName _WsKey -NotePropertyValue $wsName.ToLowerInvariant() -Force
        $e | Add-Member -NotePropertyName _TargetKey -NotePropertyValue (Get-IRAccountKey $tu $null) -Force
        $e | Add-Member -NotePropertyName _TargetDisplay -NotePropertyValue $tu -Force
        $valPool.Add($e)
    }
    foreach ($b in @(Find-IRBurst -Events $valPool.ToArray() -GroupBy '_WsKey' -DistinctProperty '_TargetKey' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        $accts = @($b.Events | ForEach-Object { $_._TargetDisplay } | Select-Object -Unique)
        $ws = [string]$b.Events[0].Workstation; if (-not $ws) { $ws = '-' }
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $desc = ("{0} distinct account(s) had NTLM credentials validated (event 4776) from workstation '{1}' within {2} min. A validation spike from one workstation is consistent with Responder / relay credential harvesting (4776 records only the workstation name, which the relay host can set). Accounts: {3}." -f `
                $b.DistinctCount, $ws, $mins, ((Get-IRFirst $accts 15) -join ', '))
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'NTLM credential-validation spike from one workstation (4776)' `
                    -Description $desc -Account '-' -SourceHost $ws `
                    -Target ((Get-IRFirst $accts 50) -join ', ') -Computer $b.Events[0].Computer `
                    -EventIds 4776 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Correlate the workstation name with a known host. If unknown or spoofed, treat as Responder / relay activity. Disable LLMNR and NBT-NS to remove the poisoning vector, and enforce SMB/LDAP signing.'))
    }

    # ---- RULE 4: NTLMv1 network logon (downgrade that is trivially relayable / crackable) ----
    $v1 = @($ntlmLogons | Where-Object { $_._IsV1 })
    foreach ($g in ($v1 | Group-Object { "$($_._TargetKey)|$($_._SourceKey)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $acct = [string]$ev[0]._TargetDisplay
        $src = [string]$ev[0]._SourceIp; $srcHost = [string]$ev[0]._SourceHost
        $srcLabel = $src; if ($srcHost) { $srcLabel = "$src ($srcHost)" }
        $sev = 'Medium'; $conf = 'Medium'
        if ($ev[0]._IsMachine -or $privSet.ContainsKey((Get-NtlmBareName $acct))) { $sev = 'High' }
        $desc = ("Account '{0}' performed {1} NTLMv1 (or LM) network logon(s) from {2} (LmPackageName '{3}'). NTLMv1 is a weak downgrade that is trivially relayable and crackable; its presence enables relay and offline recovery of the response." -f `
                $acct, $ev.Count, $srcLabel, [string]$ev[0].LmPackageName)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'NTLMv1 / LM network logon (authentication downgrade)' `
                    -Description $desc -Account $acct -SourceIp $src -SourceHost $srcHost -Computer $ev[0].Computer `
                    -EventIds (@($ev | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)) -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Identify why NTLMv1/LM is in use and remove it: set LmCompatibilityLevel to 5 (NTLMv2 only) via GPO and restrict NTLM where possible. NTLMv1 should not exist in a modern domain.'))
    }

    # ---- RULE 5: relay / coercion tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Invoke-Inveigh', 'Inveigh', 'ntlmrelayx', 'Responder', 'PetitPotam', 'PrinterBug', 'Coercer', 'MultiRelay', 'SpoolSample', 'Invoke-Petit', 'ntlmrelay', 'smbrelay', 'Get-SpoolStatus'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'NTLM relay / coercion tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched relay/coercion signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this. Correlate with NTLM logons / 4776 from the same host, and hunt for coerced machine-account authentication and resulting directory changes.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
