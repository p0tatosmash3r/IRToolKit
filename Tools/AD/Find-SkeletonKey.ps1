<#
.SYNOPSIS
    Detects AD "Skeleton Key" attacks (an in-memory LSASS patch on a domain controller that adds a master
    password for every account) from Windows Security, System and PowerShell event logs.

.DESCRIPTION
    A Skeleton Key attack patches the LSASS process on a domain controller in memory so that a single
    attacker-chosen "master" password authenticates as ANY domain account, alongside each account's real
    password. Because the injected key is an RC4/NTLM key, any logon that uses the master password must
    negotiate RC4 - so on a DC that otherwise issues AES Kerberos tickets, the attack leaks as a sudden
    RC4 encryption downgrade. The patch lives only in RAM: a DC reboot clears it, so operators re-run it
    (and must run it on EVERY DC), producing repeated LSASS access and repeated RC4 bursts over time.
    The attack changes nothing in the directory, so it cannot be found by object diffing - this tool looks
    for the behavioural and host artefacts instead. It reads logs only; it never modifies anything.

    No single artefact is conclusive (RC4 is common; sensitive-privilege use and service installs have
    benign causes), so the rules are deliberately conservative on their own and the tool escalates when
    several independent signals land on the SAME domain controller within a window (the CORRELATION stage).

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 - Kerberos RC4 encryption downgrade (Security 4768 AS-REQ). A burst of tickets issued with
        RC4 (TicketEncryptionType 0x17/0x18) to many DISTINCT user accounts on one DC within the window.
        On 2025+ event builds the AccountAvailableKeys / AccountSupportedEncryptionTypes fields let the tool
        confirm the account COULD have used AES but got RC4 (a real downgrade). Severity is High only when
        the burst carries such confirmed downgrades; otherwise Medium (broad RC4 is often legacy), with
        correlation able to raise it. A single confirmed AES-capable downgrade outside a burst is Medium.
      * RULE 2 - sensitive-privilege use consistent with an LSASS patch (Security 4673): SeDebug/SeTcb.
        This is primarily a CORRELATION FEEDER. Standalone severity is High only when the calling image
        path is anomalous (temp / user profile / admin share / script host), Medium when a SYSTEM/machine
        principal wields SeDebugPrivilege (which it has no routine need for - the operator-as-SYSTEM case),
        and Low otherwise (named debuggers / EDR / backup are the benign baseline). The benign boot-time
        pattern (SYSTEM/lsass.exe + SeTcb only) is excluded by default; -IncludeSystem surfaces it.
      * RULE 3 - suspicious service/driver install (System 7045 or Security 4697; different field names per
        event are handled). High for a known-bad credential-tool driver, a driver with an anomalous image
        path, or an anomalous-path service on a DC; otherwise Medium (service/driver installs are routine).
      * RULE 4 - credential-theft tooling in a PowerShell script block (4104) or process command line (4688),
        matched against signatures loaded from the sidecar data file Find-SkeletonKey.signatures.json. The
        skeleton-key-specific signatures are Critical, generic Mimikatz tooling is High. Matching is
        INVOCATION-anchored - merely naming a tool (a comment, a hunt query, a filename, opening its output)
        does not fire, and a module::command token only fires when the block also shows a real invocation.
      * CORRELATION - a DC showing two or more of {RC4 downgrade, notable LSASS privilege use, tooling}
        within -CorrelationWindowMinutes has every finding on it escalated to Critical with a note. A lone
        service/driver install does not by itself make a DC "hot".

    The tooling signatures are deliberately kept OUT of this script and in the sidecar data file, because a
    detector that embeds verbatim Mimikatz command strings is quarantined by AMSI / EDR on load. If the
    sidecar file is absent the tool still runs RULES 1-3 and simply skips RULE 4. The signatures live in
    Common\Signatures\ (resolved beside the tool first, for standalone/local drop-ins); Build-Standalone
    copies the sidecar beside each single-file build so RULE 4 keeps working there.

    Required audit policy / log sources (domain controllers):
      * Account Logon > Audit Kerberos Authentication Service = Success -> 4768 (RULE 1).
      * Privilege Use > Audit Sensitive Privilege Use = Success -> 4673 (RULE 2; off by default and noisy).
      * System log, provider Service Control Manager -> 7045 (RULE 3; always written). Security 4697 needs
        Audit Security System Extension = Success.
      * Audit Process Creation (+ command line) -> 4688; PowerShell Script Block Logging -> 4104 (RULE 4).

    Known false positives:
      * RC4 is legitimately used by legacy/non-Windows clients, trusts, and RC4-only service accounts, and
        by accounts with no AES keys yet. RULE 1 alerts on a BURST across many distinct accounts, is Medium
        without confirmed AES downgrades, and excludes machine/trust/krbtgt; add legacy accounts to
        -ExcludeAccount. Kerberoasting also produces RC4 (in 4769) - this tool keys RULE 1 on 4768 instead.
      * SeDebugPrivilege is used by debuggers, EDR/AV and backup agents (Low, correlation feeder only); the
        boot-time SYSTEM/lsass SeTcb case is excluded by default. Service/driver installs are routine.

.PARAMETER ComputerName
    Remote computer to read the live logs from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders) to analyse offline (include the System log for RULE 3).
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
    Domain controller names / IPs. Used to recognise DCs for RULE 3 scoping (offline supplies the list).
.PARAMETER DowngradeThreshold
    Distinct user accounts issued RC4 (4768) on one DC within the window to raise the RULE 1 burst (default 8).
.PARAMETER WindowMinutes
    Sliding window length in minutes for the RULE 1 burst (default 10).
.PARAMETER CorrelationWindowMinutes
    Max span between different signal classes on one DC for the correlation escalation (default 180).
.PARAMETER ExcludeAccount
    Known-good accounts to suppress: legacy RC4 accounts (RULE 1), known SeDebug/SeTcb tools (RULE 2), and
    service-installing admins (RULE 3). Matched on the bare name (UPN / DOMAIN\ / trailing-$ aware).
.PARAMETER IncludeSystem
    Also surface the benign boot-time SYSTEM/lsass SeTcb 4673 that RULE 2 excludes by default.
.PARAMETER SignatureFile
    Path to the RULE 4 signature data file. Default: Find-SkeletonKey.signatures.json beside the tool (a
    standalone build / local drop-in), otherwise Common\Signatures\Find-SkeletonKey.signatures.json.

.EXAMPLE
    .\Find-SkeletonKey.ps1 -Path C:\Evidence\DC01-Security.evtx, C:\Evidence\DC01-System.evtx -DomainController DC01,DC02
    Hunt Skeleton Key artefacts across an exported DC Security + System log offline.

.EXAMPLE
    .\Find-SkeletonKey.ps1 -StartTime (Get-Date).AddDays(-14) -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1556.001 (Modify Authentication Process: Domain Controller Authentication)
    Events : 4768, 4673, 4697 (Security); 7045 (System); 4104, 4688 (PowerShell / process)
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

    [int]$DowngradeThreshold = 8,
    [int]$WindowMinutes = 10,
    [int]$CorrelationWindowMinutes = 180,
    [string[]]$ExcludeAccount,
    [switch]$IncludeSystem,
    [string]$SignatureFile
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
    if (-not $toolName) { $toolName = 'Find-SkeletonKey' }
    $technique = 'T1556.001'; $techniqueName = 'Skeleton Key (Modify Authentication Process)'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $excludeSet = @{}
    foreach ($x in @($ExcludeAccount)) {
        if ($x) {
            $xb = [string]$x
            if ($xb -match '^(.+)@[^@]+$') { $xb = $matches[1] }
            if ($xb -match '\\([^\\]+)$') { $xb = $matches[1] }
            $excludeSet[$xb.Trim().ToLowerInvariant().TrimEnd('$')] = $true
        }
    }
    $scriptDir = $PSScriptRoot
    # Central signature directory (Common\Signatures). $irModule is undefined in a Build-Standalone copy
    # (the module-locate block is replaced by the inlined module), so guard it - standalones resolve the
    # sidecar beside the script instead (Build-Standalone copies it there).
    $sigDir = $null
    if ($irModule) { $sigDir = Join-Path (Split-Path $irModule -Parent) 'Signatures' }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Skeleton Key (in-memory DC LSASS patch / master password)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController

    function Test-SKExcluded {
        param([string]$Actor)
        if ($excludeSet.Count -eq 0) { return $false }
        $a = ([string]$Actor).Trim().ToLowerInvariant()
        if (-not $a) { return $false }
        if ($excludeSet.ContainsKey($a.TrimEnd('$'))) { return $true }
        if ($a -match '\\([^\\]+)$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        if ($a -match '^(.+)@[^@]+$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        return $false
    }
    function Test-SKSystemPrincipal {
        param([string]$Name, [string]$Sid)
        $n = ([string]$Name).Trim()
        $s = ([string]$Sid).Trim()
        if ($s -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') { return $true }
        if ($n -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|LOCALSYSTEM)$') { return $true }
        if ($n -match '(?i)\$$') { return $true }   # machine account
        return $false
    }
    function Test-SKRc4 {
        param($Value)
        $k = ConvertTo-IRHexString $Value
        return ($k -in '0x17', '0x18')
    }
    function Test-SKAesAvailable {
        # True when the 2025+ fields show the account had an AES key available (so RC4 was a real downgrade).
        param($Evt)
        foreach ($p in 'AccountAvailableKeys', 'AccountSupportedEncryptionTypes', 'AvailableKeys') {
            if ($Evt.PSObject.Properties[$p]) {
                $v = [string]$Evt.$p
                if ($v -match '(?i)AES') { return $true }
                $n = ConvertTo-IRInt $v
                if ($null -ne $n -and ($n -band 0x18) -ne 0) { return $true }   # AES128/256 bits
            }
        }
        return $false
    }
    function Get-SKBareName {
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@[^@]+$') { $u = $matches[1] }
        if ($u -match '\\([^\\]+)$') { $u = $matches[1] }
        return $u.Trim()
    }
    function Get-SKDcKey {
        # Canonical DC identity for correlation: short host name, lower-case, no trailing '$'.
        # Folds DC01 / DC01.corp.local / DC01$ to the same bucket so signals from different providers tie.
        param($Computer)
        $c = ([string]$Computer).Trim()
        if (-not $c) { return '' }
        if ($c -match '\\([^\\]+)$') { $c = $matches[1] }
        $c = ($c -split '[.]')[0]
        return $c.TrimEnd('$').ToLowerInvariant()
    }
    function Test-SKSuspiciousImage {
        param([string]$ImagePath)
        $p = ([string]$ImagePath).ToLowerInvariant()
        if (-not $p) { return $false }
        # Microsoft Defender legitimately runs its platform binaries from a versioned folder under
        # ProgramData. Anchor the exception TIGHTLY - drive-rooted, the exact Defender path, a version
        # directory, and one of the KNOWN Defender binaries, with no '..' traversal - so a malicious
        # service cannot evade this rule by embedding the Defender path as a substring of its image or
        # dropping a non-Defender binary into that folder.
        $pp = $p.Trim().Trim('"')
        if ($pp -notmatch '\\\.\.\\' -and $pp -match '^(?:\\\\\?\\)?[a-z]:\\programdata\\microsoft\\windows defender\\platform\\[0-9.\-]+\\(msmpeng|nissrv|mpdefendercoreservice|mpcmdrun)\.exe\b') { return $false }
        if ($p -match '\\(temp|tmp)\\|\\windows\\temp\\|\\users\\|\\appdata\\|\\programdata\\|\\\$recycle|\\perflogs\\') { return $true }
        if ($p -match '\\admin\$|\\ipc\$|\\[a-z]\$\\|^\\\\') { return $true }                 # admin/IPC share or UNC
        # a script-host / LOLBin as the service IMAGE (anchored to the interpreter .exe, not any path text)
        if ($p -match '(?i)(?:^|\\)(rundll32|regsvr32|cmd|powershell|pwsh|mshta|wscript|cscript)\.exe\b') { return $true }
        return $false
    }
    function Test-SKIsDriver {
        param($ServiceType)
        $s = ([string]$ServiceType)
        if ($s -match '(?i)kernel|file system|driver') { return $true }            # 7045 string form
        if ((ConvertTo-IRHexString $s) -in '0x1', '0x2') { return $true }           # 4697 hex form (kernel / FS driver)
        return $false
    }
    function ConvertFrom-SKJsonSafe {
        # Parse untrusted JSON WITHOUT letting any terminating error reach this runspace: a caught throw
        # here would still be recorded to the caller's -ErrorVariable (PS 5.1), so the parse runs in an
        # isolated runspace that catches the error internally and returns $null on failure.
        param([string]$Text)
        if (-not $Text) { return $null }
        $t = $Text.TrimStart()
        if (-not ($t.StartsWith('{') -or $t.StartsWith('['))) { return $null }
        $ps = [powershell]::Create()
        try {
            $null = $ps.AddScript('param($t) $ErrorActionPreference = ''Stop''; try { ,($t | ConvertFrom-Json) } catch { ,$null }').AddArgument($Text)
            $res = $ps.Invoke()
            if ($ps.HadErrors) { return $null }
            if ($res -and $res.Count -gt 0) { return $res[0] }
            return $null
        }
        catch { return $null }
        finally { $ps.Dispose() }
    }

    # Correlation bookkeeping: per canonical DC, the signal classes seen and their times.
    $signalByDc = @{}
    function Add-SKSignal {
        param([string]$Computer, [string]$Class, $Time)
        $k = Get-SKDcKey $Computer
        if (-not $k) { return }
        if (-not $signalByDc.ContainsKey($k)) { $signalByDc[$k] = New-Object System.Collections.Generic.List[object] }
        $ticks = $null
        if ($Time -is [datetime]) { $ticks = $Time.Ticks }
        $signalByDc[$k].Add([pscustomobject]@{ Class = $Class; Ticks = $ticks })
    }

    # ---- RULE 4 signature set (loaded from the sidecar data file; never embedded in this script) ----
    if (-not $SignatureFile) {
        # Resolve the sidecar: beside the script first (a standalone build / local drop-in), then the
        # central Common\Signatures directory (normal repo layout).
        $SignatureFile = Join-Path $scriptDir ($toolName + '.signatures.json')
        if (-not (Test-Path -LiteralPath $SignatureFile) -and $sigDir) {
            $central = Join-Path $sigDir ($toolName + '.signatures.json')
            if (Test-Path -LiteralPath $central) { $SignatureFile = $central }
        }
    }
    $critCmdlet = New-Object System.Collections.Generic.List[string]   # crit, cmdlet/wrapper form (no '::')
    $critModule = New-Object System.Collections.Generic.List[string]   # crit, module::command form
    $highSigs = New-Object System.Collections.Generic.List[string]
    $binSigs = New-Object System.Collections.Generic.List[string]
    $modSigs = New-Object System.Collections.Generic.List[string]
    $driverSigs = New-Object System.Collections.Generic.List[string]
    $sigLabels = @{}
    $toolingEnabled = $false
    if (Test-Path -LiteralPath $SignatureFile) {
        $raw = $null
        try { $raw = Get-Content -LiteralPath $SignatureFile -Raw -Encoding UTF8 } catch { $raw = $null }
        $sig = ConvertFrom-SKJsonSafe $raw
        if ($null -eq $sig) {
            Write-IRStatus "Signature file '$SignatureFile' is missing or not valid JSON - RULE 4 (tooling) disabled; behavioural rules still run." -Level Warning
        }
        else {
            foreach ($t in @($sig.tooling)) {
                $v = [string]$t.value; if (-not $v) { continue }
                switch ([string]$t.category) {
                    'crit' { if ($v -match '::') { $critModule.Add($v) } else { $critCmdlet.Add($v) } }
                    'high' { $highSigs.Add($v) }
                    'bin' { $binSigs.Add($v) }
                    'mod' { $modSigs.Add($v) }
                }
                if ($t.label) { $sigLabels[$v] = [string]$t.label }
            }
            foreach ($d in @($sig.drivers)) { if ($d) { $driverSigs.Add([string]$d) } }
            $toolingEnabled = (($critCmdlet.Count + $critModule.Count + $highSigs.Count + $binSigs.Count + $modSigs.Count) -gt 0)
        }
    }
    else {
        Write-IRStatus "Signature file not found (looked beside the tool and in Common\Signatures) - RULE 4 (tooling) disabled; behavioural rules still run. Expected: $SignatureFile" -Level Detail
    }
    $modRe = $null
    if ($modSigs.Count -gt 0) {
        $cc = ':' + ':'
        $modRe = '(?i)((?:' + (($modSigs | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')' + $cc + '[a-z0-9_]+)'
    }
    # A command / pipeline position. Quote characters are deliberately NOT included: a tool name inside a
    # quoted string literal (a hunt query like @('Invoke-SkeletonKey'), a -like pattern) is NAMING, not
    # invoking, and must not match. Chained invocations after ; | & { ( = and line starts still match.
    $cmdPosRe = '(?im)(?:^|[\n;&{(=|])\s*(?:\$\w+\s*=\s*)?'
    function Test-SKInvoked {
        # Is there a genuine tool INVOCATION in the text (a wrapper cmdlet at a command position, or the
        # tool binary invoked as a program)? Used to gate the module-token signatures, which otherwise
        # match a tool merely NAMED in a comment / hunt query / string.
        param([string]$Text)
        foreach ($h in ($critCmdlet + $highSigs)) {
            if ($Text -match ($cmdPosRe + [regex]::Escape($h) + '\b')) { return $true }
        }
        foreach ($b in $binSigs) {
            if ($Text -match ($cmdPosRe + [regex]::Escape($b) + '(\.exe|\.dll)?\b')) { return $true }
        }
        return $false
    }
    function Get-SKToolHit {
        param([string]$Text)
        if (-not $Text) { return $null }
        $invoked = Test-SKInvoked $Text
        foreach ($c in $critCmdlet) {
            if ($Text -match ($cmdPosRe + [regex]::Escape($c) + '\b')) { return @{ Hit = $c; Severity = 'Critical' } }
        }
        foreach ($c in $critModule) {
            if ($invoked -and $Text -match ('(?i)(?<![\w:])' + [regex]::Escape($c) + '(?![\w])')) { return @{ Hit = $c; Severity = 'Critical' } }
        }
        foreach ($h in $highSigs) {
            if ($Text -match ($cmdPosRe + [regex]::Escape($h) + '\b')) { return @{ Hit = $h; Severity = 'High' } }
        }
        if ($invoked -and $modRe -and $Text -match $modRe) { return @{ Hit = $matches[1]; Severity = 'High' } }
        foreach ($b in $binSigs) {
            if ($Text -match ($cmdPosRe + [regex]::Escape($b) + '(\.exe|\.dll)?\b')) { return @{ Hit = $b; Severity = 'High' } }
        }
        return $null
    }

    # ---- RULE 1: Kerberos RC4 encryption downgrade (Security 4768) ----
    $asreq = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
    Write-IRStatus "Loaded $($asreq.Count) 4768 event(s)" -Level Detail
    $rc4 = New-Object System.Collections.Generic.List[object]
    foreach ($e in $asreq) {
        $user = [string]$e.TargetUserName
        if (-not $user) { continue }
        if (Test-IRMachineAccount $user) { continue }                 # machine/trust RC4 is common - exclude
        if ($user -match '(?i)^krbtgt') { continue }
        if ($user -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$') { continue }   # realm/FQDN target (cross-realm artefact), not a user logon
        $status = ConvertTo-IRHexString $e.Status
        if ($status -and $status -ne '0x0' -and $status -ne '0x') { continue }   # issued tickets only
        if (-not (Test-SKRc4 $e.TicketEncryptionType)) { continue }
        $bare = (Get-SKBareName $user)
        if (Test-SKExcluded $bare) { continue }
        $e | Add-Member -NotePropertyName _User -NotePropertyValue $user -Force
        $e | Add-Member -NotePropertyName _UserKey -NotePropertyValue ($bare.ToLowerInvariant()) -Force
        $e | Add-Member -NotePropertyName _AesAvail -NotePropertyValue (Test-SKAesAvailable $e) -Force
        $e | Add-Member -NotePropertyName _SourceIp -NotePropertyValue (ConvertTo-IRIpAddress $e.IpAddress) -Force
        $rc4.Add($e)
    }
    Write-IRStatus "$($rc4.Count) RC4 AS-REQ ticket(s) after filtering" -Level Detail

    # RULE 1 burst: many distinct user accounts issued RC4 on one DC within the window.
    $burstUserKeys = @{}
    foreach ($b in @(Find-IRBurst -Events $rc4.ToArray() -GroupBy 'Computer' -DistinctProperty '_UserKey' -WindowMinutes $WindowMinutes -Threshold $DowngradeThreshold)) {
        $dc = [string]$b.Events[0].Computer
        $users = @($b.Events | ForEach-Object { $_._User } | Select-Object -Unique)
        $aesCount = @($b.Events | Where-Object { $_._AesAvail } | ForEach-Object { $_._UserKey } | Select-Object -Unique).Count
        $mins = [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)
        $sev = 'Medium'; $conf = 'Low'; $aesNote = ' No per-event AES-key evidence is present, so this may be legacy RC4 - treat as a lead and corroborate.'
        if ($aesCount -gt 0) {
            $sev = 'High'; $conf = 'High'
            $aesNote = " $aesCount of these are AES-capable accounts that were nonetheless issued RC4 (a confirmed downgrade), which is the behavioural signature of a Skeleton Key master-password implant on a DC that otherwise issues AES."
        }
        foreach ($k in $users) { $burstUserKeys[("$($dc.ToLowerInvariant())|$($k.ToLowerInvariant())")] = $true }
        Add-SKSignal -Computer $dc -Class 'rc4' -Time $b.Events[0].TimeCreated
        $desc = ("{0} distinct user account(s) were issued RC4 Kerberos tickets (event 4768, TicketEncryptionType 0x17/0x18) on DC {1} within {2} min.{3} Accounts: {4}." -f `
                $users.Count, $dc, $mins, $aesNote, ((Get-IRFirst $users 12) -join ', '))
        if ($users.Count -gt 12) { $desc += " (+$($users.Count - 12) more)" }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Kerberos RC4 encryption downgrade across many accounts (possible Skeleton Key)' `
                    -Description $desc -Account '(multiple)' -Target $dc -Computer $dc `
                    -EventIds 4768 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Correlate with LSASS sensitive-privilege use (4673) and credential-tooling (4104/4688) on this DC, and check whether the same RC4 onset appears on other DCs or recurs after reboots. If confirmed, reboot the DC to clear the in-memory patch, rotate krbtgt twice, enforce AES-only Kerberos, enable LSA Protection (RunAsPPL), and treat the DC as compromised.'))
    }

    # RULE 1 single: a confirmed AES-capable account issued RC4 outside any burst -> Medium (needs the 2025+ fields).
    foreach ($g in ($rc4 | Where-Object { $_._AesAvail } | Group-Object { "$((Get-SKDcKey $_.Computer))|$($_._UserKey)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $dc = [string]$ev[0].Computer
        if ($burstUserKeys.ContainsKey("$($dc.ToLowerInvariant())|$($ev[0]._UserKey)")) { continue }
        Add-SKSignal -Computer $dc -Class 'rc4' -Time $ev[0].TimeCreated
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'AES-capable account issued an RC4 Kerberos ticket (encryption downgrade)' `
                    -Description ("Account {0} is AES-capable (the event lists an AES key) but was issued an RC4 ticket (event 4768) on DC {1}. A single downgrade can be benign (an RC4-pinned client) but is also the per-logon tell of a Skeleton Key master-password authentication - watch for more across accounts." -f $ev[0]._User, $dc) `
                    -Account $ev[0]._User -SourceIp $ev[0]._SourceIp -Target $ev[0]._User -Computer $dc `
                    -EventIds 4768 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Confirm whether this account/client legitimately uses RC4. If not, correlate with LSASS access and tooling on the issuing DC.'))
    }

    # ---- RULE 2: sensitive-privilege use consistent with an LSASS patch (Security 4673) ----
    # Primarily a correlation feeder. Standalone High only for an anomalous image path; Medium for a
    # SYSTEM/machine principal wielding SeDebug; Low otherwise (benign debuggers / EDR / backup baseline).
    $priv = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4673)
    Write-IRStatus "Loaded $($priv.Count) 4673 event(s)" -Level Detail
    $privNorm = New-Object System.Collections.Generic.List[object]
    foreach ($e in $priv) {
        $privs = [string]$e.PrivilegeList
        if ($privs -notmatch '(?i)SeTcbPrivilege|SeDebugPrivilege') { continue }
        $subj = [string]$e.SubjectUserName
        $hasSeDebug = ($privs -match '(?i)SeDebugPrivilege')
        $hasSeTcb = ($privs -match '(?i)SeTcbPrivilege')
        $procLeaf = ((([string]$e.ProcessName) -split '[\\/]')[-1]).ToLowerInvariant()
        $isLsass = ($procLeaf -eq 'lsass.exe')
        $anom = Test-SKSuspiciousImage ([string]$e.ProcessName)
        $isSys = Test-SKSystemPrincipal $subj $e.SubjectUserSid
        # Benign boot-time pattern: SYSTEM/machine, SeTcb only (no SeDebug), lsass.exe, normal path.
        if (-not $IncludeSystem -and $isSys -and $hasSeTcb -and -not $hasSeDebug -and $isLsass -and -not $anom) { continue }
        if (Test-SKExcluded (Get-SKBareName $subj)) { continue }
        $e | Add-Member -NotePropertyName _Which -NotePropertyValue (($privs | Select-String -Pattern 'Se(Tcb|Debug)Privilege' -AllMatches).Matches.Value -join ', ') -Force
        $e | Add-Member -NotePropertyName _Anom -NotePropertyValue $anom -Force
        $e | Add-Member -NotePropertyName _SysSeDebug -NotePropertyValue ($isSys -and $hasSeDebug) -Force
        $privNorm.Add($e)
    }
    foreach ($g in ($privNorm | Group-Object { "$(([string]$_.SubjectUserName).ToLowerInvariant())|$(([string]$_.ProcessName).ToLowerInvariant())|$(Get-SKDcKey $_.Computer)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $e0 = $ev[0]
        $subj = [string]$e0.SubjectUserName
        $proc = [string]$e0.ProcessName
        $sev = 'Low'; $notable = $false
        if ($e0._Anom) { $sev = 'High'; $notable = $true }
        elseif ($e0._SysSeDebug) { $sev = 'Medium'; $notable = $true }
        $which = [string]$e0._Which; if (-not $which) { $which = 'SeTcbPrivilege/SeDebugPrivilege' }
        $why = if ($e0._Anom) { 'the calling image sits in a temp / user / share / script-host path' } elseif ($e0._SysSeDebug) { 'a SYSTEM/machine principal is wielding SeDebugPrivilege, which it has no routine need for (the operator-as-SYSTEM case)' } else { 'standalone this is usually a benign debugger / EDR / backup agent, surfaced here as a correlation lead' }
        if ($notable) { Add-SKSignal -Computer $e0.Computer -Class 'priv' -Time $e0.TimeCreated }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Sensitive privilege use consistent with an LSASS patch (SeDebug/SeTcb)' `
                    -Description ("{0} invoked {1} via process {2} on {3} ({4} event(s), event 4673); {5}. SeDebug/SeTcb is how credential tools open and patch LSASS - the step a Skeleton Key implant performs." -f $subj, $which, $proc, $e0.Computer, $ev.Count, $why) `
                    -Account $subj -Target $proc -Computer $e0.Computer `
                    -EventIds 4673 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Confirm whether this account/process legitimately debugs or acts as part of the OS (debuggers, EDR, backup). If not, correlate with an RC4 downgrade and credential tooling on the same DC and treat as LSASS tampering.'))
    }

    # ---- RULE 3: suspicious service / driver install (System 7045 or Security 4697) ----
    function Add-SKServiceFinding {
        param([string]$ServiceName, [string]$ImagePath, [bool]$IsDriver, [bool]$Suspicious, [string]$Actor, $Evt, [int]$EventId, [bool]$KnownBad)
        if ($Actor -and (Test-SKExcluded (Get-SKBareName $Actor))) { return }
        $onDc = $false
        if ($dcLookup.Count -gt 0) { $onDc = (Test-IRDomainController -Lookup $dcLookup -Value (Get-SKBareName $Evt.Computer)) }
        $sev = 'Medium'
        if ($KnownBad) { $sev = 'High' }
        elseif ($IsDriver -and $Suspicious) { $sev = 'High' }
        elseif ($Suspicious -and $onDc) { $sev = 'High' }
        $kind = if ($IsDriver) { 'driver' } else { 'service' }
        Add-SKSignal -Computer $Evt.Computer -Class 'service' -Time $Evt.TimeCreated
        $actorNote = if ($Actor) { " by $Actor" } else { '' }
        $badNote = if ($KnownBad) { ' The image name matches a known credential-tool driver.' } elseif ($IsDriver -and $Suspicious) { ' It installs a kernel/file-system driver from an anomalous path.' } elseif ($IsDriver) { ' It installs a kernel/file-system driver.' } elseif ($Suspicious) { ' Its image path is anomalous (temp / user profile / admin share / script host).' } else { '' }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Low' `
                    -Technique $technique -TechniqueName $techniqueName -Title ("Suspicious {0} installed (possible credential-tool deployment)" -f $kind) `
                    -Description ("A {0} '{1}' was installed{2} on {3} (event {4}), image: {5}.{6} Skeleton Key is sometimes deployed as a driver or pushed as a service; most service installs are routine, so confirm this one." -f $kind, $ServiceName, $actorNote, $Evt.Computer, $EventId, $ImagePath, $badNote) `
                    -Account $Actor -Target $ServiceName -Computer $Evt.Computer `
                    -EventIds $EventId -Evidence (Get-IRFirst @($Evt) 200) `
                    -Recommendation 'Verify the service/driver against change control and software deployments. If unexpected (especially a driver or a temp/share image path on a DC), acquire the binary, and correlate with RC4 downgrade / LSASS access on the host.'))
    }
    function Test-SKKnownBadDriver {
        param([string]$Text)
        $t = ([string]$Text).ToLowerInvariant()
        foreach ($d in $driverSigs) { if ($d -and $t -match ('(?i)(?<![\w.-])' + [regex]::Escape($d) + '(\.sys|\.dll|\.exe)?(?![\w])')) { return $true } }
        return $false
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'System' -EventId 7045 -NoLogNameFilter)) {
        $svc = [string]$e.ServiceName
        $img = [string]$e.ImagePath
        $isDriver = (Test-SKIsDriver $e.ServiceType)
        $susp = (Test-SKSuspiciousImage $img)
        $bad = ((Test-SKKnownBadDriver $img) -or (Test-SKKnownBadDriver $svc))
        if (-not ($isDriver -or $susp -or $bad)) { continue }
        Add-SKServiceFinding -ServiceName $svc -ImagePath $img -IsDriver $isDriver -Suspicious $susp -Actor '' -Evt $e -EventId 7045 -KnownBad $bad
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4697)) {
        $svc = [string]$e.ServiceName
        $img = [string]$e.ServiceFileName
        $isDriver = (Test-SKIsDriver $e.ServiceType)
        $susp = (Test-SKSuspiciousImage $img)
        $bad = ((Test-SKKnownBadDriver $img) -or (Test-SKKnownBadDriver $svc))
        if (-not ($isDriver -or $susp -or $bad)) { continue }
        $actor = [string]$e.SubjectUserName
        Add-SKServiceFinding -ServiceName $svc -ImagePath $img -IsDriver $isDriver -Suspicious $susp -Actor $actor -Evt $e -EventId 4697 -KnownBad $bad
    }

    # ---- RULE 4: credential-theft tooling in PowerShell (4104) and processes (4688) ----
    if ($toolingEnabled) {
        foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $text = $text -replace '(?is)^\s*Creating Scriptblock text \(\d+ of \d+\):\s*', ''   # strip PS logging preamble
            $hit = Get-SKToolHit $text
            if (-not $hit) { continue }
            $label = $sigLabels[$hit.Hit]; if (-not $label) { $label = 'credential-theft tooling' }
            $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
            Add-SKSignal -Computer $e.Computer -Class 'tool' -Time $e.TimeCreated
            $findings.Add((New-IRFinding -Tool $toolName -Severity $hit.Severity -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Credential-theft / Skeleton Key tooling in PowerShell script block' `
                        -Description ("PowerShell script block on {0} matched {1} signature. Excerpt: {2}" -f $e.Computer, $label, $excerpt) `
                        -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Identify the user and process. Correlate with an RC4 downgrade (4768) and LSASS sensitive-privilege use (4673) on the DCs in the same window.'))
        }
        foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4688)) {
            $img = [string]$e.NewProcessName
            $cmd = [string]$e.CommandLine
            $leaf = (($img -split '[\\/]')[-1]).ToLowerInvariant()
            $hit = $null
            foreach ($b in $binSigs) { if ($leaf -eq ([string]$b).ToLowerInvariant() + '.exe') { $hit = @{ Hit = $b; Severity = 'High' }; break } }
            if (-not $hit) { $hit = Get-SKToolHit $cmd }
            if (-not $hit) { continue }
            $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
            $label = $sigLabels[$hit.Hit]; if (-not $label) { $label = 'credential-theft tooling' }
            Add-SKSignal -Computer $e.Computer -Class 'tool' -Time $e.TimeCreated
            $findings.Add((New-IRFinding -Tool $toolName -Severity $hit.Severity -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Credential-theft / Skeleton Key tool executed' `
                        -Description ("{0} ran {1} on {2}: {3}. Command: {4}" -f $actor, $label, $e.Computer, $hit.Hit, $(if ($cmd) { $cmd } else { $img })) `
                        -Account $actor -Target $hit.Hit -Computer $e.Computer -EventIds 4688 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm whether authorised. Correlate with an RC4 downgrade (4768) and LSASS sensitive-privilege use (4673) on the DCs from the same host and window.'))
        }
    }

    # ---- CORRELATION: a DC showing >= 2 of {rc4, priv, tool} within the window is the high-fidelity case ----
    $corrTicks = [TimeSpan]::FromMinutes($CorrelationWindowMinutes).Ticks
    $countedClasses = 'rc4', 'priv', 'tool'
    $hotDcs = @{}
    foreach ($dc in $signalByDc.Keys) {
        $sigs = @($signalByDc[$dc] | Where-Object { $_.Class -in $countedClasses })
        $distinct = @($sigs | ForEach-Object { $_.Class } | Select-Object -Unique)
        if ($distinct.Count -lt 2) { continue }
        $hot = $false
        $untimed = @($sigs | Where-Object { $null -eq $_.Ticks })
        if ($untimed.Count -gt 0) {
            # cannot bound an undated signal - fall back to "2 distinct classes anywhere" so a real case is not missed
            $hot = $true
        }
        else {
            $sorted = @($sigs | Sort-Object Ticks)
            $lo = 0
            for ($hi = 0; $hi -lt $sorted.Count -and -not $hot; $hi++) {
                while ($sorted[$hi].Ticks - $sorted[$lo].Ticks -gt $corrTicks) { $lo++ }
                $win = @($sorted[$lo..$hi] | ForEach-Object { $_.Class } | Select-Object -Unique)
                if ($win.Count -ge 2) { $hot = $true }
            }
        }
        if ($hot) { $hotDcs[$dc] = ($distinct | Sort-Object) -join ', ' }
    }
    if ($hotDcs.Count -gt 0) {
        foreach ($f in $findings) {
            $k = Get-SKDcKey $f.Computer
            if ($k -and $hotDcs.ContainsKey($k)) {
                if ($f.Severity -ne 'Critical') { $f.Severity = 'Critical' }
                $f.Confidence = 'High'
                $f.Description = [string]$f.Description + (" CORRELATION: DC {0} independently shows multiple Skeleton Key signal classes within {1} min ({2}) - together these are high-fidelity for an active implant." -f $f.Computer, $CorrelationWindowMinutes, $hotDcs[$k])
            }
        }
        Write-IRStatus ("Correlation: {0} DC(s) show multiple Skeleton Key signal classes." -f $hotDcs.Count) -Level Detail
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
