<#
.SYNOPSIS
    Detects Active Directory trust abuse - malicious trust creation / modification / removal, and the
    SID-filtering weakening that makes cross-trust SID-history escalation possible - from Windows Security
    and PowerShell event logs.

.DESCRIPTION
    A domain or forest trust lets principals from one domain authenticate into another. SID filtering (aka
    quarantine) is the security boundary that stops an attacker who controls the trusted side from forging
    SID-history / ExtraSids to impersonate privileged principals across the trust. Attackers abuse trusts by
    (a) WEAKENING that boundary - clearing the QUARANTINED_DOMAIN bit on an external trust, or setting
    TREAT_AS_EXTERNAL on a forest trust (what "netdom /enablesidhistory:yes" does), which then lets any
    principal with RID >= 1000 be impersonated across the forest; (b) enabling cross-forest TGT delegation
    or disabling NTLM target validation; (c) creating a rogue trust to a domain they control, or stealing
    the trust key to forge inter-realm TGTs. This tool watches the TRUST OBJECT itself; it reads logs only.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 - a dangerous trust-configuration change (Security 5136 on the trustedDomain object, paired
        old->new via OpCorrelationID; or 4716 "trusted domain information was modified" which carries only
        the new state). Flags: SID filtering disabled (QUARANTINED_DOMAIN 0x4 cleared, or SidFilteringEnabled
        Disabled) -> High; TREAT_AS_EXTERNAL 0x40 set on a forest trust (0x8) -> Critical (cross-forest
        SID-history escalation); cross-forest TGT delegation enabled (0x800 set / 0x200 cleared) or NTLM
        auth-target validation disabled (0x1000 set) -> High; an AES->RC4 downgrade of the trust key
        (msDS-SupportedEncryptionTypes, or USES_RC4_ENCRYPTION 0x80 on a non-MIT trust) -> Medium.
      * RULE 2 - a new trust was created (Security 4706). Baseline Medium; High when the new trust already
        has SID filtering disabled or a dangerous attribute (treat-as-external / TGT delegation).
      * RULE 3 - a trust was removed (4707) or a forest-trust name-suffix routing entry was added / removed /
        modified (4865 / 4866 / 4867) -> Medium (trust teardown, or name-suffix routing abuse).
      * RULE 4 - a trust-modifying COMMAND (process 4688 / script block 4104): netdom with a dangerous flag
        (/quarantine:No, /enablesidhistory:Yes, /enabletgtdelegation:Yes, /authtargetvalidation:No,
        /selectiveauth:No, /passwordt), or the .NET SetSidFilteringStatus / SetSelectiveAuthenticationStatus
        / Create/DeleteTrustRelationship, or a direct Set-ADObject write to trustAttributes -> High/Medium.
      * RULE 5 - offensive trust-key tooling (4104 / 4688) matched against the signatures in the sidecar
        data file Find-TrustAbuse.signatures.json (the exact tool/command signatures live in that file, not
        in this script, so the detector does not self-quarantine under AMSI/EDR). Invocation-anchored;
        merely naming a tool does not fire. Skipped if the sidecar is absent.

    Required audit policy / log sources (domain controllers):
      * Policy Change > Audit Authentication Policy Change = Success -> 4706 / 4707 / 4716 / 4865-4867
        (on by default in most DC baselines).
      * DS Access > Audit Directory Service Changes = Success + a SACL on the trustedDomain objects -> 5136
        (gives the precise old->new attribute diff; not guaranteed by default).
      * Audit Process Creation (+ command line) -> 4688; PowerShell Script Block Logging -> 4104.

    Known false positives:
      * Mergers/acquisitions create trusts (4706); domain MIGRATIONS with ADMT legitimately run
        /quarantine:No or /enablesidhistory:yes and write SID history; decommissioning removes trusts
        (4707/4866). Distinguish by change control, the acting account (trust admin / ADMT service account
        vs unexpected), the window, and whether cross-realm ticket anomalies follow. Add known trust admins
        to -ExcludeAccount. Automatic trust-password resets fire 4716/5136 as ANONYMOUS LOGON (S-1-5-7,
        LogonId 0x3E6) and are excluded by default unless they carry a dangerous end-state.

.PARAMETER ComputerName
    Remote computer to read the live logs from (default: local machine).
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
.PARAMETER ExcludeAccount
    Known-good trust administrators / migration (ADMT) service accounts. Their trust changes are suppressed;
    matched on the bare name (UPN / DOMAIN\ / trailing-$ aware).
.PARAMETER IncludeAnonymousResets
    Also report ANONYMOUS-LOGON trust-info modifications (the automatic trust-password resets excluded by default).
.PARAMETER SignatureFile
    Path to the RULE 5 signature data file. Default: Find-TrustAbuse.signatures.json beside the tool (a
    standalone build / local drop-in), otherwise Common\Signatures\Find-TrustAbuse.signatures.json.

.EXAMPLE
    .\Find-TrustAbuse.ps1 -Path C:\Evidence\DC01-Security.evtx -ExcludeAccount CORP\trustadmin
    Hunt trust abuse in an exported DC Security log, suppressing a known trust admin.

.EXAMPLE
    .\Find-TrustAbuse.ps1 -StartTime (Get-Date).AddDays(-30) -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1484.002 (Domain Policy Modification: Domain Trust Modification); enables T1134.005 (SID-History Injection)
    Events : 4706, 4707, 4716, 4865, 4866, 4867, 5136, 4688 (Security); 4104 (PowerShell)
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

    [string[]]$ExcludeAccount,
    [switch]$IncludeAnonymousResets,
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
    if (-not $toolName) { $toolName = 'Find-TrustAbuse' }
    $technique = 'T1484.002'; $techniqueName = 'Domain Trust Modification'
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
    Write-IRToolHeader -Name $toolName -Description 'AD trust abuse (trust creation / modification / SID-filtering weakening)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # trustAttributes bit flags (MS-ADTS).
    $TA_QUARANTINED = 0x4; $TA_FOREST = 0x8; $TA_TREAT_AS_EXTERNAL = 0x40; $TA_RC4 = 0x80
    $TA_NO_TGT_DELEG = 0x200; $TA_ENABLE_TGT_DELEG = 0x800; $TA_DISABLE_AUTH_TARGET = 0x1000
    $trustFlagNames = [ordered]@{
        0x1 = 'NON_TRANSITIVE'; 0x2 = 'UPLEVEL_ONLY'; 0x4 = 'QUARANTINED_DOMAIN(SID-filtering)'; 0x8 = 'FOREST_TRANSITIVE'
        0x10 = 'CROSS_ORGANIZATION'; 0x20 = 'WITHIN_FOREST'; 0x40 = 'TREAT_AS_EXTERNAL'; 0x80 = 'USES_RC4_ENCRYPTION'
        0x100 = 'USES_AES_KEYS'; 0x200 = 'NO_TGT_DELEGATION'; 0x400 = 'PIM_TRUST'; 0x800 = 'ENABLE_TGT_DELEGATION'; 0x1000 = 'DISABLE_AUTH_TARGET_VALIDATION'
    }
    $sevRank = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1; 'Informational' = 0 }

    function Get-TAInt {
        # Non-throwing parse (TryParse). A throwing cast/[Convert] here would record an ErrorRecord to the
        # caller's -ErrorVariable even when caught (PS 5.1), so an out-of-range AttributeValue must not throw.
        param($v)
        $s = ([string]$v).Trim()
        if (-not $s) { return $null }
        if ($s -match '^0x[0-9a-fA-F]+$') {
            $u = [uint64]0
            if ([uint64]::TryParse($s.Substring(2), [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$u)) {
                if ($u -le [uint64][int64]::MaxValue) { return [int64]$u }
            }
            return $null
        }
        if ($s -match '^-?\d+$') {
            $n = [int64]0
            if ([int64]::TryParse($s, [ref]$n)) { return $n }
            return $null
        }
        return $null
    }
    function Test-TABit { param([int64]$Value, [int64]$Bit) return (($Value -band $Bit) -ne 0) }
    function Get-TAFlagNames {
        param([int64]$Value)
        $names = @(); foreach ($entry in $trustFlagNames.GetEnumerator()) { if (($Value -band $entry.Key) -ne 0) { $names += $entry.Value } }
        if ($names.Count -eq 0) { return '(none)' }
        $names -join ' | '
    }
    function Get-TASidFilterState {
        # $true = disabled, $false = enabled, $null = unknown, from the SidFilteringEnabled field.
        param($Value)
        $v = ([string]$Value).Trim()
        if (-not $v) { return $null }
        if ($v -match '(?i)disabl' -or $v -match '%%1797') { return $true }
        if ($v -match '(?i)enabl' -or $v -match '%%1796') { return $false }
        return $null
    }
    function Get-TADirection {
        param($Value)
        switch (([string]$Value).Trim()) { '0' { 'disabled' } '1' { 'inbound' } '2' { 'outbound' } '3' { 'bidirectional' } default { "direction=$Value" } }
    }
    function Get-TAType {
        param($Value)
        switch (([string]$Value).Trim()) { '1' { 'downlevel (NT4)' } '2' { 'uplevel (AD)' } '3' { 'MIT realm' } '4' { 'DCE' } default { "type=$Value" } }
    }
    function Test-TAExcluded {
        param([string]$Actor)
        if ($excludeSet.Count -eq 0) { return $false }
        $a = ([string]$Actor).Trim().ToLowerInvariant()
        if (-not $a) { return $false }
        if ($excludeSet.ContainsKey($a.TrimEnd('$'))) { return $true }
        if ($a -match '\\([^\\]+)$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        if ($a -match '^(.+)@[^@]+$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        return $false
    }
    function Test-TAAnonymous {
        param($Evt)
        $n = ([string]$Evt.SubjectUserName).Trim()
        $sid = ([string]$Evt.SubjectUserSid).Trim()
        $lid = ([string]$Evt.SubjectLogonId).Trim().ToLowerInvariant()
        if ($n -match '(?i)^ANONYMOUS LOGON$') { return $true }
        if ($sid -eq 'S-1-5-7') { return $true }
        if ($lid -eq '0x3e6') { return $true }
        return $false
    }
    function Remove-TAComments {
        # Strip PowerShell comments so a commented-out / documented command (which never executes) does not
        # match RULE 4 / RULE 5. Applied to 4104 script-block text only (not 4688 command lines).
        param([string]$Text)
        if (-not $Text) { return $Text }
        $t = $Text -replace '(?s)<#.*?#>', ' '
        $t = $t -replace '(?m)#.*$', ''
        return $t
    }

    # ---- RULE 5 signature set (loaded from the sidecar data file; never embedded in this script) ----
    if (-not $SignatureFile) {
        # Resolve the sidecar: beside the script first (a standalone build / local drop-in), then the
        # central Common\Signatures directory (normal repo layout).
        $SignatureFile = Join-Path $scriptDir ($toolName + '.signatures.json')
        if (-not (Test-Path -LiteralPath $SignatureFile) -and $sigDir) {
            $central = Join-Path $sigDir ($toolName + '.signatures.json')
            if (Test-Path -LiteralPath $central) { $SignatureFile = $central }
        }
    }
    $critCmdlet = New-Object System.Collections.Generic.List[string]
    $critModule = New-Object System.Collections.Generic.List[string]
    $highSigs = New-Object System.Collections.Generic.List[string]
    $binSigs = New-Object System.Collections.Generic.List[string]
    $modSigs = New-Object System.Collections.Generic.List[string]
    $sigLabels = @{}
    $toolingEnabled = $false
    function ConvertFrom-TAJsonSafe {
        # Parse untrusted JSON in an isolated runspace so no terminating error reaches this runspace
        # (a caught throw still lands in the caller's -ErrorVariable in PS 5.1).
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
    if (Test-Path -LiteralPath $SignatureFile) {
        $raw = $null
        try { $raw = Get-Content -LiteralPath $SignatureFile -Raw -Encoding UTF8 } catch { $raw = $null }
        $sig = ConvertFrom-TAJsonSafe $raw
        if ($null -eq $sig) {
            Write-IRStatus "Signature file '$SignatureFile' is missing or not valid JSON - RULE 5 (offensive tooling) disabled; the trust-object rules still run." -Level Warning
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
            $toolingEnabled = (($critCmdlet.Count + $critModule.Count + $highSigs.Count + $binSigs.Count + $modSigs.Count) -gt 0)
        }
    }
    else {
        Write-IRStatus "Signature file not found (looked beside the tool and in Common\Signatures) - RULE 5 disabled; trust-object rules still run. Expected: $SignatureFile" -Level Detail
    }
    $modRe = $null
    if ($modSigs.Count -gt 0) {
        $cc = ':' + ':'
        $modRe = '(?i)((?:' + (($modSigs | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')' + $cc + '[a-z0-9_]+)'
    }
    $cmdPosRe = '(?im)(?:^|[\n;&{(=|])\s*(?:\$\w+\s*=\s*)?'
    function Test-TAInvoked {
        param([string]$Text)
        foreach ($h in ($critCmdlet + $highSigs)) { if ($Text -match ($cmdPosRe + [regex]::Escape($h) + '\b')) { return $true } }
        foreach ($b in $binSigs) { if ($Text -match ($cmdPosRe + [regex]::Escape($b) + '(\.exe|\.dll)?\b')) { return $true } }
        return $false
    }
    function Get-TAToolHit {
        param([string]$Text)
        if (-not $Text) { return $null }
        $invoked = Test-TAInvoked $Text
        foreach ($c in $critCmdlet) { if ($Text -match ($cmdPosRe + [regex]::Escape($c) + '\b')) { return @{ Hit = $c; Severity = 'Critical' } } }
        foreach ($c in $critModule) { if ($invoked -and $Text -match ('(?i)(?<![\w:])' + [regex]::Escape($c) + '(?![\w])')) { return @{ Hit = $c; Severity = 'Critical' } } }
        foreach ($h in $highSigs) { if ($Text -match ($cmdPosRe + [regex]::Escape($h) + '\b')) { return @{ Hit = $h; Severity = 'High' } } }
        if ($invoked -and $modRe -and $Text -match $modRe) { return @{ Hit = $matches[1]; Severity = 'High' } }
        foreach ($b in $binSigs) { if ($Text -match ($cmdPosRe + [regex]::Escape($b) + '(\.exe|\.dll)?\b')) { return @{ Hit = $b; Severity = 'High' } } }
        return $null
    }

    # Evaluate a trust-attribute state (new, and old when known) and return dangerous observations.
    function Get-TARisk {
        param([Nullable[int64]]$OldInt, [Nullable[int64]]$NewInt, [Nullable[bool]]$SidFilterDisabled, $TrustTypeValue)
        $obs = New-Object System.Collections.Generic.List[object]
        $haveOld = ($null -ne $OldInt)
        $new = if ($null -ne $NewInt) { [int64]$NewInt } else { 0 }
        $old = if ($haveOld) { [int64]$OldInt } else { 0 }
        $isForest = ((($new -bor $old) -band $TA_FOREST) -ne 0)
        $isMit = ((([string]$TrustTypeValue).Trim()) -eq '3')
        $confFromTransition = if ($haveOld) { 'High' } else { 'Medium' }
        $addedOrPresent = { param($bit) if ($haveOld) { ((($new -band $bit) -ne 0) -and (($old -band $bit) -eq 0)) } else { (($new -band $bit) -ne 0) } }
        $clearedOrAbsent = { param($bit) if ($haveOld) { ((($new -band $bit) -eq 0) -and (($old -band $bit) -ne 0)) } else { (($new -band $bit) -eq 0) } }

        # SID filtering disabled: QUARANTINED cleared, or the SidFilteringEnabled field says Disabled.
        $quarCleared = (& $clearedOrAbsent $TA_QUARANTINED)
        if (($SidFilterDisabled -eq $true) -or ($haveOld -and $quarCleared)) {
            $txt = if ($haveOld -and $quarCleared) { 'the QUARANTINED_DOMAIN bit was cleared' } else { 'SID filtering is disabled' }
            $obs.Add([pscustomobject]@{ Sev = 'High'; Conf = $confFromTransition; Tech = 'T1134.005'; Text = "SID filtering disabled ($txt) - an attacker controlling the trusted side can now forge SID history / ExtraSids across the trust" })
        }
        # Treat-as-external on a forest trust: the cross-forest SID-history escalation.
        if ((& $addedOrPresent $TA_TREAT_AS_EXTERNAL) -and $isForest) {
            $obs.Add([pscustomobject]@{ Sev = 'Critical'; Conf = $confFromTransition; Tech = 'T1134.005'; Text = 'TREAT_AS_EXTERNAL set on a forest trust (what netdom /enablesidhistory:yes does) - forest SID filtering relaxed to external rules, so any principal with RID >= 1000 can be impersonated across the forest boundary' })
        }
        elseif ((& $addedOrPresent $TA_TREAT_AS_EXTERNAL)) {
            $obs.Add([pscustomobject]@{ Sev = 'High'; Conf = $confFromTransition; Tech = 'T1134.005'; Text = 'TREAT_AS_EXTERNAL set on the trust - relaxes SID filtering to external rules' })
        }
        # Cross-forest TGT delegation enabled.
        if ((& $addedOrPresent $TA_ENABLE_TGT_DELEG) -or ($haveOld -and (& $clearedOrAbsent $TA_NO_TGT_DELEG))) {
            $obs.Add([pscustomobject]@{ Sev = 'High'; Conf = $confFromTransition; Tech = 'T1484.002'; Text = 'cross-forest TGT delegation enabled (ENABLE_TGT_DELEGATION set / NO_TGT_DELEGATION cleared) - enables unconstrained-delegation abuse across the forest trust' })
        }
        # NTLM auth target validation disabled.
        if (& $addedOrPresent $TA_DISABLE_AUTH_TARGET) {
            $obs.Add([pscustomobject]@{ Sev = 'High'; Conf = $confFromTransition; Tech = 'T1484.002'; Text = 'NTLM auth-target validation disabled (DISABLE_AUTH_TARGET_VALIDATION set) - weakens NTLM relay protection over the trust' })
        }
        # RC4 on a non-MIT trust.
        if ((& $addedOrPresent $TA_RC4) -and -not $isMit) {
            $obs.Add([pscustomobject]@{ Sev = 'Medium'; Conf = $confFromTransition; Tech = 'T1484.002'; Text = 'USES_RC4_ENCRYPTION set on a non-MIT trust - a downgrade that weakens the trust key' })
        }
        $obs
    }

    function Add-TAFinding {
        param($Observations, [string]$Domain, [string]$Actor, $Evt, [int]$EventId, [string]$Via, [string]$Context)
        $obs = @($Observations | Where-Object { $_ })
        if ($obs.Count -eq 0) { return }
        $top = ($obs | Sort-Object { $sevRank[$_.Sev] } -Descending)[0]
        $actorTxt = $Actor; if (-not $actorTxt) { $actorTxt = '-' }
        $desc = ("Trust '{0}' was modified by {1} ({2}).{3} Dangerous change(s): {4}." -f $Domain, $actorTxt, $Via, $(if ($Context) { " $Context" } else { '' }), (($obs | ForEach-Object { $_.Text }) -join '; '))
        $findings.Add((New-IRFinding -Tool $toolName -Severity $top.Sev -Confidence $top.Conf `
                    -Technique $top.Tech -TechniqueName $techniqueName -Title 'Dangerous trust configuration change' `
                    -Description $desc -Account $actorTxt -Target $Domain -Computer $Evt.Computer `
                    -EventIds $EventId -Evidence (Get-IRFirst @($Evt) 200) `
                    -Recommendation 'Confirm the trust change was authorised (change control, trust-admin actor, migration window). If not, restore SID filtering / selective authentication (netdom /quarantine:Yes, /enablesidhistory:no, Set-ADObject on trustAttributes), rotate the trust password, and hunt for cross-realm forged-TGT use (4769 krbtgt/REALM) and SID-history writes that follow.'))
    }

    # ---- RULE 1a: 5136 trustedDomain attribute changes (precise old->new via OpCorrelationID) ----
    $trustAttrNames = 'trustattributes', 'msds-supportedencryptiontypes', 'trustdirection', 'trusttype', 'securityidentifier', 'trustpartner'
    $tdMods = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136 | Where-Object {
            (([string]$_.ObjectClass) -match '(?i)trustedDomain') -or
            ((-not ([string]$_.ObjectClass).Trim()) -and (([string]$_.AttributeLDAPDisplayName).ToLowerInvariant() -in $trustAttrNames) -and (([string]$_.ObjectDN) -match '(?i)CN=System'))
        })
    # Group trustAttributes changes by OpCorrelationID (a single change = Value Deleted old + Value Added new).
    $attrEvents = @($tdMods | Where-Object { ([string]$_.AttributeLDAPDisplayName).ToLowerInvariant() -eq 'trustattributes' })
    $encEvents = @($tdMods | Where-Object { ([string]$_.AttributeLDAPDisplayName).ToLowerInvariant() -eq 'msds-supportedencryptiontypes' })
    foreach ($g in ($attrEvents | Group-Object { "$([string]$_.OpCorrelationID)|$([string]$_.ObjectDN)" })) {
        $items = @($g.Group)
        $added = @($items | Where-Object { -not (([string]$_.OperationType) -match '14675|Value Deleted') })
        $deleted = @($items | Where-Object { ([string]$_.OperationType) -match '14675|Value Deleted' })
        if ($added.Count -eq 0) { continue }   # deleted-only (no resulting value logged) - cannot assess the new state
        $newEvt = $added[0]
        if (-not $IncludeAnonymousResets -and (Test-TAAnonymous $newEvt)) { continue }
        if (Test-TAExcluded ([string]$newEvt.SubjectUserName)) { continue }
        $newInt = if ($added.Count -gt 0) { Get-TAInt $added[0].AttributeValue } else { $null }
        $oldInt = if ($deleted.Count -gt 0) { Get-TAInt $deleted[0].AttributeValue } else { $null }
        if ($null -eq $newInt -and $null -eq $oldInt) { continue }
        $dom = [string]$newEvt.ObjectDN; if ($dom -match '^\s*CN=([^,]+)') { $dom = $matches[1].Trim() }
        $obs = @((Get-TARisk -OldInt $oldInt -NewInt $newInt -SidFilterDisabled $null -TrustTypeValue $null) | Where-Object { $_ })
        $ctxTxt = if ($null -ne $oldInt) { ("trustAttributes {0} -> {1}." -f (Get-TAFlagNames $oldInt), (Get-TAFlagNames $newInt)) } else { ("trustAttributes now {0}." -f (Get-TAFlagNames $newInt)) }
        Add-TAFinding -Observations $obs -Domain $dom -Actor ([string]$newEvt.SubjectUserName) -Evt $newEvt -EventId 5136 -Via '5136 trustAttributes change' -Context $ctxTxt
    }
    foreach ($g in ($encEvents | Group-Object { "$([string]$_.OpCorrelationID)|$([string]$_.ObjectDN)" })) {
        $items = @($g.Group)
        $added = @($items | Where-Object { -not (([string]$_.OperationType) -match '14675|Value Deleted') })
        $deleted = @($items | Where-Object { ([string]$_.OperationType) -match '14675|Value Deleted' })
        if ($added.Count -eq 0) { continue }
        $newEvt = $added[0]
        if (-not $IncludeAnonymousResets -and (Test-TAAnonymous $newEvt)) { continue }
        if (Test-TAExcluded ([string]$newEvt.SubjectUserName)) { continue }
        $newEnc = Get-TAInt $added[0].AttributeValue
        $oldEnc = if ($deleted.Count -gt 0) { Get-TAInt $deleted[0].AttributeValue } else { $null }
        if ($null -eq $newEnc) { continue }
        $newHasAes = (($newEnc -band 0x18) -ne 0); $newHasRc4 = (($newEnc -band 0x4) -ne 0)
        $oldHadAes = ($null -ne $oldEnc -and (($oldEnc -band 0x18) -ne 0))
        if ($newHasRc4 -and -not $newHasAes -and ($oldHadAes -or $null -eq $oldEnc)) {
            $dom = [string]$newEvt.ObjectDN; if ($dom -match '^\s*CN=([^,]+)') { $dom = $matches[1].Trim() }
            $conf = if ($oldHadAes) { 'High' } else { 'Medium' }
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence $conf `
                        -Technique 'T1484.002' -TechniqueName $techniqueName -Title 'Trust encryption downgraded to RC4' `
                        -Description ("The trusted-domain object '{0}' had msDS-SupportedEncryptionTypes set to an RC4-only value (0x{1:x}) by {2} (event 5136){3}. An RC4 trust key is weaker and easier to forge/crack (inter-realm TGT forging)." -f $dom, $newEnc, ([string]$newEvt.SubjectUserName), $(if ($oldHadAes) { ', removing AES' } else { '' })) `
                        -Account ([string]$newEvt.SubjectUserName) -Target $dom -Computer $newEvt.Computer `
                        -EventIds 5136 -Evidence (Get-IRFirst @($newEvt) 200) `
                        -Recommendation 'Confirm the trust was intended to use RC4 (rare). Restore AES support on the trust (msDS-SupportedEncryptionTypes) and rotate the trust password.'))
        }
    }

    # ---- RULE 1b: 4716 "trusted domain information was modified" (new state only) ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4716)) {
        if (-not $IncludeAnonymousResets -and (Test-TAAnonymous $e)) { continue }
        if (Test-TAExcluded ([string]$e.SubjectUserName)) { continue }
        $newInt = Get-TAInt $e.TdoAttributes
        $sidDis = Get-TASidFilterState $e.SidFilteringEnabled
        $obs = @((Get-TARisk -OldInt $null -NewInt $newInt -SidFilterDisabled $sidDis -TrustTypeValue $e.TdoType) | Where-Object { $_ })
        if ($obs.Count -eq 0) { continue }
        $ctxTxt = ("New state: {0}, direction {1}, {2}." -f $(if ($null -ne $newInt) { Get-TAFlagNames $newInt } else { 'attributes unknown' }), (Get-TADirection $e.TdoDirection), (Get-TAType $e.TdoType))
        Add-TAFinding -Observations $obs -Domain ([string]$e.DomainName) -Actor ([string]$e.SubjectUserName) -Evt $e -EventId 4716 -Via '4716 trusted-domain-info modified' -Context $ctxTxt
    }

    # ---- RULE 2: new trust created (4706) ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4706)) {
        if (Test-TAExcluded ([string]$e.SubjectUserName)) { continue }
        if (-not ([string]$e.DomainName).Trim()) { continue }
        $newInt = Get-TAInt $e.TdoAttributes
        $sidDis = Get-TASidFilterState $e.SidFilteringEnabled
        $obs = @((Get-TARisk -OldInt $null -NewInt $newInt -SidFilterDisabled $sidDis -TrustTypeValue $e.TdoType) | Where-Object { $_ })
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $dom = [string]$e.DomainName
        $dir = Get-TADirection $e.TdoDirection; $typ = Get-TAType $e.TdoType
        $sev = 'Medium'; $conf = 'Medium'; $tech = 'T1484.002'
        $extra = ''
        if ($obs.Count -gt 0) {
            $top = ($obs | Sort-Object { $sevRank[$_.Sev] } -Descending)[0]
            $sev = $top.Sev; $tech = $top.Tech; $conf = 'High'
            $extra = ' Dangerous attribute(s): ' + (($obs | ForEach-Object { $_.Text }) -join '; ') + '.'
        }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $tech -TechniqueName $techniqueName -Title 'New domain/forest trust created' `
                    -Description ("{0} created a new {1} trust to '{2}' ({3}, event 4706), SID filtering {4}.{5} Attackers create a trust to a domain they control to forge tickets into this domain; confirm this trust is expected." -f $actor, $typ, $dom, $dir, $(if ($sidDis -eq $true) { 'DISABLED' } elseif ($sidDis -eq $false) { 'enabled' } else { 'unspecified' }), $extra) `
                    -Account $actor -Target $dom -Computer $e.Computer `
                    -EventIds 4706 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the new trust is authorised (M&A / migration change control). If not, remove it (netdom /remove), and review what the trusted domain can now access. Ensure SID filtering / selective authentication are enabled on any trust you keep.'))
    }

    # ---- RULE 3: trust removed (4707) / forest-trust routing entry changes (4865/4866/4867) ----
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4707)) {
        if (Test-TAExcluded ([string]$e.SubjectUserName)) { continue }
        if (-not ([string]$e.DomainName).Trim()) { continue }
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $dom = [string]$e.DomainName
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique 'T1484.002' -TechniqueName $techniqueName -Title 'Domain/forest trust removed' `
                    -Description ("{0} removed the trust to '{1}' (event 4707). Trust removal is routine during decommissioning but can also be disruption or covering tracks after trust abuse; confirm it was planned." -f $actor, $dom) `
                    -Account $actor -Target $dom -Computer $e.Computer `
                    -EventIds 4707 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the trust removal was planned. If not, investigate the actor and restore the trust if required.'))
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4865, 4866, 4867)) {
        if (Test-TAExcluded ([string]$e.SubjectUserName)) { continue }
        $id = [int]$e.EventId
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $root = [string]$e.ForestRoot; if (-not $root) { $root = [string]$e.DomainName }
        $tln = [string]$e.TopLevelName; if (-not $tln) { $tln = [string]$e.DnsName }
        if (-not $root.Trim() -and -not $tln.Trim()) { continue }
        $act = switch ($id) { 4865 { 'added' } 4866 { 'removed' } default { 'modified' } }
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique 'T1484.002' -TechniqueName $techniqueName -Title ("Forest-trust name-suffix routing entry {0}" -f $act) `
                    -Description ("{0} {1} a trusted-forest routing entry (event {2}) on forest '{3}'{4}. Name-suffix (TLN) routing controls which name spaces route over the forest trust; adding/toggling entries can broaden what an attacker can reach or spoof across the trust." -f $actor, $act, $id, $root, $(if ($tln) { " for '$tln'" } else { '' })) `
                    -Account $actor -Target $(if ($tln) { $tln } else { $root }) -Computer $e.Computer `
                    -EventIds $id -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the routing change was authorised. Unexpected TLN additions/toggles can enable name-based routing abuse across the forest trust.'))
    }

    # ---- RULE 4: trust-modifying commands (netdom / .NET) in processes (4688) and script blocks (4104) ----
    # netdom dangerous flag must be on the SAME command as the netdom invocation (not merely co-mentioned
    # somewhere in a script/comment). Comments are stripped from 4104 text before this runs.
    $netdomDanger = '(?im)\bnetdom\b[^\n]*?/(quarantine\s*:\s*no|enablesidhistory\s*:\s*yes|enabletgtdelegation\s*:\s*yes|authtargetvalidation\s*:\s*no|selectiveauth\s*:\s*no|passwordt)\b'
    # Only the DISABLE form fires - re-enabling (SetSidFilteringStatus(...,$true)) is a defensive action.
    $dotNetTrust = '(?i)\b(SetSidFilteringStatus|SetSelectiveAuthenticationStatus)\b[^\n]*,\s*\$?(false|0)\b'
    $dotNetLifecycle = '(?i)\b(CreateTrustRelationship|CreateLocalSideOfTrustRelationship|DeleteTrustRelationship)\b'
    $adObjTrust = '(?i)Set-ADObject\b[^\n]*trustAttributes'
    function Add-TACmdFinding {
        param([string]$What, [string]$Sev, [string]$Tech, [string]$Actor, $Evt, [int]$EventId, [string]$CmdText)
        $actorTxt = $Actor; if (-not $actorTxt) { $actorTxt = '-' }
        $excerpt = ([string]$CmdText); if ($excerpt.Length -gt 300) { $excerpt = $excerpt.Substring(0, 300) }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $Sev -Confidence 'High' `
                    -Technique $Tech -TechniqueName $techniqueName -Title 'Trust-modifying command executed' `
                    -Description ("{0} on {1} (event {2}): {3}. Command: {4}" -f $actorTxt, $Evt.Computer, $EventId, $What, $excerpt) `
                    -Account $actorTxt -Target $What -Computer $Evt.Computer `
                    -EventIds $EventId -Evidence (Get-IRFirst @($Evt) 200) `
                    -Recommendation 'Confirm the trust change was authorised. These commands disable SID filtering / selective auth or create/delete trusts; if unexpected, treat as trust tampering and restore the protections.'))
    }
    function Test-TACmd {
        param([string]$Text, $Evt, [int]$EventId)
        if (-not $Text) { return }
        if ($Text -match $netdomDanger) {
            $tech = if ($Text -match '(?im)\bnetdom\b[^\n]*?/(quarantine|enablesidhistory)') { 'T1134.005' } else { 'T1484.002' }
            Add-TACmdFinding -What 'netdom trust change that disables a trust protection' -Sev 'High' -Tech $tech -Actor ([string]$Evt.SubjectUserName) -Evt $Evt -EventId $EventId -CmdText $Text
            return
        }
        if ($Text -match $dotNetTrust) {
            Add-TACmdFinding -What '.NET trust SID-filtering / selective-auth change (SetSidFilteringStatus / SetSelectiveAuthenticationStatus)' -Sev 'High' -Tech 'T1134.005' -Actor ([string]$Evt.SubjectUserName) -Evt $Evt -EventId $EventId -CmdText $Text
            return
        }
        if ($Text -match $adObjTrust) {
            Add-TACmdFinding -What 'direct Set-ADObject write to trustAttributes' -Sev 'High' -Tech 'T1484.002' -Actor ([string]$Evt.SubjectUserName) -Evt $Evt -EventId $EventId -CmdText $Text
            return
        }
        if ($Text -match $dotNetLifecycle) {
            Add-TACmdFinding -What '.NET trust create/delete (DirectoryServices)' -Sev 'Medium' -Tech 'T1484.002' -Actor ([string]$Evt.SubjectUserName) -Evt $Evt -EventId $EventId -CmdText $Text
            return
        }
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4688)) {
        $cmd = [string]$e.CommandLine; if (-not $cmd) { $cmd = [string]$e.NewProcessName }
        Test-TACmd -Text $cmd -Evt $e -EventId 4688
    }
    foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)) {
        $text = [string]$e.ScriptBlockText
        if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
        Test-TACmd -Text (Remove-TAComments $text) -Evt $e -EventId 4104
    }

    # ---- RULE 5: offensive trust-key tooling (sidecar signatures) in 4104 / 4688 ----
    if ($toolingEnabled) {
        foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $text = $text -replace '(?is)^\s*Creating Scriptblock text \(\d+ of \d+\):\s*', ''
            $text = Remove-TAComments $text
            $hit = Get-TAToolHit $text
            if (-not $hit) { continue }
            $label = $sigLabels[$hit.Hit]; if (-not $label) { $label = 'trust-key / credential tooling' }
            $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
            $findings.Add((New-IRFinding -Tool $toolName -Severity $hit.Severity -Confidence 'High' `
                        -Technique 'T1134.005' -TechniqueName $techniqueName -Title 'Trust-key / credential tooling in PowerShell script block' `
                        -Description ("PowerShell script block on {0} matched {1} signature. Excerpt: {2}" -f $e.Computer, $label, $excerpt) `
                        -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Identify the user and process. A trust-key dump enables forging inter-realm TGTs into/across the trust - rotate the trust password(s), and correlate with 4769 krbtgt/REALM anomalies.'))
        }
        foreach ($e in @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4688)) {
            $img = [string]$e.NewProcessName
            $cmd = [string]$e.CommandLine
            $leaf = (($img -split '[\\/]')[-1]).ToLowerInvariant()
            $hit = $null
            foreach ($b in $binSigs) { if ($leaf -eq ([string]$b).ToLowerInvariant() + '.exe') { $hit = @{ Hit = $b; Severity = 'High' }; break } }
            if (-not $hit) { $hit = Get-TAToolHit $cmd }
            if (-not $hit) { continue }
            $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
            $label = $sigLabels[$hit.Hit]; if (-not $label) { $label = 'trust-key / credential tooling' }
            $findings.Add((New-IRFinding -Tool $toolName -Severity $hit.Severity -Confidence 'High' `
                        -Technique 'T1134.005' -TechniqueName $techniqueName -Title 'Trust-key / credential tool executed' `
                        -Description ("{0} ran {1} on {2}: {3}. Command: {4}" -f $actor, $label, $e.Computer, $hit.Hit, $(if ($cmd) { $cmd } else { $img })) `
                        -Account $actor -Target $hit.Hit -Computer $e.Computer -EventIds 4688 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm whether authorised. Rotate the trust password(s) and correlate with cross-realm 4769 anomalies and trust-attribute changes.'))
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
