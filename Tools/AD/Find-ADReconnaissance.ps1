<#
.SYNOPSIS
    Detects Active Directory reconnaissance / enumeration (BloodHound / SharpHound, PowerView, LDAP and
    SAMR sweeps) from Windows Directory Service, Security and PowerShell event logs.

.DESCRIPTION
    Before moving laterally or escalating, an attacker maps the domain: users, groups, computers, ACLs,
    trusts, GPOs and local-admin relationships. This is overwhelmingly done with BloodHound/SharpHound,
    PowerView, ldapdomaindump, AdFind and similar - large LDAP queries plus mass local-group enumeration.
    This tool looks for the footprints that collection leaves; it does not enumerate anything itself.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 (High/Medium) - expensive / recon LDAP queries (Directory Service event 1644). A query
        whose filter carries BloodHound/PowerView-characteristic tokens (samAccountType=805306368,
        objectClass=trustedDomain, groupPolicyContainer, ms-Mcs-AdmPwd/LAPS, msDS-AllowedToDelegateTo,
        servicePrincipalName sweeps) is High; a high VOLUME of 1644 from one client in the window is
        Medium. 1644 requires the NTDS "Field Engineering" diagnostic (or expensive/inefficient-search
        logging) to be enabled - it is off by default.
      * RULE 2 (High) - mass local-group / user-membership enumeration (Security 4798 / 4799) - a burst
        from one principal in the window. SharpHound's session / local-admin collection enumerates the
        Administrators group (and user memberships) across many hosts, producing a flood of 4799/4798.
      * RULE 3 (High) - BloodHound / PowerView tooling in a PowerShell script block (4104).
      * RULE 4 (High/Medium) - recon tooling executed as a process (4688): sharphound / adfind (High);
        dsquery / csvde / ldifde / nltest / "net group|user ... /domain" (Medium, needs command-line
        auditing).

    Required audit policy / log sources:
      * Directory Service log (DCs): enable NTDS Diagnostics "15 Field Engineering" = 5 (or expensive /
        inefficient search logging) for 1644. Off by default - RULE 1 is silent without it.
      * Security (DCs / member hosts): Audit Detailed Directory Service Access and the local-group
        enumeration subcategory are not required, but 4798/4799 come from "Audit Security Group
        Management" / built-in membership-enumeration auditing on the hosts being enumerated.
      * Security (4688) with command-line auditing for RULE 4.
      * PowerShell Script Block Logging (4104) for RULE 3.

    Known false positives:
      * Vulnerability scanners (Nessus, Qualys, Tenable), asset-inventory / CMDB tools, EDR, and some
        management suites perform large LDAP queries and mass local-group enumeration as normal operation
        and will trip RULE 1 / RULE 2. Add their service accounts / hosts to -ExcludeAccount. Treat these
        rules as "who is enumerating the directory" leads, corroborated by RULE 3 / RULE 4 tooling.

.PARAMETER ComputerName
    Remote computer to read the live logs from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders) to analyse offline (include the Directory Service log).
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
    Events from one principal / client within the window to raise a burst (1644 volume, 4798/4799
    enumeration). Default 20.
.PARAMETER WindowMinutes
    Sliding window length in minutes for the burst rules (default 10).
.PARAMETER ExcludeAccount
    Principals / hosts (users, machine accounts, or IPs) known to perform legitimate bulk enumeration -
    vulnerability scanners, inventory tools, EDR. Suppressed from the LDAP burst rule (matched against the
    client IP AND the 1644 issuing account), the enumeration burst rule (subject name / SID / caller
    process), and the process rule (subject / image).
.PARAMETER IncludeMachineAndSystem
    By default the mass-enumeration rule (4798/4799) ignores SYSTEM / LOCAL SERVICE / NETWORK SERVICE and
    machine ($) accounts, which enumerate local groups routinely (GPO, SCCM, EDR). Pass this to include
    them (e.g. when hunting SharpHound run under SYSTEM).

.EXAMPLE
    .\Find-ADReconnaissance.ps1 -Path C:\Evidence\DC01-DirectoryService.evtx, C:\Evidence\DC01-Security.evtx
    Hunt SharpHound / LDAP recon across an exported DC Directory Service + Security log.

.EXAMPLE
    .\Find-ADReconnaissance.ps1 -StartTime (Get-Date).AddDays(-2) -ExcludeAccount NESSUS_SVC,CMDB01$ -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), T1482 (Domain Trust
             Discovery), T1018 (Remote System Discovery)
    Events : 1644 (Directory Service); 4798, 4799, 4688 (Security); 4104 (PowerShell Operational)
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

    [int]$Threshold = 20,
    [int]$WindowMinutes = 10,
    [string[]]$ExcludeAccount,
    [switch]$IncludeMachineAndSystem
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
    if (-not $toolName) { $toolName = 'Find-ADReconnaissance' }
    $technique = 'T1087.002'; $techniqueName = 'Active Directory Reconnaissance'
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
            $excludeSet[([string]$x).Trim().ToLowerInvariant()] = $true
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Active Directory reconnaissance (BloodHound/SharpHound, LDAP & group enumeration)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    function Test-ReconExcluded {
        param([string[]]$Values)
        if ($excludeSet.Count -eq 0) { return $false }
        foreach ($v in @($Values)) {
            if (-not $v) { continue }
            $u = ([string]$v).Trim().ToLowerInvariant()
            if ($excludeSet.ContainsKey($u)) { return $true }
            if ($excludeSet.ContainsKey($u.TrimEnd('$'))) { return $true }
            if ($u -match '\\([^\\]+)$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
            if ($u -match '^(.+)@[^@]+$' -and $excludeSet.ContainsKey($matches[1].TrimEnd('$'))) { return $true }
        }
        return $false
    }

    # ---- RULE 1: expensive / recon LDAP queries (1644, Directory Service log) ----
    # -NoLogNameFilter: 1644 is NTDS-specific; read it even if a SIEM export relabelled the channel.
    $ldap = @(Get-IRSourceEvents -Context $ctx -LogName 'Directory Service' -EventId 1644 -IncludeMessage -NoLogNameFilter)
    Write-IRStatus "Loaded $($ldap.Count) 1644 LDAP-search event(s)" -Level Detail

    $reconFilterSigs = 'samAccountType=805306368', 'samAccountType=805306369', 'objectClass=trustedDomain', 'objectCategory=trustedDomain', 'groupPolicyContainer', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msDS-AllowedToDelegateTo', 'msDS-GroupMSAMembership', 'ntSecurityDescriptor', 'servicePrincipalName=*', '(objectClass=domainTrust)', 'trustAttributes'
    function Get-LdapField {
        param($Evt, [string[]]$Names)
        foreach ($n in $Names) { if ($Evt.PSObject.Properties[$n] -and $Evt.$n) { return [string]$Evt.$n } }
        return $null
    }
    function Get-LdapClientKey {
        param($Evt)
        $c = Get-LdapField $Evt @('Client', 'ClientIPAddress', 'IpAddress', 'CallerIPAddress')
        if (-not $c) { $m = [string]$Evt.Message; if ($m -match '(?im)Client[:\s]+([0-9a-fA-F:.]+)') { $c = $matches[1] } }
        $c = ([string]$c).Trim()
        # Strip a trailing :port ONLY for bracketed IPv6 ([::1]:port) or dotted IPv4 (a.b.c.d:port).
        # A bare IPv6 (fe80::...) must be left intact - a greedy ':\d+' strip would eat its last group
        # and both fragment bursts and defeat an IPv6 entry in -ExcludeAccount.
        if ($c -match '^\[(.+)\]:\d+$') { $c = $matches[1] }
        elseif ($c -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') { $c = $matches[1] }
        return $c
    }

    $ldapNorm = New-Object System.Collections.Generic.List[object]
    foreach ($e in $ldap) {
        $client = Get-LdapClientKey $e
        $filter = Get-LdapField $e @('Filter', 'SearchFilter', 'LdapFilter')
        if (-not $filter) { $filter = [string]$e.Message }
        # Modern 1644 also records the issuing account ('User'); honour -ExcludeAccount against it too, so
        # a scanner on DHCP can be suppressed by its service account and not only by IP.
        $ldapUser = Get-LdapField $e @('User', 'UserName', 'Account', 'SubjectUserName')
        if (Test-ReconExcluded @($client, $ldapUser)) { continue }
        # Recon-characteristic filter -> High per client (dedup by client+matched signature).
        $sigHit = Test-IRPatternMatch -Text $filter -Patterns $reconFilterSigs
        $e | Add-Member -NotePropertyName _Client -NotePropertyValue $(if ($client) { $client } else { '(unknown)' }) -Force
        $e | Add-Member -NotePropertyName _LdapUser -NotePropertyValue $ldapUser -Force
        $e | Add-Member -NotePropertyName _SigHit -NotePropertyValue $sigHit -Force
        $ldapNorm.Add($e)
    }
    # High: recon-signature filters, grouped by client.
    foreach ($g in ($ldapNorm | Where-Object { $_._SigHit } | Group-Object _Client)) {
        $ev = @($g.Group)
        $sigs = @($ev | ForEach-Object { $_._SigHit } | Select-Object -Unique)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'BloodHound/PowerView-style LDAP reconnaissance (1644)' `
                    -Description ("Client {0} issued {1} LDAP search(es) whose filter matched directory-recon signature(s): {2}. This filter shape is characteristic of BloodHound/SharpHound / PowerView / ldapdomaindump collection." -f $ev[0]._Client, $ev.Count, ($sigs -join ', ')) `
                    -Account $ev[0]._Client -SourceIp $ev[0]._Client -Target ($sigs -join ', ') -Computer $ev[0].Computer `
                    -EventIds 1644 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Identify the client host/account. If it is not an authorised scanner/inventory tool (add those to -ExcludeAccount), treat as pre-attack reconnaissance: correlate with session/local-group enumeration and tooling, and review what the account could reach.'))
    }
    # Medium: sheer volume of 1644 from one client (no signature match), via burst.
    $volPool = @($ldapNorm | Where-Object { -not $_._SigHit })
    foreach ($b in @(Find-IRBurst -Events $volPool -GroupBy '_Client' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'High volume of LDAP searches from one client (1644)' `
                    -Description ("Client {0} issued {1} LDAP search(es) within {2} min. A high volume of directory queries from one client can indicate enumeration (BloodHound/ldapdomaindump) or a noisy but legitimate scanner/application." -f $b.Events[0]._Client, $b.EventCount, [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1)) `
                    -Account $b.Events[0]._Client -SourceIp $b.Events[0]._Client -Computer $b.Events[0].Computer `
                    -EventIds 1644 -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Confirm whether the client is an authorised scanner / inventory tool (add it to -ExcludeAccount). Otherwise review the queries for enumeration patterns.'))
    }

    # ---- RULE 2: mass local-group / user-membership enumeration (4798 / 4799) ----
    $enum = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4798, 4799)
    $enumNorm = New-Object System.Collections.Generic.List[object]
    # Well-known local principals that enumerate local groups as part of normal operation.
    $builtinSvcSids = @{ 'S-1-5-18' = $true; 'S-1-5-19' = $true; 'S-1-5-20' = $true }
    foreach ($e in $enum) {
        $subj = [string]$e.SubjectUserName
        $sid = [string]$e.SubjectUserSid
        $proc = [string]$e.CallerProcessName
        if (Test-ReconExcluded @($subj, $proc, $sid)) { continue }
        # Build the grouping key from the subject name, else the SID. An event with NEITHER cannot be
        # attributed to one principal, so it is NOT burstable (dropping it prevents unrelated blank-subject
        # enumeration across many hosts from fabricating one synthetic '(unknown)' burst).
        $subjKey = if ($subj) { $subj.ToLowerInvariant() } elseif ($sid) { $sid.ToLowerInvariant() } else { $null }
        if (-not $subjKey) { continue }
        # SYSTEM / LOCAL SERVICE / NETWORK SERVICE and machine accounts enumerate local groups routinely
        # (GPO, SCCM, EDR). Exclude them from this burst rule by default; -IncludeMachineAndSystem keeps them.
        if (-not $IncludeMachineAndSystem) {
            if ($builtinSvcSids.ContainsKey($sid.ToUpperInvariant())) { continue }
            if ($subj -and ($subj -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$' -or (Test-IRMachineAccount $subj))) { continue }
        }
        $e | Add-Member -NotePropertyName _SubjKey -NotePropertyValue $subjKey -Force
        $enumNorm.Add($e)
    }
    foreach ($b in @(Find-IRBurst -Events $enumNorm.ToArray() -GroupBy '_SubjKey' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        $subj = [string]$b.Events[0].SubjectUserName; if (-not $subj) { $subj = '(unknown)' }
        $procs = @($b.Events | ForEach-Object { $_.CallerProcessName } | Where-Object { $_ } | Select-Object -Unique)
        $eids = @($b.Events | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique 'T1069.002' -TechniqueName 'Permission Groups Discovery (Domain Groups)' -Title 'Mass local-group / membership enumeration (SharpHound-style)' `
                    -Description ("{0} enumerated group / user memberships {1} time(s) within {2} min (events {3}){4}. A burst of membership enumeration from one principal is characteristic of SharpHound session / local-admin collection." -f `
                        $subj, $b.EventCount, [Math]::Round(($b.WindowEnd - $b.WindowStart).TotalMinutes, 1), ($eids -join '/'), $(if ($procs.Count) { ' via ' + ((Get-IRFirst $procs 3) -join ', ') } else { '' })) `
                    -Account $subj -Computer $b.Events[0].Computer `
                    -EventIds $eids -Evidence (Get-IRFirst $b.Events 200) `
                    -Recommendation 'Confirm whether the principal is an authorised scanner / inventory tool (add it to -ExcludeAccount). Otherwise treat as reconnaissance and correlate with LDAP recon (1644) and tooling from the same host.'))
    }

    # ---- RULE 3: BloodHound / PowerView tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Invoke-BloodHound', 'SharpHound', 'Get-DomainUser', 'Get-DomainComputer', 'Get-DomainGroup', 'Get-NetUser', 'Get-NetComputer', 'Get-NetSession', 'Get-NetLocalGroup', 'Invoke-ShareFinder', 'Invoke-UserHunter', 'Get-DomainTrust', 'Get-NetDomainTrust', 'Get-DomainGPO', 'Find-DomainShare', 'ldapdomaindump'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'BloodHound / PowerView reconnaissance tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched AD-recon signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process. Correlate with 1644 LDAP recon and 4798/4799 enumeration bursts from the same host and window.'))
            }
        }
    }

    # ---- RULE 4: recon tooling executed as a process (4688) ----
    $proc = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4688)
    foreach ($e in $proc) {
        $img = [string]$e.NewProcessName
        $cmd = [string]$e.CommandLine
        $leaf = ($img -split '[\\/]')[-1]
        $leafLc = $leaf.ToLowerInvariant()
        # Match tool names against the image LEAF only (anchored), never as bare substrings of the whole
        # command line + path - otherwise opening SharpHound/AdFind OUTPUT in notepad, or a binary run from
        # a directory named 'adfind', self-flags as a recon tool. The nltest/net branches scope their
        # argument check to the specific leaf, so they cannot over-match either.
        $cmdLc = ([string]$cmd).ToLowerInvariant()
        $sev = $null
        if ($leafLc -eq 'sharphound.exe' -or $leafLc -eq 'adfind.exe') { $sev = 'High' }
        elseif ($leafLc -in @('dsquery.exe', 'csvde.exe', 'ldifde.exe') ) { $sev = 'Medium' }
        elseif ($leafLc -eq 'nltest.exe' -and $cmdLc -match '(?i)/dclist|/domain_trusts|/trusted_domains') { $sev = 'Medium' }
        elseif ($leafLc -in @('net.exe', 'net1.exe') -and $cmdLc -match '(?i)\b(group|user|accounts)\b.*\/domain') { $sev = 'Medium' }
        if (-not $sev) { continue }
        $subj = [string]$e.SubjectUserName
        if (Test-ReconExcluded @($subj, $leaf)) { continue }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'AD reconnaissance tool executed' `
                    -Description ("{0} ran a directory-reconnaissance process on {1}: {2}. Command: {3}" -f $(if ($subj) { $subj } else { '-' }), $e.Computer, $leaf, $(if ($cmd) { $cmd } else { $img })) `
                    -Account $subj -Target $leaf -Computer $e.Computer `
                    -EventIds 4688 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm whether this was authorised administration. sharphound/adfind are rarely legitimate; dsquery/csvde/ldifde/nltest/net are dual-use - review the arguments and the running account.'))
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
