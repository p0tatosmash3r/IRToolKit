<#
.SYNOPSIS
    Reports whether the Windows audit policy and event-log settings needed by the IRToolKit AD
    detections are actually enabled, so you know a hunt will have the data it depends on.

.DESCRIPTION
    Every detection is only as good as the events being logged. This readiness check inspects the
    local (or remote) host's advanced audit policy subcategories and key event-log sizes/retention,
    and reports each gap as a finding so you can fix logging before (or explain findings after) a hunt.

    It checks:
      * Advanced audit policy subcategories required by the AD tools (Kerberos auth/service ticket
        operations, logon/account-lockout, directory service access/changes, security group
        management, user/computer account management, sensitive privilege use).
      * Security log size and retention window.
      * Presence and size of the PowerShell Operational and (if present) Sysmon Operational logs.
      * Whether PowerShell Script Block Logging is enabled (registry).

    This tool reports Informational/Low/Medium "findings" describing gaps; it does not detect attacks.
    Reading audit policy requires local administrator rights (auditpol). Run elevated on the DC.

.PARAMETER ComputerName
    Remote computer to inspect (audit policy read requires admin + remote registry/RPC).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER OutputPath
    Directory or file to write the readiness report to.
.PARAMETER Format
    Csv, Json, Html or All (default Json).
.PARAMETER Quiet
    Suppress console status output.

.EXAMPLE
    .\Get-IRAuditReadiness.ps1
    Check the local host's audit readiness.

.EXAMPLE
    .\Get-IRAuditReadiness.ps1 -OutputPath C:\Evidence\Readiness -Format Html

.NOTES
    ATT&CK : n/a (defensive logging posture)
    Part of IRToolKit. Run elevated for accurate audit-policy results.
#>
[CmdletBinding()]
param(
    [string]$ComputerName,
    [pscredential]$Credential,
    [string]$OutputPath,
    [ValidateSet('Csv', 'Json', 'Html', 'All')][string]$Format = 'Json',
    [switch]$Quiet
)

$irModule = $null; $irDir = $PSScriptRoot
for ($i = 0; $i -lt 5 -and $irDir; $i++) {
    $candidate = Join-Path $irDir 'Common\IRToolKit.Common.psm1'
    if (Test-Path -LiteralPath $candidate) { $irModule = $candidate; break }
    $irDir = Split-Path -Parent $irDir
}
if (-not $irModule) { throw "IRToolKit.Common.psm1 not found above $PSScriptRoot. Keep the folder structure intact." }
Import-Module $irModule -Force
$toolName = 'Get-IRAuditReadiness'
Set-IRQuiet ([bool]$Quiet)

Write-IRToolHeader -Name $toolName -Description 'Audit policy and log-source readiness for AD hunting'
$findings = New-Object System.Collections.Generic.List[object]
$isRemote = [bool]$ComputerName
$targetHost = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }

# ---- Required audit subcategories: name pattern -> (why, severity if off) ----
$required = @(
    @{ Match = 'Kerberos Authentication Service';     Why = 'AS-REQ events 4768 (AS-REP roasting, golden/forged TGT anomalies)'; Sev = 'High' }
    @{ Match = 'Kerberos Service Ticket Operations';  Why = 'TGS events 4769 (Kerberoasting, silver tickets)';                    Sev = 'High' }
    @{ Match = 'Credential Validation';               Why = 'NTLM validation 4776 and failures (password spray)';                Sev = 'Medium' }
    @{ Match = 'Logon';                               Why = 'Logon success/failure 4624/4625 (spray, lateral movement)';         Sev = 'High' }
    @{ Match = 'Account Lockout';                     Why = 'Lockouts 4740 (brute force / spray side effects)';                  Sev = 'Low' }
    @{ Match = 'Directory Service Access';            Why = 'Object access 4662 (DCSync, dangerous ACL use)';                    Sev = 'High' }
    @{ Match = 'Directory Service Changes';           Why = 'Attribute changes 5136 (RBCD, shadow credentials, ADCS, delegation)'; Sev = 'High' }
    @{ Match = 'Security Group Management';           Why = 'Group membership 4728/4732/4756 (privileged group adds)';           Sev = 'High' }
    @{ Match = 'User Account Management';             Why = 'User changes 4720/4722/4738 (account manipulation, UAC changes)';   Sev = 'Medium' }
    @{ Match = 'Computer Account Management';         Why = 'Computer changes 4741/4742 (delegation, machine account abuse)';    Sev = 'Medium' }
    @{ Match = 'Sensitive Privilege Use';             Why = 'Privilege use 4672/4673 (SeDebug / token abuse / skeleton key)';    Sev = 'Low' }
    @{ Match = 'Other Account Logon Events';          Why = 'Additional Kerberos/NTLM detail';                                    Sev = 'Low' }
)

$auditPolicy = @()
if ($isRemote) {
    try {
        $auditPolicy = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $raw = & auditpol.exe /get /category:* /r 2>$null
            $raw | Where-Object { $_ -and $_ -notmatch '^\s*$' } | ConvertFrom-Csv | ForEach-Object {
                [pscustomobject]@{ Subcategory = $_.Subcategory; Setting = $_.'Inclusion Setting' }
            }
        } -ErrorAction Stop
    }
    catch { Write-IRStatus "Could not read remote audit policy on $ComputerName ($($_.Exception.Message)). Need admin + WinRM." -Level Warning }
}
else {
    $auditPolicy = @(Get-IRAuditPolicy | ForEach-Object { [pscustomobject]@{ Subcategory = $_.Subcategory; Setting = $_.Setting } })
}

if (-not $auditPolicy -or $auditPolicy.Count -eq 0) {
    $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' -Title 'Audit policy could not be read' `
                -Description 'auditpol returned no data. Run this tool elevated (local admin) on the target. Without it, audit-policy gaps cannot be verified.' `
                -Computer $targetHost -Recommendation 'Re-run as administrator on the host (ideally the domain controller).'))
}
else {
    foreach ($req in $required) {
        $rows = @($auditPolicy | Where-Object { $_.Subcategory -and $_.Subcategory.Trim() -like "*$($req.Match)*" })
        if ($rows.Count -eq 0) { continue }
        foreach ($row in $rows) {
            $setting = [string]$row.Setting
            $hasSuccess = $setting -match 'Success'
            $needsFailure = ($req.Match -match 'Logon|Credential Validation|Kerberos Authentication')
            $gap = $null
            if ($setting -match 'No Auditing' -or $setting.Trim() -eq '') { $gap = 'not audited at all' }
            elseif (-not $hasSuccess) { $gap = "success auditing is off (current: $setting)" }
            elseif ($needsFailure -and $setting -notmatch 'Failure') { $gap = "failure auditing is off (current: $setting) - needed for brute-force/spray detection" }
            if ($gap) {
                $sev = $req.Sev
                if ($gap -like 'failure auditing*' -and $sev -eq 'High') { $sev = 'Medium' }
                $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'High' -Title ("Audit gap: {0}" -f $row.Subcategory.Trim()) `
                            -Description ("Subcategory '{0}' {1}. Needed for: {2}." -f $row.Subcategory.Trim(), $gap, $req.Why) `
                            -Computer $targetHost -Recommendation ("Enable with: auditpol /set /subcategory:`"{0}`" /success:enable{1}" -f $row.Subcategory.Trim(), $(if ($needsFailure) { ' /failure:enable' } else { '' }))))
            }
        }
    }
}

# ---- Log sizes / retention ----
$logs = @(
    @{ Name = 'Security'; MinMB = 1024; Sev = 'Medium' }
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; MinMB = 256; Sev = 'Low' }
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; MinMB = 512; Sev = 'Low'; Optional = $true }
    @{ Name = 'System'; MinMB = 64; Sev = 'Low' }
)
foreach ($l in $logs) {
    $info = Get-IRLogInfo -LogName $l.Name -ComputerName $ComputerName -Credential $Credential
    if (-not $info) {
        if (-not $l.Optional) {
            $findings.Add((New-IRFinding -Tool $toolName -Severity $l.Sev -Confidence 'Medium' -Title ("Log not available: {0}" -f $l.Name) `
                        -Description ("The {0} log could not be queried (missing, disabled, or access denied)." -f $l.Name) `
                        -Computer $targetHost -Recommendation 'Confirm the log exists and is enabled; run elevated.'))
        }
        continue
    }
    if (-not $info.IsEnabled) {
        $findings.Add((New-IRFinding -Tool $toolName -Severity $l.Sev -Confidence 'High' -Title ("Log disabled: {0}" -f $l.Name) `
                    -Description ("The {0} log is disabled." -f $l.Name) -Computer $targetHost -Recommendation ("Enable with: wevtutil sl `"{0}`" /e:true" -f $l.Name)))
    }
    if ($info.MaximumSizeMB -lt $l.MinMB) {
        $findings.Add((New-IRFinding -Tool $toolName -Severity $l.Sev -Confidence 'Medium' -Title ("Log may be too small: {0}" -f $l.Name) `
                    -Description ("{0} maximum size is {1} MB (recommended >= {2} MB). Retention window currently about {3} days ({4} records)." -f $l.Name, $info.MaximumSizeMB, $l.MinMB, $info.RetentionDays, $info.RecordCount) `
                    -Computer $targetHost -Recommendation ("Increase with: wevtutil sl `"{0}`" /ms:{1}" -f $l.Name, ($l.MinMB * 1MB))))
    }
    else {
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'High' -Title ("Log OK: {0}" -f $l.Name) `
                    -Description ("{0}: {1} MB max, {2} records, ~{3} day retention (oldest {4})." -f $l.Name, $info.MaximumSizeMB, $info.RecordCount, $info.RetentionDays, $info.OldestEvent) `
                    -Computer $targetHost -Recommendation 'No action.'))
    }
}

# ---- PowerShell Script Block Logging (registry) ----
if (-not $isRemote) {
    $sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sbl = $null
    if (Test-Path -LiteralPath $sblPath) {
        try { $sbl = (Get-ItemProperty -LiteralPath $sblPath -ErrorAction Stop).EnableScriptBlockLogging } catch { Write-Verbose "SBL read: $($_.Exception.Message)" }
    }
    if ($sbl -ne 1) {
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Low' -Confidence 'High' -Title 'PowerShell Script Block Logging is off' `
                    -Description 'EnableScriptBlockLogging is not set. Event 4104 is used by several tools to catch attack tooling (Rubeus, mimikatz, Certify, Whisker).' `
                    -Computer $targetHost -Recommendation 'Enable via GPO: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.'))
    }
    else {
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'High' -Title 'PowerShell Script Block Logging is on' `
                    -Description 'EnableScriptBlockLogging = 1. Event 4104 is being recorded.' -Computer $targetHost -Recommendation 'No action.'))
    }
}

Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
