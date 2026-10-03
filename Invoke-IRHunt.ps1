<#
.SYNOPSIS
    Runs every IRToolKit detection tool in one or more attack-chain phases and consolidates the
    findings into a single sorted report (console + optional CSV/JSON/HTML).

.DESCRIPTION
    Invoke-IRHunt discovers the tool scripts under Tools\<Phase>\*.ps1, runs each against the same
    event source (live log, remote host, exported .evtx, or pre-parsed JSON), collects their
    IRToolKit.Finding objects, and produces one combined, severity-sorted report. It is the fast way
    to sweep a collected log set for everything the kit knows about.

    Each tool is run in-process. A tool that errors is reported but does not stop the hunt. The source
    parameters are forwarded to every tool, so -Path C:\Evidence\DC01-Security.evtx runs the whole AD
    phase against that one exported log.

.PARAMETER Phase
    One or more phase folder names under Tools\ (e.g. AD). Default: all phases found.
.PARAMETER Tool
    Wildcard to limit which tool scripts run (matched on the file base name, default Find-* so only
    detection tools run; utility tools like Get-IRAuditReadiness are run on their own).
.PARAMETER ComputerName
    Remote computer to read live logs from.
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    Exported .evtx file(s) / folder(s) to analyse offline. Forwarded to every tool.
.PARAMETER InputPath
    JSON / CSV / CliXml of pre-flattened events. Forwarded to every tool.
.PARAMETER StartTime
    Only analyse events at or after this time.
.PARAMETER EndTime
    Only analyse events at or before this time.
.PARAMETER MaxEvents
    Cap on events read per event-ID batch per tool (0 = unlimited).
.PARAMETER OutputPath
    Directory to write the consolidated report into.
.PARAMETER Format
    Consolidated report format: Csv, Json, Html or All (default Html).
.PARAMETER DomainController
    Extra DC names / IPs forwarded to tools that need DC awareness.
.PARAMETER MinimumSeverity
    Only keep findings at or above this severity (Critical > High > Medium > Low > Informational).
.PARAMETER ListOnly
    List the tools that would run and exit.

.EXAMPLE
    .\Invoke-IRHunt.ps1 -Phase AD -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Report -Format All
    Run every AD tool against an exported DC log and write a consolidated report.

.EXAMPLE
    .\Invoke-IRHunt.ps1 -StartTime (Get-Date).AddDays(-2) -MinimumSeverity High
    Run every tool against the local live logs for the last two days, keeping only High+ findings.

.EXAMPLE
    .\Invoke-IRHunt.ps1 -Phase AD -ListOnly

.NOTES
    Part of IRToolKit. Tools live under Tools\<Phase>\*.ps1 and all share the standard parameter block.
#>
[CmdletBinding()]
param(
    [string[]]$Phase,
    [string]$Tool = 'Find-*',
    [string]$ComputerName,
    [pscredential]$Credential,
    [string[]]$Path,
    [string]$InputPath,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [int]$MaxEvents = 0,
    [string]$OutputPath,
    [ValidateSet('Csv', 'Json', 'Html', 'All')][string]$Format = 'Html',
    [string[]]$DomainController,
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')][string]$MinimumSeverity = 'Informational',
    [switch]$ListOnly
)

$irModule = Join-Path $PSScriptRoot 'Common\IRToolKit.Common.psm1'
if (-not (Test-Path -LiteralPath $irModule)) { throw "Cannot find Common\IRToolKit.Common.psm1 next to Invoke-IRHunt.ps1." }
Import-Module $irModule -Force

$toolsRoot = Join-Path $PSScriptRoot 'Tools'
if (-not (Test-Path -LiteralPath $toolsRoot)) { throw "No Tools folder found at $toolsRoot." }

$phaseDirs = @()
if ($Phase) {
    foreach ($p in $Phase) {
        $d = Join-Path $toolsRoot $p
        if (Test-Path -LiteralPath $d) { $phaseDirs += Get-Item -LiteralPath $d } else { Write-IRStatus "Phase not found: $p" -Level Warning }
    }
}
else { $phaseDirs = @(Get-ChildItem -LiteralPath $toolsRoot -Directory) }

$toolScripts = New-Object System.Collections.Generic.List[object]
foreach ($pd in $phaseDirs) {
    foreach ($s in @(Get-ChildItem -LiteralPath $pd.FullName -Filter '*.ps1' -File | Sort-Object Name)) {
        if ($s.BaseName -like $Tool) { $toolScripts.Add([pscustomobject]@{ Phase = $pd.Name; Script = $s }) }
    }
}

if ($toolScripts.Count -eq 0) { Write-IRStatus 'No matching tools found.' -Level Warning; return }

Write-IRToolHeader -Name 'Invoke-IRHunt' -Description ("Running {0} tool(s) across phase(s): {1}" -f $toolScripts.Count, (($phaseDirs | ForEach-Object Name) -join ', '))

if ($ListOnly) {
    $toolScripts | ForEach-Object { Write-Host ("  [{0}] {1}" -f $_.Phase, $_.Script.BaseName) -ForegroundColor Gray }
    return
}

# Build the argument set forwarded to every tool (only the source + context parameters they all accept).
$common = @{}
if ($PSBoundParameters.ContainsKey('ComputerName') -and $ComputerName) { $common['ComputerName'] = $ComputerName }
if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) { $common['Credential'] = $Credential }
if ($PSBoundParameters.ContainsKey('Path') -and $Path) { $common['Path'] = $Path }
if ($PSBoundParameters.ContainsKey('InputPath') -and $InputPath) { $common['InputPath'] = $InputPath }
if ($PSBoundParameters.ContainsKey('StartTime')) { $common['StartTime'] = $StartTime }
if ($PSBoundParameters.ContainsKey('EndTime')) { $common['EndTime'] = $EndTime }
if ($MaxEvents -gt 0) { $common['MaxEvents'] = $MaxEvents }
$common['Quiet'] = $true

$allFindings = New-Object System.Collections.Generic.List[object]
$runLog = New-Object System.Collections.Generic.List[object]

foreach ($t in $toolScripts) {
    $name = $t.Script.BaseName
    # Forward only the parameters the tool actually declares, so posture/utility tools with a
    # different parameter set are not handed -InputPath/-Path/etc.
    $decl = @()
    try { $decl = @((Get-Command -Name $t.Script.FullName -ErrorAction Stop).Parameters.Keys) } catch {}
    $toolArgs = @{}
    foreach ($k in $common.Keys) { if ($decl -contains $k) { $toolArgs[$k] = $common[$k] } }
    if ($DomainController -and ($decl -contains 'DomainController')) { $toolArgs['DomainController'] = $DomainController }

    # Skip a tool that cannot consume the hunt's source mode (e.g. a live-only posture tool during a file hunt).
    $sourceModeParam = $null
    if ($common.ContainsKey('InputPath')) { $sourceModeParam = 'InputPath' }
    elseif ($common.ContainsKey('Path')) { $sourceModeParam = 'Path' }
    if ($sourceModeParam -and ($decl -notcontains $sourceModeParam)) {
        Write-Host ("  Skipping {0} ({1}) - does not accept -{2}" -f $name, $t.Phase, $sourceModeParam) -ForegroundColor DarkGray
        $runLog.Add([pscustomobject]@{ Tool = $name; Phase = $t.Phase; Findings = 0; Seconds = 0; Error = "skipped (no -$sourceModeParam)" })
        continue
    }

    Write-Host ("  Running {0} ({1}) ..." -f $name, $t.Phase) -ForegroundColor Cyan -NoNewline
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $findings = @()
    $errMsg = $null
    try {
        $findings = @(& $t.Script.FullName @toolArgs -ErrorAction Continue)
        $findings = @($findings | Where-Object { $_ -and ($_.PSObject.TypeNames -contains 'IRToolKit.Finding') })
    }
    catch { $errMsg = $_.Exception.Message }
    $sw.Stop()
    foreach ($f in $findings) { $allFindings.Add($f) }
    $status = if ($errMsg) { "ERROR: $errMsg" } else { "$($findings.Count) finding(s)" }
    $color = if ($errMsg) { 'Red' } elseif ($findings.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("  {0}  [{1:N1}s]" -f $status, $sw.Elapsed.TotalSeconds) -ForegroundColor $color
    $runLog.Add([pscustomobject]@{ Tool = $name; Phase = $t.Phase; Findings = $findings.Count; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1); Error = $errMsg })
}

# Filter by minimum severity.
$minRank = Get-IRSeverityRank $MinimumSeverity
$kept = @($allFindings | Where-Object { (Get-IRSeverityRank $_.Severity) -ge $minRank })

Write-Host ''
Write-Host ('=' * 78) -ForegroundColor DarkCyan
Write-IRFindingSummary -Findings $kept -Tool 'Invoke-IRHunt (consolidated)'
Write-Host ''
Write-Host 'Per-tool run log:' -ForegroundColor White
$runLog | Format-Table Tool, Phase, Findings, Seconds, Error -AutoSize | Out-String | Write-Host

if ($OutputPath) {
    $notes = @(
        "Hunt run $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME.",
        "Tools run: $($toolScripts.Count). Phases: $((($phaseDirs | ForEach-Object Name) -join ', ')). Minimum severity: $MinimumSeverity.",
        ("Per-tool: " + (($runLog | ForEach-Object { "$($_.Tool)=$($_.Findings)" }) -join ', '))
    )
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $formats = @($Format); if ($Format -eq 'All') { $formats = @('Csv', 'Json', 'Html') }
    foreach ($fmt in $formats) {
        $file = Join-Path $OutputPath ("IRHunt-{0}.{1}" -f $stamp, $fmt.ToLower())
        switch ($fmt) {
            'Html' { ConvertTo-IRHtmlReport -Findings $kept -Title 'IRToolKit Consolidated Hunt' -Notes $notes | Out-File -LiteralPath $file -Encoding UTF8 }
            default { Export-IRFindings -Findings $kept -Path $file -Format $fmt -Name 'IRHunt' | Out-Null }
        }
        if ($fmt -eq 'Html') { Write-IRStatus "Wrote consolidated HTML report: $file" -Level Success }
    }
}

$kept
