<#
.SYNOPSIS
    Detects <ATTACK NAME> from Windows event logs.

.DESCRIPTION
    <Two or three sentences on the attack and why it leaves this trace.>

    Detection logic:
      * <bullet per rule, with the event IDs and fields used>

    Required audit policy / log sources:
      * <e.g. Security: Audit Kerberos Service Ticket Operations (Success) -> 4769>

    Known false positives:
      * <bullets>

.PARAMETER ComputerName
    Remote computer to read the live event log from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders of .evtx) to analyse offline.
.PARAMETER InputObject
    Pre-flattened IRToolKit event objects (from Get-IRSourceEvents / Import-IREvents) via the pipeline.
.PARAMETER InputPath
    JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents).
.PARAMETER StartTime
    Only analyse events at or after this time. Live mode defaults to the last 7 days; file / object modes default to everything.
.PARAMETER EndTime
    Only analyse events at or before this time.
.PARAMETER MaxEvents
    Cap on events read per event-ID batch (0 = unlimited).
.PARAMETER OutputPath
    Directory or file to write results to. When a directory is given the file is named <Tool>-<timestamp>.<ext>.
.PARAMETER Format
    Export format: Csv, Json, Html or All (default Json).
.PARAMETER Quiet
    Suppress console status output. Findings are still returned as objects.
.PARAMETER NoADLookup
    Skip live Active Directory look-ups even when the host is domain joined.
.PARAMETER DomainController
    Extra domain controller names / IPs to treat as DCs (useful offline).
.PARAMETER <ToolSpecific>
    <description, default>

.EXAMPLE
    .\Find-Template.ps1 -StartTime (Get-Date).AddDays(-30)
    Analyse the local Security log for the last 30 days.

.EXAMPLE
    .\Find-Template.ps1 -Path C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Results -Format All
    Analyse an exported log and write CSV, JSON and HTML reports.

.EXAMPLE
    .\Find-Template.ps1 -ComputerName DC01 -Credential (Get-Credential) | Where-Object Severity -eq 'High'

.NOTES
    ATT&CK : T0000.000 (<name>)
    Events : 4769, ...
    Part of IRToolKit - https://github.com/ (internal)
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

    # ---- tool specific parameters (with defaults) ----
    [int]$Threshold = 10,
    [int]$WindowMinutes = 10
)

begin {
    # Locate Common\IRToolKit.Common.psm1 by walking up from the script folder (works from Tools\<Phase>\, Templates\, or a copied tree)
    $irModule = $null; $irDir = $PSScriptRoot
    for ($i = 0; $i -lt 5 -and $irDir; $i++) {
        $candidate = Join-Path $irDir 'Common\IRToolKit.Common.psm1'
        if (Test-Path -LiteralPath $candidate) { $irModule = $candidate; break }
        $irDir = Split-Path -Parent $irDir
    }
    if (-not $irModule) { throw "IRToolKit.Common.psm1 not found in a Common folder above $PSScriptRoot. Keep the IRToolKit folder structure intact or use Build-Standalone.ps1." }
    Import-Module $irModule -Force
    $toolName = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $technique = 'T0000.000'
    $techniqueName = '<ATT&CK technique name>'
    Set-IRQuiet ([bool]$Quiet)
    # Capture whether anything is being piped in (True even for an empty pipeline) so an empty
    # filtered set does not silently fall back to scanning the live machine.
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description '<one line>' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    # ---- collect ----
    $events = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4769)
    Write-IRStatus "Loaded $($events.Count) event(s)" -Level Detail

    # ---- optional AD context ----
    $adAvailable = (-not $NoADLookup) -and (Test-IRAdAvailable)
    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController

    # ---- analyse ----
    # Example burst rule:
    foreach ($b in @(Find-IRBurst -Events $events -GroupBy 'TargetUserName', 'IpAddress' -DistinctProperty 'ServiceName' -WindowMinutes $WindowMinutes -Threshold $Threshold)) {
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                    -Technique $technique -TechniqueName $techniqueName `
                    -Title '<short title>' `
                    -Description ("{0} distinct services requested by {1} from {2} in {3:N1} minutes" -f $b.DistinctCount, $b.Key.TargetUserName, $b.Key.IpAddress, ($b.WindowEnd - $b.WindowStart).TotalMinutes) `
                    -Account $b.Key.TargetUserName -SourceIp (ConvertTo-IRIpAddress $b.Key.IpAddress) `
                    -EventIds 4769 -Evidence @($b.Events | Select-Object -First 200) `
                    -Recommendation '<triage step>'))
    }

    # ---- finish ----
    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
