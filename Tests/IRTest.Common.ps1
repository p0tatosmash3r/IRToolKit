# Minimal test harness (no Pester dependency - Windows ships Pester 3.4 which is incompatible with Pester 5 syntax).
# Dot-source this file at the top of every *.Test.ps1, call Assert-IR for each check, and finish with Complete-IRTest.

$script:IRTestResults = New-Object System.Collections.Generic.List[object]
$script:IRTestName = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
if (-not $script:IRTestName) { $script:IRTestName = 'test' }

Import-Module (Join-Path $PSScriptRoot '..\Common\IRToolKit.Common.psm1') -Force -ErrorAction Stop

function Assert-IR {
    <# .SYNOPSIS Records a pass/fail. #>
    param(
        [Parameter(Mandatory, Position = 0)][AllowNull()]$Condition,
        [Parameter(Mandatory, Position = 1)][string]$Message
    )
    $ok = [bool]$Condition
    $script:IRTestResults.Add([pscustomobject]@{ Test = $script:IRTestName; Passed = $ok; Message = $Message })
    if ($ok) { Write-Host "  [PASS] $Message" -ForegroundColor Green } else { Write-Host "  [FAIL] $Message" -ForegroundColor Red }
}

function Invoke-IRToolSafely {
    <#
    .SYNOPSIS  Runs a tool script and captures findings, errors and non-finding output separately.
    .OUTPUTS   [pscustomobject] with Findings, Errors (ErrorRecord[]), Extraneous (non-finding output objects)
    #>
    param([Parameter(Mandatory)][string]$ToolPath, [hashtable]$Arguments = @{})
    $errs = @()
    $out = @()
    try {
        $out = @(& $ToolPath @Arguments -ErrorVariable toolErrors -ErrorAction Continue 2>&1)
        $errs = @($toolErrors)
    }
    catch { $errs += $_ }
    $findings = @($out | Where-Object { $_ -is [psobject] -and $_.PSObject.TypeNames -contains 'IRToolKit.Finding' })
    $errorRecords = @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
    $extraneous = @($out | Where-Object { -not ($_ -is [System.Management.Automation.ErrorRecord]) -and -not ($_.PSObject.TypeNames -contains 'IRToolKit.Finding') })
    [pscustomobject]@{
        Findings   = $findings
        Errors     = @($errs + $errorRecords | Select-Object -Unique)
        Extraneous = $extraneous
    }
}

function Complete-IRTest {
    <# .SYNOPSIS Prints the summary and returns the result objects (the runner aggregates them). #>
    $passed = @($script:IRTestResults | Where-Object Passed).Count
    $total = $script:IRTestResults.Count
    $color = 'Green'; if ($passed -lt $total) { $color = 'Red' }
    Write-Host ("  {0}: {1}/{2} passed" -f $script:IRTestName, $passed, $total) -ForegroundColor $color
    $script:IRTestResults.ToArray()
}
