<#
.SYNOPSIS
    Runs every IRToolKit test (Tests\**\*.Test.ps1) plus a syntax/help check over every tool and prints a summary.
.PARAMETER Filter
    Wildcard on the test file name (e.g. *Kerberoast*).
.PARAMETER SkipSyntax
    Skip the parser / help checks of Tools\**\*.ps1.
.EXAMPLE
    .\Tests\Invoke-IRTests.ps1
.EXAMPLE
    .\Tests\Invoke-IRTests.ps1 -Filter *DCSync*
#>
[CmdletBinding()]
param(
    [string]$Filter = '*',
    [switch]$SkipSyntax
)

$root = Split-Path -Parent $PSScriptRoot
$results = New-Object System.Collections.Generic.List[object]
$failures = 0

if (-not $SkipSyntax) {
    Write-Host "== Syntax / help checks ==" -ForegroundColor Cyan
    $scripts = @(Get-ChildItem -Path (Join-Path $root 'Tools') -Recurse -Filter '*.ps1' -File) + @(Get-ChildItem -Path $root -Filter '*.ps1' -File)
    $scripts += Get-ChildItem -Path (Join-Path $root 'Common') -Filter '*.psm1' -File
    foreach ($s in $scripts) {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$tokens, [ref]$errors)
        $ok = ($errors.Count -eq 0)
        $nonAscii = Select-String -LiteralPath $s.FullName -Pattern '[^\x00-\x7F]' -AllMatches | Select-Object -First 1
        $rel = $s.FullName.Substring($root.Length + 1)
        if (-not $ok) { Write-Host "  [FAIL] $rel : $($errors[0].Message)" -ForegroundColor Red; $failures++ }
        elseif ($nonAscii) { Write-Host "  [FAIL] $rel : non-ASCII character at line $($nonAscii.LineNumber)" -ForegroundColor Red; $failures++ }
        else {
            $helpOk = $true
            if ($s.Extension -eq '.ps1' -and $s.DirectoryName -like '*\Tools\*') {
                $h = Get-Help $s.FullName -ErrorAction SilentlyContinue
                $helpOk = ($h -and $h.Synopsis -and $h.Synopsis -notlike '*.ps1*' -and @($h.examples.example).Count -ge 2)
            }
            if ($helpOk) { Write-Host "  [PASS] $rel" -ForegroundColor Green }
            else { Write-Host "  [FAIL] $rel : comment-based help missing synopsis or <2 examples" -ForegroundColor Red; $failures++ }
        }
    }
}

Write-Host "== Tool tests ==" -ForegroundColor Cyan
$tests = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.Test.ps1' -File | Where-Object { $_.Name -like $Filter } | Sort-Object FullName
foreach ($t in $tests) {
    Write-Host "-- $($t.Name)" -ForegroundColor White
    try {
        $r = @(& $t.FullName)
        foreach ($x in $r) { if ($x.PSObject.Properties['Passed']) { $results.Add($x) } }
    }
    catch {
        Write-Host "  [FAIL] test script threw: $($_.Exception.Message)" -ForegroundColor Red
        $results.Add([pscustomobject]@{ Test = $t.BaseName; Passed = $false; Message = "threw: $($_.Exception.Message)" })
    }
}

$passed = @($results | Where-Object Passed).Count
$failed = @($results | Where-Object { -not $_.Passed }).Count
Write-Host ''
Write-Host ("== Summary: {0} assertions passed, {1} failed, {2} syntax/help failures ==" -f $passed, $failed, $failures) -ForegroundColor $(if (($failed + $failures) -eq 0) { 'Green' } else { 'Red' })
if ($failed -gt 0) { $results | Where-Object { -not $_.Passed } | Format-Table Test, Message -AutoSize }
if (($failed + $failures) -gt 0) { exit 1 } else { exit 0 }
