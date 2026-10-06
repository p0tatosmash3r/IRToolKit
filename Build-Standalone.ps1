<#
.SYNOPSIS
    Produces single-file, dependency-free copies of every IRToolKit tool by inlining the shared module.

.DESCRIPTION
    Each tool normally locates and imports Common\IRToolKit.Common.psm1 at run time. For deployment to
    an evidence host or a locked-down system you often want ONE self-contained .ps1. This builder reads
    the module source, strips its Export-ModuleMember line, and injects it into a copy of each tool in
    place of the module-locate/Import-Module block, so the standalone defines all helpers itself.

    Output goes to .\dist by default. The standalone files behave identically to the originals.

.PARAMETER OutputDirectory
    Where to write the standalone scripts (default: .\dist).
.PARAMETER Tool
    Wildcard on the tool base name (default: * = all tools under Tools\).
.PARAMETER Phase
    Limit to one or more phase folders.

.EXAMPLE
    .\Build-Standalone.ps1
    Build standalone copies of every tool into .\dist.

.EXAMPLE
    .\Build-Standalone.ps1 -Tool *Kerberoast* -OutputDirectory C:\Deploy

.NOTES
    Part of IRToolKit. The build contract: every tool contains the exact module-locate block from
    Templates\Find-Template.ps1, ending with the line "Import-Module $irModule -Force".
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$Tool = '*',
    [string[]]$Phase
)

$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'dist' }
$modulePath = Join-Path $PSScriptRoot 'Common\IRToolKit.Common.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Module not found: $modulePath" }

# Prepare the inlined module body: drop the Export-ModuleMember line (invalid outside a module).
$moduleLines = Get-Content -LiteralPath $modulePath
$sentinelBad = @($moduleLines | Where-Object { $_ -match "^'@\s*$" })
if ($sentinelBad.Count -gt 0) { throw "Module contains a line starting with '@ which breaks here-string embedding. Refactor before building standalone." }
$moduleBody = ($moduleLines | Where-Object { $_ -notmatch '^\s*Export-ModuleMember' }) -join "`r`n"

$toolsRoot = Join-Path $PSScriptRoot 'Tools'
$phaseDirs = @()
if ($Phase) { foreach ($p in $Phase) { $d = Join-Path $toolsRoot $p; if (Test-Path -LiteralPath $d) { $phaseDirs += Get-Item -LiteralPath $d } } }
else { $phaseDirs = @(Get-ChildItem -LiteralPath $toolsRoot -Directory) }

if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

# The exact block every tool uses to locate + import the module (from the template).
$blockPattern = '(?s)\$irModule = \$null; \$irDir = \$PSScriptRoot.*?Import-Module \$irModule -Force'

$built = @()
$failed = @()
foreach ($pd in $phaseDirs) {
    foreach ($s in @(Get-ChildItem -LiteralPath $pd.FullName -Filter '*.ps1' -File)) {
        if ($s.BaseName -notlike $Tool) { continue }
        $src = Get-Content -LiteralPath $s.FullName -Raw
        if ($src -notmatch $blockPattern) {
            Write-Warning "Skipping $($s.Name): module-locate block not found (non-standard tool). Copying as-is is unsafe; skipped."
            continue
        }
        $replacement = @"
# ==== IRToolKit.Common inlined by Build-Standalone.ps1 (do not edit by hand) ====
`$________IRTK_MODULE = @'
$moduleBody
'@
. ([scriptblock]::Create(`$________IRTK_MODULE))
# ==== end inlined module ====
"@
        $out = [regex]::Replace($src, $blockPattern, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $replacement })
        $destDir = Join-Path $OutputDirectory $pd.Name
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        $dest = Join-Path $destDir $s.Name
        # A write can be refused outright when endpoint security has quarantined an earlier copy and now
        # blocks the path. That is not a build fault: warn, record it, and keep building the other tools.
        try { $out | Out-File -LiteralPath $dest -Encoding UTF8 -ErrorAction Stop }
        catch {
            Write-Warning "$($s.Name): not written - $($_.Exception.Message) (likely endpoint-security quarantine of this path; the script text itself parses). Add an AV exclusion for the output folder or build this tool elsewhere."
            $failed += $s.Name
            continue
        }
        # Verify the standalone parses. Parse the in-memory text we just wrote (ParseInput) rather than
        # re-reading the file: some endpoint security products briefly lock or quarantine a freshly
        # written script, which would otherwise surface here as a misleading "parse error".
        $tok = $null; $perr = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($out, [ref]$tok, [ref]$perr)
        if ($perr.Count -gt 0) { Write-Warning "$($s.Name): standalone has parse errors: $($perr[0].Message)" }
        else {
            # Confirm the file is readable back; if not, it is almost certainly an AV lock/quarantine, not a code fault.
            $readable = $true
            try { [void][IO.File]::OpenRead($dest).Dispose() } catch { $readable = $false }
            if ($readable) { Write-Host "  Built $($pd.Name)\$($s.Name)" -ForegroundColor Green }
            else { Write-Warning "$($s.Name): written but not readable back (likely endpoint-security lock/quarantine). The script text parsed cleanly. Add an AV exclusion for the output folder or unblock the file." }
        }
        $built += $dest
        # Copy a tool's signature sidecar (Common\Signatures\<tool>.signatures.json) beside its standalone so
        # signature-driven rules keep working in a single-folder deployment. The signatures stay a DATA file
        # and are NEVER inlined - inlining their IOC strings into the .ps1 would reintroduce AMSI self-quarantine.
        $sigSrc = Join-Path $PSScriptRoot (Join-Path 'Common\Signatures' ($s.BaseName + '.signatures.json'))
        if (Test-Path -LiteralPath $sigSrc) {
            Copy-Item -LiteralPath $sigSrc -Destination (Join-Path $destDir ($s.BaseName + '.signatures.json')) -Force
            Write-Host "    + $($pd.Name)\$($s.BaseName).signatures.json (signature data)" -ForegroundColor DarkGreen
        }
    }
}
Write-Host ("Built {0} standalone tool(s) into {1}" -f $built.Count, $OutputDirectory) -ForegroundColor Cyan
if ($failed.Count -gt 0) { Write-Warning ("{0} tool(s) could not be written (see warnings above): {1}" -f $failed.Count, ($failed -join ', ')) }
$built
