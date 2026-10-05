. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$module = Join-Path $PSScriptRoot '..\..\Common\IRToolKit.Common.psm1'
$sample = Join-Path $PSScriptRoot '..\SampleData\Common\MalformedXmlRecord.evtx'
Import-Module $module -Force
Set-IRQuiet $true

# The fixture (see SampleData\Common\README.md) makes an event-ID-filtered Get-WinEvent throw a TERMINATING
# "The specified XML text was not well-formed" EventLogException. Before the isolated file read that error
# escaped every tool's -ErrorVariable AND the file's good events were dropped.
$before = $global:Error.Count
$recs = @(Get-IRWinEvent -Path $sample -EventId 4742, 4743 -ErrorVariable readErr 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
Assert-IR (@($readErr).Count -eq 0) 'filtered read of a malformed-record evtx leaks no error'
Assert-IR ($global:Error.Count -eq $before) 'filtered read adds nothing to $Error'
Assert-IR ($recs.Count -eq 3) 'all 3 events recovered (none dropped)'
$flat = @($recs | ConvertFrom-IRWinEvent)
Assert-IR ($flat.Count -eq 3 -and (@($flat | Where-Object { $_.EventId -in 4742, 4743 }).Count -eq 3)) 'recovered records flatten and carry the requested IDs'

# The other file-read paths stay clean through the isolated read.
$none = @(Get-IRWinEvent -Path $sample -EventId 9999 -ErrorVariable e2 2>&1)
Assert-IR ($none.Count -eq 0 -and @($e2).Count -eq 0) 'no-matching-events is silent'
$one = @(Get-IRWinEvent -Path $sample -MaxEvents 1 -ErrorVariable e3 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
Assert-IR ($one.Count -eq 1 -and @($e3).Count -eq 0) 'MaxEvents honoured through the isolated read'
$t0 = $flat[0].TimeCreated
$win = @(Get-IRWinEvent -Path $sample -EventId 4742, 4743 -StartTime $t0.AddMinutes(-5) -EndTime $t0.AddMinutes(5) -ErrorVariable e4 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
Assert-IR ($win.Count -ge 1 -and @($e4).Count -eq 0) 'time window honoured through the isolated read'
$dir = @(Get-IRWinEvent -Path (Split-Path $sample -Parent) -EventId 4742 -ErrorVariable e5 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
Assert-IR ($dir.Count -ge 1 -and @($e5).Count -eq 0) 'folder read covers the fixture without errors'

# More than one ID chunk (> 20 IDs) on the malformed file: the first chunk falls back, the remaining chunks are
# served by ONE extra unfiltered pass - every event still comes back exactly once.
$ids = @(1..19) + @(4742, 4743) + @(5000..5030)
$multi = @(Get-IRWinEvent -Path $sample -EventId $ids -ErrorVariable e7 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
Assert-IR ($multi.Count -eq 3 -and @($e7).Count -eq 0) 'multi-chunk read of the malformed file returns all 3 events once, error-free'

# A file that is not an .evtx at all must produce a visible warning (not silence) and still no error.
$garbage = Join-Path $env:TEMP ('irtk-notevtx-' + [guid]::NewGuid().ToString('n') + '.evtx')
[IO.File]::WriteAllBytes($garbage, [Text.Encoding]::ASCII.GetBytes('this is not an event log file at all'))
try {
    $g = @(Get-IRWinEvent -Path $garbage -EventId 4742 -ErrorVariable e6 -WarningVariable w6 3>$null 2>&1 | Where-Object { $_ -is [System.Diagnostics.Eventing.Reader.EventRecord] })
    Assert-IR ($g.Count -eq 0 -and @($e6).Count -eq 0 -and ((@($w6) -join ' ') -like '*ElfFile*')) 'non-evtx file: no events, no error, one visible warning'
}
finally { Remove-Item -LiteralPath $garbage -Force -ErrorAction SilentlyContinue }

# A tool reading the file end-to-end must be error-free and emit only findings.
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-DCShadow.ps1'
$r = Invoke-IRToolSafely -ToolPath $tool -Arguments @{ Path = $sample; Quiet = $true; DomainController = @('DC01') }
Assert-IR ($r.Errors.Count -eq 0) 'tool run over the malformed evtx has no stray errors'
Assert-IR ($r.Extraneous.Count -eq 0) 'tool emits only finding objects'

Complete-IRTest
