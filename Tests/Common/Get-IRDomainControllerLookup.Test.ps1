. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$module = Join-Path $PSScriptRoot '..\..\Common\IRToolKit.Common.psm1'
Import-Module $module -Force
Set-IRQuiet $true

# -NoDiscovery is what every tool's -NoADLookup maps to: build the DC lookup from -Additional only,
# with the same name-variant expansion as discovery, and never touch live AD or its cache.
$before = $global:Error.Count
$lk = Get-IRDomainControllerLookup -Additional @('DC01', 'dc02.corp.local', '10.10.20.5') -NoDiscovery
Assert-IR ($global:Error.Count -eq $before) '-NoDiscovery adds nothing to $Error'
Assert-IR ($lk.ContainsKey('dc01') -and $lk.ContainsKey('dc01$')) 'short name expands to name + machine account'
Assert-IR ($lk.ContainsKey('dc02.corp.local') -and $lk.ContainsKey('dc02') -and $lk.ContainsKey('dc02$')) 'FQDN expands to FQDN + short + machine account'
Assert-IR ($lk.ContainsKey('10.10.20.5')) 'IP entries are kept'
Assert-IR (Test-IRDomainController -Lookup $lk -Value 'DC02$') 'machine-account form matches'
Assert-IR (Test-IRDomainController -Lookup $lk -Value '::ffff:10.10.20.5') 'IPv4-mapped IP form matches'
Assert-IR (-not (Test-IRDomainController -Lookup $lk -Value 'WS-10')) 'non-DC does not match'

# -NoDiscovery with no -Additional must be EMPTY even if a previous discovery populated the module
# cache (a prior live run must not leak into a -NoADLookup call).
$null = Get-IRDomainControllerLookup -Additional @('cachedc')          # may populate the discovery cache
$empty = Get-IRDomainControllerLookup -NoDiscovery
Assert-IR ($empty.Count -eq 0) '-NoDiscovery with no -Additional is empty (cache not consulted)'

Complete-IRTest
