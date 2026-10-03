# IRToolKit tool conventions

Every tool in this kit is a standalone PowerShell script that an incident responder can run on a
domain controller, a member server, a workstation, or offline against exported `.evtx` files.
Consistency matters more than cleverness: an analyst who has used one tool must be able to use all of them.

## Hard requirements

1. **Windows PowerShell 5.1 and PowerShell 7 compatible.** No ternary (`? :`), no `??`, no `?.`,
   no `ForEach-Object -Parallel`, no `-Oldest`-only tricks, no classes with inheritance surprises.
   ASCII only in source files (no smart quotes, em dashes, emoji, or box drawing characters).
2. **Standard parameter block** (copy from `Templates/Find-Template.ps1`). Every tool accepts the same
   source parameters: `-ComputerName`, `-Credential`, `-Path` (evtx), `-InputObject` / `-InputPath`
   (pre-flattened events), `-StartTime`, `-EndTime`, `-MaxEvents`, `-OutputPath`, `-Format`, `-Quiet`.
   Tool-specific thresholds go after those and must have sane defaults.
3. **Import the common module once** at the top of `begin {}` using the walk-up block from the template
   (it searches for `Common\IRToolKit.Common.psm1` up to five levels above `$PSScriptRoot`, so the tool works
   from `Tools\AD\`, `Templates\`, or a copied folder tree). Copy the block verbatim; do not hard-code `..\..`.
4. **Collect events only through `Get-IRSourceEvents`** (never call `Get-WinEvent` directly) so that
   live, remote, `.evtx` and pre-parsed JSON all work. Wrap every call in `@()`.
5. **Emit findings only through `New-IRFinding`** and finish with `Complete-IRTool`.
   The script's pipeline output is the array of finding objects. Nothing else may be written to the
   output stream. Status text goes through `Write-IRStatus` (suppressed by `-Quiet`).
6. **Comment-based help** with `.SYNOPSIS`, `.DESCRIPTION` (attack summary, what the detection looks for,
   required audit policy and log sources, known false positives), `.PARAMETER` for each tool-specific
   parameter, at least two `.EXAMPLE`s (live and `-Path`), and `.NOTES` listing ATT&CK IDs and event IDs.
7. **Never throw on empty input.** Zero events -> zero findings -> exit cleanly. Missing properties on
   an event object must not break the tool (use `$e.PSObject.Properties['Name']` checks or just rely on
   `$null` propagation; StrictMode is OFF in the module and must stay off in tools).
8. **Performance:** use `System.Collections.Generic.List[object]` for accumulation, hashtables for
   grouping (`Group-IRByKey`), and `Find-IRBurst` for time-window logic. Never nest loops over the full
   event set (O(n^2)). Tools must handle 500k events of a single ID without pathological behaviour.
9. **No destructive or network-noisy actions.** Tools read logs; optional AD look-ups via the module
   helpers are read-only and must be guarded by `Test-IRAdAvailable` and a `-NoADLookup` switch.
10. **Every tool ships with a synthetic sample and a test**: `Tests/SampleData/AD/<ToolName>.json`
    (both malicious and benign events) and `Tests/AD/<ToolName>.Test.ps1` using the mini harness in
    `Tests/IRTest.Common.ps1`. The test must assert that (a) the malicious sample produces the expected
    findings (title / technique / severity / account), (b) the benign subset produces no finding,
    (c) an empty input produces no error and no findings.

## Severity and confidence guidance

| Severity | Use when |
|---|---|
| Critical | Near-certain compromise of domain-level secrets or control (DCSync by non-DC, DCShadow, KRBTGT abuse, Zerologon success, Golden/Silver ticket evidence, ntds.dit extraction, Skeleton Key). |
| High | Strong attack signal that needs immediate triage (Kerberoast burst, AS-REP roast burst, privileged group add, shadow credential add, RBCD write, LSASS dump, ESC1 request, password spray hitting many accounts). |
| Medium | Suspicious but plausible in some environments (single RC4 service ticket request, delegation flag change, PKINIT logon for an account that normally uses a password, SAM enumeration from a workstation). |
| Low | Weak signal / hygiene (DES or RC4 enabled on an account, pre-auth disabled, single failed DCSync attempt from a service account). |
| Informational | Context the analyst should see but which is not itself suspicious (audit policy gaps, log retention window, baseline statistics). |

Confidence reflects how specific the evidence is (High = the event pattern is almost exclusively produced
by the attack; Low = many legitimate causes).

## Finding fields

`New-IRFinding` parameters: `-Tool` (script base name), `-Severity`, `-Confidence`, `-Title` (short, no trailing period),
`-Description` (what was seen, with the key numbers), `-Technique` (`T1558.003`), `-TechniqueName`,
`-Account` (the principal that performed or was targeted), `-SourceIp`, `-SourceHost`, `-Target` (service, group, object DN),
`-Computer` (log source), `-EventIds`, `-Evidence` (array of flattened events, cap at 200 per finding, keep the first/last),
`-Recommendation` (one or two concrete triage steps).

## Event objects

`Get-IRSourceEvents` returns flattened `IRToolKit.Event` objects. Base properties:
`TimeCreated` ([datetime]), `EventId` ([int]), `Computer`, `ProviderName`, `LogName`, `RecordId`, `Level`,
`AuditResult` ('Success' / 'Failure' / $null), then every `<Data Name="...">` element from EventData as a
property with the same name (e.g. `TargetUserName`, `IpAddress`, `TicketEncryptionType`, `GrantedAccess`).
Hex fields arrive as strings exactly as logged (`0x17`, `0x40810000`). Use the module decoders:
`ConvertTo-IRHexString`, `ConvertTo-IRInt`, `Test-IRWeakKerberosEncryption`, `ConvertFrom-IRKerberosEncryptionType`,
`ConvertFrom-IRKerberosStatus`, `ConvertFrom-IRPreAuthType`, `ConvertFrom-IRTicketOptions`, `ConvertFrom-IRLogonType`,
`ConvertFrom-IRNtStatus`, `ConvertFrom-IRSamUac`, `Compare-IRSamUac`, `ConvertFrom-IRLdapUac`,
`ConvertFrom-IRUacChangeString`, `ConvertFrom-IRDsAccessMask`, `Get-IRGuidsFromText`, `Resolve-IRGuidName`,
`ConvertTo-IRIpAddress`, `Test-IRLocalIp`, `Test-IRMachineAccount`, `Get-IRAccountKey`, `Test-IRPrivilegedGroup`,
`Get-IRPrivilegedGroupName`, `Get-IRReferenceTable`.

AD helpers (read-only, all return $null / empty when not domain joined): `Test-IRAdAvailable`, `Get-IRDomainControllers`,
`Get-IRDomainControllerLookup`, `Test-IRDomainController`, `Get-IRAdObject`, `Get-IRSchemaAttributeGuid`, `Resolve-IRSchemaGuid`.

Analysis helpers: `Find-IRBurst` (sliding window; `-GroupBy`, `-DistinctProperty`, `-WindowMinutes`, `-Threshold`),
`Group-IRByKey`, `Test-IRPatternMatch`.

Important PowerShell gotchas (all learned the hard way in this kit):
- Functions that return collections unroll them. Always wrap the *call* in `@()`: `$events = @(Get-IRSourceEvents ...)`,
  `$bursts = @(Find-IRBurst ...)`. Do not wrap a variable that may already be `$null`.
- Never `... | Select-Object -First N` on a plain array inside a function: Windows PowerShell 5.1 leaks a
  `StopUpstreamCommandsException` to the error stream. Use the module helper `Get-IRFirst $array N` (always returns an array).
- `@($hashtable[$key])` where the value is a `List[object]` of typed objects throws "Argument types do not match" in
  PS 5.1. `Group-IRByKey` returns hashtable values that are `List[object]`. Use `$groups[$key].ToArray()` (or iterate with
  `foreach`) instead of `@($groups[$key])`.
- Suppressing expected errors from a live cmdlet so they do NOT reach a caller's `-ErrorVariable`: neither
  `-ErrorAction SilentlyContinue` nor `-ErrorAction Stop`/try-catch is enough (both still record the error). Use
  `SomeCmdlet ... -ErrorVariable local 2>$null` and inspect `$local` yourself (this is how `Get-IRWinEvent` does it), or
  `-ErrorAction Ignore` when you do not need the error object. A caught .NET *method* exception (e.g. `GetCurrentDomain()`
  on a non-domain host) also leaks to `-ErrorVariable`; gate such calls behind a cheap non-throwing probe
  (`Test-IRAdAvailable`) instead of relying on try-catch. `Get-IRDomainControllers` already does this.
- `Test-IRMachineAccount` accepts UPN (`NAME$@REALM`) and `DOMAIN\NAME$` forms, so you may pass `TargetUserName` directly.

## Multiple log sources in one tool

Call `Get-IRSourceEvents` once per (LogName, EventId set). Example: Security 4769 plus
Sysmon 1 (`-LogName 'Microsoft-Windows-Sysmon/Operational' -ProviderName 'Microsoft-Windows-Sysmon'`).
In `-Path` mode the LogName filter is applied to the `LogName` property of each record, so an analyst can pass
`Security.evtx` and `Sysmon.evtx` together. If a tool needs the rendered message text (events whose data is not
named, e.g. Netlogon 5827-5831), pass `-IncludeMessage` and fall back to `$e.Message` (may be `$null` offline).

## Domain controller awareness

Tools that must exclude DC-to-DC activity (DCSync, replication, machine-account NTLM) call
`$dcLookup = Get-IRDomainControllerLookup -Additional $DomainController` and expose a `-DomainController <string[]>`
parameter so the analyst can supply DC names/IPs when running offline. `Test-IRDomainController -Lookup $dcLookup -Value $x`
returns `$false` when the lookup is empty, so document in the finding description when DC exclusion was not possible.

## Sample data (`Tests/SampleData/AD/<Tool>.json`)

A JSON array of flattened events. Required properties per event: `TimeCreated` (ISO 8601 string),
`EventId`, `Computer`, `LogName`, `ProviderName`, `AuditResult` plus the exact EventData field names of the real event.
Use realistic values (domain `CORP`, DCs `DC01`/`DC02` at `10.10.10.11`/`10.10.10.12`, workstations `WS-xxx`
at `10.10.20.x`, attacker host at `10.10.20.66`). Spread timestamps realistically (seconds apart within a burst,
hours apart for benign noise). Include benign look-alike events that must NOT fire. Put a top-level `_comment`
property in the first event or keep a sibling `<Tool>.md` describing what each block represents.

## Test script (`Tests/AD/<Tool>.Test.ps1`)

```powershell
. (Join-Path $PSScriptRoot '..\IRTest.Common.ps1')
$tool = Join-Path $PSScriptRoot '..\..\Tools\AD\Find-Kerberoasting.ps1'
$sample = Join-Path $PSScriptRoot '..\SampleData\AD\Find-Kerberoasting.json'

$findings = @(& $tool -InputPath $sample -Quiet)
Assert-IR ($findings.Count -ge 1) 'malicious sample produces findings'
Assert-IR (@($findings | Where-Object Technique -eq 'T1558.003').Count -ge 1) 'technique tagged'
Assert-IR (@($findings | Where-Object { $_.Account -like '*svc_attacker*' }).Count -eq 0) 'benign account not flagged'

$benign = @(Import-IREvents -Path $sample | Where-Object { $_.TargetUserName -ne 'jdoe' })
Assert-IR (@(& $tool -InputObject $benign -Quiet).Count -eq 0) 'benign subset is clean'
Assert-IR (@(& $tool -InputObject @() -Quiet).Count -eq 0) 'empty input is clean'
Complete-IRTest
```

Run everything with `Tests\Invoke-IRTests.ps1`.

## Layout

```
IRToolKit/
  Common/            shared module + format file
  Docs/              conventions, coverage matrix, event reference, audit policy requirements
  Templates/         Find-Template.ps1 (copy this to start a new tool)
  Tools/AD/          one script per detection (this delivery)
  Tools/<Phase>/     future phases (InitialAccess, Execution, Persistence, PrivilegeEscalation,
                     DefenseEvasion, CredentialAccess, Discovery, LateralMovement, Collection,
                     CommandAndControl, Exfiltration, Impact)
  Tests/             harness, per-tool tests, sample data
  Invoke-IRHunt.ps1  runner that executes every tool in a phase and builds one consolidated report
  Build-Standalone.ps1  inlines the module into each tool for single-file deployment
```
