<#
.SYNOPSIS
    Detects Golden gMSA activity - theft of the KDS root key and abuse of group Managed Service Account
    (gMSA) passwords - from Windows Security and PowerShell event logs.

.DESCRIPTION
    A gMSA password is never stored; the DC computes it on demand from the forest KDS root key (held in
    CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...) plus the
    gMSA's SID and password id. Only principals listed in a gMSA's msDS-GroupMSAMembership may retrieve
    its password (exposed through the computed msDS-ManagedPassword attribute).

    In a "Golden gMSA" attack an adversary who can read the KDS root key once (Domain Admin / SYSTEM on a
    DC, or by replicating the secret) can then compute the password of ANY gMSA in the forest OFFLINE and
    indefinitely - without being in the allowed-principals list and without ever touching the DC again.
    The single detectable moment is the KDS root key read; afterwards the forgery is offline and silent.
    Tools: GoldenGMSA, gMSADumper, DSInternals.

    Detection logic (each rule -> New-IRFinding):
      * RULE 1 (Critical) - the KDS root key was read by a principal that is NOT a domain controller
        (Security 4662 whose ObjectName is under "Master Root Keys" / "Group Key Distribution Service").
        DCs read it constantly as part of gMSA operation and are excluded; any other reader is stealing
        the key that lets every gMSA password be forged offline.
      * RULE 2 (High) - a gMSA's password blob (msDS-ManagedPassword) was retrieved by a USER account
        (4662 whose Properties contain the msDS-ManagedPassword GUID). gMSA passwords are read by the
        service host's MACHINE account; a human/user reading the blob is the gMSADumper-style direct
        retrieval. Machine-account reads are only reported with -IncludeMachineReaders (and -ExpectedGmsaReader
        suppresses known service hosts); DC readers are always excluded.
      * RULE 3 (High) - a gMSA's retrieval principals were changed (5136 Value-Added on
        msDS-GroupMSAMembership): the actor granted an account the right to retrieve the gMSA password - a
        persistence / privilege-to-credential step.
      * RULE 4 (High) - named Golden gMSA / gMSA-dumping tooling in a PowerShell script block (4104):
        GoldenGMSA, Get-GoldenGMSAPassword, gMSADumper, msKds-RootKeyData, ConvertFrom-ADManagedPasswordBlob,
        Get-ADDBServiceAccount. Dual-use RSAT strings (Get-ADServiceAccount, msDS-ManagedPassword,
        Get-KdsRootKey) are intentionally NOT signatures - they are routine administration.

    Required audit policy / log sources (domain controllers):
      * DS Access > Audit Directory Service Access = Success, with a SACL on the KDS root key object /
        the Group Key Distribution Service container and on the gMSA objects -> 4662.
      * DS Access > Audit Directory Service Changes = Success (SACL) -> 5136.
      * Optional: PowerShell Script Block Logging (4104) for RULE 4.
      NOTE: the KDS root key object is NOT audited by default; without a SACL on it RULE 1 has nothing to
      read. Consider adding auditing to the Group Key Distribution Service container as a tripwire.

    Known false positives:
      * Domain controllers read the KDS root key and compute gMSA passwords as normal operation - they are
        excluded via -DomainController / machine-account-is-DC checks. Supply your DCs so legitimate reads
        are not flagged.
      * Backup / directory-sync products may read KDS material; confirm the reader before escalating.

.PARAMETER ComputerName
    Remote computer to read the live Security log from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders) to analyse offline.
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
.PARAMETER NoADLookup
    Skip live Active Directory look-ups.
.PARAMETER DomainController
    Domain controller names / IPs. Readers that are DCs are excluded from RULE 1 / RULE 2 (DCs read KDS
    material and compute gMSA passwords normally); offline, this also supplies the DC list.
.PARAMETER ExpectedGmsaReader
    Machine / service accounts known to legitimately retrieve gMSA passwords; suppressed in RULE 2.
.PARAMETER IncludeMachineReaders
    Also report machine-account reads of msDS-ManagedPassword in RULE 2 (off by default, as machine reads
    are the normal path and are numerous).

.EXAMPLE
    .\Find-GoldenGMSA.ps1 -Path C:\Evidence\DC01-Security.evtx -DomainController DC01,DC02
    Hunt KDS root key theft and gMSA password abuse in an exported DC Security log.

.EXAMPLE
    .\Find-GoldenGMSA.ps1 -StartTime (Get-Date).AddDays(-30) -ExpectedGmsaReader SQLSVC01$,WEB01$ -OutputPath C:\Evidence\Out -Format All

.NOTES
    ATT&CK : T1555 (Credentials from Password Stores) - KDS root key / gMSA credential theft
    Events : 4662, 5136 (Security), 4104 (PowerShell Operational)
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
    [switch]$NoADLookup,
    [string[]]$DomainController,

    [string[]]$ExpectedGmsaReader,
    [switch]$IncludeMachineReaders
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
    if (-not $toolName) { $toolName = 'Find-GoldenGMSA' }
    $technique = 'T1555'; $techniqueName = 'Golden gMSA (KDS root key / gMSA credential theft)'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
    $expectedReaderSet = @{}
    foreach ($x in @($ExpectedGmsaReader)) {
        if ($x) { $xb = [string]$x; if ($xb -match '^(.+)@[^@]+$') { $xb = $matches[1] }; if ($xb -match '\\([^\\]+)$') { $xb = $matches[1] }; $expectedReaderSet[$xb.Trim().ToLowerInvariant().TrimEnd('$')] = $true }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Golden gMSA (KDS root key theft / gMSA password abuse)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $managedPwGuid = 'e362ed86-b728-0842-b27d-2dea7a9df218'   # msDS-ManagedPassword (gMSA password blob)
    $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - DC readers cannot be excluded; findings carry a caveat.' -Level Detail }

    function Get-GGBareName {
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)@[^@]+$') { $u = $matches[1] }
        if ($u -match '\\([^\\]+)$') { $u = $matches[1] }
        return $u.Trim()
    }
    function Test-GGIsDcReader {
        param([string]$Subject)
        if ($dcLookup.Count -eq 0) { return $false }
        return (Test-IRDomainController -Lookup $dcLookup -Value (Get-GGBareName $Subject))
    }
    function Get-GGDnLeaf {
        param([string]$Dn)
        if (-not $Dn) { return $null }
        if ($Dn -match '^\s*CN=([^,]+)') { return $matches[1].Trim() }
        return $Dn.Trim()
    }

    $ds = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4662)
    Write-IRStatus "Loaded $($ds.Count) 4662 event(s)" -Level Detail

    foreach ($e in $ds) {
        $subject = [string]$e.SubjectUserName
        if (-not $subject) { continue }
        $objName = [string]$e.ObjectName
        $noDcCaveat = if ($dcLookup.Count -eq 0) { ' No DC list supplied, so a legitimate DC reader could not be excluded; supply -DomainController.' } else { '' }

        # ---- RULE 1: KDS root key read by a non-DC ----
        $isKds = ($objName -match '(?i)CN=Master Root Keys' -or $objName -match '(?i)Group Key Distribution Service')
        if ($isKds) {
            if (Test-GGIsDcReader $subject) { continue }   # DCs read KDS material normally
            $conf = if ($dcLookup.Count -eq 0) { 'Medium' } else { 'High' }
            $desc = ("{0} accessed the KDS root key object '{1}' (event 4662) on {2}. The KDS root key is the forest secret from which every gMSA password is derived; reading it - by anyone other than a domain controller - lets the attacker compute ANY gMSA password offline and indefinitely (Golden gMSA).{3}" -f `
                    $subject, $objName, $e.Computer, $noDcCaveat)
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence $conf `
                        -Technique $technique -TechniqueName $techniqueName -Title 'KDS root key read by a non-DC (Golden gMSA key theft)' `
                        -Description $desc -Account $subject -Target $objName -Computer $e.Computer `
                        -EventIds 4662 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Treat every gMSA in the forest as compromised: their passwords can now be computed offline. Roll the affected gMSA credentials (and plan a KDS root key rotation, which requires recreating/ reprovisioning gMSAs), investigate how the actor obtained DC-level read access, and add a SACL tripwire on the Group Key Distribution Service container.'))
            continue
        }

        # ---- RULE 2: gMSA managed-password blob read ----
        $guids = @(Get-IRGuidsFromText ([string]$e.Properties))
        if ($guids -contains $managedPwGuid) {
            if (Test-GGIsDcReader $subject) { continue }                 # DC computes/returns the blob - normal
            $readerBare = (Get-GGBareName $subject).ToLowerInvariant().TrimEnd('$')
            if ($expectedReaderSet.ContainsKey($readerBare)) { continue }  # known service host
            $isMachine = Test-IRMachineAccount $subject
            if ($isMachine -and -not $IncludeMachineReaders) { continue }  # machine reads are the normal path
            $sev = if ($isMachine) { 'Medium' } else { 'High' }
            $who = if ($isMachine) { 'machine account' } else { 'user account' }
            $desc = ("{0} ({1}) retrieved a gMSA managed-password blob (msDS-ManagedPassword) on {2} (event 4662, target {3}). A user account reading a gMSA password blob is the gMSADumper-style direct retrieval; it should normally only be read by the service's authorised host machine account.{4}" -f `
                    $subject, $who, $e.Computer, $objName, $noDcCaveat)
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'gMSA managed-password blob retrieved' `
                        -Description $desc -Account $subject -Target $objName -Computer $e.Computer `
                        -EventIds 4662 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the reader is an authorised host for this gMSA (add it to -ExpectedGmsaReader if so). If not, treat the gMSA as compromised, roll its credential, and review msDS-GroupMSAMembership on the account.'))
        }
    }

    # ---- RULE 3: gMSA retrieval principals changed (5136 msDS-GroupMSAMembership) ----
    $mods = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136 | Where-Object { ([string]$_.AttributeLDAPDisplayName) -ieq 'msDS-GroupMSAMembership' })
    foreach ($e in $mods) {
        $op = [string]$e.OperationType
        if ($op -match '14675' -or $op -match 'Value Deleted') { continue }   # additions grant retrieval
        $actor = [string]$e.SubjectUserName; if (-not $actor) { $actor = '-' }
        $objDn = [string]$e.ObjectDN
        $desc = ("{0} changed the gMSA retrieval principals (msDS-GroupMSAMembership, PrincipalsAllowedToRetrieveManagedPassword) on {1} (event 5136). Granting an account this right lets it retrieve the gMSA's password - a persistence / privilege-to-credential step." -f `
                $actor, $objDn)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'gMSA password-retrieval principals changed (msDS-GroupMSAMembership)' `
                    -Description $desc -Account $actor -Target $objDn -Computer $e.Computer `
                    -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the change was authorised. If not, remove the added principal from msDS-GroupMSAMembership, treat the gMSA as compromised, and roll its credential.'))
    }

    # ---- RULE 4: Golden gMSA tooling in PowerShell script blocks (4104) ----
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        # Attack-specific signatures only. Dual-use RSAT / admin strings (Get-ADServiceAccount,
        # msDS-ManagedPassword, Get-KdsRootKey) are DELIBERATELY excluded: they appear in routine gMSA
        # administration and would flood High-severity false positives. The KDS read (RULE 1) and the
        # user-account managed-password retrieval (RULE 2) are the behavioural signals; this rule only
        # catches named offensive tooling.
        $sigs = 'GoldenGMSA', 'Get-GoldenGMSAPassword', 'gMSADumper', 'msKds-RootKeyData', 'ConvertFrom-ADManagedPasswordBlob', 'Get-ADDBServiceAccount'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Golden gMSA / gMSA credential tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched Golden gMSA tooling signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this. Correlate with KDS root key reads (4662) and gMSA managed-password retrievals (RULE 1 / RULE 2) from the same host and window.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
