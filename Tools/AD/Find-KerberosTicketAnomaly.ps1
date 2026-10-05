<#
.SYNOPSIS
    Detects forged / stolen Kerberos tickets (Golden Ticket, Silver Ticket, Pass-the-Ticket)
    from Windows Security and PowerShell event logs.

.DESCRIPTION
    Attackers who obtain the right key material can mint or replay Kerberos tickets instead of
    authenticating normally:
      * GOLDEN TICKET  - a TGT forged with the stolen krbtgt hash. It grants access to anything and
        is often minted with anomalous properties: RC4 (0x17) encryption in a domain that otherwise
        uses AES, an absurd lifetime, a blank, foreign or lower-case realm, or the krbtgt account appearing as a
        client principal.
      * SILVER TICKET  - a TGS forged for one service and signed with that service account's hash.
        It shows up as a 4769 service-ticket request for a principal that never obtained a TGT
        (no preceding 4768 AS-REQ), because the TGT was injected rather than issued by the KDC.
      * PASS-THE-TICKET - a ticket stolen from one host and replayed from another. Like a silver
        ticket, the tell-tale is service-ticket activity with no matching AS-REQ on the KDC.

    This tool is heuristic. Offline it cannot know the environment baseline, so confidence is kept
    deliberately honest and false positives are documented per rule.

    Detection logic:
      * Sources: Security 4768 (AS-REQ / TGT) and 4769 (TGS). 4770/4624/4672 may enrich but are not
        required. PowerShell 4104 is used for tooling signatures.
      * RULE 1 (High / Medium) - per-principal RC4 encryption downgrade: a 4768 TGT issued with RC4
        (0x17/0x18) for a principal that is otherwise AES-capable. AES-capability is shown either by an
        AES (0x11-0x14) TGT for the same principal, OR by an AES service ticket (4769) that principal
        requested as a client - the latter catches OVERPASS-THE-HASH, where the only TGTs are RC4 (the
        AS-REQ used a cracked / forged RC4 key, e.g. from a Kerberoast) but the account's own service
        traffic is AES, so there is no AES TGT to compare against. Because the baseline is unknown offline,
        only a same-principal downgrade is flagged. A non-upper-case TGT realm is noted as a further tell.
      * RULE 2 (High when corroborated, else Informational rollup) - service tickets without a preceding
        TGT (possible Silver Ticket / PTT): a principal with 4769 TGS requests but NO successful 4768 TGT
        within -TgtLookbackMinutes before its first TGS. Because a missing in-window TGT is ALSO the normal
        case on a short / windowed log export (the TGT predates the export - the most common real scenario),
        a bare miss is NOT raised per principal. It becomes a per-principal High finding only when
        corroborated by an attacker-associated source IP, an RC4 service ticket, or a blank / mismatched
        realm; all other TGT-less principals are summarised in ONE Informational finding (so a partial
        export cannot flood the report). Only evaluated when the dataset contains some 4768 traffic.
        Machine accounts and cross-realm referral requests (ServiceName 'krbtgt/...') are excluded.
      * RULE 3 (Informational, supporting) - anomalous TGT options / lifetime: a 4768 RC4 TGT that is both
        forwardable and renewable is weak supporting evidence; an explicit lifetime beyond
        -MaxTicketLifetimeYears (when the schema carries one) is escalated. On its own this is not a
        standalone high finding.
      * RULE 4 (Critical / High) - the krbtgt account authenticating as a client: any 4768/4769 whose
        TargetUserName (the requesting principal) is krbtgt. krbtgt never logs on or requests tickets
        for itself; this is near-certain krbtgt-key abuse.
      * RULE 5 (High) - blank or mismatched realm: a 4769 whose TargetDomainName is empty, or differs
        from -ExpectedDomain when supplied. Referrals and machine accounts are excluded.
      * RULE 6 (Medium) - PowerShell 4104 script blocks containing ticket-forging tooling signatures.
      * RULE 7 (High / Medium) - lower / mixed-case client realm in a 4769. The KDC writes the client
        principal of every service ticket it issues as NAME@REALM with the realm in UPPER CASE (it comes
        from the TGT the KDC itself issued). A forged TGT carries the realm exactly as the forger typed it
        (mimikatz /domain:corp.local), so a non-upper-case realm is a cheap Golden Ticket artefact; every
        KDC-issued 4769 in the reference corpora examined was upper case. The source IP feeds RULE 2.

    Required audit policy / log sources:
      * DC: Advanced Audit Policy > Account Logon > Audit Kerberos Authentication Service = Success
        (4768) and Audit Kerberos Service Ticket Operations = Success (4769).
      * Optional: PowerShell Script Block Logging (4104) for Rule 6.

    Known false positives:
      * RULE 1: some applications legitimately request RC4 for specific principals; a mixed RC4/AES
        history can be benign for legacy accounts. Medium confidence reflects this.
      * RULE 2: by far the noisiest rule. A user who obtained their TGT from a different DC whose log
        is not in the dataset will look TGT-less here. Short collection windows, ticket renewals, and
        U2U / S4U flows can all mimic the pattern. Always confirm the AS-REQ is genuinely absent on
        every DC before escalating. Referral TGS (ServiceName 'krbtgt/REALM') are NOT silver tickets
        and are excluded.
      * RULE 3: forwardable+renewable is the default for most normal TGTs, hence supporting-only.
      * RULE 5: multi-domain / multi-forest environments produce legitimate foreign realms; only use
        -ExpectedDomain when the dataset is from a single known domain.
      * RULE 6: broad keyword matches ('golden', 'ptt', 'silver') can hit benign scripts; treat as a
        lead, not proof.
      * RULE 7: a non-Windows Kerberos client whose realm is configured in lower case could in theory
        present such a TGT; AD realms are upper case by definition, so verify the client host rather than
        dismiss the finding. An export whose fields were lower-cased by a SIEM / parser would make every
        principal look forged: when NO upper-case realm exists in the dataset and several principals are
        affected, the rule emits one Informational note and is not evaluated; with a single affected
        principal it reports at Medium / Low with a caveat. Use the native .evtx for this rule.

.PARAMETER ComputerName
    Remote computer to read the live Security log from (default: local machine).
.PARAMETER Credential
    Credential for the remote computer.
.PARAMETER Path
    One or more exported .evtx files (or folders of .evtx) to analyse offline.
.PARAMETER InputObject
    Pre-flattened IRToolKit event objects (from Get-IRSourceEvents / Import-IREvents) via the pipeline.
.PARAMETER InputPath
    JSON / CSV / CliXml file of pre-flattened events (see Export-IREvents).
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
    Suppress console status output. Findings are still returned as objects.
.PARAMETER TgtLookbackMinutes
    How far back (minutes) before a principal's first 4769 TGS a successful 4768 TGT may be and still
    count as normal in RULE 2. Default 10080 (7 days) to cover the renewable TGT lifetime, so long-lived
    or renewed sessions are not false positives.
.PARAMETER ExpectedDomain
    The single domain / realm the dataset is expected to belong to. When supplied, RULE 5 flags any
    4769 whose TargetDomainName does not match it. Leave unset for multi-domain datasets.
.PARAMETER MaxTicketLifetimeYears
    Sanity ceiling (years) for an explicit ticket lifetime in RULE 3 (default 10). Only used when the
    event schema actually carries a lifetime field.

.EXAMPLE
    .\Find-KerberosTicketAnomaly.ps1 -StartTime (Get-Date).AddDays(-7) -ExpectedDomain CORP.LOCAL
    Analyse the local DC Security log for the last 7 days against the CORP.LOCAL realm.

.EXAMPLE
    .\Find-KerberosTicketAnomaly.ps1 -Path C:\Evidence\DC01-Security.evtx -ExpectedDomain CORP.LOCAL -OutputPath C:\Evidence\Out -Format All
    Analyse an exported log and write CSV, JSON and HTML reports.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768,4769} | ConvertFrom-IRWinEvent | .\Find-KerberosTicketAnomaly.ps1

.NOTES
    ATT&CK : T1558.001 (Golden Ticket), T1558.002 (Silver Ticket), T1550.003 (Pass the Ticket)
    Events : 4768, 4769 (Security); 4770, 4624, 4672 (optional context); 4104 (PowerShell Operational)
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

    [int]$TgtLookbackMinutes = 10080,
    [string]$ExpectedDomain,
    [int]$MaxTicketLifetimeYears = 10
)

begin {
    # Locate Common\IRToolKit.Common.psm1 by walking up from the script folder (works from Tools\<Phase>\, Templates\, or a copied tree)
    $irModule = $null; $irDir = $PSScriptRoot
    for ($i = 0; $i -lt 5 -and $irDir; $i++) {
        $candidate = Join-Path $irDir 'Common\IRToolKit.Common.psm1'
        if (Test-Path -LiteralPath $candidate) { $irModule = $candidate; break }
        $irDir = Split-Path -Parent $irDir
    }
    if (-not $irModule) { throw "IRToolKit.Common.psm1 not found above $PSScriptRoot. Keep the folder structure intact." }
    Import-Module $irModule -Force
    $toolName = [IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    if (-not $toolName) { $toolName = 'Find-KerberosTicketAnomaly' }
    $technique = 'T1558.001'; $techniqueName = 'Steal or Forge Kerberos Tickets'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'Forged / stolen Kerberos tickets (Golden / Silver / Pass-the-Ticket)' -Technique @('T1558.001', 'T1558.002', 'T1550.003')
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $tgt = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
    $tgs = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4769)
    Write-IRStatus "Loaded $($tgt.Count) 4768 (TGT) and $($tgs.Count) 4769 (TGS) event(s)" -Level Detail

    $expected = $null
    if ($ExpectedDomain) { $expected = $ExpectedDomain.Trim().ToLowerInvariant() }

    # --- Normalise both event sets once (adds private _ properties; never emits output). ---
    foreach ($e in @($tgt + $tgs)) {
        if ($null -eq $e) { continue }
        $u = [string]$e.TargetUserName
        $bare = $u
        if ($bare -match '^(.+)@') { $bare = $matches[1] }
        elseif ($bare -match '\\(.+)$') { $bare = $matches[1] }
        $bareLower = $bare.ToLowerInvariant().TrimEnd('$')
        $svcLower = ([string]$e.ServiceName).ToLowerInvariant()
        $statusHex = ConvertTo-IRHexString $e.Status
        $isSuccess = (-not $statusHex) -or ($statusHex -eq '0x0') -or ($statusHex -eq '0x')
        $encHex = ConvertTo-IRHexString $e.TicketEncryptionType
        $e | Add-Member -NotePropertyName _Ip -NotePropertyValue (ConvertTo-IRIpAddress $e.IpAddress) -Force
        $e | Add-Member -NotePropertyName _AcctKey -NotePropertyValue (Get-IRAccountKey $e.TargetUserName $e.TargetDomainName) -Force
        $e | Add-Member -NotePropertyName _AcctBare -NotePropertyValue $bareLower -Force
        $e | Add-Member -NotePropertyName _IsSuccess -NotePropertyValue $isSuccess -Force
        $e | Add-Member -NotePropertyName _IsRc4 -NotePropertyValue ($encHex -in @('0x17', '0x18')) -Force
        $e | Add-Member -NotePropertyName _IsAes -NotePropertyValue ($encHex -in @('0x11', '0x12', '0x13', '0x14')) -Force
        $e | Add-Member -NotePropertyName _IsMachine -NotePropertyValue (Test-IRMachineAccount $bare) -Force
        $e | Add-Member -NotePropertyName _IsReferral -NotePropertyValue (($svcLower -like 'krbtgt*') -or ($svcLower -like 'kadmin*')) -Force
    }

    # Source IPs implicated by a high-specificity rule, used to raise RULE 2 confidence (combo).
    $suspiciousIps = @{}

    # --- RULE 4: krbtgt account authenticating as a client principal. Critical. ---
    $krbAsClient = @(@($tgt + $tgs) | Where-Object { $_ -and $_._AcctBare -eq 'krbtgt' })
    if ($krbAsClient.Count -gt 0) {
        foreach ($g in ($krbAsClient | Group-Object { "$($_._AcctKey)|$($_._Ip)" })) {
            $ev = @($g.Group)
            $ids = @($ev | ForEach-Object { [int]$_.EventId } | Select-Object -Unique)
            if ($ev[0]._Ip) { $suspiciousIps[$ev[0]._Ip] = $true }
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                        -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                        -Title 'krbtgt account authenticating as a client' `
                        -Description ("The krbtgt account was seen authenticating as a client principal in {0} Kerberos event(s) from {1}. krbtgt never logs on interactively or requests tickets for itself; this is a near-certain sign of a forged ticket (Golden Ticket) or krbtgt key abuse." -f $ev.Count, $ev[0]._Ip) `
                        -Account ([string]$ev[0].TargetUserName) -SourceIp $ev[0]._Ip -Target 'krbtgt' `
                        -Computer $ev[0].Computer -EventIds $ids -Evidence (Get-IRFirst $ev 200) `
                        -Recommendation 'Treat the domain as compromised: the krbtgt key is almost certainly known to the attacker. Rotate the krbtgt password twice (with replication between resets), hunt for Golden Ticket usage, and isolate the source host.'))
        }
    }

    # --- RULE 1: per-principal RC4 encryption downgrade (RC4 TGT while the same principal is AES-capable). ---
    # AES-capability evidence for a principal comes from TWO sources: an AES TGT (4768) for that principal,
    # OR an AES service ticket (4769) requested BY that principal as a client. The second source catches
    # OVERPASS-THE-HASH, where the only TGTs are RC4 (the AS-REQ used a cracked / forged RC4 key) but the
    # account's own service-ticket traffic is AES - so there is no AES 4768 to compare against, and the
    # original RC4-vs-RC4-4768 test stayed silent. Service-ticket encryption reflects the SERVICE key, so an
    # AES 4769 by the principal independently shows the principal operates in an AES world.
    $aesTgsAcct = @{}   # _AcctKey -> the principal requested AES service ticket(s) as a client
    foreach ($e in @($tgs | Where-Object { $_ -and $_._IsSuccess -and $_._IsAes -and (-not $_._IsMachine) -and (-not $_._IsReferral) -and ($_._AcctBare -ne 'krbtgt') })) {
        $aesTgsAcct[[string]$e._AcctKey] = $true
    }
    $tgtDowngradePool = @($tgt | Where-Object { $_ -and $_._IsSuccess -and ($_._AcctBare -ne 'krbtgt') -and (-not $_._IsMachine) })
    $byAcct = Group-IRByKey -Events $tgtDowngradePool -KeyScript { param($e) $e._AcctKey }
    foreach ($key in $byAcct.Keys) {
        $grp = $byAcct[$key].ToArray()
        $rc4 = @($grp | Where-Object { $_._IsRc4 })
        $aes = @($grp | Where-Object { $_._IsAes })
        $aesViaTgs = ($aes.Count -eq 0) -and $aesTgsAcct.ContainsKey([string]$key)
        if ($rc4.Count -gt 0 -and ($aes.Count -gt 0 -or $aesViaTgs)) {
            foreach ($ip in @($rc4 | ForEach-Object { $_._Ip } | Select-Object -Unique)) { if ($ip) { $suspiciousIps[$ip] = $true } }
            # A lowercase / mixed-case TGT realm (TargetDomainName) is a further forged-key tell: the KDC
            # normalises the realm it issues to upper case, so an RC4 TGT whose realm is not upper case did
            # not come from this KDC in the normal way.
            $rc4Realm = ([string]$rc4[0].TargetDomainName).Trim()
            $realmNote = ''
            if ($rc4Realm -and ($rc4Realm -cne $rc4Realm.ToUpperInvariant())) { $realmNote = (" The RC4 TGT realm is written '{0}' (not upper case), which the KDC never issues - a further sign the key was supplied by a tool." -f $rc4Realm) }
            if ($aesViaTgs) {
                $aesTgsCount = @($tgs | Where-Object { $_ -and $_._IsAes -and ([string]$_._AcctKey -eq [string]$key) }).Count
                $ev = @($rc4 + @(Get-IRFirst @($tgs | Where-Object { $_ -and $_._IsAes -and ([string]$_._AcctKey -eq [string]$key) }) 3))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                            -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                            -Title 'Kerberos encryption downgrade (RC4 TGT for an AES-capable principal - possible overpass-the-hash)' `
                            -Description ("Principal {0} obtained {1} RC4 TGT(s) (event 4768) from {2}, yet the same principal requested {3} AES service ticket(s) (event 4769) in this dataset - it has no AES TGT at all. A principal whose service-ticket traffic is AES but whose TGT is RC4 is the overpass-the-hash pattern: the AS-REQ was made with a cracked / forged RC4 key (e.g. from a Kerberoast) while the account is otherwise an AES principal.{4}" -f ([string]$rc4[0].TargetUserName), $rc4.Count, $rc4[0]._Ip, $aesTgsCount, $realmNote) `
                            -Account ([string]$rc4[0].TargetUserName) -SourceIp $rc4[0]._Ip -Target 'krbtgt (TGT)' `
                            -Computer $rc4[0].Computer -EventIds @(4768, 4769) -Evidence (Get-IRFirst $ev 200) `
                            -Recommendation 'Treat as a likely cracked-credential reuse: correlate with a preceding Kerberoast (RC4 4769 for this account''s SPN) and with what the account did next (privileged logons, group changes). Reset the account''s password, and if it is a service account rotate it and set a long random password / move it to a gMSA.'))
            }
            else {
                $encSeen = @(@($grp) | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
                $ev = @($rc4 + @(Get-IRFirst $aes 3))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                            -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                            -Title 'Kerberos encryption downgrade (RC4 TGT for AES-capable principal)' `
                            -Description ("Principal {0} was issued an RC4 TGT from {1} while the same principal also obtained AES TGT(s) in this dataset ({2} RC4 vs {3} AES request(s)). Encryption seen: {4}. A per-principal downgrade to RC4 is a common Golden Ticket artifact - older mimikatz forges RC4 by default.{5}" -f ([string]$rc4[0].TargetUserName), $rc4[0]._Ip, $rc4.Count, $aes.Count, ($encSeen -join ', '), $realmNote) `
                            -Account ([string]$rc4[0].TargetUserName) -SourceIp $rc4[0]._Ip -Target 'krbtgt (TGT)' `
                            -Computer $rc4[0].Computer -EventIds 4768 -Evidence (Get-IRFirst $ev 200) `
                            -Recommendation 'Confirm whether this principal legitimately uses RC4. If not, treat as a possible Golden Ticket: review 4768/4769 from the source IP, check the host for mimikatz/Rubeus, and consider rotating the krbtgt key.'))
            }
        }
    }

    # --- RULE 7: lower / mixed-case client realm in a service-ticket request (forged-ticket artefact). ---
    # The KDC writes the 4769 client principal as NAME@REALM with the realm normalised to UPPER CASE (it is
    # copied from the TGT the KDC issued). A forged TGT carries the realm exactly as typed into the forging
    # tool (mimikatz /domain:corp.local), so a non-upper-case realm is a cheap, high-signal artefact. Runs
    # before RULE 2 so the source IP can corroborate that principal's TGS-without-TGT finding.
    $rule7Pool = New-Object System.Collections.Generic.List[object]
    $upperRealmSeen = $false
    $lowerPrincipals = @{}
    foreach ($e in $tgs) {
        if ($null -eq $e) { continue }
        $u = [string]$e.TargetUserName
        if (-not ($u -match '@([^@]+)$')) { continue }
        $realm = $matches[1].Trim()
        if (-not $realm) { continue }
        if ($realm -ceq $realm.ToUpperInvariant()) { $upperRealmSeen = $true; continue }
        $rule7Pool.Add($e)
        $lowerPrincipals[[string]$e._AcctKey] = $true
    }
    # Dataset gate: a SIEM / parser export that lower-cases every field would make EVERY principal look
    # forged. If no upper-case realm exists anywhere in the 4769 set and several principals are affected,
    # the source is case-normalised - say so once (Informational) and do not evaluate the rule. A single
    # affected principal with no upper-case reference is still reported, at reduced severity / confidence.
    $rule7Caveat = ''; $rule7Sev = 'High'; $rule7Conf = 'Medium'
    if ($rule7Pool.Count -gt 0 -and -not $upperRealmSeen) {
        if ($lowerPrincipals.Count -ge 2) {
            $names = @($rule7Pool | ForEach-Object { [string]$_.TargetUserName } | Select-Object -Unique)
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'Low' `
                        -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                        -Title 'Service-ticket realms appear case-normalised (lower-case realm rule not evaluated)' `
                        -Description ("Every 4769 client principal in this dataset carries a lower / mixed-case realm ({0} principal(s), e.g. {1}) and none is upper case. A Windows KDC always writes the realm in UPPER CASE, so this looks like an export whose fields were case-normalised by a SIEM / parser rather than {0} forged tickets. The lower-case-realm rule was therefore not evaluated; re-run against the original .evtx to use it." -f $names.Count, ((Get-IRFirst $names 5) -join ', ')) `
                        -Account (($(if ($names.Count -le 3) { $names } else { @((Get-IRFirst $names 3) + "+$($names.Count - 3) more") })) -join ', ') `
                        -Computer $rule7Pool[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $rule7Pool.ToArray() 200) `
                        -Recommendation 'Collect the native Security .evtx (or confirm the pipeline preserves field case) and re-run; the lower-case-realm artefact is only meaningful on unmodified KDC events.'))
            $rule7Pool.Clear()
        }
        else {
            $rule7Sev = 'Medium'; $rule7Conf = 'Low'
            $rule7Caveat = ' No upper-case realm was seen anywhere in this dataset, so this may also be a case-normalised export (SIEM / parser) - confirm against the native .evtx before escalating.'
        }
    }
    foreach ($g in ($rule7Pool.ToArray() | Group-Object { "$($_._AcctKey)|$($_._Ip)" })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $u = [string]$ev[0].TargetUserName
        $realm = ''; if ($u -match '@([^@]+)$') { $realm = $matches[1].Trim() }
        if ($ev[0]._Ip) { $suspiciousIps[$ev[0]._Ip] = $true }
        $svcs = @($ev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
        $encSeen = @($ev | ForEach-Object { ConvertFrom-IRKerberosEncryptionType $_.TicketEncryptionType } | Select-Object -Unique)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $rule7Sev -Confidence $rule7Conf `
                    -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                    -Title 'Service tickets for a principal whose realm is not upper case (forged-ticket artefact)' `
                    -Description ("{0} requested {1} service ticket(s) [{2}] from {3} with the client realm written as '{4}'. The KDC normalises the realm of every ticket it issues to UPPER CASE, so a lower / mixed-case realm means the TGT presented was not issued by this KDC - it carries the realm exactly as typed into the forging tool (e.g. mimikatz /domain:{4}). Encryption seen: {5}. The principal may not even exist in AD.{6}" -f $u, $svcs.Count, ((Get-IRFirst $svcs 10) -join ', '), $ev[0]._Ip, $realm, ($encSeen -join ', '), $rule7Caveat) `
                    -Account $u -SourceIp $ev[0]._Ip -Target ((Get-IRFirst $svcs 25) -join ', ') `
                    -Computer $ev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Treat as a probable forged (Golden) ticket: confirm the principal exists in AD and that it obtained a 4768 TGT from some DC; if not, isolate the source host, capture memory for injected tickets, and rotate the krbtgt key twice once the host is contained.'))
    }

    # --- RULE 2: service tickets with no preceding TGT (possible Silver Ticket / Pass-the-Ticket). ---
    # Absence of an in-window TGT is ALSO the normal case on short / windowed log exports (the TGT simply
    # predates the export), which is the most common real-world scenario. So a bare "TGS without TGT" is
    # only raised as a per-principal High finding when it is CORROBORATED - an attacker-associated source
    # IP (already implicated by another rule), an RC4 service ticket, or a blank / mismatched realm.
    # Uncorroborated principals are rolled up into a SINGLE Informational finding so a partial export
    # cannot flood the report with one High per normal user.
    $tgtSuccessAll = @($tgt | Where-Object { $_ -and $_._IsSuccess })
    if ($tgtSuccessAll.Count -gt 0) {
        $qualTgs = @($tgs | Where-Object { $_ -and $_._IsSuccess -and (-not $_._IsMachine) -and (-not $_._IsReferral) -and ($_._AcctBare -ne 'krbtgt') })
        $tgsByAcct = Group-IRByKey -Events $qualTgs -KeyScript { param($e) $e._AcctKey }
        $tgtByAcct = Group-IRByKey -Events $tgtSuccessAll -KeyScript { param($e) $e._AcctKey }
        $uncorroborated = New-Object System.Collections.Generic.List[object]
        foreach ($key in $tgsByAcct.Keys) {
            $uev = @($tgsByAcct[$key].ToArray() | Sort-Object TimeCreated)
            $firstTgs = $uev[0].TimeCreated
            $hasTgt = $false
            if ($tgtByAcct.ContainsKey($key)) {
                foreach ($t in $tgtByAcct[$key].ToArray()) {
                    if (($t.TimeCreated -is [datetime]) -and ($firstTgs -is [datetime])) {
                        if (($t.TimeCreated -le $firstTgs) -and ($t.TimeCreated -ge $firstTgs.AddMinutes(-1 * $TgtLookbackMinutes))) { $hasTgt = $true; break }
                    }
                }
            }
            if ($hasTgt) { continue }

            # Corroboration signals.
            $ipSuspicious = $false
            foreach ($x in $uev) { if ($suspiciousIps.ContainsKey([string]$x._Ip)) { $ipSuspicious = $true; break } }
            $anyRc4 = [bool](@($uev | Where-Object { $_._IsRc4 }).Count -gt 0)
            $realmOdd = $false
            $dom0 = [string]$uev[0].TargetDomainName
            if (-not $dom0) { $realmOdd = $true }
            elseif ($ExpectedDomain -and ($dom0 -ne $ExpectedDomain) -and ($dom0 -notlike "*$ExpectedDomain*")) { $realmOdd = $true }

            $svcs = @($uev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
            if ($ipSuspicious -or $anyRc4 -or $realmOdd) {
                $why = @(); if ($ipSuspicious) { $why += 'the source IP is already implicated by another rule' }; if ($anyRc4) { $why += 'an RC4 service ticket was issued' }; if ($realmOdd) { $why += 'the realm is blank or does not match the expected domain' }
                $conf = 'Medium'; if ($ipSuspicious) { $conf = 'High' }
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence $conf `
                            -Technique 'T1558.002' -TechniqueName 'Silver Ticket / Pass-the-Ticket' `
                            -Title 'Service tickets without a preceding TGT (possible silver ticket / pass-the-ticket)' `
                            -Description ("{0} requested {1} service ticket(s) [{2}] from {3} but no TGT (event 4768) was issued to this principal in the {4}-minute window before the first request, AND {5}. A missing AS-REQ means the TGT was not obtained from the KDC - consistent with a forged service ticket (Silver Ticket) or a stolen TGT replayed from another host (Pass-the-Ticket)." -f ([string]$uev[0].TargetUserName), $svcs.Count, ((Get-IRFirst $svcs 10) -join ', '), $uev[0]._Ip, $TgtLookbackMinutes, ($why -join ', and ')) `
                            -Account ([string]$uev[0].TargetUserName) -SourceIp $uev[0]._Ip -Target ((Get-IRFirst $svcs 25) -join ', ') `
                            -Computer $uev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $uev 200) `
                            -Recommendation 'Verify whether the principal obtained a TGT from a different DC not present in this dataset. If not, treat the source host as compromised: capture memory for injected tickets and reset the affected service-account / user keys.'))
            }
            else {
                $uncorroborated.Add([pscustomobject]@{ Account = [string]$uev[0].TargetUserName; Ip = $uev[0]._Ip; Events = $uev })
            }
        }
        if ($uncorroborated.Count -gt 0) {
            $names = @($uncorroborated | ForEach-Object { $_.Account } | Select-Object -Unique)
            $evAll = New-Object System.Collections.Generic.List[object]
            foreach ($u in $uncorroborated) { foreach ($x in $u.Events) { $evAll.Add($x) } }
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'Low' `
                        -Technique 'T1558.002' -TechniqueName 'Silver Ticket / Pass-the-Ticket' `
                        -Title 'Service tickets without an in-window TGT (likely partial log - review if the export is complete)' `
                        -Description ("{0} principal(s) requested service tickets with no successful TGT (4768) in the preceding {1}-minute window, and with no corroborating signal (no attacker-associated IP, no RC4, no realm anomaly). On a short or windowed log export this is EXPECTED because the TGT predates the export, so these are not raised individually. Investigate only if the export is believed complete. Principals: {2}." -f $names.Count, $TgtLookbackMinutes, ((Get-IRFirst $names 20) -join ', ')) `
                        -Account (($(if ($names.Count -le 3) { $names } else { @((Get-IRFirst $names 3) + "+$($names.Count - 3) more") })) -join ', ') `
                        -Computer $evAll[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $evAll.ToArray() 200) `
                        -Recommendation 'If the export is complete, review these principals for injected / forged tickets. Otherwise widen the export window to include the AS-REQ (4768) events that precede these service-ticket requests.'))
        }
    }
    else {
        Write-IRStatus 'No successful 4768 TGT events in dataset - skipping silver/PTT inference (partial logs).' -Level Detail
    }

    # --- RULE 3: anomalous TGT options / lifetime (supporting evidence). ---
    # The forwardable+renewable context signal is collected per principal and emitted ONCE (a principal with
    # many RC4 TGTs from an implicated IP - e.g. an overpass-the-hash service account - would otherwise
    # produce one near-identical Informational per TGT).
    $fwdRenewByAcct = @{}
    foreach ($e in @($tgt | Where-Object { $_ -and $_._IsSuccess -and $_._IsRc4 -and ($_._AcctBare -ne 'krbtgt') -and (-not $_._IsMachine) })) {
        $opts = @(ConvertFrom-IRTicketOptions $e.TicketOptions)
        $fwd = ($opts -contains 'Forwardable')
        $renew = ($opts -contains 'Renewable')

        # Explicit lifetime is absent from most 4768/4769 schemas; guard for missing fields.
        $absurd = $false; $yrs = $null
        $lifeRaw = $null
        foreach ($pn in @('TicketLifetime', 'Lifetime', 'TicketLifetimeHours')) {
            if ($e.PSObject.Properties[$pn] -and $e.$pn) { $lifeRaw = [string]$e.$pn; break }
        }
        if ($lifeRaw) {
            $years = $null
            $ts = [TimeSpan]::Zero
            if ([TimeSpan]::TryParse($lifeRaw, [ref]$ts)) { $years = $ts.TotalDays / 365.0 }
            else { $num = ConvertTo-IRInt $lifeRaw; if ($null -ne $num) { $years = $num / 8760.0 } }
            if (($null -ne $years) -and ($years -gt $MaxTicketLifetimeYears)) { $absurd = $true; $yrs = [Math]::Round($years, 1) }
        }

        if ($absurd) {
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                        -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                        -Title 'Abnormal Kerberos ticket lifetime' `
                        -Description ("TGT for {0} from {1} has an abnormal lifetime of ~{2} year(s), beyond the {3}-year sanity ceiling. Forged tickets are frequently minted with multi-year lifetimes." -f ([string]$e.TargetUserName), $e._Ip, $yrs, $MaxTicketLifetimeYears) `
                        -Account ([string]$e.TargetUserName) -SourceIp $e._Ip -Target 'krbtgt (TGT)' `
                        -Computer $e.Computer -EventIds 4768 -Evidence @($e) `
                        -Recommendation 'Compare against the domain maximum ticket lifetime policy. A lifetime far beyond policy indicates a forged ticket - isolate the source host.'))
        }
        elseif ($fwd -and $renew -and $suspiciousIps.ContainsKey([string]$e._Ip)) {
            # forwardable+renewable is the DEFAULT for normal TGTs, so on its own it is not a finding. Only
            # surface it (as low-noise context) when the source IP is already implicated by another rule for
            # this principal; collect per principal and emit once below.
            $k = [string]$e._AcctKey
            if (-not $fwdRenewByAcct.ContainsKey($k)) { $fwdRenewByAcct[$k] = New-Object System.Collections.Generic.List[object] }
            $fwdRenewByAcct[$k].Add($e)
        }
    }
    foreach ($k in $fwdRenewByAcct.Keys) {
        $ev = @($fwdRenewByAcct[$k] | Sort-Object TimeCreated)
        $opts = @(ConvertFrom-IRTicketOptions $ev[0].TicketOptions)
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Informational' -Confidence 'Low' `
                    -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                    -Title 'Anomalous RC4 TGT options (forwardable + renewable)' `
                    -Description ("{0} RC4 TGT(s) for {1} from {2} carry forwardable+renewable options ({3}). On its own this is weak evidence (it is also the default for normal TGTs), but combined with an encryption downgrade or a missing AS-REQ for the same principal it supports a Golden Ticket hypothesis." -f $ev.Count, ([string]$ev[0].TargetUserName), $ev[0]._Ip, ($opts -join ', ')) `
                    -Account ([string]$ev[0].TargetUserName) -SourceIp $ev[0]._Ip -Target 'krbtgt (TGT)' `
                    -Computer $ev[0].Computer -EventIds 4768 -Evidence (Get-IRFirst $ev 200) `
                    -Recommendation 'Treat as supporting context only. Correlate with encryption-downgrade and missing-TGT findings for the same principal / host before escalating.'))
    }

    # --- RULE 5: blank or mismatched realm in a service-ticket request. ---
    $rule5Pool = @($tgs | Where-Object { $_ -and (-not $_._IsMachine) -and (-not $_._IsReferral) -and ($_._AcctBare -ne 'krbtgt') })
    foreach ($g in ($rule5Pool | Group-Object { "$($_._AcctKey)|$([string]$_.TargetDomainName)" })) {
        $ev = @($g.Group)
        $dom = [string]$ev[0].TargetDomainName
        $domTrim = $dom.Trim()
        $fire = $false; $reason = ''
        if ($domTrim -eq '') { $fire = $true; $reason = 'blank realm' }
        elseif ($expected -and ($domTrim.ToLowerInvariant() -ne $expected)) { $fire = $true; $reason = ("realm does not match expected '{0}'" -f $ExpectedDomain) }
        if ($fire) {
            $svcs = @($ev | ForEach-Object { $_.ServiceName } | Select-Object -Unique)
            $domDisplay = $domTrim; if ($domDisplay -eq '') { $domDisplay = '(blank)' }
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                        -Technique 'T1558.001' -TechniqueName 'Golden Ticket' `
                        -Title 'Forged ticket with mismatched or blank realm' `
                        -Description ("{0} requested service ticket(s) for {1} carrying realm '{2}' ({3}) from {4}. Forged golden/silver tickets frequently present a blank or incorrect realm." -f ([string]$ev[0].TargetUserName), ((Get-IRFirst $svcs 10) -join ', '), $domDisplay, $reason, $ev[0]._Ip) `
                        -Account ([string]$ev[0].TargetUserName) -SourceIp $ev[0]._Ip -Target ((Get-IRFirst $svcs 25) -join ', ') `
                        -Computer $ev[0].Computer -EventIds 4769 -Evidence (Get-IRFirst $ev 200) `
                        -Recommendation 'Validate the realm against the true domain. A blank or foreign realm on an intra-domain request indicates a forged ticket - isolate the source host and review for mimikatz/Rubeus.'))
        }
    }

    # --- RULE 6: PowerShell script-block ticket-forging tooling signatures. ---
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'kerberos::golden', 'kerberos::ptt', 'Invoke-Mimikatz', 'mimikatz', 'Rubeus', 'ticketer', 'asktgt', 'golden', 'silver', 'ptt'
        foreach ($e in $psEvents) {
            $text = [string]$e.ScriptBlockText
            if (-not $text -and $e.PSObject.Properties['Message']) { $text = [string]$e.Message }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Medium' `
                            -Technique $technique -TechniqueName $techniqueName `
                            -Title 'Kerberos ticket-forging tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched ticket-forging signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence @($e) `
                            -Recommendation 'Identify the user and process that ran this script block and correlate with 4768/4769 anomalies from the same host.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
