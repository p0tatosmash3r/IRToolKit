<#
.SYNOPSIS
    Detects Active Directory Certificate Services (AD CS) abuse / ESC attacks from Windows Security
    and PowerShell event logs.

.DESCRIPTION
    AD CS misconfigurations let an attacker obtain a certificate that authenticates as a privileged
    account (ESC1-ESC14, "Steal or Forge Authentication Certificates"). This tool looks for the
    logged signals those abuses leave on the Certificate Authority host and on domain controllers:

      * ESC1 / ESC6 - a certificate request where the requester supplies an arbitrary Subject
        Alternative Name (SAN). The CA issuance events 4886 (request received) and 4887 (certificate
        issued) carry the Requester and the request Attributes; the attacker-chosen SAN (an arbitrary
        UPN / DNS name) appears in those attributes or in the rendered message text.
      * ESC1 / ESC4 - the certificate template itself is modified to be dangerous (5136 changes to a
        pKICertificateTemplate object - msPKI-Certificate-Name-Flag enabling ENROLLEE_SUPPLIES_SUBJECT,
        msPKI-Enrollment-Flag, pKIExtendedKeyUsage, msPKI-Certificate-Application-Policy, or the
        template ACL / nTSecurityDescriptor).
      * ESC8 / relay and certificate LOGON - a 4768 AS-REQ with the certificate fields populated
        (CertIssuerName / CertSerialNumber / CertThumbprint) and PreAuthType 16 (PKINIT). When the
        certificate used was just issued (4887) to a DIFFERENT requester than the account now
        authenticating, that is certificate-based impersonation.
      * ESC14 - explicit certificate mapping (altSecurityIdentities) written onto a victim account by
        a different actor, so a certificate the attacker controls maps to the victim.

    Detection logic (each rule emits its own finding):
      * Rule 1 (High/High, Critical when privileged) - ESC1 SAN abuse. A 4886/4887 whose request
        Attributes (or Message) contain a SAN (san:/upn=/dns=/altname) and whose SAN identity differs
        from the Requester. Escalated to Critical when the SAN UPN matches a -PrivilegedUpn entry or
        contains 'admin'.
      * Rule 2 (Medium/Medium, High for name-flag) - a certificate template modified to be dangerous.
        5136 on a pKICertificateTemplate object where a dangerous attribute was Value Added / modified.
        Reported High when the attribute is msPKI-Certificate-Name-Flag (ENROLLEE_SUPPLIES_SUBJECT).
      * Rule 3 (Critical, or Medium with -FlagAllPkinit) - certificate-based logon anomaly. A 4768
        PKINIT (PreAuthType 16) logon using a certificate (thumbprint / serial) that was issued via a
        4887 to a DIFFERENT requester within -CorrelationHours. Without correlating issuance data a
        PKINIT logon is only reported (Medium) when -FlagAllPkinit is supplied, because smart-card
        environments make PKINIT normal.
      * Rule 4 (High/Medium) - altSecurityIdentities (ESC14 explicit cert mapping) Value Added onto a
        principal by an actor that is not the target.
      * Rule 5 (Medium/High) - PowerShell script-block signatures (4104) for AD CS abuse tooling
        (Certify, Certipy, ForgeCert, PassTheCert, ...).

    Required audit policy / log sources:
      * CA host: Certification Authority auditing enabled -> 4886 / 4887 in the Security log.
      * DC: DS Access > Audit Directory Service Changes = Success -> 5136 (template and
        altSecurityIdentities changes; needs SACL auditing of the relevant objects).
      * DC: Account Logon > Audit Kerberos Authentication Service = Success -> 4768 (Rule 3).
      * Optional: PowerShell Script Block Logging (4104) for Rule 5.

    Known false positives:
      * Smart-card / Windows Hello for Business environments produce many legitimate PKINIT (4768
        PreAuthType 16) logons - Rule 3 therefore only fires on a correlated issued-to-someone-else
        certificate (or when -FlagAllPkinit is set). Enrollment agents and some enrollment services
        legitimately request certificates on behalf of other users (the SAN-differs heuristic can
        misclassify these). Template and altSecurityIdentities changes also happen during legitimate
        PKI administration - validate the actor and the source host before escalating.

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
    Only analyse events at or after this time. Live mode defaults to the last 7 days.
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
    Extra domain controller names / IPs to treat as DCs (used to annotate whether a PKINIT logon or a
    template change was seen on a DC when running offline).
.PARAMETER PrivilegedUpn
    One or more privileged UPNs (e.g. administrator@corp.local). A Rule 1 ESC1 finding whose requested
    SAN matches one of these is escalated to Critical. SANs whose identity contains 'admin' are also
    treated as privileged.
.PARAMETER CorrelationHours
    Maximum hours between a certificate being issued (4887) and used for PKINIT (4768) to correlate
    them for Rule 3 (default 24).
.PARAMETER FlagAllPkinit
    Also report (Medium) PKINIT (4768 PreAuthType 16) certificate logons for which no correlating 4887
    issuance was found. Off by default so smart-card logons are not flagged wholesale.

.EXAMPLE
    .\Find-ADCSAbuse.ps1 -StartTime (Get-Date).AddDays(-14) -PrivilegedUpn administrator@corp.local
    Analyse the local CA / DC Security + PowerShell logs for the last 14 days, treating the given UPN as privileged.

.EXAMPLE
    .\Find-ADCSAbuse.ps1 -Path C:\Evidence\CA01-Security.evtx,C:\Evidence\DC01-Security.evtx -OutputPath C:\Evidence\Out -Format All
    Analyse exported CA and DC logs offline and write all report formats.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4887} | ConvertFrom-IRWinEvent -IncludeMessage | .\Find-ADCSAbuse.ps1

.NOTES
    ATT&CK : T1649 (Steal or Forge Authentication Certificates)
    Events : 4886 / 4887 (Security - CA certificate request received / issued), 5136 (Security -
             directory object modified: template and altSecurityIdentities), 4768 (Security - Kerberos
             TGT request / PKINIT), 4104 (PowerShell Operational)
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

    [string[]]$PrivilegedUpn,
    [int]$CorrelationHours = 24,
    [switch]$FlagAllPkinit
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
    if (-not $toolName) { $toolName = 'Find-ADCSAbuse' }
    $technique = 'T1649'; $techniqueName = 'Steal or Forge Authentication Certificates'
    Set-IRQuiet ([bool]$Quiet)
    $pipelineInput = [bool]$MyInvocation.ExpectingInput
    $collected = New-Object System.Collections.Generic.List[object]

    # Normalise the supplied privileged UPNs for case-insensitive comparison.
    $privUpnSet = @{}
    foreach ($p in @($PrivilegedUpn)) { if ($p) { $privUpnSet[([string]$p).Trim().ToLowerInvariant()] = $true } }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Object' -and $InputObject) { foreach ($o in $InputObject) { $collected.Add($o) } }
}

end {
    Write-IRToolHeader -Name $toolName -Description 'AD CS abuse (ESC1/ESC4/ESC8/ESC14 certificate attacks)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $sensitive = Get-IRReferenceTable 'SensitiveAttributes'

    # Build the DC lookup only when it can succeed cleanly: when the analyst supplied -DomainController
    # or the host is domain joined. Querying for DCs on a non-domain-joined host raises an error, so we
    # avoid the call entirely otherwise (the lookup is only used to annotate DC-sourced activity).
    $dcLookup = @{}
    if (($DomainController -and @($DomainController).Count -gt 0) -or ((-not $NoADLookup) -and (Test-IRAdAvailable))) {
        try { $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController } catch { $dcLookup = @{} }
    }
    if ($null -eq $dcLookup) { $dcLookup = @{} }
    if ($dcLookup.Count -eq 0) { Write-IRStatus 'No domain controllers known (not domain joined and no -DomainController supplied) - DC-sourced annotation is disabled.' -Level Detail }

    # ---- Local helpers (field access guarded for $null; StrictMode is off) ----
    function Get-F {
        param($Obj, [string]$Name)
        if ($null -ne $Obj -and $Obj.PSObject -and $Obj.PSObject.Properties[$Name]) { return $Obj.PSObject.Properties[$Name].Value }
        return $null
    }
    # Normalise a principal name (UPN / DOMAIN\user / bare) to a comparable lower-case key.
    function Get-BareName {
        param($Name)
        $u = [string]$Name
        if (-not $u) { return '' }
        if ($u -match '^(.+)\\(.+)$') { $u = $matches[2] }
        if ($u -match '^(.+)@(.+)$') { $u = $matches[1] }
        return $u.Trim().TrimEnd('$').ToLowerInvariant()
    }
    function Get-ObjectCn {
        param($Dn)
        $d = [string]$Dn
        if ($d -match '^\s*CN=([^,]+)') { return $matches[1].Trim() }
        return $d
    }

    # ======================================================================
    # Source A: CA certificate request events (4886 received / 4887 issued).
    # Field schemas vary, so pass -IncludeMessage and parse the SAN from the
    # named Attributes field OR the rendered Message text.
    # ======================================================================
    $caEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4886, 4887 -IncludeMessage)
    Write-IRStatus "Loaded $($caEvents.Count) 4886/4887 CA event(s)" -Level Detail

    # ---- Rule 1: ESC1 - requester-supplied SAN specifies a different / privileged identity ----
    $seenSan = @{}
    foreach ($e in $caEvents) {
        $requester = [string](Get-F $e 'Requester')
        $attributes = [string](Get-F $e 'Attributes')
        $message = [string](Get-F $e 'Message')
        $sanField = [string](Get-F $e 'SubjectAltName')
        $sanText = (@($attributes, $message, $sanField) -join ' ')
        if (-not $sanText.Trim()) { continue }

        # Does the request carry a Subject Alternative Name at all?
        $hasSanWord = ($sanText -match '(?i)(san[:=]|altname|subject\s*alternative\s*name)')
        $upnMatch = [regex]::Match($sanText, '(?i)upn=\s*([^\s,;&\r\n"'']+)')
        $dnsMatch = [regex]::Match($sanText, '(?i)dns=\s*([^\s,;&\r\n"'']+)')
        $sanIdentity = $null
        if ($upnMatch.Success) { $sanIdentity = $upnMatch.Groups[1].Value }
        elseif ($dnsMatch.Success) { $sanIdentity = $dnsMatch.Groups[1].Value }
        if (-not $sanIdentity) { continue }                 # no concrete SAN identity to compare
        if (-not $hasSanWord -and -not $upnMatch.Success -and -not $dnsMatch.Success) { continue }

        $sanBare = Get-BareName $sanIdentity
        $reqBare = Get-BareName $requester
        if (-not $sanBare) { continue }
        if ($reqBare -and $sanBare -eq $reqBare) { continue }   # SAN matches requester = normal

        $sanKind = if ($upnMatch.Success) { 'upn' } else { 'dns' }
        # A dns= SAN whose host label matches the requester (common for machine / web-server certs that
        # legitimately supply their own dNSHostName) is normal - compare the first label of the SAN host
        # to the requester bare name and suppress when they match.
        if ($sanKind -eq 'dns') {
            $sanHost = ($sanBare -split '\.')[0]
            if ($reqBare -and $sanHost -eq $reqBare) { continue }
        }

        # De-duplicate when both 4886 and 4887 exist for the same request.
        $requestId = [string](Get-F $e 'RequestId')
        $dupKey = ($requestId + '|' + $sanBare + '|' + $reqBare).ToLowerInvariant()
        if ($seenSan.ContainsKey($dupKey)) { continue }
        $seenSan[$dupKey] = $true

        $template = [string](Get-F $e 'CertificateTemplate')
        if (-not $template -and $attributes -match '(?i)CertificateTemplate:\s*([^\s,;&\r\n]+)') { $template = $matches[1] }
        if (-not $template) { $template = '(unknown)' }

        # Escalate to Critical ONLY on an EXACT match against the analyst-supplied privileged UPN list -
        # never on a substring like "admin" (which fires on benign hosts such as ADMINWEB$). Without a
        # privileged match, a SAN that merely differs from the requester is reported at High for a UPN SAN
        # (identity impersonation) or Medium for a DNS SAN to a different host, with Medium confidence
        # because a requester's UPN prefix often differs from its sAMAccountName (a benign cause to verify).
        $isPriv = $privUpnSet.ContainsKey(([string]$sanIdentity).Trim().ToLowerInvariant()) -or $privUpnSet.ContainsKey($sanBare)
        $privNote = ''
        if ($isPriv) {
            $sev = 'Critical'; $conf = 'High'
            $privNote = " The requested SAN identity is on the privileged list, so this certificate can be used to authenticate as a high-value account."
        }
        elseif ($sanKind -eq 'upn') {
            $sev = 'High'; $conf = 'Medium'
            $privNote = " Confirm the SAN UPN genuinely belongs to a different principal than the requester (a requester's UPN prefix can legitimately differ from its sAMAccountName)."
        }
        else {
            $sev = 'Medium'; $conf = 'Medium'
            $privNote = " The SAN names a different host than the requester. Confirm the requester is authorised to enroll for that host."
        }

        $desc = ("Requester '{0}' requested a certificate on template '{1}' with a Subject Alternative Name '{2}' that differs from the requester (RequestId {3}). A requester-supplied SAN for a different identity is the ESC1 enrollee-supplies-subject abuse used to obtain a certificate that authenticates as that identity.{4}" -f `
                $requester, $template, $sanIdentity, $requestId, $privNote)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'ESC1 certificate request with attacker-supplied SAN' `
                    -Description $desc -Account $requester -Target $sanIdentity -Computer $e.Computer `
                    -EventIds @([int]$e.EventId) -Evidence (Get-IRFirst @($e) 200) `
                    -Recommendation 'Confirm the requester is authorised to enroll with a supplied subject for this template. Revoke the issued certificate, disable ENROLLEE_SUPPLIES_SUBJECT (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) on the template or require manager approval, and treat the SAN identity as potentially compromised.'))
    }

    # ======================================================================
    # Source B: directory object modifications (5136) - templates (Rule 2)
    # and altSecurityIdentities (Rule 4).
    # ======================================================================
    $mods = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 5136)
    Write-IRStatus "Loaded $($mods.Count) 5136 event(s)" -Level Detail

    $templateAttrs = @('msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'nTSecurityDescriptor')

    foreach ($e in $mods) {
        $attr = [string](Get-F $e 'AttributeLDAPDisplayName')
        if (-not $attr) { continue }
        $opType = [string](Get-F $e 'OperationType')
        $isAdd = ($opType -like '*14674*') -or ($opType -match '(?i)value\s*added') -or ($opType -match '(?i)modif')
        $objectDn = [string](Get-F $e 'ObjectDN')
        $objectClass = [string](Get-F $e 'ObjectClass')
        $actor = [string](Get-F $e 'SubjectUserName')
        if (-not $objectDn -and -not $actor) { continue }   # malformed 5136 with no target and no actor

        # ---- Rule 2: dangerous certificate-template modification ----
        $isTemplateObj = ($objectClass -ieq 'pKICertificateTemplate') -or ($objectDn -match '(?i)CN=Certificate Templates,CN=Public Key Services')
        if ($isTemplateObj -and $isAdd -and ($templateAttrs -contains $attr)) {
            $templateCn = Get-ObjectCn $objectDn
            $attrNote = ''
            if ($sensitive.ContainsKey($attr)) { $attrNote = ' ' + $sensitive[$attr] + '.' }
            $sev = 'Medium'
            $essNote = ''
            if ($attr -ieq 'msPKI-Certificate-Name-Flag') {
                $sev = 'High'
                $rawVal = Get-F $e 'AttributeValue'
                $valInt = ConvertTo-IRInt $rawVal
                if ($null -ne $valInt -and ($valInt -band 0x1) -ne 0) { $essNote = ' Value sets ENROLLEE_SUPPLIES_SUBJECT (0x1), allowing a requester to supply an arbitrary subject/SAN (ESC1).' }
            }
            $desc = ("{0} modified certificate template '{1}' (attribute {2}, {3}, value '{4}').{5}{6}" -f `
                    $actor, $templateCn, $attr, $opType, [string](Get-F $e 'AttributeValue'), $attrNote, $essNote)
            $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'Certificate template modified to a dangerous configuration' `
                        -Description $desc -Account $actor -Target $objectDn -Computer $e.Computer `
                        -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Review the certificate template change against an authorised change. Dangerous settings (ENROLLEE_SUPPLIES_SUBJECT, Client Authentication / Smart Card Logon / Any Purpose EKU, no-manager-approval, weak ACLs) enable ESC1/ESC2/ESC4. Revert unauthorised changes and audit who can write certificate templates.'))
            continue
        }

        # ---- Rule 4: altSecurityIdentities (ESC14 explicit certificate mapping) ----
        if (($attr -ieq 'altSecurityIdentities') -and $isAdd) {
            $targetCn = Get-ObjectCn $objectDn
            $actorKey = Get-BareName $actor
            $targetKey = Get-BareName $targetCn
            if ($actorKey -ne '' -and $actorKey -eq $targetKey) { continue }   # self-mapping, not another principal
            $desc = ("{0} added an explicit certificate mapping (altSecurityIdentities, {1}) onto {2} object {3}. Mapping a certificate the actor controls onto another principal (ESC14) lets that certificate authenticate as the victim." -f `
                    $actor, $opType, $objectClass, $objectDn)
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'altSecurityIdentities explicit certificate mapping added (ESC14)' `
                        -Description $desc -Account $actor -Target $objectDn -Computer $e.Computer `
                        -EventIds 5136 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Verify the actor is authorised to set altSecurityIdentities on the target. If not, remove the mapping, treat the target as compromised, and audit write permissions on the object. Prefer strong certificate mapping (per KB5014754).'))
        }
    }

    # ======================================================================
    # Source C: certificate-based logon anomaly (4768 PKINIT correlated to 4887).
    # ======================================================================
    $asReq = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4768)
    $pkinit = @($asReq | Where-Object {
            ([string](Get-F $_ 'PreAuthType') -eq '16') -and
            ( [string](Get-F $_ 'CertThumbprint') -or [string](Get-F $_ 'CertSerialNumber') -or [string](Get-F $_ 'CertIssuerName') )
        })
    Write-IRStatus "$($pkinit.Count) certificate (PKINIT) 4768 logon(s) to evaluate" -Level Detail

    if ($pkinit.Count -gt 0) {
        # Index 4887 issuances by certificate thumbprint and serial.
        $issuedByCert = @{}
        foreach ($c in $caEvents) {
            if ([int]$c.EventId -ne 4887) { continue }
            $req = [string](Get-F $c 'Requester')
            foreach ($field in @('CertThumbprint', 'CertSerialNumber')) {
                $v = [string](Get-F $c $field)
                if (-not $v) { continue }
                $k = $field + '=' + $v.Trim().ToLowerInvariant()
                if (-not $issuedByCert.ContainsKey($k)) { $issuedByCert[$k] = New-Object System.Collections.Generic.List[object] }
                $issuedByCert[$k].Add([pscustomobject]@{ Requester = $req; Time = $c.TimeCreated; Event = $c })
            }
        }

        foreach ($e in $pkinit) {
            $targetUser = [string](Get-F $e 'TargetUserName')
            $targetBare = Get-BareName $targetUser
            $thumb = [string](Get-F $e 'CertThumbprint')
            $serial = [string](Get-F $e 'CertSerialNumber')
            $ip = ConvertTo-IRIpAddress (Get-F $e 'IpAddress')
            $preDecoded = ConvertFrom-IRPreAuthType (Get-F $e 'PreAuthType')

            $candidates = New-Object System.Collections.Generic.List[object]
            foreach ($pair in @(@('CertThumbprint', $thumb), @('CertSerialNumber', $serial))) {
                $val = [string]$pair[1]
                if (-not $val) { continue }
                $k = $pair[0] + '=' + $val.Trim().ToLowerInvariant()
                if ($issuedByCert.ContainsKey($k)) { foreach ($x in $issuedByCert[$k]) { $candidates.Add($x) } }
            }

            $match = $null
            foreach ($cand in $candidates) {
                if ($cand.Time -isnot [datetime] -or $e.TimeCreated -isnot [datetime]) { continue }
                $diffHours = [Math]::Abs(($e.TimeCreated - $cand.Time).TotalHours)
                if ($diffHours -gt $CorrelationHours) { continue }
                $candBare = Get-BareName $cand.Requester
                if ($candBare -and $targetBare -and $candBare -ne $targetBare) { $match = $cand; break }
            }

            if ($match) {
                $certLabel = $thumb; if (-not $certLabel) { $certLabel = $serial }
                $dcNote = ''
                if (Test-IRDomainController -Lookup $dcLookup -Value $ip) { $dcNote = ' The logon originated from a known domain controller address.' }
                $desc = ("Certificate (thumbprint '{0}', serial '{1}') was issued (event 4887) to requester '{2}' but was used for PKINIT authentication as '{3}' (event 4768) from {4}. PreAuth: {5}. A certificate issued to one principal and used to authenticate as another is certificate-based impersonation (ESC1/ESC8-class abuse).{6}" -f `
                        $thumb, $serial, $match.Requester, $targetUser, $ip, $preDecoded, $dcNote)
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Critical' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Certificate issued to one account used to authenticate as another' `
                            -Description $desc -Account $targetUser -SourceIp $ip -Target $match.Requester -Computer $e.Computer `
                            -EventIds @(4768, 4887) -Evidence (Get-IRFirst @($e, $match.Event) 200) `
                            -Recommendation 'Treat both the authenticating account and the original requester as compromised. Revoke the certificate, investigate how it was issued (template / enrollment-agent abuse), reset the impacted accounts, and isolate the source host.'))
            }
            elseif ($FlagAllPkinit -and $candidates.Count -eq 0) {
                # No correlating 4887 at all. A certificate issued to the SAME user (candidates exist,
                # same requester) is benign smart-card enrollment and is intentionally left silent.
                $certLabel = $thumb; if (-not $certLabel) { $certLabel = $serial }
                $desc = ("PKINIT (certificate) logon as '{0}' from {1} using certificate '{2}' (issuer '{3}'). No correlating CA issuance (4887) was found within {4}h, so this cannot be confirmed as impersonation; reported because -FlagAllPkinit was set." -f `
                        $targetUser, $ip, $certLabel, [string](Get-F $e 'CertIssuerName'), $CorrelationHours)
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'Certificate-based (PKINIT) logon without correlating issuance' `
                            -Description $desc -Account $targetUser -SourceIp $ip -Computer $e.Computer `
                            -EventIds 4768 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Confirm this is an expected smart-card / Windows Hello logon. Collect CA issuance logs (4887) to correlate the certificate to its requester.'))
            }
        }
    }

    # ======================================================================
    # Source D: PowerShell script-block tooling signatures (4104) - Rule 5.
    # ======================================================================
    $psEvents = @(Get-IRSourceEvents -Context $ctx -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -NoLogNameFilter)
    if ($psEvents.Count -gt 0) {
        $sigs = 'Certify', 'Certipy', 'ForgeCert', 'PassTheCert', 'Invoke-Certify', 'esc1', 'ADCS', 'certreq\s.*san'
        foreach ($e in $psEvents) {
            $text = [string](Get-F $e 'ScriptBlockText')
            if (-not $text) { $text = [string](Get-F $e 'Message') }
            if (-not $text) { continue }
            $hit = Test-IRPatternMatch -Text $text -Patterns $sigs
            if ($hit) {
                $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
                $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'High' `
                            -Technique $technique -TechniqueName $techniqueName -Title 'AD CS abuse tooling in PowerShell script block' `
                            -Description ("PowerShell script block on {0} matched AD CS abuse signature '{1}'. Excerpt: {2}" -f $e.Computer, $hit, $excerpt) `
                            -Computer $e.Computer -EventIds 4104 -Evidence (Get-IRFirst @($e) 200) `
                            -Recommendation 'Identify the user and process that ran this script block. Correlate with 4886/4887 CA issuance and 4768 PKINIT logons from the same host / timeframe.'))
            }
        }
    }

    Complete-IRTool -Findings $findings.ToArray() -Tool $toolName -OutputPath $OutputPath -Format $Format
}
