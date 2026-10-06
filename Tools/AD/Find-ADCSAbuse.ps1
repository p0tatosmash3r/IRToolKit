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
      * ESC2 / ESC3 - an Enrollment Agent (or Any Purpose) certificate used to request a logon
        certificate ON BEHALF OF another principal: the 4887 Requester differs from the identity in the
        issued certificate's Subject Alternative Name while the request carried no requester-supplied SAN.
      * ESC7 - the CA's own security permissions (4882) granting CA Administrator / Certificate Manager
        to a broad principal (Everyone, Authenticated Users, Domain Users, ...).
      * Weak / mismatched certificate mapping at logon - KDC events 39 / 40 / 41 (System log, KB5014754):
        a certificate that could not be strongly mapped, predates its account, or carries a SID that does
        not match the account it authenticated.

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
      * Rule 1b (High/Medium per requester, Critical when privileged; otherwise ONE Medium/Low roll-up) -
        on-behalf-of issuance (ESC3 / ESC2). A 4887 whose Requester matches NONE of the UPN / e-mail / DNS
        identities in the issued certificate's SubjectAlternativeName while the request Attributes carry no
        requester-supplied SAN (that case is Rule 1). Naming-convention variants of the requester (jsmith /
        john.smith, a host's own FQDN) and - when a directory is reachable - the requester's real UPN count
        as its own identity. Because a lone mismatch is usually a UPN-prefix difference, it is only reported
        per requester when that requester obtained certificates for >= 2 different user identities (an
        agent serving several users; a user's own enrolment never does that) or a -PrivilegedUpn identity;
        all remaining single mismatches are rolled up into one review finding. Approved agents are
        suppressed with -KnownEnrollmentAgent.
      * Rule 6 (High/High, otherwise Low) - CA permissions changed (4882). CA Administrator (0x1) or
        Certificate Manager (0x2) held by a broad principal after the change is ESC7 (High); any other 4882
        that leaves those rights with someone is reported Low for review (4882 renders the whole ACL).
      * Rule 7 (Critical when correlated; else 41 High, 40 Medium, 39 Medium only when the certificate
        subject names a different principal than the account) - KDC certificate-mapping events 39 / 40 / 41.
        Critical when the certificate serial / thumbprint matches a 4887 issued to a DIFFERENT requester (an
        exact match, so it is not time-bounded - certificates are used for their whole lifetime). A bare 39
        with a matching subject is configuration hygiene and is not reported.

    Required audit policy / log sources:
      * CA host: Certification Authority auditing enabled -> 4886 / 4887 in the Security log; the same
        subcategory logs 4882 (Rule 6).
      * DC: System log, provider Microsoft-Windows-Kerberos-Key-Distribution-Center -> 39 / 40 / 41
        (Rule 7). Logged by default once KB5014754 is installed.
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
      * Rule 1b fires on legitimate enrollment agents (smart-card enrollment stations, MDM / NDES
        connectors that enroll on behalf of users) - pass them via -KnownEnrollmentAgent. Rule 6 Low
        findings accompany routine CA administration. Rule 7 event 39 is common while a domain is still
        in Compatibility mode, which is why it is only reported with a subject mismatch or a correlated
        issuance.

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
.PARAMETER KnownEnrollmentAgent
    Accounts (bare name, DOMAIN\name or UPN) that legitimately request certificates on behalf of other
    principals (enrollment-agent stations, MDM / NDES connectors). Rule 1b does not report them.
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
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4887} -ErrorAction Ignore | ConvertFrom-IRWinEvent -IncludeMessage | .\Find-ADCSAbuse.ps1

.NOTES
    ATT&CK : T1649 (Steal or Forge Authentication Certificates)
    Events : 4886 / 4887 (Security - CA certificate request received / issued), 4882 (Security - CA
             security permissions changed), 5136 (Security - directory object modified: template and
             altSecurityIdentities), 4768 (Security - Kerberos TGT request / PKINIT), 39 / 40 / 41
             (System - KDC certificate mapping), 4104 (PowerShell Operational)
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
    [string[]]$KnownEnrollmentAgent,
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
    Write-IRToolHeader -Name $toolName -Description 'AD CS abuse (ESC1/ESC2/ESC3/ESC4/ESC7/ESC8/ESC14 certificate attacks)' -Technique $technique
    $ctx = New-IRSourceContext -BoundParameters $PSBoundParameters -InputObject $collected.ToArray() -PipelineInput $pipelineInput
    Write-IRStatus "Source: $($ctx.Description)"
    $findings = New-Object System.Collections.Generic.List[object]

    $sensitive = Get-IRReferenceTable 'SensitiveAttributes'

    # Build the DC lookup only when it can succeed cleanly: when the analyst supplied -DomainController
    # or the host is domain joined. Querying for DCs on a non-domain-joined host raises an error, so we
    # avoid the call entirely otherwise (the lookup is only used to annotate DC-sourced activity).
    $dcLookup = @{}
    if (($DomainController -and @($DomainController).Count -gt 0) -or ((-not $NoADLookup) -and (Test-IRAdAvailable))) {
        try { $dcLookup = Get-IRDomainControllerLookup -Additional $DomainController -NoDiscovery:$NoADLookup } catch { $dcLookup = @{} }
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
    # Normalised index key for a certificate thumbprint / serial (schemas render them with spaces, colons
    # or dashes and in either case).
    function Get-CertKey {
        param([string]$Kind, $Value)
        $v = (([string]$Value) -replace '[\s:\-]', '').ToLowerInvariant()
        if (-not $v) { return $null }
        return ($Kind + '=' + $v)
    }
    $agentSet = @{}
    foreach ($a in @($KnownEnrollmentAgent)) { $k = Get-BareName $a; if ($k) { $agentSet[$k] = $true } }
    # Same principal under a different naming convention? Both inputs are bare lower-case names. Equal, equal
    # once separators are removed (john.doe / johndoe / john_doe), or first.last against the usual short forms
    # (jdoe, johnd, doej, djohn, j.doe, doe.j). A user's certificate UPN prefix very often differs from the
    # sAMAccountName this way, so every certificate-identity-vs-account comparison goes through here.
    function Test-ShortForm {
        param([string]$Long, [string]$Short)
        if (-not ($Long -match '^([a-z0-9]+)[._\-]([a-z0-9]+)$')) { return $false }
        $first = $matches[1]; $last = $matches[2]
        $forms = @(($first.Substring(0, 1) + $last), ($first + $last.Substring(0, 1)), ($last + $first.Substring(0, 1)), ($last.Substring(0, 1) + $first), ($first.Substring(0, 1) + '.' + $last), ($last + '.' + $first.Substring(0, 1)))
        return ($forms -contains $Short)
    }
    function Test-SameIdentity {
        param([string]$A, [string]$B)
        if (-not $A -or -not $B) { return $false }
        if ($A -eq $B) { return $true }
        if (($A -replace '[._\-]', '') -eq ($B -replace '[._\-]', '')) { return $true }
        if (Test-ShortForm $A $B) { return $true }
        if (Test-ShortForm $B $A) { return $true }
        return $false
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
    $rule1Requests = @{}     # RequestIds already reported here, so Rule 1b does not report them again
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
        if ($reqBare -and (Test-SameIdentity $sanBare $reqBare)) { continue }   # SAN is the requester's own identity = normal

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
        if ($requestId) { $rule1Requests[$requestId.Trim().ToLowerInvariant()] = $true }

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

    # ---- Rule 1b: certificate ISSUED for a different identity than the requester (ESC3 enrollment-agent /
    # ESC2 any-purpose "on behalf of" request). Unlike ESC1 the request Attributes carry NO requester-
    # supplied SAN: the CA builds the subject from the on-behalf-of principal, so the mismatch is only
    # visible between the 4887 Requester and the issued certificate's SubjectAlternativeName.
    # Every SAN identity is compared (an autoenrolled web certificate carries several DNS names; a user's
    # UPN prefix often differs from the sAMAccountName), the requester's real UPN is consulted when a
    # directory is reachable, and a lone uncorroborated mismatch is rolled up into ONE review finding so a
    # busy CA cannot flood the report: a per-requester High needs >= 2 distinct user identities (an agent
    # serving several users - a user's own enrolment never does that) or a -PrivilegedUpn hit (Critical). ----
    $sanIdRe = '(?i)(principal\s*name|upn|rfc822\s*name|e-?mail|dns(?:\s*name)?)\s*[=:]\s*([^\s,;&\r\n"'']+)'
    $adReachable = (-not $NoADLookup) -and (Test-IRAdAvailable)
    $adUpnByBare = @{}      # requester bare name -> UPN prefix from AD (only when a directory is reachable)
    $oboPairs = New-Object System.Collections.Generic.List[object]
    $seenObo = @{}
    foreach ($e in $caEvents) {
        if ([int]$e.EventId -ne 4887) { continue }
        $requestId = [string](Get-F $e 'RequestId')
        if ($requestId -and $rule1Requests.ContainsKey($requestId.Trim().ToLowerInvariant())) { continue }   # already an ESC1 finding
        $attributes = [string](Get-F $e 'Attributes')
        if ($attributes -match '(?i)san[:=]|upn=|dns=') { continue }                                      # requester-supplied SAN: Rule 1 territory
        $requester = [string](Get-F $e 'Requester')
        $reqBare = Get-BareName $requester
        if (-not $reqBare) { continue }
        if ($agentSet.ContainsKey($reqBare)) { continue }                                                 # approved enrollment agent
        $sanField = [string](Get-F $e 'SubjectAlternativeName')
        if (-not $sanField) { $sanField = [string](Get-F $e 'SubjectAltName') }
        if (-not $sanField.Trim()) { continue }
        $sanIds = @([regex]::Matches($sanField, $sanIdRe) | ForEach-Object {
                [pscustomobject]@{ Kind = $(if ($_.Groups[1].Value -match '(?i)^dns') { 'dns' } else { 'upn' }); Value = $_.Groups[2].Value; Bare = (Get-BareName $_.Groups[2].Value) } })
        if ($sanIds.Count -eq 0) { continue }

        # The requester's own identity in ANY SAN entry means this is the requester's own certificate.
        $reqUpnPrefix = $null
        if ($adReachable -and ($requester -notmatch '\$$')) {
            if (-not $adUpnByBare.ContainsKey($reqBare)) {
                $adUpnByBare[$reqBare] = $null
                $ado = Get-IRAdObject -SamAccountName $reqBare -Properties @('userPrincipalName')
                if ($ado -and $ado.userPrincipalName) { $adUpnByBare[$reqBare] = Get-BareName ([string]$ado.userPrincipalName) }
            }
            $reqUpnPrefix = $adUpnByBare[$reqBare]
        }
        $own = $false
        foreach ($i in $sanIds) {
            if (-not $i.Bare) { continue }
            if ($i.Kind -eq 'dns') { if ((($i.Bare -split '\.')[0]) -eq $reqBare) { $own = $true; break } }
            elseif ((Test-SameIdentity $i.Bare $reqBare) -or ($reqUpnPrefix -and ($i.Bare -eq $reqUpnPrefix))) { $own = $true; break }
        }
        if ($own) { continue }

        $template = [string](Get-F $e 'CertificateTemplate')
        if (-not $template) { $template = '(unknown)' }
        foreach ($i in $sanIds) {
            if (-not $i.Bare) { continue }
            $dupKey = ($requestId + '|' + $i.Bare + '|' + $reqBare).ToLowerInvariant()
            if ($seenObo.ContainsKey($dupKey)) { continue }
            $seenObo[$dupKey] = $true
            $isPriv = $privUpnSet.ContainsKey(([string]$i.Value).Trim().ToLowerInvariant()) -or $privUpnSet.ContainsKey($i.Bare)
            $oboPairs.Add([pscustomobject]@{ Requester = $requester; ReqBare = $reqBare; Identity = $i.Value; Bare = $i.Bare; Kind = $i.Kind; IsPriv = $isPriv; RequestId = $requestId; Template = $template; Event = $e })
        }
    }
    $oboRollup = New-Object System.Collections.Generic.List[object]
    foreach ($g in ($oboPairs.ToArray() | Group-Object ReqBare)) {
        $pairs = @($g.Group | Sort-Object { $_.Event.TimeCreated })
        $userIds = @($pairs | Where-Object { $_.Kind -eq 'upn' } | ForEach-Object { $_.Bare } | Select-Object -Unique)
        $privHits = @($pairs | Where-Object { $_.IsPriv })
        if ($privHits.Count -eq 0 -and $userIds.Count -lt 2) { foreach ($p in $pairs) { $oboRollup.Add($p) }; continue }

        $idList = @($pairs | ForEach-Object { $_.Identity } | Select-Object -Unique)
        $reqIds = @($pairs | ForEach-Object { $_.RequestId } | Where-Object { $_ } | Select-Object -Unique)
        $templates = @($pairs | ForEach-Object { $_.Template } | Select-Object -Unique)
        $events = @($pairs | ForEach-Object { $_.Event })
        $sev = 'High'; $conf = 'Medium'
        if ($privHits.Count -gt 0) {
            $sev = 'Critical'; $conf = 'High'
            $note = (" The issued identity '{0}' is on the privileged list, so this certificate authenticates as a high-value account." -f $privHits[0].Identity)
        }
        else {
            $note = (" The requester obtained certificates for {0} different user identities - a user's own enrolment never does that, so an Enrollment Agent (or Any Purpose) certificate is in use." -f $userIds.Count)
        }
        $desc = ("Requester '{0}' was issued {1} certificate(s) (RequestId {2}; template(s) {3}) whose Subject Alternative Name identifies other principal(s): {4} (event 4887). The requests carried no requester-supplied SAN, so the identities were set by the CA from on-behalf-of requests - the pattern of an Enrollment Agent certificate (ESC3) or an Any Purpose certificate (ESC2) being used to obtain logon certificates for other principals.{5} Legitimate enrollment agents do this too; pass them via -KnownEnrollmentAgent." -f `
                $pairs[0].Requester, $events.Count, ((Get-IRFirst $reqIds 10) -join ', '), ((Get-IRFirst $templates 5) -join ', '), ((Get-IRFirst $idList 10) -join ', '), $note)
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Certificate issued for a different identity than the requester (enrollment agent / ESC3-ESC2)' `
                    -Description $desc -Account $pairs[0].Requester -Target ((Get-IRFirst $idList 25) -join ', ') -Computer $events[0].Computer `
                    -EventIds 4887 -Evidence (Get-IRFirst $events 200) `
                    -Recommendation 'Confirm the requester is an authorised enrollment agent for these templates. If not, revoke the certificates, treat the issued identities as compromised, restrict Enrollment Agent / Any Purpose templates (manager approval, enrollment-agent restrictions on the CA) and audit which principals can enroll on them.'))
    }
    if ($oboRollup.Count -gt 0) {
        $byReq = @($oboRollup.ToArray() | Group-Object ReqBare)
        $pairText = @($byReq | ForEach-Object { '{0} -> {1}' -f $_.Group[0].Requester, ((@($_.Group | ForEach-Object { $_.Identity } | Select-Object -Unique)) -join ', ') })
        $reqNames = @($byReq | ForEach-Object { $_.Group[0].Requester })
        $events = @($oboRollup | ForEach-Object { $_.Event })
        $desc = ("{0} requester(s) were each issued a certificate whose Subject Alternative Name names ONE other identity (event 4887, no requester-supplied SAN). A single mismatch is usually benign - a UPN prefix that differs from the sAMAccountName, or a server certificate requested by an administrator for another host - but it is also what a one-off enrollment-agent abuse (ESC3 / ESC2) looks like. Review any unexpected pair; pass genuine agents via -KnownEnrollmentAgent and high-value identities via -PrivilegedUpn (a hit is raised to Critical). Pairs: {1}." -f `
                $byReq.Count, ((Get-IRFirst $pairText 20) -join '; '))
        $findings.Add((New-IRFinding -Tool $toolName -Severity 'Medium' -Confidence 'Low' `
                    -Technique $technique -TechniqueName $techniqueName -Title 'Certificates issued naming a different identity than the requester (one each - review)' `
                    -Description $desc -Account (($(if ($reqNames.Count -le 3) { $reqNames } else { @((Get-IRFirst $reqNames 3) + "+$($reqNames.Count - 3) more") })) -join ', ') `
                    -Target ((Get-IRFirst @($oboRollup | ForEach-Object { $_.Identity } | Select-Object -Unique) 10) -join ', ') -Computer $events[0].Computer `
                    -EventIds 4887 -Evidence (Get-IRFirst $events 200) `
                    -Recommendation 'Compare each pair against the directory (is the SAN identity simply the requester''s own UPN?) and against the list of approved enrollment agents. Unexplained pairs: revoke the certificate and treat the named identity as compromised.'))
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

    # Index 4887 issuances by certificate thumbprint and serial. The live 4887 schema renders the serial as
    # SerialNumber; older / synthetic exports use CertSerialNumber / CertThumbprint - index every form.
    # Shared by Rule 3 (PKINIT 4768) and Rule 7 (KDC 39/40/41).
    $issuedByCert = @{}
    foreach ($c in $caEvents) {
        if ([int]$c.EventId -ne 4887) { continue }
        $req = [string](Get-F $c 'Requester')
        $keys = @((Get-CertKey 'thumb' (Get-F $c 'CertThumbprint')), (Get-CertKey 'thumb' (Get-F $c 'Thumbprint')), (Get-CertKey 'serial' (Get-F $c 'CertSerialNumber')), (Get-CertKey 'serial' (Get-F $c 'SerialNumber')))
        foreach ($k in @($keys | Where-Object { $_ } | Select-Object -Unique)) {
            if (-not $issuedByCert.ContainsKey($k)) { $issuedByCert[$k] = New-Object System.Collections.Generic.List[object] }
            $issuedByCert[$k].Add([pscustomobject]@{ Requester = $req; Time = $c.TimeCreated; Event = $c })
        }
    }

    if ($pkinit.Count -gt 0) {
        foreach ($e in $pkinit) {
            $targetUser = [string](Get-F $e 'TargetUserName')
            $targetBare = Get-BareName $targetUser
            $thumb = [string](Get-F $e 'CertThumbprint')
            $serial = [string](Get-F $e 'CertSerialNumber')
            $ip = ConvertTo-IRIpAddress (Get-F $e 'IpAddress')
            $preDecoded = ConvertFrom-IRPreAuthType (Get-F $e 'PreAuthType')

            $candidates = New-Object System.Collections.Generic.List[object]
            foreach ($k in @((Get-CertKey 'thumb' $thumb), (Get-CertKey 'serial' $serial))) {
                if ($k -and $issuedByCert.ContainsKey($k)) { foreach ($x in $issuedByCert[$k]) { $candidates.Add($x) } }
            }

            $match = $null
            foreach ($cand in $candidates) {
                if ($cand.Time -isnot [datetime] -or $e.TimeCreated -isnot [datetime]) { continue }
                $diffHours = [Math]::Abs(($e.TimeCreated - $cand.Time).TotalHours)
                if ($diffHours -gt $CorrelationHours) { continue }
                $candBare = Get-BareName $cand.Requester
                if ($candBare -and $targetBare -and -not (Test-SameIdentity $candBare $targetBare)) { $match = $cand; break }
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
    # Source E: CA security-descriptor changes (4882) - Rule 6 (ESC7).
    # 4882 renders the WHOLE resulting CA ACL as "Allow(0x<mask>) <principal> <right names> ..." segments.
    # Mask bits: 0x1 CA Administrator (Manage CA), 0x2 Certificate Manager (Issue and Manage
    # Certificates), 0x100 Read, 0x200 Enroll (Request Certificates).
    # ======================================================================
    $caAcl = @(Get-IRSourceEvents -Context $ctx -LogName 'Security' -EventId 4882 -IncludeMessage)
    Write-IRStatus "Loaded $($caAcl.Count) 4882 CA permission-change event(s)" -Level Detail
    $broadPrincipal = '(?i)^(everyone|s-1-1-0|(nt authority\\)?authenticated users|s-1-5-11|(nt authority\\)?anonymous logon|s-1-5-7|(builtin\\)?(users|guests)|s-1-5-32-54[56]|(?:[^\\]+\\)?(domain users|domain computers|domain guests)|s-1-5-21-[0-9-]+-51[345])$'
    $rightWords = '(?i)\s*(CA Administrator|Certificate Manager|Manage CA|Issue and Manage Certificates|Request Certificates|Read|Enroll)\s*$'
    foreach ($e in $caAcl) {
        $text = [string](Get-F $e 'SecuritySettings')
        if (-not $text) { $text = [string](Get-F $e 'Message') }
        if (-not $text) { continue }
        $actor = [string](Get-F $e 'SubjectUserName')
        $holders = New-Object System.Collections.Generic.List[string]
        $broad = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($text, '(?is)\bAllow\s*\(\s*0x([0-9a-f]+)\s*\)\s*(.*?)(?=\s*\b(?:Allow|Deny)\s*\(|\s*$)')) {
            $mask = [int64]0
            if (-not [int64]::TryParse($m.Groups[1].Value, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$mask)) { continue }
            if (($mask -band 0x3) -eq 0) { continue }
            # The principal is what remains of the segment once the trailing right names are stripped.
            $who = $m.Groups[2].Value.Trim(); $prev = $null
            while ($who -and ($who -ne $prev)) { $prev = $who; $who = ($who -replace $rightWords, '').Trim() }
            if (-not $who) { continue }
            $rights = @(); if ($mask -band 0x1) { $rights += 'CA Administrator' }; if ($mask -band 0x2) { $rights += 'Certificate Manager' }
            $label = ('{0} [{1}]' -f $who, ($rights -join ' + '))
            $holders.Add($label)
            if ($who -match $broadPrincipal) { $broad.Add($label) }
        }
        if ($holders.Count -eq 0) { continue }
        if ($broad.Count -gt 0) {
            $desc = ("{0} changed the Certification Authority security permissions on {1} (event 4882); the resulting ACL grants CA management rights to broad principal(s): {2}. CA Administrator lets any member approve requests and change templates / CA settings (ESC7); Certificate Manager lets them issue pending or denied requests for any identity. All holders of management rights after the change: {3}." -f `
                    $actor, $e.Computer, ($broad -join '; '), ($holders -join '; '))
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'High' -Confidence 'High' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'CA Administrator / Certificate Manager right granted to a broad principal (ESC7)' `
                        -Description $desc -Account $actor -Target ($broad -join '; ') -Computer $e.Computer `
                        -EventIds 4882 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Remove the broad grant immediately and audit every certificate approved or issued since the change (4886 / 4887 on the CA). Treat the actor as a compromised or malicious administrator unless the change is covered by change control.'))
        }
        else {
            $desc = ("{0} changed the Certification Authority security permissions on {1} (event 4882). Holders of CA management rights after the change: {2}. 4882 renders the whole resulting ACL, so this is reported for review rather than as a confirmed abuse." -f `
                    $actor, $e.Computer, ($holders -join '; '))
            $findings.Add((New-IRFinding -Tool $toolName -Severity 'Low' -Confidence 'Medium' `
                        -Technique $technique -TechniqueName $techniqueName -Title 'CA security permissions changed (review CA Administrator / Certificate Manager holders)' `
                        -Description $desc -Account $actor -Target ($holders -join '; ') -Computer $e.Computer `
                        -EventIds 4882 -Evidence (Get-IRFirst @($e) 200) `
                        -Recommendation 'Confirm the change against change control and that every CA Administrator / Certificate Manager holder is an intended PKI administration group. An attacker granting themselves these rights is ESC7.'))
        }
    }

    # ======================================================================
    # Source F: KDC certificate-mapping events (System log, provider
    # Microsoft-Windows-Kerberos-Key-Distribution-Center, 39 / 40 / 41 - KB5014754) - Rule 7.
    # ======================================================================
    $kdc = @(Get-IRSourceEvents -Context $ctx -LogName 'System' -EventId 39, 40, 41 -ProviderName 'Microsoft-Windows-Kerberos-Key-Distribution-Center')
    Write-IRStatus "Loaded $($kdc.Count) KDC certificate-mapping event(s) (39/40/41)" -Level Detail
    $kdcMeaning = @{
        39 = 'the certificate was valid but could not be strongly mapped to the account (no SID extension / weak mapping)'
        40 = 'the certificate predates the account it was used to authenticate (account re-created or certificate back-dated)'
        41 = 'the SID embedded in the certificate does not match the account it was used to authenticate'
    }
    foreach ($g in ($kdc | Group-Object { ("{0}|{1}|{2}|{3}" -f [int]$_.EventId, [string](Get-F $_ 'AccountName'), [string](Get-F $_ 'Thumbprint'), [string](Get-F $_ 'SerialNumber')).ToLowerInvariant() })) {
        $ev = @($g.Group | Sort-Object TimeCreated)
        $e = $ev[0]
        $id = [int]$e.EventId
        $acct = [string](Get-F $e 'AccountName')
        $acctBare = Get-BareName $acct
        $subject = ([string](Get-F $e 'Subject')).TrimStart('@').Trim()
        $cn = ''; if ($subject -match '(?i)CN=([^,]+)') { $cn = $matches[1].Trim() }
        $cnBare = Get-BareName $cn
        $thumb = [string](Get-F $e 'Thumbprint'); $serial = [string](Get-F $e 'SerialNumber')
        $issuer = [string](Get-F $e 'Issuer')
        # An event with no account AND no certificate identity is not a KDC mapping event (an unfiltered System
        # export can carry e.g. Kernel-Power 41 without a provider name in Object mode) - skip it.
        if (-not $acct -and -not $thumb -and -not $serial) { continue }

        # Correlate to a 4887 issued to a DIFFERENT requester. The serial / thumbprint match is exact, so it is
        # deliberately NOT time-bounded: a certificate is used for its whole lifetime, long after -CorrelationHours.
        $match = $null
        foreach ($k in @((Get-CertKey 'thumb' $thumb), (Get-CertKey 'serial' $serial))) {
            if (-not $k -or -not $issuedByCert.ContainsKey($k)) { continue }
            foreach ($cand in $issuedByCert[$k]) {
                $candBare = Get-BareName $cand.Requester
                if ($candBare -and $acctBare -and -not (Test-SameIdentity $candBare $acctBare)) { $match = $cand; break }
            }
            if ($match) { break }
        }
        # A single-token subject CN (an account-style name) that is not the account - allowing for a host FQDN
        # (CN=host01.corp.local for HOST01$) and the usual naming-convention variants - is a visible mismatch.
        $cnSame = $false
        if ($cnBare -and $acctBare) {
            $cnSame = Test-SameIdentity $cnBare $acctBare                                               # john.doe vs jdoe
            if (-not $cnSame -and ($cn -notmatch '@') -and ($cnBare -match '\.')) { $cnSame = Test-SameIdentity (($cnBare -split '\.')[0]) $acctBare }   # host01.corp.local vs HOST01$
        }
        $cnMismatch = [bool]($cnBare -and $acctBare -and ($cn -notmatch '\s') -and -not $cnSame)

        $sev = $null; $conf = 'Medium'
        if ($match) { $sev = 'Critical'; $conf = 'High' }
        elseif ($id -eq 41) { $sev = 'High'; $conf = 'High' }
        elseif ($id -eq 40) { $sev = 'Medium' }
        elseif ($cnMismatch) { $sev = 'Medium' }
        if (-not $sev) { continue }    # bare 39 with a matching subject: configuration hygiene, not reported

        $desc = ("Account '{0}' authenticated with a certificate (subject '{1}', issuer '{2}', serial '{3}') and the KDC reported event {4}: {5}. {6} occurrence(s)." -f `
                $acct, $subject, $issuer, $serial, $id, $kdcMeaning[$id], $ev.Count)
        if ($cnMismatch) { $desc += (" The certificate subject names '{0}', not the account that used it." -f $cn) }
        if ($match) { $desc += (" The same certificate was issued (event 4887) to requester '{0}' - a certificate issued to one principal and used to authenticate as another is certificate-based impersonation." -f $match.Requester) }
        $eids = @($id); if ($match) { $eids += 4887 }
        $evidence = @($ev); if ($match) { $evidence = @($ev) + @($match.Event) }
        $findings.Add((New-IRFinding -Tool $toolName -Severity $sev -Confidence $conf `
                    -Technique $technique -TechniqueName $techniqueName -Title ("Certificate logon with weak / mismatched certificate mapping (KDC event {0})" -f $id) `
                    -Description $desc -Account $acct -Target $subject -Computer $e.Computer `
                    -EventIds $eids -Evidence (Get-IRFirst $evidence 200) `
                    -Recommendation 'Identify who holds the certificate and how it was issued (4886 / 4887 on the CA). A SID mismatch or an issued-to-someone-else correlation means the certificate authenticates as a victim account: revoke it, reset the account, and move the KDC to Full Enforcement (KB5014754) so weakly mapped certificates are rejected.'))
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
