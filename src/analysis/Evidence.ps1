# =====================================================================
# FIX MY PC - Evidence.ps1
#
# Collector runner + evidence records.
# - Invoke-FmpCollector wraps a collector body: times it, captures
#   unexpected errors, and produces a normalized module record.
# - Sub-checks and evidence entries give every later finding a
#   traceable source. Nothing here touches the system itself.
# =====================================================================

function New-FmpCollectorContext {
    param([Parameter(Mandatory)][string]$Name)
    return [ordered]@{
        module     = $Name
        startedAt  = Get-FmpTimestamp
        data       = [ordered]@{}
        subChecks  = @()
        errors     = @()
        limits     = @()
        evidence   = @()
        _evCounter = 0
    }
}

function Add-FmpContextListItem {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Ctx,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][object]$Item
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($existing in @(Get-FmpValue -Data $Ctx -Path $Key)) { $list.Add($existing) }
    $list.Add($Item)
    if ($Ctx.Contains($Key)) { $Ctx.Remove($Key) }
    $Ctx.Add($Key, $list.ToArray())
}

function Add-FmpSubCheck {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Ctx,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('pass', 'finding', 'unknown', 'unsupported', 'access_denied', 'not_collected', 'error')][string]$State,
        [hashtable]$Detail = @{},
        [string]$Confidence = ''
    )
    $rec = [ordered]@{ id = $Id; state = $State }
    if ($Detail.Count -gt 0) { $rec['detail'] = $Detail }
    if ($Confidence -ne '') { $rec['confidence'] = $Confidence }
    Add-FmpContextListItem -Ctx $Ctx -Key 'subChecks' -Item $rec
}

function Add-FmpCollectorError {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Ctx, [Parameter(Mandatory)][string]$Where, [Parameter(Mandatory)][string]$Message)
    Add-FmpContextListItem -Ctx $Ctx -Key 'errors' -Item ([ordered]@{ where = $Where; message = ($Message -replace '\s+', ' ').Trim() })
}

function Add-FmpLimitation {
    # key/detail stay canonical. LocaleKey names the report text when the key
    # carries a dynamic suffix; Values fill that text's {0}.. placeholders.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Ctx, [Parameter(Mandatory)][string]$Key, [string]$DetailText = '',
          [string]$LocaleKey = '', [object[]]$Values = @())
    $rec = [ordered]@{ key = $Key; detail = $DetailText }
    if ($LocaleKey -ne '') { $rec['localeKey'] = $LocaleKey }
    if ($Values.Count -gt 0) { $rec['values'] = $Values }
    Add-FmpContextListItem -Ctx $Ctx -Key 'limits' -Item $rec
}

function Resolve-FmpCollectorErrorState {
    param([Parameter(Mandatory)][object]$ErrorRecord)
    $ex = Get-FmpValue -Data $ErrorRecord -Path 'Exception'
    $msg = [string](Get-FmpValue -Data $ex -Path 'Message')
    $cat = [string](Get-FmpValue -Data $ErrorRecord -Path 'CategoryInfo.Category')
    $fqid = [string](Get-FmpValue -Data $ErrorRecord -Path 'FullyQualifiedErrorId')
    if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException] -or
        $cat -in @('PermissionDenied', 'SecurityError') -or
        $msg -match '(?i)access\s*(is\s*)?denied|unauthorized|acesso\s*negado|permission\s*denied') {
        return 'access_denied'
    }
    if ($ex -is [System.Management.Automation.CommandNotFoundException] -or
        $cat -in @('ObjectNotFound', 'NotImplemented', 'NotInstalled', 'ResourceUnavailable') -or
        $fqid -match 'InvalidClass|InvalidNamespace|CommandNotFound' -or
        $msg -match '(?i)invalid class|invalid namespace|classe inv[aá]lida|not supported|not implemented|not recognized as the name of a cmdlet') {
        return 'unsupported'
    }
    return 'error'
}

function New-FmpEvidence {
    # Attaches a piece of source evidence to the run and returns its id.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Ctx,
        [Parameter(Mandatory)][string]$CheckId,
        [string]$Summary = '',
        [object]$Data = $null
    )
    $Ctx._evCounter++
    $id = 'ev-' + $Ctx.module + '-' + $Ctx._evCounter
    $rec = [ordered]@{ id = $id; module = $Ctx.module; checkId = $CheckId; at = Get-FmpTimestamp }
    if ($Summary -ne '') { $rec['summary'] = $Summary }
    if ($null -ne $Data) { $rec['data'] = $Data }
    Add-FmpContextListItem -Ctx $Ctx -Key 'evidence' -Item $rec
    return $id
}

function Invoke-FmpCollector {
    # Runs one collector body under timing + error isolation. The body
    # receives the context and fills ctx.data; it must never write to the
    # system (enforced by the read-only compliance scan over collectors).
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string[]]$Commands = @()
    )
    $ctx = New-FmpCollectorContext -Name $Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'ok'
    try {
        # Capture incidental output so callers always receive one module record.
        $null = & $Body $ctx
        $okCount = 0
        $problemCount = 0
        foreach ($sc in @($ctx['subChecks'])) {
            if ($sc.state -in @('pass', 'finding')) { $okCount++ }
            elseif ($sc.state -in @('unknown', 'error', 'access_denied')) { $problemCount++ }
        }
        if ($okCount -eq 0) { $status = 'failed' }
        elseif ($problemCount -gt 0 -or @($ctx['errors']).Count -gt 0) { $status = 'partial' }
    }
    catch {
        $status = 'failed'
        Add-FmpCollectorError -Ctx $ctx -Where 'module' -Message $_.Exception.Message
        Add-FmpSubCheck -Ctx $ctx -Id ($Name + '.module') -State 'error' -Detail @{ reason = $_.Exception.Message }
    }
    $sw.Stop()
    return [ordered]@{
        id         = $Name
        status     = $status
        startedAt  = $ctx.startedAt
        durationMs = $sw.ElapsedMilliseconds
        data       = $ctx.data
        subChecks  = @($ctx['subChecks'])
        errors     = @($ctx['errors'])
        limits     = @($ctx['limits'])
        evidence   = @($ctx['evidence'])
        commands   = $Commands
    }
}

function Merge-FmpDiagnostics {
    # Combines module records into the internal diagnostic document
    # (schemaVersion 1.0.0). The sanitized variant is produced later by
    # Privacy.ps1; internal data stays local to the output directory.
    param(
        [Parameter(Mandatory)][object[]]$Modules,
        [Parameter(Mandatory)][hashtable]$RunMeta
    )
    $diag = [ordered]@{}
    $diag['schemaVersion'] = $script:FmpSchemaVersion
    $diag['run'] = [ordered]@{
        id          = $RunMeta.Id
        tool        = 'FIX MY PC: PC Diagnostic & Audit Skill'
        toolVersion = $script:FmpToolVersion
        mode        = $RunMeta.Mode
        language    = $RunMeta.Language
        synthetic   = $RunMeta.Synthetic
        startedAt   = $RunMeta.StartedAt
        finishedAt  = Get-FmpTimestamp
        readOnlyPolicy = Get-FmpReadOnlyPolicySummary
    }
    foreach ($m in $Modules) {
        $diag[$m.id] = $m.data
    }
    $diag['modules'] = @($Modules | ForEach-Object {
        [ordered]@{
            id = $_.id; status = $_.status; startedAt = $_.startedAt
            durationMs = $_.durationMs; commands = $_.commands
            errors = $_.errors; limits = $_.limits
        }
    })
    $allEv = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Modules) { foreach ($e in $m.evidence) { $allEv.Add($e) } }
    $diag['evidence'] = $allEv.ToArray()
    $diag['subChecks'] = @($Modules | ForEach-Object { $_.subChecks })
    return $diag
}
