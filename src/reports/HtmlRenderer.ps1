# =====================================================================
# FIX MY PC - HtmlRenderer.ps1
#
# Builds the final self-contained HTML report (offline, zero JavaScript,
# local CSS only, CSP-friendly). EVERY dynamic value passes through
# HTML encoding; data is never inserted as markup, attribute content or
# script. URLs from data are rendered as plain text, never as links.
# The report is written only through Write-FmpUtf8File (authorized dir).
#
# Images: the only non-text resources are the project's own optimized
# assets, embedded as data: URIs read from assets/optimized/embed/*.b64
# (prepared at packaging time by tools/Optimize-Assets.ps1). Nothing is
# decoded, resized or downloaded during an audit; each payload is validated
# (manifest entry, charset, magic prefix, exact length, size caps) and
# silently replaced by a text fallback if it is missing or damaged.
# This file is ASCII-only on purpose (PowerShell 5.1 reads BOM-less .ps1
# as ANSI); typographic characters are written as HTML entities.
# =====================================================================

$script:FmpLocales = @()
$script:FmpLanguage = 'en'
$script:FmpAssetRoot = $null
$script:FmpAssetIssues = New-Object System.Collections.Generic.List[string]
$script:FmpAssetKeys = @('banner', 'logo', 'icon', 'overview', 'findings', 'hardware', 'storage', 'startup', 'privacy')
$script:FmpAssetMaxBytes = 400KB
$script:FmpAssetMaxTotalBytes = 1536KB
# The report's only script: reveals the print button and opens the browser's own print dialog on a user click.
# It reads no report data, makes no request and stores nothing. Its exact bytes are authorized by hash in the CSP.
$script:FmpPrintScript = '(function(){var b=document.getElementById("fmp-print");if(!b){return;}b.hidden=false;b.addEventListener("click",function(){window.print();});})();'

function Get-FmpPrintScriptHash {
    # Base64 SHA-256 of the script's UTF-8 bytes, as CSP 'sha256-...' expects.
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($script:FmpPrintScript)
    return [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes))
}

function Set-FmpRenderLocale {
    param([object]$Primary, [object]$Fallback = $null, [string]$Language = 'en')
    $script:FmpLocales = @($Primary) + @($Fallback | Where-Object { $null -ne $_ })
    $script:FmpLanguage = $Language
}

function Set-FmpAssetRoot {
    # Test hook: points the renderer at another assets\optimized folder.
    param([string]$Path)
    $script:FmpAssetRoot = $Path
}

function Get-FmpAssetIssues {
    return ,$script:FmpAssetIssues.ToArray()
}

function Get-FmpText {
    param([Parameter(Mandatory)][string]$Key, [object[]]$Vals = @())
    return Get-FmpLocaleString -Locales $script:FmpLocales -Key $Key -Values $Vals
}

function Get-FmpOptionalText {
    # Like Get-FmpText, but returns $null (and records nothing) when no locale has the key.
    param([Parameter(Mandatory)][string]$Key, [object[]]$Vals = @())
    foreach ($loc in $script:FmpLocales) {
        if ($null -ne $loc -and $null -ne $loc.PSObject.Properties[$Key]) {
            return Get-FmpLocaleString -Locales @($loc) -Key $Key -Values $Vals
        }
    }
    return $null
}

function Get-FmpLocalizedLimitation {
    # Localized text for a stable key; safe fallback is the canonical text, never the key.
    param([string]$Key, [object]$Canonical, [object[]]$Vals = @())
    if (-not [string]::IsNullOrEmpty($Key)) {
        $t = Get-FmpOptionalText -Key $Key -Vals $Vals
        if ($null -ne $t -and ([string]$t) -notmatch '\{\d+\}') { return [string]$t }
    }
    $c = [string]$Canonical
    if ($c.Trim() -eq '') { return (Get-FmpText 'report.limitations.unlocalized') }
    return $c
}

function Get-FmpModuleName {
    param([string]$Id)
    $t = Get-FmpOptionalText -Key ('module.' + $Id)
    if ($null -eq $t) { return $Id }
    return [string]$t
}

function Get-FmpEsc {
    param([object]$Value)
    return ConvertTo-FmpHtmlText -Value $Value
}

function Get-FmpNum {
    param([object]$Value, [int]$Decimals = 0)
    return Format-FmpNumber -Value $Value -Decimals $Decimals -Language $script:FmpLanguage
}

function Get-FmpCountText {
    # "1 finding" / "2 findings": picks <Key>.one or <Key>.other and fills {0} with the localized number.
    param([Parameter(Mandatory)][string]$Key, [object]$N)
    $suffix = '.other'
    if ((ConvertTo-FmpNullableDouble $N) -eq 1) { $suffix = '.one' }
    return Get-FmpText ($Key + $suffix) -Vals @((Get-FmpNum -Value $N))
}

function Get-FmpLocalizedBool {
    param([object]$Value)
    if ($null -eq $Value) { return Get-FmpText 'table.notAvailable' }
    if ($Value) { return Get-FmpText 'table.yes' }
    return Get-FmpText 'table.no'
}

function Get-FmpShortDate {
    param([object]$Iso)
    $d = Get-FmpParsedDate -Value $Iso
    if ($null -eq $d) { return Get-FmpText 'table.notAvailable' }
    return $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Get-FmpTimeOnly {
    param([object]$Iso)
    $d = Get-FmpParsedDate -Value $Iso
    if ($null -eq $d) { return Get-FmpText 'table.notAvailable' }
    return $d.ToUniversalTime().ToString('HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Get-FmpPctWidth {
    # Clamped 0..100 width for meter bars; digits only, safe for a style attribute.
    param([object]$Value)
    $n = ConvertTo-FmpNullableDouble $Value
    if ($null -eq $n) { return $null }
    $w = [Math]::Max(0, [Math]::Min(100, $n))
    return (Format-FmpNumber -Value $w -Decimals 1 -Language 'en')
}

function Get-FmpStatusBadge {
    param([string]$State)
    if ([string]::IsNullOrEmpty($State)) {
        return '<span class="st unknown">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</span>'
    }
    $label = Get-FmpText ('state.' + $State)
    if ($label -eq ('state.' + $State)) { $label = $State }
    return '<span class="st ' + (ConvertTo-FmpHtmlAttr $State) + '">' + (Get-FmpEsc $label) + '</span>'
}

function Get-FmpIconSvg {
    # Authored inline SVG icons (one 24px grid, 2px round stroke, currentColor).
    # Static markup only: no data is ever placed inside an icon.
    param([string]$Name)
    $body = '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.1"/>'
    if ($Name -eq 'review_recommended') { $body = '<path d="M12 2.5 21.5 12 12 21.5 2.5 12Z"/><path d="M12 8v5M12 16.2v.1"/>' }
    elseif ($Name -eq 'attention') { $body = '<path d="M12 3.5 21.8 20.5H2.2Z"/><path d="M12 10v4.5M12 17.4v.1"/>' }
    elseif ($Name -eq 'print') { $body = '<path d="M7 8V3.5h10V8"/><rect x="3" y="8" width="18" height="8.5" rx="2"/><path d="M7 13.5h10v7H7Z"/>' }
    return '<svg class="ico" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + $body + '</svg>'
}

function Get-FmpCalloutHtml {
    param([string]$Text, [string]$Kind = '')
    $cls = 'callout'
    $icon = 'info'
    if ($Kind -ne '') { $cls = 'callout ' + $Kind }
    if ($Kind -eq 'warn' -or $Kind -eq 'bad') { $icon = 'attention' }
    return '<div class="' + $cls + '">' + (Get-FmpIconSvg -Name $icon) + '<p>' + (Get-FmpEsc $Text) + '</p></div>'
}

function Get-FmpSeverityBadge {
    param([string]$Severity)
    $label = Get-FmpText ('severity.' + $Severity)
    if ($label -eq ('severity.' + $Severity)) { $label = $Severity }
    return '<span class="sev ' + (ConvertTo-FmpHtmlAttr $Severity) + '">' + (Get-FmpIconSvg -Name $Severity) + ' ' + (Get-FmpEsc $label) + '</span>'
}

function ConvertTo-FmpCellText {
    # Formats one table cell value by convention: *Bytes -> size, *Pct ->
    # percent, bool -> yes/no, numbers -> localized, null -> dash.
    param([object]$Value, [string]$Key = '')
    if ($null -eq $Value) { return Get-FmpText 'table.notAvailable' }
    if ($Value -is [bool]) { return Get-FmpLocalizedBool -Value $Value }
    if ($Key -match '(?i)bytes$') { return Format-FmpBytes -Bytes $Value -Language $script:FmpLanguage }
    if ($Key -match '(?i)(pct|percent|percentProcessorTime)$') { return Get-FmpEsc (Format-FmpPercent -Value $Value -Language $script:FmpLanguage) }
    if ($Key -match '(?i)MB$') {
        $mb = ConvertTo-FmpNullableDouble $Value
        if ($null -ne $mb) { return Format-FmpBytes -Bytes ($mb * 1MB) -Language $script:FmpLanguage }
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return Format-FmpNumber -Value $Value -Decimals 1 -Language $script:FmpLanguage
    }
    return Get-FmpEsc $Value
}

function ConvertTo-FmpTable {
    # Data table. Every cell carries its column label (data-label) so the
    # print/phone layouts can stack rows without losing the header.
    param([object[]]$Rows, [object[]]$Columns, [int]$MaxRows = 0, [string]$TruncateKey = 'report.startup.truncatedTable')
    if ($null -eq $Rows -or @($Rows).Count -eq 0) {
        return '<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.table.empty')) + '</p>'
    }
    $rows = @($Rows)
    $shown = $rows
    $truncated = $false
    if ($MaxRows -gt 0 -and $rows.Count -gt $MaxRows) {
        $shown = $rows | Select-Object -First $MaxRows
        $truncated = $true
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="scroll-x"><table class="data stack"><thead><tr>')
    foreach ($c in $Columns) {
        [void]$sb.Append('<th scope="col">' + (Get-FmpEsc (Get-FmpText $c.h)) + '</th>')
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $shown) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = Get-FmpValue -Data $r -Path $c.k
            [void]$sb.Append('<td data-label="' + (ConvertTo-FmpHtmlAttr (Get-FmpText $c.h)) + '">' + (ConvertTo-FmpCellText -Value $v -Key $c.k) + '</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($truncated) {
        [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText $TruncateKey -Vals @($MaxRows, $rows.Count))) + '</p>')
    }
    return $sb.ToString()
}

function Get-FmpKvRow {
    # One label/value pair for definition lists. Missing values are said to
    # be unavailable instead of being filled in.
    param([string]$Label, [object]$Value, [string]$Key = 'text')
    $cell = ''
    if ($null -eq $Value -or ([string]$Value) -eq '') {
        $cell = '<span class="na">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</span>'
    }
    else { $cell = ConvertTo-FmpCellText -Value $Value -Key $Key }
    return '<dt>' + (Get-FmpEsc $Label) + '</dt><dd>' + $cell + '</dd>'
}

function Get-FmpPanelOpen {
    # Opens a section: heading plus an optional decorative asset icon.
    param([string]$Id, [string]$TitleKey, [hashtable]$Assets, [string]$IconKey = '')
    $icon = ''
    if ($IconKey -ne '') { $icon = '<span class="tile">' + (Get-FmpImgHtml -Assets $Assets -Key $IconKey) + '</span>' }
    return '<section class="panel" id="' + (ConvertTo-FmpHtmlAttr $Id) + '" aria-labelledby="' + (ConvertTo-FmpHtmlAttr $Id) + '-h"><div class="panel-head">' + $icon + '<h2 id="' +
        (ConvertTo-FmpHtmlAttr $Id) + '-h">' + (Get-FmpEsc (Get-FmpText $TitleKey)) + '</h2></div>'
}

# ---------------------------------------------------------------------
# Embedded assets (data: URIs prepared at packaging time)
# ---------------------------------------------------------------------
function Get-FmpEmbeddedAssets {
    $script:FmpAssetIssues.Clear()
    $assets = @{}
    $root = $script:FmpAssetRoot
    if ([string]::IsNullOrEmpty($root)) { $root = Join-Path (Get-FmpRoot) 'assets\optimized' }
    $manifestPath = Join-Path $root 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        $script:FmpAssetIssues.Add('manifest_missing')
        return $assets
    }
    $manifest = Read-FmpJsonFile -Path $manifestPath
    if (-not $manifest.Ok) {
        $script:FmpAssetIssues.Add('manifest_invalid')
        return $assets
    }
    $total = 0
    foreach ($key in $script:FmpAssetKeys) {
        $meta = Get-FmpValue -Data $manifest.Data -Path ('assets.' + $key)
        if ($null -eq $meta) { $script:FmpAssetIssues.Add($key + ':not_in_manifest'); continue }
        $mime = [string](Get-FmpValue -Data $meta -Path 'mime')
        $prefix = ''
        if ($mime -ceq 'image/png') { $prefix = 'iVBORw0KGgo' }
        elseif ($mime -ceq 'image/jpeg') { $prefix = '/9j/' }
        else { $script:FmpAssetIssues.Add($key + ':mime_not_allowed'); continue }
        $bytes = ConvertTo-FmpNullableInt (Get-FmpValue -Data $meta -Path 'bytes')
        $width = ConvertTo-FmpNullableInt (Get-FmpValue -Data $meta -Path 'width')
        $height = ConvertTo-FmpNullableInt (Get-FmpValue -Data $meta -Path 'height')
        if ($null -eq $bytes -or $null -eq $width -or $null -eq $height -or $bytes -le 0 -or $bytes -gt $script:FmpAssetMaxBytes -or
            $width -lt 1 -or $width -gt 4096 -or $height -lt 1 -or $height -gt 4096) {
            $script:FmpAssetIssues.Add($key + ':manifest_values_invalid')
            continue
        }
        $rel = [string](Get-FmpValue -Data $meta -Path 'b64')
        if ($rel -cnotmatch '^embed/[a-z]+\.b64$') { $script:FmpAssetIssues.Add($key + ':path_not_allowed'); continue }
        $file = Join-Path $root ($rel.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $script:FmpAssetIssues.Add($key + ':file_missing'); continue }
        $expectedLength = [Math]::Floor(($bytes + 2) / 3) * 4
        $text = $null
        try {
            $checked = Get-FmpCheckedPath $file
            if ((Get-Item -LiteralPath $checked -ErrorAction Stop).Length -gt ($expectedLength + 16)) { throw 'payload too large' }
            $text = (Get-Content -LiteralPath $checked -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
        }
        catch { $script:FmpAssetIssues.Add($key + ':unreadable'); continue }
        if ($text.Length -ne $expectedLength) { $script:FmpAssetIssues.Add($key + ':length_mismatch'); continue }
        if ($text -cnotmatch ('^' + [regex]::Escape($prefix) + '[A-Za-z0-9+/]*={0,2}$')) { $script:FmpAssetIssues.Add($key + ':not_valid_image_payload'); continue }
        $total += $bytes
        if ($total -gt $script:FmpAssetMaxTotalBytes) { $script:FmpAssetIssues.Add($key + ':total_size_exceeded'); continue }
        $assets[$key] = @{ uri = ('data:' + $mime + ';base64,' + $text); width = $width; height = $height }
    }
    return $assets
}

function Get-FmpImgHtml {
    # Alt text empty => decorative image, hidden from assistive technology.
    param([hashtable]$Assets, [string]$Key, [string]$Alt = '', [string]$Class = '')
    if ($null -eq $Assets -or -not $Assets.ContainsKey($Key)) { return '' }
    $a = $Assets[$Key]
    $cls = ''
    if ($Class -ne '') { $cls = ' class="' + (ConvertTo-FmpHtmlAttr $Class) + '"' }
    $altAttr = ' alt="" aria-hidden="true"'
    if ($Alt -ne '') { $altAttr = ' alt="' + (ConvertTo-FmpHtmlAttr $Alt) + '"' }
    return '<img' + $cls + ' src="' + $a.uri + '" width="' + [int]$a.width + '" height="' + [int]$a.height + '"' + $altAttr + '>'
}

# ---------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------
$script:FmpFindingValueOrder = @{
    'storage.low_free_space'        = @('drive', 'freePct', 'lowPct')
    'storage.disk_space_critical'   = @('drive', 'freePct', 'criticalPct')
    'storage.disk_health_unhealthy' = @('items')
    'storage.smart_predict_failure' = @('count')
    'storage.disk_event_errors'     = @('items', 'recentHours')
    'events.critical_recurring'     = @('count', 'provider', 'eventId', 'log')
    'events.error_concentration'    = @('count', 'provider', 'eventId')
    'events.whea_hardware'          = @('count')
    'events.unexpected_shutdown'    = @('count')
    'events.bsod'                   = @('count')
    'perf.cpu_sustained_high'       = @('avg', 'samples', 'max', 'windowSec')
    'perf.ram_pressure'             = @('availablePct', 'availableGB')
    'perf.commit_pressure'          = @('commitPct', 'thresholdPct')
    'os.w10_eol'                    = @('os', 'displayVersion', 'endOfSupport')
    'os.long_uptime'                = @('days', 'thresholdDays')
    'startup.unsigned_autostart'    = @('count', 'names')
    'startup.high_count'            = @('total', 'threshold', 'services')
    'os.pending_reboot'             = @('wu', 'cbs', 'fileRename')
    'os.outdated_patch'             = @('days', 'thresholdDays')
    'security.defender_disabled'    = @('component')
    'security.third_party_av'       = @('names')
    'devices.problem_codes'         = @('count', 'names')
}

function Get-FmpOrderedFindings {
    # Severity order comes from the rules and is never changed; inside one
    # severity the larger score impact comes first, then the original order.
    # Unknown severities are listed last instead of being dropped.
    param([object]$Analysis)
    $findings = @(Get-FmpValue -Data $Analysis -Path 'findings')
    $base = New-Object System.Collections.Generic.List[object]
    $extra = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($bucket in @('base', 'extra')) {
        $isExtra = ($bucket -eq 'extra')
        $wrapped = New-Object System.Collections.Generic.List[object]
        $idx = 0
        foreach ($f in $findings) {
            if (([bool](Get-FmpValue -Data $f -Path 'analysisOnly')) -ne $isExtra) { continue }
            $idx++
            $pen = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $f -Path 'penalty')
            if ($null -eq $pen) { $pen = 0 }
            $sev = [string](Get-FmpValue -Data $f -Path 'severity')
            $rank = 3
            if ($sev -ceq 'review_recommended') { $rank = 0 }
            elseif ($sev -ceq 'attention') { $rank = 1 }
            elseif ($sev -ceq 'info') { $rank = 2 }
            $wrapped.Add(@{ i = $idx; f = $f; pen = $pen; rank = $rank })
        }
        $sorted = @($wrapped.ToArray() | Sort-Object -Property @{ Expression = { $_.rank }; Descending = $false }, @{ Expression = { $_.pen }; Descending = $true }, @{ Expression = { $_.i }; Descending = $false })
        foreach ($w in $sorted) {
            $n++
            $entry = @{ n = $n; id = ('finding-' + $n); f = $w.f }
            if ($isExtra) { $extra.Add($entry) } else { $base.Add($entry) }
        }
    }
    return @{ base = $base.ToArray(); extra = $extra.ToArray() }
}

function Get-FmpFindingTitle {
    param([object]$F)
    return Get-FmpText ('rules.' + [string](Get-FmpValue -Data $F -Path 'id') + '.title')
}

function Get-FmpFindingHtml {
    param([object]$F, [string]$Anchor = '')
    $id = [string](Get-FmpValue -Data $F -Path 'id')
    $sev = [string](Get-FmpValue -Data $F -Path 'severity')
    $vals = @()
    $rawVals = Get-FmpValue -Data $F -Path 'values'
    $order = $script:FmpFindingValueOrder[$id]
    if ($null -ne $rawVals -and $null -ne $order) {
        foreach ($k in $order) {
            $v = Get-FmpValue -Data $rawVals -Path $k
            if ($v -is [bool]) { $v = Get-FmpLocalizedBool -Value $v }
            elseif ($v -is [double] -or $v -is [int] -or $v -is [long]) { $v = Format-FmpNumber -Value $v -Decimals 1 -Language $script:FmpLanguage }
            $vals += $v
        }
    }
    $title = Get-FmpText ('rules.' + $id + '.title')
    $detail = Get-FmpText ('rules.' + $id + '.detail') -Vals $vals
    $human = Get-FmpText ('rules.' + $id + '.humanCheck')

    $sb = New-Object System.Text.StringBuilder
    $idAttr = ''
    $labelAttr = ''
    $titleId = ''
    if ($Anchor -ne '') {
        $idAttr = ' id="' + (ConvertTo-FmpHtmlAttr $Anchor) + '"'
        $titleId = ' id="' + (ConvertTo-FmpHtmlAttr $Anchor) + '-t"'
        $labelAttr = ' aria-labelledby="' + (ConvertTo-FmpHtmlAttr $Anchor) + '-t"'
    }
    [void]$sb.Append('<article class="finding ' + (ConvertTo-FmpHtmlAttr $sev) + '"' + $idAttr + $labelAttr + '>')
    [void]$sb.Append('<div class="finding-head">' + (Get-FmpSeverityBadge -Severity $sev) + '<h3' + $titleId + '>' + (Get-FmpEsc $title) + '</h3>')
    if ([bool](Get-FmpValue -Data $F -Path 'analysisOnly')) {
        [void]$sb.Append('<span class="tag-analysis">' + (Get-FmpEsc (Get-FmpText 'report.analysisOnly.tag')) + '</span>')
    }
    [void]$sb.Append('</div><dl>')
    [void]$sb.Append('<dt>' + (Get-FmpEsc (Get-FmpText 'report.field.explanation')) + '</dt><dd>' + (Get-FmpEsc $detail) + '</dd>')
    $evidence = Get-FmpEsc ((Get-FmpValue -Data $F -Path 'category') + ' / ' + $id)
    $measured = Get-FmpValue -Data $F -Path 'measured'
    if ($null -ne $measured) {
        $mJson = ConvertTo-FmpJsonText -Data $measured
        $evidence = '<code class="path">' + (Get-FmpEsc $mJson) + '</code><br><span class="muted small">' + $evidence + '</span>'
    }
    [void]$sb.Append('<dt>' + (Get-FmpEsc (Get-FmpText 'report.field.evidence')) + '</dt><dd>' + $evidence + '</dd>')
    [void]$sb.Append('<dt>' + (Get-FmpEsc (Get-FmpText 'report.field.confidence')) + '</dt><dd>' + (Get-FmpEsc (Get-FmpText ('confidence.' + [string](Get-FmpValue -Data $F -Path 'confidence')))) + '</dd>')
    $lims = @(Get-FmpValue -Data $F -Path 'limitations')
    $limKeys = @(Get-FmpValue -Data $F -Path 'limitationKeys')
    $lText = Get-FmpText 'report.finding.noLimitations'
    if ($lims.Count -gt 0) {
        $parts = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $lims.Count; $i++) {
            $k = ''
            if ($i -lt $limKeys.Count) { $k = [string]$limKeys[$i] }
            $parts.Add((Get-FmpLocalizedLimitation -Key $k -Canonical $lims[$i]))
        }
        $lText = ($parts.ToArray() -join '; ')
    }
    [void]$sb.Append('<dt>' + (Get-FmpEsc (Get-FmpText 'report.field.limitations')) + '</dt><dd>' + (Get-FmpEsc $lText) + '</dd>')
    [void]$sb.Append('<dt>' + (Get-FmpEsc (Get-FmpText 'report.field.humanCheck')) + '</dt><dd>' + (Get-FmpEsc $human) + '</dd>')
    [void]$sb.Append('</dl></article>')
    return $sb.ToString()
}

function Get-FmpFindingsSectionHtml {
    param([object]$Ordered)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<p class="lead small">' + (Get-FmpEsc (Get-FmpText 'report.findings.lead')) + '</p>')
    if (@($Ordered.base).Count -eq 0) {
        [void]$sb.Append('<p class="muted">' + (Get-FmpEsc (Get-FmpText 'report.findings.none')) + '</p>')
    }
    foreach ($e in @($Ordered.base)) { [void]$sb.Append((Get-FmpFindingHtml -F $e.f -Anchor $e.id)) }
    if (@($Ordered.extra).Count -gt 0) {
        [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.analysisOnly.tag')) + '</h3>')
        [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.analysisOnly.explain')) + '</p>')
        foreach ($e in @($Ordered.extra)) { [void]$sb.Append((Get-FmpFindingHtml -F $e.f -Anchor $e.id)) }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Executive summary (score, coverage, confidence, severity counts)
# ---------------------------------------------------------------------
function Get-FmpSummaryBodyHtml {
    param([object]$Score, [object]$Ordered, [string]$Intro)
    $status = [string](Get-FmpValue -Data $Score -Path 'status')
    $statusLabel = Get-FmpText ('score.status.' + $status)
    $scoreVal = Get-FmpValue -Data $Score -Path 'score'
    $hasScore = ($status -ne 'unavailable' -and $null -ne $scoreVal)
    $tone = 'ok'
    if ($status -eq 'provisional') { $tone = 'provisional' }
    if (-not $hasScore) { $tone = 'unavailable' }
    $numClass = ''
    if ($status -eq 'provisional') { $numClass = 'warn' }
    if (-not $hasScore) { $numClass = 'na' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<p class="lead">' + (Get-FmpEsc $Intro) + '</p>')
    # The risk level tints the score card so a critical report never looks like a healthy one (the brand is blue/cyan).
    $riskCls = ''
    $riskTop = [string](Get-FmpValue -Data $Score -Path 'riskLevel')
    if ($riskTop -cin @('critical', 'elevated')) { $riskCls = ' risk-' + $riskTop }
    [void]$sb.Append('<div class="exec"><div class="score-card tone-' + $tone + $riskCls + '">')
    [void]$sb.Append('<p class="label">' + (Get-FmpEsc (Get-FmpText 'report.summary.score')) + '</p>')
    if ($hasScore) {
        [void]$sb.Append('<div class="score-figure"><div class="num ' + $numClass + '">' + (Get-FmpEsc (Get-FmpNum -Value $scoreVal -Decimals 0)) + '</div>')
        [void]$sb.Append('<div class="of"><span aria-hidden="true">' + (Get-FmpEsc (Get-FmpText 'report.score.of.short')) + '</span><span class="sr"> ' + (Get-FmpEsc (Get-FmpText 'score.of')) + '</span></div></div>')
        [void]$sb.Append('<p class="state">' + (Get-FmpEsc $statusLabel) + '</p>')
        $w = Get-FmpPctWidth $scoreVal
        [void]$sb.Append('<div class="meter" aria-hidden="true"><span style="width:' + (ConvertTo-FmpHtmlAttr $w) + '%"></span></div>')
        [void]$sb.Append('<div class="meter-scale" aria-hidden="true"><span>0</span><span>50</span><span>100</span></div>')
        $coveragePctText = ''
        $coverageRaw = Get-FmpValue -Data $Score -Path 'coveragePct'
        if ($null -ne $coverageRaw) { $coveragePctText = Format-FmpPercent -Value $coverageRaw -Language $script:FmpLanguage }
        if ($status -eq 'provisional' -and $coveragePctText -ne '') {
            # A provisional number never implies proven health, and must not say "no problem" when findings exist.
            $baseCount = @($Ordered.base).Count
            if ($baseCount -gt 0) {
                $noteText = Get-FmpText 'report.score.provisionalNote.findings' -Vals @((Get-FmpCountText -Key 'count.findings' -N $baseCount), $coveragePctText)
            }
            else { $noteText = Get-FmpText 'report.score.provisionalNote' -Vals @($coveragePctText) }
            [void]$sb.Append('<p class="note">' + (Get-FmpEsc $noteText) + '</p>')
        }
        else {
            [void]$sb.Append('<p class="note">' + (Get-FmpEsc (Get-FmpText 'report.score.scale')) + '</p>')
        }
    }
    else {
        [void]$sb.Append('<div class="score-figure"><div class="num ' + $numClass + '">&ndash;</div></div>')
        [void]$sb.Append('<p class="state">' + (Get-FmpEsc $statusLabel) + '</p>')
        [void]$sb.Append('<div class="na-box">' + (Get-FmpEsc (Get-FmpText 'report.score.noGauge')) + '</div>')
    }
    [void]$sb.Append('</div><div class="exec-side">')

    # Coverage and confidence are separate concepts from the score.
    $cov = Get-FmpValue -Data $Score -Path 'coveragePct'
    $covered = Get-FmpValue -Data $Score -Path 'coveredChecks'
    $app = Get-FmpValue -Data $Score -Path 'applicableChecks'
    $conf = [string](Get-FmpValue -Data $Score -Path 'confidence')
    # Diagnostic risk is a separate axis from score availability and data confidence.
    $risk = [string](Get-FmpValue -Data $Score -Path 'riskLevel')
    [void]$sb.Append('<dl class="facts">')
    if ($risk -cin @('critical', 'elevated', 'none_detected', 'undetermined')) {
        [void]$sb.Append('<div><dt>' + (Get-FmpEsc (Get-FmpText 'report.summary.risk')) + '</dt><dd><span class="risk ' + $risk + '">' + (Get-FmpEsc (Get-FmpText ('risk.level.' + $risk))) + '</span></dd></div>')
    }
    [void]$sb.Append('<div><dt>' + (Get-FmpEsc (Get-FmpText 'report.summary.coverage')) + '</dt><dd>')
    if ($null -ne $cov) {
        [void]$sb.Append((Get-FmpEsc (Format-FmpPercent -Value $cov -Language $script:FmpLanguage)) + ' <span class="sub">(' + (Get-FmpEsc (Get-FmpNum -Value $covered)) + '/' + (Get-FmpEsc (Get-FmpNum -Value $app)) + ')</span>')
        $covClass = 'coverage-bar'
        $covNum = ConvertTo-FmpNullableDouble $cov
        if ($null -ne $covNum -and $covNum -lt 100) { $covClass = 'coverage-bar partial' }
        [void]$sb.Append('<div class="' + $covClass + '" aria-hidden="true"><span style="width:' + (ConvertTo-FmpHtmlAttr (Get-FmpPctWidth $cov)) + '%"></span></div>')
    }
    else { [void]$sb.Append('<span class="na">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</span>') }
    [void]$sb.Append('</dd></div><div><dt>' + (Get-FmpEsc (Get-FmpText 'report.summary.confidence')) + '</dt><dd class="cap">' + (Get-FmpEsc (Get-FmpText ('confidence.' + $conf))) + '</dd></div></dl>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.summary.coverage.note')) + '</p>')

    # Findings by severity (base score findings only): proportional bar + legend.
    $baseList = @($Ordered.base)
    $counts = @{}
    foreach ($sev in @('review_recommended', 'attention', 'info')) {
        $counts[$sev] = @($baseList | Where-Object { ([string](Get-FmpValue -Data $_.f -Path 'severity')) -eq $sev }).Count
    }
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.summary.bySeverity')) + '</h3>')
    if ($baseList.Count -gt 0) {
        [void]$sb.Append('<div class="sev-bar" aria-hidden="true">')
        foreach ($sev in @('review_recommended', 'attention', 'info')) {
            if ($counts[$sev] -gt 0) { [void]$sb.Append('<span class="s-' + $sev + '" style="flex:' + $counts[$sev] + '"></span>') }
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('<ul class="sev-counts">')
    foreach ($sev in @('review_recommended', 'attention', 'info')) {
        [void]$sb.Append('<li class="' + $sev + '"><span class="n">' + (Get-FmpEsc (Get-FmpNum -Value $counts[$sev])) + '</span><span class="sev-name">' + (Get-FmpIconSvg -Name $sev) + ' ' + (Get-FmpEsc (Get-FmpText ('severity.' + $sev))) + '</span></li>')
    }
    [void]$sb.Append('</ul>')
    if (@($Ordered.extra).Count -gt 0) {
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.summary.analysisOnlyCount' -Vals @((Get-FmpNum -Value @($Ordered.extra).Count)))) + '</p>')
    }

    # Main observations: the most relevant findings, linked to the details.
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.summary.observations')) + '</h3>')
    if ($baseList.Count -eq 0) {
        [void]$sb.Append('<p>' + (Get-FmpEsc (Get-FmpText 'report.summary.noFindings')) + '</p>')
    }
    else {
        [void]$sb.Append('<ol class="observations">')
        foreach ($e in ($baseList | Select-Object -First 3)) {
            $esev = [string](Get-FmpValue -Data $e.f -Path 'severity')
            [void]$sb.Append('<li class="' + (ConvertTo-FmpHtmlAttr $esev) + '"><a href="#' + (ConvertTo-FmpHtmlAttr $e.id) + '">' + (Get-FmpEsc (Get-FmpFindingTitle -F $e.f)) + '</a> ' + (Get-FmpSeverityBadge -Severity $esev) + '</li>')
        }
        [void]$sb.Append('</ol>')
        if ($baseList.Count -gt 3) {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.summary.observation.more' -Vals @((Get-FmpNum -Value ($baseList.Count - 3))))) + '</p>')
        }
    }
    [void]$sb.Append('</div></div>')

    # Score by category: bars show points kept out of the category weight and are
    # drawn only where the category had applicable checks that produced evidence.
    $cats = @(Get-FmpValue -Data $Score -Path 'categories')
    if ($cats.Count -gt 0) {
        [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.score.byCategory')) + '</h3><ul class="cat-list">')
        foreach ($c in $cats) {
            $catName = Get-FmpText ('category.' + [string](Get-FmpValue -Data $c -Path 'category'))
            $weight = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $c -Path 'weight')
            $ded = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $c -Path 'deduction')
            if ($null -eq $ded) { $ded = 0 }
            $remaining = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $c -Path 'remaining')
            if ($null -eq $remaining -and $null -ne $weight) { $remaining = $weight - $ded }
            $applicable = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $c -Path 'applicableChecks')
            $coveredN = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $c -Path 'coveredChecks')
            $dedTxt = Get-FmpText 'score.no.deduction'
            if ($ded -gt 0) { $dedTxt = Get-FmpText 'score.deduction' -Vals @((Get-FmpNum -Value $ded -Decimals 1)) }
            $dedLabel = $dedTxt
            if ($ded -gt 0) { $dedLabel = (Get-FmpText 'report.score.col.penalty') + ': ' + $dedTxt }
            $hasEvidence = ($null -ne $applicable -and $applicable -gt 0 -and $null -ne $coveredN -and $coveredN -gt 0 -and $null -ne $weight -and $weight -gt 0 -and $null -ne $remaining)
            $eligibleFlag = Get-FmpValue -Data $c -Path 'eligible'
            if ($eligibleFlag -is [bool]) { $hasEvidence = ($eligibleFlag -and $hasEvidence) }
            [void]$sb.Append('<li><div class="cat-top"><span class="name">' + (Get-FmpEsc (Get-FmpText 'score.category' -Vals @($catName, (Get-FmpNum -Value $weight)))) + '</span>')
            if ($hasEvidence) {
                [void]$sb.Append('<span class="pts">' + (Get-FmpEsc (Get-FmpText 'report.score.cat.points' -Vals @((Get-FmpNum -Value $remaining -Decimals 1), (Get-FmpNum -Value $weight)))) + '</span></div>')
                [void]$sb.Append('<div class="cat-bar" aria-hidden="true"><span style="width:' + (ConvertTo-FmpHtmlAttr (Get-FmpPctWidth (($remaining / $weight) * 100))) + '%"></span></div>')
            }
            else {
                $noneKey = 'report.score.cat.none'
                if ((Get-FmpValue -Data $c -Path 'excludedReason') -eq 'no_evidence' -or
                    ($eligibleFlag -isnot [bool] -and $null -ne $applicable -and $applicable -gt 0)) { $noneKey = 'report.score.cat.noEvidence' }
                [void]$sb.Append('<span class="pts na">' + (Get-FmpEsc (Get-FmpText $noneKey)) + '</span></div><div class="cat-bar none" aria-hidden="true"></div>')
            }
            [void]$sb.Append('<div class="cat-meta"><span>' + (Get-FmpEsc $dedLabel) + '</span><span>' + (Get-FmpEsc (Get-FmpText 'score.categoryCoverage' -Vals @((Get-FmpValue -Data $c -Path 'coveredChecks'), (Get-FmpValue -Data $c -Path 'applicableChecks')))) + '</span></div></li>')
        }
        [void]$sb.Append('</ul>')
        $eligibleWeight = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $Score -Path 'eligibleWeight')
        if ($null -ne $eligibleWeight -and $eligibleWeight -lt 100) {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.score.renormalized' -Vals @((Get-FmpNum -Value $eligibleWeight)))) + '</p>')
        }
    }
    if ($risk -eq 'critical') {
        [void]$sb.Append((Get-FmpCalloutHtml -Kind 'bad' -Text (Get-FmpText 'risk.critical.explain')))
    }
    if ((Get-FmpValue -Data $Score -Path 'capped') -eq $true) {
        [void]$sb.Append((Get-FmpCalloutHtml -Kind 'warn' -Text (Get-FmpText 'score.capped' -Vals @((Get-FmpNum -Value (Get-FmpValue -Data $Score -Path 'scoreCap')), (Get-FmpNum -Value (Get-FmpValue -Data $Score -Path 'uncappedScore'))))))
    }
    [void]$sb.Append((Get-FmpCalloutHtml -Text (Get-FmpText 'score.explanation')))
    if ($status -eq 'provisional') {
        [void]$sb.Append((Get-FmpCalloutHtml -Kind 'warn' -Text (Get-FmpText 'score.provisional.explain')))
    }
    if ($status -eq 'unavailable') {
        [void]$sb.Append((Get-FmpCalloutHtml -Kind 'warn' -Text (Get-FmpText 'score.unavailable.explain')))
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Hardware and Windows
# ---------------------------------------------------------------------
function Get-FmpHardwareSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="kv-grid">')

    $os = Get-FmpValue -Data $D -Path 'system.os'
    [void]$sb.Append('<div class="kv-card"><h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.os')) + '</h3><dl class="kv">')
    $build = Get-FmpValue -Data $os -Path 'buildNumber'
    $ubr = Get-FmpValue -Data $os -Path 'ubr'
    if ($null -ne $build -and $null -ne $ubr) { $build = [string]$build + '.' + $ubr }
    $up = Get-FmpValue -Data $os -Path 'uptimeHours'
    $upTxt = $null
    if ($null -ne $up) { $upTxt = Get-FmpText 'report.hardware.uptime.hours' -Vals @((Get-FmpNum -Value $up -Decimals 1)) }
    $installDate = Get-FmpValue -Data $os -Path 'installDate'
    $lastBoot = Get-FmpValue -Data $os -Path 'lastBootAt'
    if ($null -ne $installDate) { $installDate = Get-FmpShortDate -Iso $installDate }
    if ($null -ne $lastBoot) { $lastBoot = Get-FmpShortDate -Iso $lastBoot }
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.caption') -Value (Get-FmpValue -Data $os -Path 'caption')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.version') -Value (Get-FmpValue -Data $os -Path 'version')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.build') -Value $build))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.architecture') -Value (Get-FmpValue -Data $os -Path 'architecture')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.installDate') -Value $installDate))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.lastBoot') -Value $lastBoot))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.os.uptime') -Value $upTxt))
    [void]$sb.Append('</dl></div>')

    $cpu = Get-FmpValue -Data $D -Path 'system.cpu'
    $clock = Get-FmpValue -Data $cpu -Path 'maxClockMhz'
    $clockTxt = $null
    if ($null -ne $clock) { $clockTxt = Get-FmpText 'report.hardware.clock.mhz' -Vals @((Get-FmpNum -Value $clock)) }
    [void]$sb.Append('<div class="kv-card"><h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.cpu')) + '</h3><dl class="kv">')
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'table.name') -Value (Get-FmpValue -Data $cpu -Path 'name')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.cores') -Value (Get-FmpValue -Data $cpu -Path 'cores')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.logical') -Value (Get-FmpValue -Data $cpu -Path 'logicalProcessors')))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.clock') -Value $clockTxt))
    [void]$sb.Append('</dl></div>')

    $mem = Get-FmpValue -Data $D -Path 'system.memory'
    $availTxt = $null
    if ($null -ne (Get-FmpValue -Data $mem -Path 'freeBytes')) {
        $availTxt = (Format-FmpBytes -Bytes (Get-FmpValue -Data $mem -Path 'freeBytes') -Language $script:FmpLanguage)
        if ($null -ne (Get-FmpValue -Data $mem -Path 'availablePct')) { $availTxt = $availTxt + ' (' + (Format-FmpPercent -Value (Get-FmpValue -Data $mem -Path 'availablePct') -Language $script:FmpLanguage) + ')' }
    }
    [void]$sb.Append('<div class="kv-card"><h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.memory')) + '</h3><dl class="kv">')
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.memory.total') -Value (Get-FmpValue -Data $mem -Path 'totalBytes') -Key 'totalBytes'))
    [void]$sb.Append((Get-FmpKvRow -Label (Get-FmpText 'report.hardware.memory.available') -Value $availTxt))
    [void]$sb.Append('</dl></div></div>')

    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.gpu')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $D -Path 'system.gpu') -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'driverVersion'; h = 'table.version' }, @{ k = 'status'; h = 'table.status' }
    )))

    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.disks')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $D -Path 'system.disks') -Columns @(
        @{ k = 'model'; h = 'table.name' }, @{ k = 'sizeBytes'; h = 'table.size' }, @{ k = 'status'; h = 'table.status' }, @{ k = 'interfaceType'; h = 'table.type' }
    )))

    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.hardware.volumes')) + '</h3>')
    $vols = Get-FmpValue -Data $D -Path 'system.volumes'
    $disp = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($vols)) {
        if ($null -eq $v) { continue }
        $o = [ordered]@{}
        foreach ($p in (Get-FmpEntries -Data $v)) { $o[$p.Key] = $p.Value }
        if (Get-FmpValue -Data $v -Path 'isSystem') { $o['label'] = ((Get-FmpValue -Data $v -Path 'label') + ' (' + (Get-FmpText 'report.hardware.system') + ')') }
        $disp.Add($o)
    }
    [void]$sb.Append((ConvertTo-FmpTable -Rows $disp.ToArray() -Columns @(
        @{ k = 'driveLetter'; h = 'report.hardware.drive' }, @{ k = 'label'; h = 'report.hardware.label' },
        @{ k = 'sizeBytes'; h = 'table.size' }, @{ k = 'freeBytes'; h = 'table.free' }, @{ k = 'freePct'; h = 'table.freePct' }
    )))
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Events and reliability
# ---------------------------------------------------------------------
function Get-FmpEventsSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    $window = Get-FmpValue -Data $D -Path 'events.windowDays'
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.events.window' -Vals @((Get-FmpNum -Value $window)))) + '</p>')
    [void]$sb.Append((Get-FmpCalloutHtml -Kind 'neutral' -Text (Get-FmpText 'report.events.historicalNote')))
    $logs = Get-FmpValue -Data $D -Path 'events.logs'
    if ($null -eq $logs) {
        [void]$sb.Append('<p class="muted">' + (Get-FmpEsc (Get-FmpText 'state.not_collected')) + '</p>')
        return $sb.ToString()
    }
    $anyTruncated = $false
    foreach ($lp in (Get-FmpEntries -Data $logs)) {
        if ((Get-FmpValue -Data $lp.Value -Path 'truncated') -eq $true) { $anyTruncated = $true }
    }
    if ($anyTruncated) {
        [void]$sb.Append((Get-FmpCalloutHtml -Kind 'warn' -Text (Get-FmpText 'report.events.truncatedNote')))
    }
    foreach ($lp in (Get-FmpEntries -Data $logs)) {
        $log = $lp.Value
        $status = [string](Get-FmpValue -Data $log -Path 'status')
        # For a log, "ok" means the query finished - not that no relevant event exists.
        $logBadge = Get-FmpStatusBadge -State $status
        if ($status -eq 'ok') { $logBadge = '<span class="st ok">' + (Get-FmpEsc (Get-FmpText 'report.events.queryOk')) + '</span>' }
        [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.events.log' -Vals @($lp.Key))) + '</h3>' + $logBadge + '</div>')
        $total = Get-FmpValue -Data $log -Path 'totalEvents'
        if ($status -eq 'access_denied') {
            [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.events.denied')) + '</p>')
            continue
        }
        if ($status -ne 'ok') { continue }
        $totalDisp = Get-FmpNum -Value $total
        if ((Get-FmpValue -Data $log -Path 'truncated') -eq $true -and $totalDisp -ne '-') { $totalDisp += '+' }
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.events.total' -Vals @($totalDisp))) + '</p>')
        $groups = Get-FmpValue -Data $log -Path 'groups'
        if ($null -eq $groups -or @($groups).Count -eq 0) {
            [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.events.none')) + '</p>')
            continue
        }
        $disp = New-Object System.Collections.Generic.List[object]
        foreach ($g in @($groups)) {
            $o = [ordered]@{}
            foreach ($p in (Get-FmpEntries -Data $g)) { $o[$p.Key] = $p.Value }
            $o['firstSeen'] = Get-FmpShortDate -Iso (Get-FmpValue -Data $g -Path 'firstSeen')
            $o['lastSeen'] = Get-FmpShortDate -Iso (Get-FmpValue -Data $g -Path 'lastSeen')
            $disp.Add($o)
        }
        [void]$sb.Append((ConvertTo-FmpTable -Rows $disp.ToArray() -Columns @(
            @{ k = 'provider'; h = 'table.provider' }, @{ k = 'eventId'; h = 'table.eventId' },
            @{ k = 'count'; h = 'table.count' }, @{ k = 'firstSeen'; h = 'table.first' }, @{ k = 'lastSeen'; h = 'table.last' }
        ) -MaxRows 20))
    }
    $rel = Get-FmpValue -Data $D -Path 'events.reliability'
    if ($null -ne $rel) {
        [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.reliability.title')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $rel -Path 'status'))) + '</div>')
        $metrics = Get-FmpValue -Data $rel -Path 'metrics'
        if ($null -ne $metrics -and @($metrics).Count -gt 0) {
            $vals = @($metrics | ForEach-Object { $_.stability })
            $avg = [Math]::Round((($vals | Measure-Object -Average).Average), 1)
            [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.reliability.stabilityAvg' -Vals @((Get-FmpNum -Value $avg -Decimals 1)))) + '</p>')
        }
        $recs = Get-FmpValue -Data $rel -Path 'records'
        if ($null -ne $recs -and @($recs).Count -gt 0) {
            $relDisp = New-Object System.Collections.Generic.List[object]
            foreach ($rr in @($recs)) {
                $ro = [ordered]@{}
                foreach ($p in (Get-FmpEntries -Data $rr)) { $ro[$p.Key] = $p.Value }
                $ro['at'] = Get-FmpShortDate -Iso (Get-FmpValue -Data $rr -Path 'at')
                $relDisp.Add($ro)
            }
            [void]$sb.Append((ConvertTo-FmpTable -Rows $relDisp.ToArray() -Columns @(
                @{ k = 'source'; h = 'table.provider' }, @{ k = 'eventId'; h = 'table.eventId' },
                @{ k = 'at'; h = 'table.when' }
            ) -MaxRows 10))
        }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Storage and performance (meters are drawn only from measured values)
# ---------------------------------------------------------------------
function Get-FmpUsageItemHtml {
    param([string]$Name, [object]$Total, [object]$Free, [object]$Extra = '')
    $t = ConvertTo-FmpNullableDouble $Total
    $f = ConvertTo-FmpNullableDouble $Free
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<li><div class="usage-top"><span class="name">' + (Get-FmpEsc $Name) + '</span>')
    if ($null -ne $t -and $null -ne $f -and $t -gt 0 -and $f -ge 0 -and $f -le $t) {
        $usedPct = [Math]::Round((($t - $f) / $t) * 100, 1)
        [void]$sb.Append('<span>' + (Get-FmpEsc (Get-FmpText 'report.storage.usedOf' -Vals @((Format-FmpBytes -Bytes ($t - $f) -Language $script:FmpLanguage), (Format-FmpBytes -Bytes $t -Language $script:FmpLanguage)))) + ' &middot; ' + (Get-FmpEsc (Get-FmpText 'report.storage.usedPct' -Vals @((Get-FmpNum -Value $usedPct -Decimals 1)))) + '</span></div>')
        [void]$sb.Append('<div class="usage-bar" aria-hidden="true"><span style="width:' + (ConvertTo-FmpHtmlAttr (Get-FmpPctWidth $usedPct)) + '%"></span></div>')
        [void]$sb.Append('<div class="usage-meta"><span>' + (Get-FmpEsc (Get-FmpText 'table.free')) + ': ' + (Get-FmpEsc (Format-FmpBytes -Bytes $f -Language $script:FmpLanguage)) + '</span>' + $Extra + '</div>')
    }
    else {
        [void]$sb.Append('<span class="na">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</span></div><div class="usage-meta">' + $Extra + '</div>')
    }
    [void]$sb.Append('</li>')
    return $sb.ToString()
}

function Get-FmpStorageSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.storage.volumes')) + '</h3>')
    $vols = @(Get-FmpValue -Data $D -Path 'storage.volumes')
    if ($vols.Count -eq 0) {
        [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.table.empty')) + '</p>')
    }
    else {
        [void]$sb.Append('<ul class="usage-list">')
        foreach ($v in $vols) {
            $health = Get-FmpValue -Data $v -Path 'healthStatus'
            $healthTxt = Get-FmpText 'report.storage.unknownHealth'
            if ($null -ne $health -and ([string]$health) -ne '') { $healthTxt = (Get-FmpText 'table.health') + ': ' + [string]$health }
            $extra = '<span>' + (Get-FmpEsc $healthTxt) + '</span>'
            $op = Get-FmpValue -Data $v -Path 'operationalStatus'
            if ($null -ne $op -and ([string]$op) -ne '') { $extra += '<span>' + (Get-FmpEsc ((Get-FmpText 'table.status') + ': ' + [string]$op)) + '</span>' }
            [void]$sb.Append((Get-FmpUsageItemHtml -Name ([string](Get-FmpValue -Data $v -Path 'driveLetter')) -Total (Get-FmpValue -Data $v -Path 'sizeBytes') -Free (Get-FmpValue -Data $v -Path 'freeBytes') -Extra $extra))
        }
        [void]$sb.Append('</ul>')
    }
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.storage.disks')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $D -Path 'storage.physicalDisks') -Columns @(
        @{ k = 'friendlyName'; h = 'table.name' }, @{ k = 'mediaType'; h = 'table.type' },
        @{ k = 'busType'; h = 'table.bus' }, @{ k = 'healthStatus'; h = 'table.health' },
        @{ k = 'operationalStatus'; h = 'table.status' }, @{ k = 'sizeBytes'; h = 'table.size' }
    )))
    $smart = Get-FmpValue -Data $D -Path 'storage.smart'
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.storage.smart')) + '</h3>')
    if ($null -eq $smart) {
        [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'report.storage.smart.none')) + '</p>')
    }
    elseif ((Get-FmpValue -Data $smart -Path 'status') -eq 'ok') {
        $checked = Get-FmpValue -Data $smart -Path 'checked'
        [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.storage.smart.ok' -Vals @((Get-FmpNum -Value $checked)))) + '</p>')
    }
    else {
        [void]$sb.Append('<p class="small">' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $smart -Path 'status'))) + ' ' + (Get-FmpEsc (Get-FmpText 'report.storage.smart.none')) + '</p>')
    }
    return $sb.ToString()
}

function Get-FmpResourcesSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.perf.ramUsed')) + '</h3>')
    $mem = Get-FmpValue -Data $D -Path 'performance.memory'
    if ($null -ne $mem) {
        $total = Get-FmpValue -Data $mem -Path 'totalBytes'
        $free = Get-FmpValue -Data $mem -Path 'freeBytes'
        $pct = Get-FmpValue -Data $mem -Path 'availablePct'
        [void]$sb.Append('<ul class="usage-list">')
        $extra = '<span>' + (Get-FmpEsc (Get-FmpText 'report.hardware.memory.available')) + ': ' + (Get-FmpEsc (Format-FmpPercent -Value $pct -Language $script:FmpLanguage)) + '</span>'
        [void]$sb.Append((Get-FmpUsageItemHtml -Name (Get-FmpText 'report.hardware.memory') -Total $total -Free $free -Extra $extra))
        [void]$sb.Append('</ul>')
        $commitPct = Get-FmpValue -Data $mem -Path 'commitPct'
        if ($null -ne $commitPct) {
            [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.resources.memory.commit' -Vals @(
                (Format-FmpBytes -Bytes (Get-FmpValue -Data $mem -Path 'committedBytes') -Language $script:FmpLanguage),
                (Format-FmpBytes -Bytes (Get-FmpValue -Data $mem -Path 'commitLimitBytes') -Language $script:FmpLanguage),
                (Get-FmpNum -Value $commitPct -Decimals 1)))) + '</p>')
        }
    }
    else {
        [void]$sb.Append('<p class="na small">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</p>')
    }
    $cpu = Get-FmpValue -Data $D -Path 'performance.cpu'
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.resources.cpu')) + '</h3>')
    if ($null -ne $cpu) {
        $cnt = Get-FmpValue -Data $cpu -Path 'sampleCount'
        if ($cnt -gt 0) {
            $intSec = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $cpu -Path 'intervalSec')
            $winDisp = '-'
            if ($null -ne $intSec) { $winDisp = Get-FmpNum -Value ($cnt * $intSec) }
            [void]$sb.Append('<p>' + (Get-FmpEsc (Get-FmpText 'report.resources.cpu.summary' -Vals @(
                (Get-FmpNum -Value (Get-FmpValue -Data $cpu -Path 'avgPercent') -Decimals 1),
                (Get-FmpNum -Value $cnt),
                (Get-FmpNum -Value (Get-FmpValue -Data $cpu -Path 'minPercent')),
                (Get-FmpNum -Value (Get-FmpValue -Data $cpu -Path 'maxPercent')),
                $winDisp))) + '</p>')
            $samples = @(Get-FmpValue -Data $cpu -Path 'samples')
            if ($samples.Count -gt 0) {
                [void]$sb.Append('<ul class="samples">')
                foreach ($s in ($samples | Select-Object -First 30)) {
                    $pv = Get-FmpValue -Data $s -Path 'percent'
                    $w = Get-FmpPctWidth $pv
                    $bar = ''
                    if ($null -ne $w) { $bar = '<span class="bar" aria-hidden="true"><span style="width:' + (ConvertTo-FmpHtmlAttr $w) + '%"></span></span>' }
                    [void]$sb.Append('<li><span class="muted">' + (Get-FmpEsc (Get-FmpTimeOnly -Iso (Get-FmpValue -Data $s -Path 'at'))) + '</span><br><strong>' + (Get-FmpEsc (Format-FmpPercent -Value $pv -Language $script:FmpLanguage)) + '</strong>' + $bar + '</li>')
                }
                [void]$sb.Append('</ul>')
            }
        }
        else {
            [void]$sb.Append('<p class="muted small">' + (Get-FmpEsc (Get-FmpText 'state.unknown')) + '</p>')
        }
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.resources.cpu.note')) + '</p>')
    }
    else {
        [void]$sb.Append('<p class="na small">' + (Get-FmpEsc (Get-FmpText 'report.value.unavailable')) + '</p>')
    }
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.resources.topmem')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $D -Path 'performance.topProcessesByMemory') -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'id'; h = 'table.pid' }, @{ k = 'workingSetMB'; h = 'table.size' }
    ) -MaxRows 15))
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.resources.topcpu')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $D -Path 'performance.topProcessesByCpu') -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'idProcess'; h = 'table.pid' }, @{ k = 'percentProcessorTime'; h = 'table.value' }
    ) -MaxRows 10))
    $pf = Get-FmpValue -Data $D -Path 'performance.pagefile'
    if ($null -ne $pf) {
        $pfAlloc = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $pf -Path 'allocatedMB')
        $pfCurr = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $pf -Path 'currentUsageMB')
        $pfPeak = ConvertTo-FmpNullableDouble (Get-FmpValue -Data $pf -Path 'peakUsageMB')
        [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.resources.pagefile')) + '</h3>')
        [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.resources.pagefile.line' -Vals @(
            (Get-FmpValue -Data $pf -Path 'name'),
            (Format-FmpBytes -Bytes $(if ($null -ne $pfAlloc) { $pfAlloc * 1MB } else { $null }) -Language $script:FmpLanguage),
            (Format-FmpBytes -Bytes $(if ($null -ne $pfCurr) { $pfCurr * 1MB } else { $null }) -Language $script:FmpLanguage),
            (Format-FmpBytes -Bytes $(if ($null -ne $pfPeak) { $pfPeak * 1MB } else { $null }) -Language $script:FmpLanguage)))) + '</p>')
    }
    [void]$sb.Append((Get-FmpCalloutHtml -Kind 'neutral' -Text (Get-FmpText 'report.perf.sampling')))
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------
function Get-FmpStartupSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    $items = @(Get-FmpValue -Data $D -Path 'startup.items')
    $tasks = @(Get-FmpValue -Data $D -Path 'startup.logonTasks')
    $svcs = @(Get-FmpValue -Data $D -Path 'startup.autoServices')
    $total = $items.Count + $tasks.Count + $svcs.Count
    [void]$sb.Append('<p class="small"><strong>' + (Get-FmpEsc (Get-FmpText 'report.startup.total' -Vals @((Get-FmpNum -Value $total)))) + '</strong></p>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.startup.counts' -Vals @((Get-FmpNum -Value $items.Count), (Get-FmpNum -Value $tasks.Count), (Get-FmpNum -Value $svcs.Count)))) + '</p>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.startup.note')) + '</p>')
    [void]$sb.Append((Get-FmpCalloutHtml -Kind 'neutral' -Text (Get-FmpText 'report.startup.unknownNote')))
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.startup.registry')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows $items -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'source'; h = 'table.source' },
        @{ k = 'view'; h = 'table.type' }, @{ k = 'command'; h = 'table.command' }
    ) -MaxRows 30))
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.startup.tasks')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows $tasks -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'path'; h = 'table.location' },
        @{ k = 'state'; h = 'table.status' }, @{ k = 'action'; h = 'table.command' }
    ) -MaxRows 20))
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.startup.services')) + '</h3>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows $svcs -Columns @(
        @{ k = 'displayName'; h = 'table.name' }, @{ k = 'name'; h = 'table.item' },
        @{ k = 'state'; h = 'table.status' }, @{ k = 'delayed'; h = 'table.delayed' },
        @{ k = 'account'; h = 'table.account' }
    ) -MaxRows 30))
    foreach ($tc in @(Get-FmpValue -Data $D -Path 'privacy.truncatedCollections')) {
        $tcPath = [string](Get-FmpValue -Data $tc -Path 'path')
        if ($tcPath -like 'startup.*') {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.privacy.collectionTruncated' -Vals @(
                $tcPath,
                (Get-FmpNum -Value (Get-FmpValue -Data $tc -Path 'originalCount')),
                (Get-FmpNum -Value (Get-FmpValue -Data $tc -Path 'retainedCount'))))) + '</p>')
        }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------
# Advanced checks (Full mode)
# ---------------------------------------------------------------------
function Get-FmpAdvancedSectionHtml {
    param([object]$D)
    $sb = New-Object System.Text.StringBuilder
    $adv = Get-FmpValue -Data $D -Path 'advanced'
    if ($null -eq $adv) {
        [void]$sb.Append('<p class="muted">' + (Get-FmpEsc (Get-FmpText 'state.not_collected')) + '</p>')
        return $sb.ToString()
    }

    # Problem devices
    $pd = Get-FmpValue -Data $adv -Path 'problemDevices'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.problemDevices')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $pd -Path 'status'))) + '</div>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $pd -Path 'items') -Columns @(
        @{ k = 'name'; h = 'table.name' }, @{ k = 'code'; h = 'table.code' }
    ) -MaxRows 20))

    # Driver info
    $drv = Get-FmpValue -Data $adv -Path 'driverInfo'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.driverInfo')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $drv -Path 'status'))) + '</div>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $drv -Path 'items') -Columns @(
        @{ k = 'deviceName'; h = 'table.name' }, @{ k = 'version'; h = 'table.version' },
        @{ k = 'provider'; h = 'table.publisher' }, @{ k = 'signed'; h = 'table.signature' }
    )))

    # Defender
    $def = Get-FmpValue -Data $adv -Path 'defender'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.defender')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $def -Path 'status'))) + '</div>')
    $defData = Get-FmpValue -Data $def -Path 'data'
    if ($null -ne $defData) {
        [void]$sb.Append('<div class="scroll-x"><table class="data kvt"><tbody>')
        foreach ($p in (Get-FmpEntries -Data $defData)) {
            $v = $p.Value
            if ($p.Key -match 'Date|End|Updated') { $v = Get-FmpShortDate -Iso $v }
            [void]$sb.Append('<tr><th scope="row">' + (Get-FmpEsc $p.Key) + '</th><td>' + (ConvertTo-FmpCellText -Value $v -Key 'text') + '</td></tr>')
        }
        [void]$sb.Append('</tbody></table></div>')
    }

    # Third-party AV
    $av = Get-FmpValue -Data $adv -Path 'thirdPartyAv'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.thirdPartyAv')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $av -Path 'status'))) + '</div>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $av -Path 'items') -Columns @(
        @{ k = 'displayName'; h = 'table.name' }, @{ k = 'productState'; h = 'table.code' }
    )))

    # Pending reboot
    $pr = Get-FmpValue -Data $adv -Path 'pendingReboot'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.pendingReboot')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $pr -Path 'status'))) + '</div>')
    if ($null -ne $pr) {
        if ([bool](Get-FmpValue -Data $pr -Path 'any')) {
            [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.advanced.pendingReboot.any' -Vals @(
                (Get-FmpLocalizedBool -Value (Get-FmpValue -Data $pr -Path 'pendingWuReboot')),
                (Get-FmpLocalizedBool -Value (Get-FmpValue -Data $pr -Path 'pendingCbs')),
                (Get-FmpLocalizedBool -Value (Get-FmpValue -Data $pr -Path 'pendingFileRename'))))) + '</p>')
        }
        else {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.advanced.pendingReboot.none')) + '</p>')
        }
    }

    # Updates (not collected)
    $upd = Get-FmpValue -Data $adv -Path 'updates'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.updates')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $upd -Path 'status'))) + '</div>')
    if ($null -ne $upd) {
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.advanced.updates.notCollected')) + '</p>')
    }

    # Hotfixes
    $hf = Get-FmpValue -Data $adv -Path 'hotfixes'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.hotfixes')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $hf -Path 'status'))) + '</div>')
    $hfDisp = New-Object System.Collections.Generic.List[object]
    foreach ($h in @(Get-FmpValue -Data $hf -Path 'items')) {
        $o = [ordered]@{}
        foreach ($p in (Get-FmpEntries -Data $h)) { $o[$p.Key] = $p.Value }
        $o['installedOn'] = Get-FmpShortDate -Iso (Get-FmpValue -Data $h -Path 'installedOn')
        $hfDisp.Add($o)
    }
    [void]$sb.Append((ConvertTo-FmpTable -Rows $hfDisp.ToArray() -Columns @(
        @{ k = 'hotFixId'; h = 'table.item' }, @{ k = 'description'; h = 'table.type' }, @{ k = 'installedOn'; h = 'table.when' }
    )))

    # Installed apps
    $apps = Get-FmpValue -Data $adv -Path 'installedApps'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.installedApps')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $apps -Path 'status'))) + '</div>')
    if ($null -ne $apps) {
        $appsTotal = Get-FmpValue -Data $apps -Path 'totalCount'
        $appsCollTrunc = ((Get-FmpValue -Data $apps -Path 'collectionTruncated') -eq $true)
        $appsSanTrunc = ((Get-FmpValue -Data $apps -Path 'sanitizedTruncated') -eq $true)
        $appsAnyTrunc = ((Get-FmpValue -Data $apps -Path 'truncated') -eq $true)
        $appsTotalDisp = Get-FmpNum -Value $appsTotal
        if ($appsCollTrunc -and $appsTotalDisp -ne '-') { $appsTotalDisp += '+' }
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.events.total' -Vals @($appsTotalDisp))) + '</p>')
        $appsPresented = Get-FmpValue -Data $apps -Path 'presentedCount'
        if ($null -eq $appsPresented) { $appsPresented = @(Get-FmpValue -Data $apps -Path 'items').Count }
        if ($appsCollTrunc -and $appsSanTrunc) {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.advanced.installedApps.bothTruncated' -Vals @((Get-FmpNum -Value $appsPresented), (Get-FmpNum -Value $appsTotal)))) + '</p>')
        }
        elseif ($appsSanTrunc) {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.advanced.installedApps.sanitizedTruncated' -Vals @((Get-FmpNum -Value $appsPresented), (Get-FmpNum -Value $appsTotal)))) + '</p>')
        }
        elseif ($appsCollTrunc -or $appsAnyTrunc) {
            [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.advanced.installedApps.collectionTruncated' -Vals @((Get-FmpNum -Value $appsPresented), (Get-FmpNum -Value $appsTotal)))) + '</p>')
        }
    }
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $apps -Path 'items') -Columns @(
        @{ k = 'displayName'; h = 'table.name' }, @{ k = 'displayVersion'; h = 'table.version' },
        @{ k = 'publisher'; h = 'table.publisher' }, @{ k = 'estimatedSizeKB'; h = 'table.size' }, @{ k = 'source'; h = 'table.source' }
    ) -MaxRows 30))

    # Signatures
    $sig = Get-FmpValue -Data $adv -Path 'signatures'
    [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.signatures' -Vals @((Get-FmpNum -Value (Get-FmpValue -Data $sig -Path 'checked'))))) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $sig -Path 'status'))) + '</div>')
    [void]$sb.Append((ConvertTo-FmpTable -Rows (Get-FmpValue -Data $sig -Path 'items') -Columns @(
        @{ k = 'file'; h = 'table.file' }, @{ k = 'location'; h = 'table.location' },
        @{ k = 'status'; h = 'table.signature' }, @{ k = 'signer'; h = 'table.signer' }
    ) -MaxRows 30))

    # Security events
    $sec = Get-FmpValue -Data $D -Path 'events.security'
    if ($null -ne $sec) {
        [void]$sb.Append('<div class="log-head"><h3>' + (Get-FmpEsc (Get-FmpText 'report.advanced.securityEvents')) + '</h3>' + (Get-FmpStatusBadge -State ([string](Get-FmpValue -Data $sec -Path 'status'))) + '</div>')
        $failures = Get-FmpNum -Value (Get-FmpValue -Data $sec -Path 'logonFailures')
        if ((Get-FmpValue -Data $sec -Path 'truncated') -eq $true) { $failures += '+' }
        [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.advanced.securityEvents.line' -Vals @($failures))) + '</p>')
    }
    return $sb.ToString()
}

function Get-FmpLimitationsSectionHtml {
    param([object]$D, [object]$Score)
    $items = New-Object System.Collections.Generic.List[string]
    $modules = Get-FmpValue -Data $D -Path 'modules'
    if ($null -ne $modules) {
        foreach ($m in @($modules)) {
            $modName = Get-FmpModuleName -Id ([string](Get-FmpValue -Data $m -Path 'id'))
            foreach ($l in @(Get-FmpValue -Data $m -Path 'limits')) {
                $lk = [string](Get-FmpValue -Data $l -Path 'localeKey')
                # [string](no output) is $null in PS 5.1, not '': test with IsNullOrEmpty.
                if ([string]::IsNullOrEmpty($lk)) { $lk = [string](Get-FmpValue -Data $l -Path 'key') }
                $txt = Get-FmpLocalizedLimitation -Key ('limit.' + $lk) -Canonical (Get-FmpValue -Data $l -Path 'detail') -Vals @(Get-FmpValue -Data $l -Path 'values')
                $items.Add((Get-FmpText 'report.limitations.module' -Vals @($modName, $txt)))
            }
            # Raw error text and the failing query id stay in the JSON (technical, often redacted).
            foreach ($e in @(Get-FmpValue -Data $m -Path 'errors')) {
                $items.Add((Get-FmpText 'report.limitations.module' -Vals @($modName, (Get-FmpText 'report.limitations.moduleError'))))
            }
        }
    }
    $scoreLims = @(Get-FmpValue -Data $Score -Path 'limitations')
    $scoreKeys = @(Get-FmpValue -Data $Score -Path 'limitationKeys')
    for ($i = 0; $i -lt $scoreLims.Count; $i++) {
        $k = ''
        if ($i -lt $scoreKeys.Count) { $k = [string]$scoreKeys[$i] }
        $items.Add((Get-FmpLocalizedLimitation -Key $k -Canonical $scoreLims[$i]))
    }
    if ($items.Count -eq 0) {
        return '<p class="muted">' + (Get-FmpEsc (Get-FmpText 'report.limitations.none')) + '</p>'
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.limitations.intro')) + '</p>')
    [void]$sb.Append('<ul class="limits">')
    foreach ($i in $items) {
        [void]$sb.Append('<li class="small">' + (Get-FmpEsc $i) + '</li>')
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

function Get-FmpRecommendationsSectionHtml {
    param([object]$Analysis)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.recommendations.intro')) + '</p>')
    [void]$sb.Append('<ul class="limits">')
    $seen = @{}
    foreach ($f in @(Get-FmpValue -Data $Analysis -Path 'findings')) {
        $id = [string](Get-FmpValue -Data $f -Path 'id')
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $h = Get-FmpText ('rules.' + $id + '.humanCheck')
        if ($h -ne ('rules.' + $id + '.humanCheck')) {
            [void]$sb.Append('<li class="small">' + (Get-FmpEsc $h) + '</li>')
        }
    }
    foreach ($g in (Get-FmpText 'report.recommendations.generic' -Vals @())) {
        [void]$sb.Append('<li class="small">' + (Get-FmpEsc $g) + '</li>')
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

function Get-FmpPrivacyNextSectionHtml {
    param([object]$Analysis, [object]$RedactionCount, [object]$Diagnostic = $null)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.section.privacy')) + '</h3><ul class="privacy-points">')
    foreach ($p in (Get-FmpText 'report.privacy.points' -Vals @())) {
        [void]$sb.Append('<li>' + (Get-FmpEsc $p) + '</li>')
    }
    [void]$sb.Append('</ul>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.privacy.text')) + '</p>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.privacy.redactions' -Vals @((Get-FmpNum -Value $RedactionCount)))) + '</p>')
    if ($null -ne $Diagnostic -and (Get-FmpValue -Data $Diagnostic -Path 'privacy.truncated') -eq $true) {
        $tcList = @(Get-FmpValue -Data $Diagnostic -Path 'privacy.truncatedCollections')
        $tcLabels = New-Object System.Collections.Generic.List[string]
        foreach ($tc in $tcList) {
            $tcLabels.Add(([string](Get-FmpValue -Data $tc -Path 'path') + ' (' + (Get-FmpNum -Value (Get-FmpValue -Data $tc -Path 'retainedCount')) + '/' + (Get-FmpNum -Value (Get-FmpValue -Data $tc -Path 'originalCount')) + ')'))
        }
        [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.privacy.truncatedNotice' -Vals @((Get-FmpNum -Value $tcList.Count), ($tcLabels -join '; ')))) + '</p>')
    }
    [void]$sb.Append('<div class="two-col"><div><h3>' + (Get-FmpEsc (Get-FmpText 'report.section.recommendations')) + '</h3>')
    [void]$sb.Append((Get-FmpRecommendationsSectionHtml -Analysis $Analysis))
    [void]$sb.Append('</div><div><h3>' + (Get-FmpEsc (Get-FmpText 'report.review.title')) + '</h3><ul class="limits">')
    foreach ($s in (Get-FmpText 'report.review.steps' -Vals @())) {
        [void]$sb.Append('<li class="small">' + (Get-FmpEsc $s) + '</li>')
    }
    [void]$sb.Append('</ul></div></div>')
    return $sb.ToString()
}

function Get-FmpMethodologySectionHtml {
    param([object]$Run, [object[]]$Modules)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.methodology.tool' -Vals @((Get-FmpValue -Data $Run -Path 'toolVersion')))) + '</p>')
    [void]$sb.Append('<p class="small">' + (Get-FmpEsc (Get-FmpText 'report.methodology.states')) + '</p>')
    [void]$sb.Append('<ul class="limits small">')
    foreach ($n in (Get-FmpText 'report.methodology.notes' -Vals @())) {
        [void]$sb.Append('<li>' + (Get-FmpEsc $n) + '</li>')
    }
    [void]$sb.Append('</ul>')
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.methodology.modules')) + '</h3>')
    $modRows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Modules) {
        $modStatus = [string](Get-FmpValue -Data $m -Path 'status')
        $modStatusText = Get-FmpOptionalText -Key ('module.status.' + $modStatus)
        if ($null -eq $modStatusText) { $modStatusText = $modStatus }
        $modRows.Add([ordered]@{
            id = (Get-FmpModuleName -Id ([string](Get-FmpValue -Data $m -Path 'id')))
            status = $modStatusText
            durationMs = (Get-FmpText 'report.methodology.durationMs' -Vals @((Get-FmpNum -Value (Get-FmpValue -Data $m -Path 'durationMs'))))
        })
    }
    [void]$sb.Append((ConvertTo-FmpTable -Rows $modRows.ToArray() -Columns @(
        @{ k = 'id'; h = 'table.name' }, @{ k = 'status'; h = 'table.status' }, @{ k = 'durationMs'; h = 'table.duration' }
    )))
    [void]$sb.Append('<h3>' + (Get-FmpEsc (Get-FmpText 'report.methodology.commands')) + '</h3>')
    [void]$sb.Append('<ul class="limits small">')
    foreach ($m in $Modules) {
        $cmds = @(Get-FmpValue -Data $m -Path 'commands')
        $cmdText = Get-FmpText 'report.methodology.noCommands'
        if ($cmds.Count -gt 0) { $cmdText = ($cmds -join ', ') }
        [void]$sb.Append('<li>' + (Get-FmpEsc ((Get-FmpModuleName -Id ([string](Get-FmpValue -Data $m -Path 'id'))) + ': ' + $cmdText)) + '</li>')
    }
    [void]$sb.Append('</ul>')
    [void]$sb.Append('<p class="small muted">' + (Get-FmpEsc (Get-FmpText 'report.methodology.disclaimer')) + '</p>')
    return $sb.ToString()
}

function Get-FmpMetaItemHtml {
    # Header metadata is shown only when the run actually recorded it.
    param([string]$LabelKey, [object]$Value)
    if ($null -eq $Value -or ([string]$Value) -eq '') { return '' }
    return '<div><dt>' + (Get-FmpEsc (Get-FmpText $LabelKey)) + '</dt><dd>' + (Get-FmpEsc $Value) + '</dd></div>'
}

function Get-FmpHtmlReportText {
    param(
        [Parameter(Mandatory)][object]$Diagnostic,
        [bool]$Synthetic = $false,
        [object]$RedactionCount = 0
    )
    if ((Get-FmpValue $Diagnostic 'privacy.sanitized') -ne $true) {
        throw 'The HTML renderer requires the sanitized diagnostic document.'
    }
    $Analysis = Get-FmpValue $Diagnostic 'analysis'
    $Score = Get-FmpValue $Diagnostic 'healthScore'
    $run = Get-FmpValue -Data $Diagnostic -Path 'run'
    $lang = [string](Get-FmpValue -Data $run -Path 'language')
    if ([string]::IsNullOrEmpty($lang)) { $lang = 'en' }
    $cssPath = Join-Path (Get-FmpRoot) 'templates\style.css'
    $css = Get-Content -LiteralPath $cssPath -Raw -Encoding UTF8
    if ($css -match '<|@import|url\s*\(') { throw 'Expected a local CSS template without markup or resource references.' }
    # Localized A4 page footer. Locale text is ours, but strip anything that could end the CSS string or rule anyway.
    $printFooter = [regex]::Replace([string](Get-FmpText 'report.print.footer'), '["\\<>\x00-\x1F]', '')
    $css += ' @media print { @page { @bottom-left { content: "FIX MY PC \00B7  ' + $printFooter + '"; font: 8pt system-ui, sans-serif; color: #555; } } }'
    $assets = Get-FmpEmbeddedAssets

    # CSP: nothing is allowed except inline CSS, (only when embedded) data: images and the one static print
    # script, authorized by the SHA-256 of its exact UTF-8 bytes. Any change to the script makes the browser block it.
    $imgSrc = ''
    if ($assets.Count -gt 0) { $imgSrc = ' img-src data:;' }
    $printHash = Get-FmpPrintScriptHash
    $csp = 'default-src ''none''; script-src ''sha256-' + $printHash + '''; style-src ''unsafe-inline'';' + $imgSrc + ' base-uri ''none''; form-action ''none'''

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="' + (ConvertTo-FmpHtmlAttr $lang) + '"><head><meta charset="utf-8">')
    [void]$sb.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.Append('<meta http-equiv="Content-Security-Policy" content="' + (ConvertTo-FmpHtmlAttr $csp) + '">')
    # The run id in the title identifies the report in the browser's print header and in "Save as PDF" file names.
    $titleId = ''
    $runIdForTitle = Get-FmpValue -Data $run -Path 'id'
    if ($null -ne $runIdForTitle -and ([string]$runIdForTitle) -ne '') { $titleId = ' - ' + (Get-FmpEsc $runIdForTitle) }
    [void]$sb.Append('<title>' + (Get-FmpEsc (Get-FmpText 'report.title')) + ' - ' + (Get-FmpEsc (Get-FmpText 'app.name')) + $titleId + '</title>')
    if ($assets.ContainsKey('icon')) { [void]$sb.Append('<link rel="icon" type="image/png" href="' + $assets['icon'].uri + '">') }
    [void]$sb.Append('<style>' + $css + '</style></head><body><a class="skip" href="#main">' + (Get-FmpEsc (Get-FmpText 'report.a11y.skip')) + '</a><div class="wrap">')

    # ---- Header ----
    $mode = [string](Get-FmpValue -Data $run -Path 'mode')
    $toolVersion = Get-FmpValue -Data $run -Path 'toolVersion'
    $runId = Get-FmpValue -Data $run -Path 'id'
    [void]$sb.Append('<header class="hero">')
    $bannerImg = Get-FmpImgHtml -Assets $assets -Key 'banner' -Alt (Get-FmpText 'report.brand.bannerAlt') -Class 'hero-banner'
    if ($bannerImg -ne '') { [void]$sb.Append($bannerImg) }
    else {
        [void]$sb.Append('<div class="hero-fallback"><div class="brand">FIX MY <b>PC</b></div><div class="product">' + (Get-FmpEsc (Get-FmpText 'report.brand.product')) + '</div></div>')
    }
    [void]$sb.Append('<div class="hero-meta">')
    $logoImg = Get-FmpImgHtml -Assets $assets -Key 'logo' -Alt (Get-FmpText 'report.brand.logoAlt')
    if ($logoImg -eq '') { $logoImg = '<strong>' + (Get-FmpEsc (Get-FmpText 'app.name')) + '</strong> &middot; ' + (Get-FmpEsc (Get-FmpText 'report.brand.product')) }
    [void]$sb.Append('<div class="print-only print-brand">' + $logoImg + '</div>')
    [void]$sb.Append('<div class="hero-top"><div class="badges"><span class="pill readonly">' + (Get-FmpEsc (Get-FmpText 'app.readonly.badge')) + '</span><span class="pill mode">' + (Get-FmpEsc (Get-FmpText ('mode.' + $mode))) + '</span>')
    if ($Synthetic) {
        [void]$sb.Append('<span class="pill synthetic">' + (Get-FmpEsc (Get-FmpText 'report.banner.synthetic')) + '</span>')
    }
    # The button stays hidden until the hash-authorized script reveals it, so a blocked script never leaves a dead control.
    [void]$sb.Append('</div><div class="print-action"><button type="button" id="fmp-print" class="print-btn" hidden>' + (Get-FmpIconSvg -Name 'print') + '<span>' + (Get-FmpEsc (Get-FmpText 'report.print.button')) + '</span></button>')
    [void]$sb.Append('<p class="print-hint">' + (Get-FmpEsc (Get-FmpText 'report.print.hint')) + '</p></div></div>')
    [void]$sb.Append('<h1>' + (Get-FmpEsc (Get-FmpText 'report.title')) + '</h1>')
    [void]$sb.Append('<dl class="meta-list">')
    [void]$sb.Append((Get-FmpMetaItemHtml -LabelKey 'report.meta.tool' -Value (Get-FmpText 'app.name')))
    if ($null -ne $toolVersion -and ([string]$toolVersion) -ne '') {
        [void]$sb.Append((Get-FmpMetaItemHtml -LabelKey 'report.meta.version' -Value ('v' + [string]$toolVersion)))
    }
    $finished = Get-FmpValue -Data $run -Path 'finishedAt'
    if ($null -ne $finished) { [void]$sb.Append((Get-FmpMetaItemHtml -LabelKey 'report.meta.generated' -Value (Get-FmpShortDate -Iso $finished))) }
    [void]$sb.Append((Get-FmpMetaItemHtml -LabelKey 'report.meta.mode' -Value (Get-FmpText ('mode.' + $mode))))
    [void]$sb.Append((Get-FmpMetaItemHtml -LabelKey 'report.meta.id' -Value $runId))
    [void]$sb.Append('</dl></div></header>')

    if ($Synthetic) {
        [void]$sb.Append('<div class="banner-synthetic" role="note"><strong>' + (Get-FmpEsc (Get-FmpText 'report.banner.synthetic')) + '</strong><p>' + (Get-FmpEsc (Get-FmpText 'report.banner.synthetic.detail')) + '</p></div>')
    }

    # ---- Navigation (plain anchors, no script) ----
    $navItems = @(
        @('summary', 'report.section.summary'), @('findings', 'report.section.findings'), @('hardware', 'report.section.hardware'),
        @('storage', 'report.section.storagePerf'), @('startup', 'report.section.startup'), @('events', 'report.section.events'),
        @('advanced', 'report.section.advanced'), @('limitations', 'report.section.limitations'),
        @('privacy', 'report.section.privacyNext'), @('methodology', 'report.section.methodology')
    )
    [void]$sb.Append('<nav class="toc" aria-label="' + (ConvertTo-FmpHtmlAttr (Get-FmpText 'report.nav.label')) + '"><ul>')
    foreach ($ni in $navItems) {
        [void]$sb.Append('<li><a href="#' + $ni[0] + '">' + (Get-FmpEsc (Get-FmpText $ni[1])) + '</a></li>')
    }
    [void]$sb.Append('</ul></nav><main id="main">')

    # ---- Executive summary ----
    $modules = @(Get-FmpValue -Data $Diagnostic -Path 'modules')
    $checks = @(Get-FmpValue -Data $Analysis -Path 'checks')
    $findings = @(Get-FmpValue -Data $Analysis -Path 'findings')
    $ordered = Get-FmpOrderedFindings -Analysis $Analysis
    $unknownCount = @($checks | Where-Object { ([string](Get-FmpValue -Data $_ -Path 'state')) -in @('unknown', 'access_denied', 'unsupported', 'not_collected', 'error') }).Count
    $moduleDurations = 0
    foreach ($m in $modules) { $moduleDurations += [double](Get-FmpValue -Data $m -Path 'durationMs' -Default 0) }
    $summaryIntro = Get-FmpText 'report.summary.intro' -Vals @(
        (Get-FmpCountText -Key 'count.modules' -N $modules.Count),
        (Get-FmpNum -Value ([Math]::Round($moduleDurations / 1000.0, 1)) -Decimals 1),
        (Get-FmpCountText -Key 'count.checks' -N $checks.Count),
        (Get-FmpCountText -Key 'count.findings' -N $findings.Count),
        (Get-FmpCountText -Key 'count.inconclusive' -N $unknownCount),
        (Get-FmpNum -Value ($checks.Count - $findings.Count - $unknownCount))
    )
    [void]$sb.Append((Get-FmpPanelOpen -Id 'summary' -TitleKey 'report.section.summary' -Assets $assets -IconKey 'overview'))
    [void]$sb.Append((Get-FmpSummaryBodyHtml -Score $Score -Ordered $ordered -Intro $summaryIntro))
    [void]$sb.Append('</section>')

    # ---- Findings ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'findings' -TitleKey 'report.section.findings' -Assets $assets -IconKey 'findings'))
    [void]$sb.Append((Get-FmpFindingsSectionHtml -Ordered $ordered))
    [void]$sb.Append('</section>')

    # ---- Hardware and Windows ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'hardware' -TitleKey 'report.section.hardware' -Assets $assets -IconKey 'hardware'))
    [void]$sb.Append((Get-FmpHardwareSectionHtml -D $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Storage and performance ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'storage' -TitleKey 'report.section.storagePerf' -Assets $assets -IconKey 'storage'))
    [void]$sb.Append((Get-FmpStorageSectionHtml -D $Diagnostic))
    [void]$sb.Append((Get-FmpResourcesSectionHtml -D $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Startup ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'startup' -TitleKey 'report.section.startup' -Assets $assets -IconKey 'startup'))
    [void]$sb.Append((Get-FmpStartupSectionHtml -D $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Events and reliability ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'events' -TitleKey 'report.section.events' -Assets $assets))
    [void]$sb.Append((Get-FmpEventsSectionHtml -D $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Advanced ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'advanced' -TitleKey 'report.section.advanced' -Assets $assets))
    [void]$sb.Append((Get-FmpAdvancedSectionHtml -D $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Limitations ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'limitations' -TitleKey 'report.section.limitations' -Assets $assets))
    [void]$sb.Append((Get-FmpLimitationsSectionHtml -D $Diagnostic -Score $Score))
    [void]$sb.Append('</section>')

    # ---- Privacy and next steps ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'privacy' -TitleKey 'report.section.privacyNext' -Assets $assets -IconKey 'privacy'))
    [void]$sb.Append((Get-FmpPrivacyNextSectionHtml -Analysis $Analysis -RedactionCount $RedactionCount -Diagnostic $Diagnostic))
    [void]$sb.Append('</section>')

    # ---- Methodology ----
    [void]$sb.Append((Get-FmpPanelOpen -Id 'methodology' -TitleKey 'report.section.methodology' -Assets $assets))
    [void]$sb.Append((Get-FmpMethodologySectionHtml -Run $run -Modules $modules))
    [void]$sb.Append('</section></main>')

    $footIcon = Get-FmpImgHtml -Assets $assets -Key 'icon'
    $verText = ''
    if ($null -ne $toolVersion -and ([string]$toolVersion) -ne '') { $verText = ' &middot; v' + (Get-FmpEsc $toolVersion) }
    [void]$sb.Append('<footer class="rep-foot">' + $footIcon + '<span>' + (Get-FmpEsc (Get-FmpText 'app.name')) + ' &middot; ' + (Get-FmpEsc (Get-FmpText 'app.tagline')) + $verText + '</span><span class="disclaimer">' + (Get-FmpEsc (Get-FmpText 'report.footer.disclaimer')) + '</span></footer>')
    [void]$sb.Append('</div><script>' + $script:FmpPrintScript + '</script></body></html>')

    return $sb.ToString()
}

function Write-FmpHtmlReport {
    param(
        [Parameter(Mandatory)][object]$Diagnostic,
        [Parameter(Mandatory)][string]$OutPath,
        [bool]$Synthetic = $false,
        [object]$RedactionCount = 0
    )
    $html = Get-FmpHtmlReportText -Diagnostic $Diagnostic -Synthetic:$Synthetic -RedactionCount $RedactionCount
    Write-FmpUtf8File -Path $OutPath -Text $html
}
