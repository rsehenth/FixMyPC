# Opus 5.5 final audit - synthetic adversarial tests (isolated, offline).
# Loads ONLY non-collector modules from a copy of the project. Never dot-sources
# src\collectors, never runs fixmypc.ps1 without -Fixture, never executes the
# scanner snippets (they are parsed by the AST scanner only).
param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Work)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
. (Join-Path $Root 'src\common\Common.ps1')
. (Join-Path $Root 'src\security\ReadOnlyPolicy.ps1')
. (Join-Path $Root 'src\security\Privacy.ps1')
. (Join-Path $Root 'src\analysis\Evidence.ps1')
. (Join-Path $Root 'src\analysis\Rules.ps1')
. (Join-Path $Root 'src\analysis\HealthScore.ps1')
. (Join-Path $Root 'src\reports\HtmlRenderer.ps1')

$results = New-Object System.Collections.Generic.List[string]
function Out-Result([string]$Id, [string]$Text) { $results.Add($Id + ' | ' + $Text); Write-Host ($Id + ' | ' + $Text) }

# ---------------------------------------------------------------- A. scanner
$snippets = [ordered]@{
    'A1-priority-setter'   = '$p = @(Get-Process -ErrorAction Stop); $p[0].PriorityClass = ''Idle'''
    'A2-affinity-setter'   = '$p = @(Get-Process -ErrorAction Stop); $p[0].ProcessorAffinity = 1'
    'A3-readonly-setter'   = '$f = Get-Item -LiteralPath ''C:\fmp-audit-nonexistent\a.txt''; $f.IsReadOnly = $true'
    'A4-attributes-setter' = '$d = Get-Item -LiteralPath ''C:\fmp-audit-nonexistent''; $d.Attributes = ''Hidden'''
    'A5-fileinfo-replace'  = '$f = Get-Item -LiteralPath ''C:\fmp-audit-nonexistent\a.txt''; $null = $f.Replace(''C:\fmp-audit-nonexistent\b.txt'', ''C:\fmp-audit-nonexistent\c.bak'')'
    'A6-unc-childitem'     = '$x = @(Get-ChildItem -LiteralPath ''\\audit.invalid\share'' -ErrorAction Stop)'
    'A7-unc-evtx'          = '$e = Get-WinEvent -FilterHashtable @{ Path = ''\\audit.invalid\s\x.evtx'' } -MaxEvents 1'
    'A8-secret-read'       = '$k = Get-Content -LiteralPath ''C:\fmp-audit-nonexistent\.ssh\id_rsa'' -Raw'
    'C1-remove-item'       = 'Remove-Item -LiteralPath ''C:\x'''
    'C2-dynamic-call'      = '$a = ''Stop-Process''; & $a'
    'C3-dot-source'        = '. .\evil.ps1'
    'C4-static-delete'     = '[System.IO.File]::Delete(''x'')'
    'C5-instance-delete'   = '$x = Get-Item -LiteralPath ''C:\x''; $x.Delete()'
    'C6-opensubkey-write'  = '$k = Get-Item -LiteralPath ''HKCU:\Software\X''; $null = $k.OpenSubKey(''Y'', $true)'
    'C7-invoke-script'     = '$null = $ExecutionContext.InvokeCommand.InvokeScript(''x'')'
    'C8-computername'      = '$x = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName ''h'''
    'C9-type-from-string'  = '$t = [type]''System.IO.File''; $t::Delete(''x'')'
}
$snipDir = Join-Path $Work 'snippets'
$null = [System.IO.Directory]::CreateDirectory($snipDir)
foreach ($k in $snippets.Keys) {
    $p = Join-Path $snipDir ($k + '.ps1')
    [System.IO.File]::WriteAllText($p, $snippets[$k])
    $r = Test-FmpScriptCompliance -Path $p -Role 'collector'
    $types = (@($r.Violations | ForEach-Object { $_.type }) | Sort-Object -Unique) -join ','
    Out-Result $k ('scanner_ok=' + $r.Ok + ' violations=' + $types)
}

# ---------------------------------------------------------------- B. pipeline
$cfg = Get-FmpRuleConfig -Root $Root
$loc = @{}
foreach ($l in 'pt-BR', 'en') { $loc[$l] = (Read-FmpJsonFile -Path (Join-Path $Root ('locales\' + $l + '.json'))).Data }

function Invoke-Pipeline([object]$Fx, [string]$Mode, [string]$Lang, [string[]]$PrivateIds = @()) {
    $diag = ConvertTo-FmpSerializable -Value $Fx
    $diag['run']['mode'] = $Mode; $diag['run']['language'] = $Lang
    $an = Invoke-FmpRules -Diagnostic $diag -RuleConfig $cfg -Mode $Mode
    $sc = Get-FmpHealthScore -Analysis $an -RuleConfig $cfg -Modules @($diag['modules'])
    $diag['analysis'] = $an; $diag['healthScore'] = $sc
    $san = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diag -PrivateIdentifiers $PrivateIds
    $fb = if ($Lang -eq 'en') { 'pt-BR' } else { 'en' }
    Set-FmpRenderLocale -Primary $loc[$Lang] -Fallback $loc[$fb] -Language $Lang
    $html = Get-FmpHtmlReportText -Diagnostic $san -Synthetic:$true -RedactionCount (Get-FmpRedactionCount)
    return @{ Analysis = $an; Score = $sc; Sanitized = $san; Html = $html; Json = (ConvertTo-FmpJsonText -Data $san) }
}
function Get-Base { return (Read-FmpJsonFile -Path (Join-Path $Root 'tests\fixtures\win11-healthy.json')).Data | ConvertTo-Json -Depth 30 | ConvertFrom-Json }
function Get-State($Res, $Id) { (@($Res.Analysis.checks) | Where-Object { $_.id -eq $Id }).state }

# B0 baseline
$r0 = Invoke-Pipeline (Get-Base) 'simple' 'pt-BR'
Out-Result 'B0-baseline' ('score=' + $r0.Score.score + ' status=' + $r0.Score.status + ' conf=' + $r0.Score.confidence + ' cov=' + $r0.Score.coveragePct)
$catTxt = (@($r0.Score.categories) | ForEach-Object { $_.category + ':' + $_.coveredChecks + '/' + $_.applicableChecks + ' rem=' + $_.remaining }) -join '; '
Out-Result 'B0-categories' $catTxt

# B1 confirmed failing disk (Unhealthy + SMART predictFailure + disk events) - simple mode
$fx = Get-Base
$fx.storage.physicalDisks[0].healthStatus = 'Unhealthy'
$fx.storage.smart.items[0].predictFailure = $true
$fx.events.logs.System.status = 'ok'
$fx.events.logs.System.groups = @([pscustomobject]@{ provider = 'disk'; eventId = 7; count = 12; maxLevel = 2; firstSeen = '2026-11-19T02:00:00.000Z'; lastSeen = '2026-11-19T11:00:00.000Z'; occurrences = @(1..12 | ForEach-Object { [pscustomobject]@{ at = '2026-11-19T1' + ($_ % 10) + ':00:00.000Z'; level = 2 } }) })
$r1 = Invoke-Pipeline $fx 'simple' 'pt-BR'
$f1 = (@($r1.Analysis.findings) | ForEach-Object { $_.id }) -join ','
Out-Result 'B1-failing-disk' ('score=' + $r1.Score.score + ' status=' + $r1.Score.status + ' conf=' + $r1.Score.confidence + ' deduction=' + $r1.Score.totalDeduction + ' findings=' + $f1)

# B2 theoretical minimum: everything that can penalize in simple mode
$fx = Get-Base
$fx.storage.physicalDisks[0].healthStatus = 'Unhealthy'
$fx.storage.smart.items[0].predictFailure = $true
foreach ($v in $fx.storage.volumes) { if ($v.isSystem) { $v.freePct = 1.0 } }
$fx.performance.cpu.avgPercent = 99.0; $fx.performance.cpu.maxPercent = 100.0
$fx.performance.memory.commitPct = 99.0
$fx.system.os.caption = 'Windows 10 Pro'; $fx.system.os.displayVersion = '22H2'
$occ = @(1..8 | ForEach-Object { [pscustomobject]@{ at = '2026-11-19T0' + $_ + ':00:00.000Z'; level = 1 } })
$fx.events.logs.System.groups = @(
    [pscustomobject]@{ provider = 'Microsoft-Windows-Kernel-Power'; eventId = 41; count = 8; maxLevel = 1; firstSeen = '2026-11-19T01:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $occ },
    [pscustomobject]@{ provider = 'Microsoft-Windows-WHEA-Logger'; eventId = 18; count = 8; maxLevel = 1; firstSeen = '2026-11-19T01:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $occ },
    [pscustomobject]@{ provider = 'BugCheck'; eventId = 1001; count = 8; maxLevel = 2; firstSeen = '2026-11-19T01:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $occ }
)
$r2 = Invoke-Pipeline $fx 'simple' 'pt-BR'
Out-Result 'B2-worst-case' ('score=' + $r2.Score.score + ' status=' + $r2.Score.status + ' deduction=' + $r2.Score.totalDeduction + ' perCategory=' + ((@($r2.Score.categories) | ForEach-Object { $_.category + '-' + $_.deduction }) -join ','))

# B3 HTML / attribute / CSS injection through untrusted names
$payloads = @('<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'><svg onload=alert(1)>", '</style><style>*{display:none}</style>', 'javascript:alert(1)', '{1}{2}<b>x</b>', ([string][char]0x202E + 'exe.txt'))
$fx = Get-Base
$i = 0
foreach ($it in $fx.startup.items) { $it.name = $payloads[$i % $payloads.Count]; $i++ }
$fx.performance.topProcessesByMemory[0].name = $payloads[1]
$fx.performance.topProcessesByCpu[0].name = $payloads[2]
$fx.storage.physicalDisks[0].friendlyName = $payloads[3]
$fx.storage.physicalDisks[0].healthStatus = 'Warning'
$fx.system.gpu[0].name = $payloads[0]
$fx.advanced.installedApps.items[0].displayName = $payloads[4]
$fx.advanced.installedApps.items[0].publisher = $payloads[5]
$fx.events.logs.System.groups = @([pscustomobject]@{ provider = $payloads[5]; eventId = 9; count = 40; maxLevel = 2; firstSeen = '2026-11-19T01:00:00.000Z'; lastSeen = '2026-11-19T10:00:00.000Z'; occurrences = @(1..40 | ForEach-Object { [pscustomobject]@{ at = '2026-11-19T10:00:00.000Z'; level = 2 } }) })
$fx.modules[0].limits = @([pscustomobject]@{ key = $payloads[0]; detail = $payloads[1] })
$r3 = Invoke-Pipeline $fx 'full' 'en'
$h = $r3.Html -replace 'data:image/[a-z]+;base64,[A-Za-z0-9+/=]+', 'DATA'
$raw = @('<script', 'onerror=', 'onload=', '<img src=x', '<svg onload', '</style><style>', 'href="javascript')
$hits = @($raw | Where-Object { $h.Contains($_) })
Out-Result 'B3-injection' ('raw_markup_hits=' + ($hits -join ',') + ' scriptTags=' + ([regex]::Matches($h, '<script', 'IgnoreCase').Count) + ' styleTags=' + ([regex]::Matches($h, '<style', 'IgnoreCase').Count) + ' bidiChar=' + $h.Contains([string][char]0x202E))
$conc = @($r3.Analysis.findings | Where-Object { $_.id -eq 'events.error_concentration' })
if ($conc.Count -gt 0) {
    $vals = @($conc[0].values.count, $conc[0].values.provider, $conc[0].values.eventId)
    Set-FmpRenderLocale -Primary $loc['en'] -Fallback $loc['pt-BR'] -Language 'en'
    Out-Result 'B3-template-cascade' (Get-FmpText 'rules.events.error_concentration.detail' -Vals $vals)
}

# B4 identifiers that survive sanitization
$fx = Get-Base
$fx.startup.logonTasks = @([pscustomobject]@{ name = 'OneDrive Reporting Task-S-1-5-21-1004336348-1177238915-682003330-1001'; path = '\'; state = 'Ready'; action = 'C:\x.exe' })
$fx.startup.autoServices[0].name = 'CDPUserSvc_4a7f3c'
$fx.storage.physicalDisks[0].friendlyName = 'Samsung SSD 990 PRO 2TB S7DNNJ0W123456X'
$fx.system.disks[0].model = 'WDC WD10EZEX-08WN4A0 WD-WCC6Y1234567'
$fx.advanced.installedApps.items[0].displayName = 'Agent for DESKTOP-AUDIT01'
$fx.system.cpu.name = 'CPU at host DESKTOP-AUDIT01 user jsilva'
$r4 = Invoke-Pipeline $fx 'full' 'en' @('DESKTOP-AUDIT01', 'jsilva')
foreach ($needle in 'S-1-5-21-1004336348', 'CDPUserSvc_4a7f3c', 'S7DNNJ0W123456X', 'WD-WCC6Y1234567', 'DESKTOP-AUDIT01', 'jsilva') {
    Out-Result 'B4-survives' ($needle + ' json=' + $r4.Json.Contains($needle) + ' html=' + $r4.Html.Contains($needle))
}

# B5 severity ordering with system volume at 3%
$fx = Get-Base
foreach ($v in $fx.storage.volumes) { if ($v.isSystem) { $v.freePct = 3.0 } }
$r5 = Invoke-Pipeline $fx 'simple' 'pt-BR'
$ord = Get-FmpOrderedFindings -Analysis $r5.Analysis
Out-Result 'B5-order' ((@($ord.base) | ForEach-Object { $_.f.id + '(' + $_.f.severity + ',pen ' + $_.f.penalty + ')' }) -join ' > ')

# B6 realistic stock Windows: 90 automatic services, nothing else unusual (full mode)
$fx = Get-Base
$svc = $fx.startup.autoServices[0]
$fx.startup.autoServices = @(1..90 | ForEach-Object { $s = $svc.PSObject.Copy(); $s.name = 'Svc' + $_; $s })
$r6 = Invoke-Pipeline $fx 'full' 'pt-BR'
Out-Result 'B6-startup-high-count' ('state=' + (Get-State $r6 'startup.high_count'))

# B7 CPU 4-second burst
$fx = Get-Base
$fx.performance.cpu.avgPercent = 95.0; $fx.performance.cpu.maxPercent = 100.0
$r7 = Invoke-Pipeline $fx 'simple' 'pt-BR'
$c7 = @($r7.Analysis.findings | Where-Object { $_.id -eq 'perf.cpu_sustained_high' })[0]
Out-Result 'B7-cpu-burst' ('severity=' + $c7.severity + ' penalty=' + $c7.penalty + ' score=' + $r7.Score.score + ' status=' + $r7.Score.status)

# B8 English text in the PT-BR report (full mode, demo fixture)
$demo = (Read-FmpJsonFile -Path (Join-Path $Root 'tests\fixtures\demo-synthetic.json')).Data
$r8 = Invoke-Pipeline $demo 'full' 'pt-BR'
$t8 = $r8.Html -replace 'data:image/[a-z]+;base64,[A-Za-z0-9+/=]+', ''
$en = New-Object System.Collections.Generic.List[string]
foreach ($m in [regex]::Matches($t8, '<dt>Limita&#231;&#245;es</dt><dd>([^<]*)</dd>|<li class="small">([^<]*)</li>')) {
    $txt = [System.Net.WebUtility]::HtmlDecode(($m.Groups[1].Value + $m.Groups[2].Value))
    if ($txt -cmatch '\b(the|not|is|are|only|from|may|never|cannot|unavailable|historical|reading|evidence|common)\b') { $en.Add($txt) }
}
Out-Result 'B8-english-in-ptBR' ('count=' + $en.Count)
foreach ($e in $en) { Out-Result 'B8-item' $e }

# B9 provisional state never shown with a full bar for zero-check category
$catStartup = @($r0.Score.categories | Where-Object { $_.category -eq 'startup' })[0]
Out-Result 'B9-startup-category' ('applicable=' + $catStartup.applicableChecks + ' remaining=' + $catStartup.remaining + ' weight=' + $catStartup.weight)

[System.IO.File]::WriteAllText((Join-Path $Work 'adversarial-results.txt'), ($results -join [Environment]::NewLine))
[System.IO.File]::WriteAllText((Join-Path $Work 'b1-failing-disk.pt-BR.html'), $r1.Html)
[System.IO.File]::WriteAllText((Join-Path $Work 'b3-injection.en.html'), $r3.Html)
