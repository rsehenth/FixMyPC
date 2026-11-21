# =====================================================================
# FIX MY PC - Visual.Tests.ps1
# Regression tests for the redesigned HTML report (Stage 4): embedded
# assets, offline/zero-JavaScript guarantees, CSP, escaping, states,
# fallback, i18n, print and responsive CSS. Synthetic data ONLY: it renders
# tests/fixtures/*.json through the real analysis + renderer. It never loads a
# collector and never touches the host. Run:
#   powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\Visual.Tests.ps1
# Visual approval (screenshots) is separate and manual: see docs/reviews.
# =====================================================================
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\common\Common.ps1')
. (Join-Path $root 'src\security\ReadOnlyPolicy.ps1')
. (Join-Path $root 'src\security\Privacy.ps1')
. (Join-Path $root 'src\analysis\Evidence.ps1')
. (Join-Path $root 'src\analysis\Rules.ps1')
. (Join-Path $root 'src\analysis\HealthScore.ps1')
. (Join-Path $root 'src\reports\HtmlRenderer.ps1')

$script:PassCount = 0
$script:FailCount = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:CurrentSuite = ''

function Assert-FmpTrue {
    param([Parameter(Mandatory)][string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:PassCount++; Write-Host ('  [PASS] ' + $Name) }
    else {
        $script:FailCount++
        $msg = $Name
        if ($Detail -ne '') { $msg = $msg + ' :: ' + $Detail }
        $script:Failures.Add('[' + $script:CurrentSuite + '] ' + $msg)
        Write-Host ('  [FAIL] ' + $msg) -ForegroundColor Red
    }
}
function Assert-FmpEqual {
    param([Parameter(Mandatory)][string]$Name, $Expected, $Actual)
    Assert-FmpTrue -Name $Name -Condition ($Expected -eq $Actual) -Detail ('expected=' + $Expected + ' actual=' + $Actual)
}
function Start-FmpSuite {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentSuite = $Name
    Write-Host ('== ' + $Name + ' ==')
}
function Get-Count {
    param([string]$Text, [string]$Pattern)
    return [regex]::Matches($Text, $Pattern).Count
}
# Stage 10 contract: the only script allowed in a report is the static print script, authorized by its hash.
# The hash is recomputed here independently of the renderer helper.
$script:PrintTag = '<script>' + $script:FmpPrintScript + '</script>'
$script:PrintHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($script:FmpPrintScript)))
function Remove-FmpPrintTag {
    param([string]$Html)
    return $Html.Replace($script:PrintTag, '')
}

$scratch = Join-Path $root ('out\fmp-visual-tests-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $scratch
Set-FmpAllowedWriteRoot -Root $scratch

$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data
$ruleConfig = Get-FmpRuleConfig -Root $root
$cssText = [System.IO.File]::ReadAllText((Join-Path $root 'templates\style.css'))

function New-VisualDoc {
    param([string]$Fixture = 'demo-synthetic.json', [string]$Mode = 'full', [string]$Lang = 'pt-BR', [scriptblock]$Mutate = $null)
    $fx = Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $Fixture))
    if (-not $fx.Ok) { throw ('fixture load failed: ' + $Fixture + ' :: ' + $fx.Error) }
    $diag = ConvertTo-FmpSerializable -Value $fx.Data
    $diag['run']['language'] = $Lang
    if ($null -ne $Mutate) { & $Mutate $diag }
    $analysis = Invoke-FmpRules -Diagnostic $diag -RuleConfig $ruleConfig -Mode $Mode
    $diag['analysis'] = $analysis
    $diag['healthScore'] = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue -Data $diag -Path 'modules')
    return (ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diag)
}
function Get-VisualHtml {
    param([object]$Doc, [string]$Lang = 'pt-BR')
    Reset-FmpMissingLocaleKeys
    if ($Lang -eq 'en') { Set-FmpRenderLocale -Primary $locEn -Fallback $locPt -Language 'en' }
    else { Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR' }
    return (Get-FmpHtmlReportText -Diagnostic $Doc -Synthetic:$true -RedactionCount 3)
}
function Set-DefaultAssetRoot { Set-FmpAssetRoot -Path (Join-Path $root 'assets\optimized') }
Set-DefaultAssetRoot

# =====================================================================
Start-FmpSuite 'V1. Assets oficiais e variantes otimizadas'
$keys = @('banner', 'logo', 'icon', 'overview', 'findings', 'hardware', 'storage', 'startup', 'privacy')
$originals = @('assets\branding\fixmypc-logo-v2.png', 'assets\branding\fixmypc-icon-v2.png', 'assets\report\fixmypc-report-banner-v2.png', 'assets\report\fixmypc-overview-v2.png',
    'assets\report\fixmypc-hardware-v2.png', 'assets\report\fixmypc-findings-v2.png', 'assets\report\fixmypc-startup-v2.png', 'assets\report\fixmypc-storage-v2.png', 'assets\report\fixmypc-privacy-v2.png')
foreach ($o in $originals) {
    Assert-FmpTrue -Name ('asset original presente: ' + $o) -Condition (Test-Path -LiteralPath (Join-Path $root $o) -PathType Leaf)
}
$manifest = (Read-FmpJsonFile -Path (Join-Path $root 'assets\optimized\manifest.json')).Data
$totalBytes = 0
foreach ($k in $keys) {
    $m = Get-FmpValue -Data $manifest -Path ('assets.' + $k)
    Assert-FmpTrue -Name ('manifest tem ' + $k) -Condition ($null -ne $m)
    $b64 = [System.IO.File]::ReadAllText((Join-Path $root ('assets\optimized\' + ([string]$m.b64).Replace('/', '\')))).Trim()
    $bytes = [Convert]::FromBase64String($b64)
    $totalBytes += $bytes.Length
    $sha = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    Assert-FmpEqual -Name ($k + ': bytes do manifesto conferem') -Expected $m.bytes -Actual $bytes.Length
    Assert-FmpEqual -Name ($k + ': SHA-256 do manifesto confere') -Expected $m.sha256 -Actual $sha
    Assert-FmpTrue -Name ($k + ': variante menor que o original') -Condition ($m.bytes -lt $m.sourceBytes)
    if ($m.mime -eq 'image/png') {
        $isPng = ($bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47)
        $w = ($bytes[16] * 16777216) + ($bytes[17] * 65536) + ($bytes[18] * 256) + $bytes[19]
        $h = ($bytes[20] * 16777216) + ($bytes[21] * 65536) + ($bytes[22] * 256) + $bytes[23]
        Assert-FmpTrue -Name ($k + ': assinatura PNG real e dimensoes do manifesto') -Condition ($isPng -and $w -eq $m.width -and $h -eq $m.height)
        Assert-FmpEqual -Name ($k + ': PNG preserva transparencia (RGBA)') -Expected 6 -Actual $bytes[25]
    }
    else {
        Assert-FmpTrue -Name ($k + ': JPEG real (so o banner opaco)') -Condition ($k -eq 'banner' -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8 -and $bytes[2] -eq 0xFF)
    }
}
Assert-FmpTrue -Name 'soma dos assets embutidos abaixo de 1,5 MiB' -Condition ($totalBytes -lt 1536KB) -Detail ('total=' + $totalBytes)

# =====================================================================
Start-FmpSuite 'V2. HTML gerado (PT-BR e EN): offline, zero JavaScript, CSP'
$docPt = New-VisualDoc -Lang 'pt-BR'
$htmlPt = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpEqual -Name 'PT-BR: nenhuma chave de idioma faltando' -Expected 0 -Actual @(Get-FmpMissingLocaleKeys | ForEach-Object { $_ }).Count
$docEn = New-VisualDoc -Lang 'en'
$htmlEn = Get-VisualHtml -Doc $docEn -Lang 'en'
Assert-FmpEqual -Name 'EN: nenhuma chave de idioma faltando' -Expected 0 -Actual @(Get-FmpMissingLocaleKeys | ForEach-Object { $_ }).Count
foreach ($pair in @(@('pt-BR', $htmlPt), @('en', $htmlEn))) {
    $l = $pair[0]; $h = $pair[1]
    Assert-FmpTrue -Name ($l + ': somente o script de impressao autorizado, uma vez') -Condition ((Get-Count $h '(?i)<script') -eq 1 -and (Get-Count $h ([regex]::Escape($script:PrintTag))) -eq 1 -and (Remove-FmpPrintTag $h) -notmatch '(?i)<script')
    Assert-FmpTrue -Name ($l + ': sem manipuladores on* em tags') -Condition ($h -notmatch '(?i)<[^>]*\son[a-z]+\s*=')
    Assert-FmpTrue -Name ($l + ': sem javascript: ou vbscript:') -Condition ($h -notmatch '(?i)(javascript|vbscript):')
    Assert-FmpTrue -Name ($l + ': sem recurso externo (src/href/action http)') -Condition ($h -notmatch '(?i)(src|href|action|data)\s*=\s*["'']?(https?:|//|ftp:|file:)')
    Assert-FmpTrue -Name ($l + ': nenhuma URL http(s) em todo o documento') -Condition ($h -notmatch '(?i)https?://')
    Assert-FmpTrue -Name ($l + ': sem link/iframe/object/embed/form/base/meta refresh') -Condition ($h -notmatch '(?i)<(link\s+rel="stylesheet|iframe|object|embed|form|base|meta\s+http-equiv="refresh)')
    Assert-FmpTrue -Name ($l + ': sem @import/url()/expression() no CSS embutido') -Condition ($h -notmatch '(?i)@import|url\s*\(|expression\s*\(')
    Assert-FmpTrue -Name ($l + ': sem font-face (fontes locais)') -Condition ($h -notmatch '(?i)@font-face')
    $csp = [regex]::Match($h, '<meta http-equiv="Content-Security-Policy" content="([^"]*)"').Groups[1].Value
    $csp = [System.Net.WebUtility]::HtmlDecode($csp)
    Assert-FmpTrue -Name ($l + ': CSP presente') -Condition ($csp -ne '')
    Assert-FmpTrue -Name ($l + ': CSP default-src none e script-src somente o hash do script de impressao') -Condition ($csp -match "default-src 'none'" -and $csp.Contains("script-src 'sha256-" + $script:PrintHash + "';") -and (Get-Count $csp 'script-src') -eq 1 -and $csp -notmatch 'script-src[^;]*unsafe')
    Assert-FmpTrue -Name ($l + ': CSP permite apenas img-src data:') -Condition ($csp -match 'img-src data:(;|$)' -and $csp -notmatch 'img-src[^;]*(https?:|\*|blob:|filesystem:)')
    Assert-FmpTrue -Name ($l + ': CSP sem unsafe-eval, wildcard ou http') -Condition ($csp -notmatch "unsafe-eval|\*|https?:|connect-src|frame-src|font-src")
    Assert-FmpTrue -Name ($l + ': CSP style-src unsafe-inline somente para o CSS local') -Condition ($csp -match "style-src 'unsafe-inline'" -and (Get-Count $csp 'style-src') -eq 1)
    Assert-FmpTrue -Name ($l + ': base-uri e form-action none') -Condition ($csp -match "base-uri 'none'" -and $csp -match "form-action 'none'")
}
Assert-FmpTrue -Name 'html lang acompanha o idioma' -Condition ($htmlPt -match '<html lang="pt-BR">' -and $htmlEn -match '<html lang="en">')
Assert-FmpTrue -Name 'titulo identifica o relatorio e a execucao' -Condition ($htmlEn -match '<title>PC diagnostic report - FIX MY PC - fmp-demo-synthetic</title>')
Assert-FmpTrue -Name 'EN e PT usam textos diferentes' -Condition ($htmlEn -match '<h2 id="summary-h">Executive summary</h2>' -and $htmlPt -match '<h2 id="summary-h">Resumo executivo</h2>' -and $htmlPt -notmatch '<h2 id="summary-h">Executive')

# =====================================================================
Start-FmpSuite 'V3. Imagens embutidas'
Assert-FmpEqual -Name 'nove <img> (banner, logo de impressao, 6 icones, icone do rodape)' -Expected 9 -Actual (Get-Count $htmlPt '<img ')
Assert-FmpEqual -Name 'todo src de imagem e data:image/png|jpeg;base64' -Expected 9 -Actual (Get-Count $htmlPt '<img [^>]*src="data:image/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}"')
Assert-FmpEqual -Name 'favicon embutido como data URI' -Expected 1 -Actual (Get-Count $htmlPt '<link rel="icon" type="image/png" href="data:image/png;base64,')
Assert-FmpTrue -Name 'nenhum SVG como imagem' -Condition ($htmlPt -notmatch '(?i)image/svg|\.svg"')
Assert-FmpTrue -Name 'img com width e height (sem deformacao nem salto de layout)' -Condition ((Get-Count $htmlPt '<img [^>]*width="\d+" height="\d+"') -eq 9)
Assert-FmpTrue -Name 'banner informativo tem alt; icones de secao sao decorativos' -Condition ($htmlPt -match 'class="hero-banner"[^>]*alt="FIX MY PC &#8212;|class="hero-banner"[^>]*alt="FIX MY PC \u2014' -and (Get-Count $htmlPt 'alt="" aria-hidden="true"') -ge 7)
Assert-FmpTrue -Name 'toda imagem tem atributo alt' -Condition ((Get-Count $htmlPt '<img ') -eq (Get-Count $htmlPt '<img [^>]*\salt="'))
$imgPositions = @('summary', 'findings', 'hardware', 'storage', 'startup', 'privacy')
foreach ($sid in $imgPositions) {
    $sec = [regex]::Match($htmlPt, '<section class="panel" id="' + $sid + '".*?</div>').Value
    Assert-FmpTrue -Name ('icone no cabecalho da secao ' + $sid) -Condition ($sec -match '<span class="tile"><img ')
}
Assert-FmpTrue -Name 'secoes sem asset nao ganham imagem inventada' -Condition ([regex]::Match($htmlPt, '<section class="panel" id="events".*?</div>').Value -notmatch '<img ')

# =====================================================================
Start-FmpSuite 'V4. Limite de 8 MiB e desempenho'
$bytesPt = [System.Text.Encoding]::UTF8.GetByteCount($htmlPt)
Assert-FmpTrue -Name 'relatorio demo bem abaixo de 8 MiB' -Condition ($bytesPt -lt 2MB) -Detail ('bytes=' + $bytesPt)
$sizeFile = Join-Path $scratch 'size-check.html'
Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR'
Write-FmpHtmlReport -Diagnostic $docPt -OutPath $sizeFile -Synthetic:$true -RedactionCount 3
Assert-FmpTrue -Name 'arquivo gravado em UTF-8 sem BOM e legivel' -Condition ((Get-Item -LiteralPath $sizeFile).Length -eq $bytesPt)
Write-Host ('  [INFO] demo PT-BR: ' + $bytesPt + ' bytes; assets: ' + $totalBytes + ' bytes (antes: 10770083 bytes de originais)')

# =====================================================================
Start-FmpSuite 'V5. Estrutura semantica e acessibilidade'
Assert-FmpEqual -Name 'um unico h1' -Expected 1 -Actual (Get-Count $htmlPt '<h1[ >]')
Assert-FmpEqual -Name 'dez secoes h2' -Expected 10 -Actual (Get-Count $htmlPt '<h2[ >]')
Assert-FmpTrue -Name 'h1 antes do primeiro h2 e h2 antes do primeiro h3' -Condition ($htmlPt.IndexOf('<h1') -lt $htmlPt.IndexOf('<h2') -and $htmlPt.IndexOf('<h2') -lt $htmlPt.IndexOf('<h3'))
Assert-FmpTrue -Name 'landmarks: header, nav com rotulo, main, footer' -Condition ($htmlPt -match '<header class="hero">' -and $htmlPt -match '<nav class="toc" aria-label="[^"]+">' -and $htmlPt -match '<main id="main">' -and $htmlPt -match '<footer ')
Assert-FmpTrue -Name 'skip link aponta para o main' -Condition ($htmlPt -match '<a class="skip" href="#main">')
Assert-FmpEqual -Name 'cada secao tem aria-labelledby valido' -Expected 10 -Actual (Get-Count $htmlPt '<section class="panel" id="([a-z]+)" aria-labelledby="\1-h"><div class="panel-head">')
Assert-FmpTrue -Name 'toda tabela tem cabecalhos com scope' -Condition ((Get-Count $htmlPt '<table ') -gt 5 -and (Get-Count $htmlPt '<table ') -le (Get-Count $htmlPt '<(thead|tbody><tr><th scope="row")'))
Assert-FmpTrue -Name 'celulas empilhaveis carregam data-label' -Condition ((Get-Count $htmlPt '<td data-label="') -gt 20)
$navTargets = [regex]::Matches($htmlPt, '<li><a href="#([a-z]+)">') | ForEach-Object { $_.Groups[1].Value }
$allNavOk = $true
foreach ($t in $navTargets) { if ($htmlPt -notmatch ('<section class="panel" id="' + $t + '"')) { $allNavOk = $false } }
Assert-FmpTrue -Name 'todos os links do indice levam a uma secao existente' -Condition ($allNavOk -and @($navTargets).Count -eq 10)
$ids = [regex]::Matches($htmlPt, '\sid="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
Assert-FmpEqual -Name 'ids unicos no documento' -Expected @($ids).Count -Actual @($ids | Sort-Object -Unique).Count
$hrefs = [regex]::Matches($htmlPt, 'href="#([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
$hrefOk = $true
foreach ($h in $hrefs) { if ($ids -notcontains $h) { $hrefOk = $false } }
Assert-FmpTrue -Name 'toda ancora interna tem destino' -Condition $hrefOk
Assert-FmpTrue -Name 'severidade e texto + icone SVG decorativo (nao so cor)' -Condition ($htmlPt -match '<span class="sev review_recommended"><svg class="ico"[^>]*aria-hidden="true"[^>]*>.*?</svg> Recomendado revisar</span>')
Assert-FmpTrue -Name 'icones SVG sao estaticos (sem script, sem dados)' -Condition ((Get-Count $htmlPt '<svg ') -ge 6 -and $htmlPt -notmatch '<svg[^>]*(href|xlink)')
Assert-FmpTrue -Name 'medidores visuais ficam ocultos do leitor de tela e o valor e texto' -Condition ($htmlPt -match 'class="meter" aria-hidden="true"' -and $htmlPt -match '<span class="sr"> de 100</span>')
Assert-FmpTrue -Name 'CSS: foco visivel, selecao e fonte de sistema' -Condition ($cssText -match ':focus-visible' -and $cssText -match '::selection' -and $cssText -match 'font-family: var\(--font\)' -and $cssText -match '--font: system-ui')

# =====================================================================
Start-FmpSuite 'V6. Nota, cobertura e estados (sem cor enganosa)'
# FMP-01: demo score is round(100*(85-18)/85) = 79 after renormalization.
Assert-FmpTrue -Name 'nota 79 aparece como 79 + /100' -Condition ($htmlPt -match '<div class="num ">79</div>' -and $htmlPt -match '<span aria-hidden="true">/100</span>')
Assert-FmpTrue -Name 'medidor da nota tem largura igual a nota' -Condition ($htmlPt -match '<div class="meter" aria-hidden="true"><span style="width:79%">')
Assert-FmpTrue -Name 'cobertura tem barra propria e nota explicativa' -Condition ($htmlPt -match 'class="coverage-bar" aria-hidden="true"' -and $htmlPt -match 'Cobertura &#233; a parte|Cobertura é a parte')
Assert-FmpTrue -Name 'CSS: a nota nunca usa a cor verde de sucesso' -Condition ($cssText -notmatch '\.score-card[^{}]*\{[^}]*var\(--ok')
Assert-FmpTrue -Name 'CSS: medidor da nota usa ciano/azul, nao verde' -Condition ($cssText -match '\.meter > span \{[^}]*var\(--cyan\)')
$limited = New-VisualDoc -Fixture 'limited-access.json' -Mode 'simple' -Lang 'en'
$htmlLim = Get-VisualHtml -Doc $limited -Lang 'en'
Assert-FmpEqual -Name 'estado provisorio: sem chaves faltando' -Expected 0 -Actual @(Get-FmpMissingLocaleKeys | ForEach-Object { $_ }).Count
Assert-FmpTrue -Name 'nota provisoria: rotulo, tom e aviso visiveis' -Condition ($htmlLim -match 'class="score-card tone-provisional"' -and $htmlLim -match '<p class="state">Provisional score</p>' -and $htmlLim -match 'class="callout warn"')
Assert-FmpTrue -Name 'cobertura parcial: barra em estado partial e valor' -Condition ($htmlLim -match 'class="coverage-bar partial"' -and $htmlLim -match '86[.,]7%')
$deg = New-VisualDoc -Fixture 'degenerate.json' -Mode 'simple' -Lang 'en'
$htmlDeg = Get-VisualHtml -Doc $deg -Lang 'en'
Assert-FmpTrue -Name 'nota indisponivel: sem numero, sem medidor, sem denominador' -Condition ($htmlDeg -match 'class="score-card tone-unavailable"' -and $htmlDeg -match '<div class="num na">&ndash;</div>' -and $htmlDeg -notmatch '<div class="meter"' -and $htmlDeg -notmatch '<div class="of">' -and $htmlDeg -match 'No gauge is shown')
Assert-FmpTrue -Name 'categoria sem evidencia nao mostra barra preenchida' -Condition ($htmlDeg -match 'class="cat-bar none"' -and $htmlDeg -match 'No applicable checks|No usable evidence' -and $htmlDeg -notmatch '30 of 30 pts')
Assert-FmpTrue -Name 'sem achados: texto neutro, sem afirmar saude' -Condition ($htmlDeg -match 'does not replace a technical review' -and $htmlDeg -notmatch '<article class="finding')
$healthy = New-VisualDoc -Fixture 'win11-healthy.json' -Mode 'simple' -Lang 'pt-BR'
$htmlHealthy = Get-VisualHtml -Doc $healthy -Lang 'pt-BR'
Assert-FmpTrue -Name 'nota 100 completa: mesmo tom neutro (cobertura completa nao vira verde)' -Condition ($htmlHealthy -match 'class="score-card tone-ok"' -and $htmlHealthy -match '<div class="num ">100</div>')

# =====================================================================
Start-FmpSuite 'V7. Achados: ordem, campos e anchors'
$arts = [regex]::Matches($htmlPt, '<article class="finding (\w+)" id="(finding-\d+)"') | ForEach-Object { $_.Groups[1].Value }
Assert-FmpEqual -Name 'seis achados renderizados' -Expected 6 -Actual @($arts).Count
Assert-FmpEqual -Name 'ordem por severidade das regras (review, review, attention na base)' -Expected 'review_recommended,review_recommended,attention' -Actual ((@($arts)[0..2]) -join ',')
foreach ($label in @('Explica', 'Evid', 'Confian', 'Limita', 'Verifica')) {
    Assert-FmpTrue -Name ('cada achado traz o campo ' + $label) -Condition ((Get-Count $htmlPt ('<dt>' + $label)) -ge 6)
}
Assert-FmpTrue -Name 'resumo executivo liga as principais observacoes aos achados' -Condition ($htmlPt -match '<ol class="observations"><li class="review_recommended"><a href="#finding-1">')
Assert-FmpTrue -Name 'verificacoes sugeridas sao texto, nunca comando executavel' -Condition ((Get-Count $htmlPt '<button') -eq 1 -and ($htmlPt -replace '<button type="button" id="fmp-print" class="print-btn" hidden>', '') -notmatch '<(pre|button|input)' -and $htmlPt -notmatch '(?i)href="(cmd|powershell|ms-settings|file)')
Assert-FmpTrue -Name 'analise adicional separada e rotulada' -Condition ($htmlPt -match '<h3>An&#225;lise adicional|<h3>Análise adicional')

# =====================================================================
Start-FmpSuite 'V8. Conteudo malicioso, Unicode, campos vazios e conteudo longo'
$evil = {
    param($d)
    $d['run']['id'] = 'x"><script>alert(1)</script>'
    $d['startup']['items'][0]['name'] = '<script>alert(1)</script>'
    $d['startup']['items'][1]['name'] = '"><img src=x onerror=alert(1)>'
    $d['startup']['items'][2]['name'] = 'javascript:alert(1)'
    $d['startup']['items'][3]['name'] = "' onmouseover='alert(1)"
    $d['system']['gpu'][0]['name'] = '</td><svg onload=alert(1)>'
    $d['events']['logs']['System']['groups'][0]['provider'] = '<iframe src=//evil.example></iframe>'
    $d['modules'][0]['id'] = '<style>body{display:none}</style>'
}
$htmlEvil = Get-VisualHtml -Doc (New-VisualDoc -Mutate $evil) -Lang 'pt-BR'
Assert-FmpTrue -Name 'XSS: nenhuma tag perigosa viva' -Condition ((Remove-FmpPrintTag $htmlEvil) -notmatch '(?i)<(script|iframe|svg\s+onload|img\s+src=x|style>body)' -and (Get-Count $htmlEvil '(?i)<script') -eq 1)
Assert-FmpTrue -Name 'XSS: nenhum manipulador on* dentro de tag' -Condition ($htmlEvil -notmatch '(?i)<[^>]*\son[a-z]+\s*=')
Assert-FmpTrue -Name 'XSS: texto escapado e visivel como dado' -Condition ($htmlEvil -match '&lt;script&gt;alert\(1\)&lt;/script&gt;' -and $htmlEvil -match '&lt;iframe')
Assert-FmpTrue -Name 'XSS: id da execucao nao quebra o titulo nem atributos' -Condition ($htmlEvil -match '<title>[^<]*x&quot;&gt;&lt;script&gt;' -and $htmlEvil -notmatch '(?i)<title>[^<]*<script')
Assert-FmpTrue -Name 'XSS: contagem de <img> e <svg> inalterada' -Condition ((Get-Count $htmlEvil '<img ') -eq 9 -and (Get-Count $htmlEvil '<svg ') -eq (Get-Count $htmlPt '<svg '))
Assert-FmpTrue -Name 'XSS: CSP continua identica' -Condition (([regex]::Match($htmlEvil, 'Content-Security-Policy" content="[^"]*"').Value) -eq ([regex]::Match($htmlPt, 'Content-Security-Policy" content="[^"]*"').Value))
$uni = 'Aplica' + [char]0x00E7 + [char]0x00E3 + 'o ' + [char]0x65E5 + [char]0x672C + [char]0x8A9E + ' ' + [char]0x00DC + 'n' + [char]0x00EF + 'c' + [char]0x00F8 + 'd' + [char]0x00E9 + ' ' + [char]0x2013 + ' ' + [char]::ConvertFromUtf32(0x1F600)
$uniDoc = New-VisualDoc -Mutate { param($d) $d['startup']['items'][0]['name'] = $script:uni }
$uniFile = Join-Path $scratch 'unicode.html'
Reset-FmpMissingLocaleKeys; Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR'
Write-FmpHtmlReport -Diagnostic $uniDoc -OutPath $uniFile -Synthetic:$true -RedactionCount 0
$uniBack = [System.Net.WebUtility]::HtmlDecode([System.IO.File]::ReadAllText($uniFile))
Assert-FmpTrue -Name 'Unicode (acentos, CJK, emoji) sobrevive ao arquivo UTF-8' -Condition ($uniBack.Contains($uni))
$emptyDoc = New-VisualDoc -Mutate {
    param($d)
    $d['system']['cpu'] = $null; $d['system']['memory'] = $null; $d['system']['os'] = $null
    $d['system']['gpu'] = @(); $d['startup']['items'] = @(); $d['startup']['logonTasks'] = @(); $d['startup']['autoServices'] = @()
    $d['storage']['volumes'] = @(); $d['performance']['topProcessesByMemory'] = @(); $d['performance']['cpu'] = $null
}
$htmlEmpty = Get-VisualHtml -Doc $emptyDoc -Lang 'pt-BR'
Assert-FmpEqual -Name 'campos vazios: nenhuma chave faltando' -Expected 0 -Actual @(Get-FmpMissingLocaleKeys | ForEach-Object { $_ }).Count
Assert-FmpTrue -Name 'campos ausentes dizem Indisponivel, sem valores inventados' -Condition ((Get-Count $htmlEmpty '<span class="na">Indispon') -ge 8)
Assert-FmpTrue -Name 'listas vazias dizem que nao ha registros' -Condition ($htmlEmpty -match 'Nenhum registro nos dados coletados')
Assert-FmpTrue -Name 'campos vazios: nenhum vazamento de nome de chave bruta' -Condition ($htmlEmpty -notmatch '>(report|table|score|state)\.[a-z.]+<')
$long = ('Z' * 400)
$cmd = ('C:\' + ('Pasta\' * 200) + 'app.exe')
$longDoc = New-VisualDoc -Mutate { param($d) $d['startup']['items'][0]['name'] = $script:long; $d['startup']['items'][0]['command'] = $script:cmd; $d['startup']['items'][1]['name'] = 'palavra ' * 60 }
$htmlLong = Get-VisualHtml -Doc $longDoc -Lang 'en'
Assert-FmpTrue -Name 'nome longo sem espacos (ate o limite do sanitizador, 400) chega inteiro e abaixo do limite' -Condition ($htmlLong.Contains($long) -and [System.Text.Encoding]::UTF8.GetByteCount($htmlLong) -lt 8MB)
Assert-FmpTrue -Name 'CSS: celulas e codigo quebram texto longo (sem corte horizontal)' -Condition ($cssText -match 'table\.data td \{[^}]*overflow-wrap: anywhere' -and $cssText -match 'code\.path \{[^}]*overflow-wrap: anywhere' -and $cssText -match '\.kv dd[^}]*overflow-wrap: anywhere')

# =====================================================================
Start-FmpSuite 'V9. Imagens ausentes ou corrompidas (fallback)'
Set-FmpAssetRoot -Path (Join-Path $scratch 'does-not-exist')
$htmlNone = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'sem assets: relatorio renderiza completo com cabecalho de texto' -Condition ($htmlNone -notmatch '<img ' -and $htmlNone -match 'class="hero-fallback"' -and $htmlNone -match '<h1>' -and $htmlNone -match 'id="privacy"')
Assert-FmpTrue -Name 'sem assets: CSP nao libera imagens e problema registrado' -Condition ($htmlNone -notmatch 'img-src' -and (@(Get-FmpAssetIssues | ForEach-Object { $_ }) -contains 'manifest_missing'))
Assert-FmpTrue -Name 'sem assets: nenhum recurso data: restante' -Condition ($htmlNone -notmatch 'data:image')

function New-AssetCopy {
    param([string]$Name)
    $dest = Join-Path $scratch $Name
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $dest 'embed')
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $root 'assets\optimized\embed') -File) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $dest ('embed\' + $f.Name)) }
    Copy-Item -LiteralPath (Join-Path $root 'assets\optimized\manifest.json') -Destination (Join-Path $dest 'manifest.json')
    return $dest
}
function Update-Manifest {
    param([string]$Dir, [scriptblock]$Edit)
    $m = [System.IO.File]::ReadAllText((Join-Path $Dir 'manifest.json')) | ConvertFrom-Json
    & $Edit $m
    [System.IO.File]::WriteAllText((Join-Path $Dir 'manifest.json'), ($m | ConvertTo-Json -Depth 8))
}
function Get-IssueText { return ((@(Get-FmpAssetIssues | ForEach-Object { $_ })) -join ',') }

$d1 = New-AssetCopy -Name 'assets-truncated'
$iconText = [System.IO.File]::ReadAllText((Join-Path $d1 'embed\icon.b64')).Trim()
[System.IO.File]::WriteAllText((Join-Path $d1 'embed\icon.b64'), $iconText.Substring(0, $iconText.Length - 40))
Set-FmpAssetRoot -Path $d1
$h1 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'asset truncado e rejeitado, demais permanecem' -Condition ((Get-IssueText) -eq 'icon:length_mismatch' -and (Get-Count $h1 '<img ') -eq 8 -and $h1 -notmatch '<link rel="icon"')

$d2 = New-AssetCopy -Name 'assets-notpng'
$bannerText = [System.IO.File]::ReadAllText((Join-Path $d2 'embed\banner.b64')).Trim()
[System.IO.File]::WriteAllText((Join-Path $d2 'embed\banner.b64'), ('PGh0bWw+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' + ('A' * ($bannerText.Length - 44))))
Set-FmpAssetRoot -Path $d2
$h2 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'payload que nao e PNG/JPEG (HTML em Base64) e rejeitado' -Condition ((Get-IssueText) -eq 'banner:not_valid_image_payload' -and $h2 -match 'class="hero-fallback"' -and $h2 -notmatch 'PGh0bWw')

$d3 = New-AssetCopy -Name 'assets-badchars'
$logoText = [System.IO.File]::ReadAllText((Join-Path $d3 'embed\logo.b64')).Trim()
[System.IO.File]::WriteAllText((Join-Path $d3 'embed\logo.b64'), $logoText.Substring(0, 200) + '"><script>alert(1)</script>' + $logoText.Substring(227))
Set-FmpAssetRoot -Path $d3
$h3 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'caracteres fora do Base64 (injecao) sao rejeitados' -Condition ((Get-IssueText) -eq 'logo:not_valid_image_payload' -and (Remove-FmpPrintTag $h3) -notmatch '(?i)<script')

$d4 = New-AssetCopy -Name 'assets-svg'
Update-Manifest -Dir $d4 -Edit { param($m) $m.assets.overview.mime = 'image/svg+xml' }
Set-FmpAssetRoot -Path $d4
$h4 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'mime SVG nao e aceito' -Condition ((Get-IssueText) -eq 'overview:mime_not_allowed' -and $h4 -notmatch 'svg\+xml')

$d5 = New-AssetCopy -Name 'assets-traversal'
Update-Manifest -Dir $d5 -Edit { param($m) $m.assets.storage.b64 = '../../../src/common/Common.ps1' }
Set-FmpAssetRoot -Path $d5
$h5 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'caminho fora de embed/ (traversal) e recusado' -Condition ((Get-IssueText) -eq 'storage:path_not_allowed' -and $h5 -notmatch 'Set-StrictMode')

$d6 = New-AssetCopy -Name 'assets-oversize'
Update-Manifest -Dir $d6 -Edit { param($m) $m.assets.hardware.bytes = 900000 }
Set-FmpAssetRoot -Path $d6
$h6 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'asset acima do limite por arquivo e recusado' -Condition ((Get-IssueText) -eq 'hardware:manifest_values_invalid' -and (Get-Count $h6 '<img ') -eq 8)

$d7 = New-AssetCopy -Name 'assets-empty-missing'
[System.IO.File]::WriteAllText((Join-Path $d7 'embed\startup.b64'), '')
Remove-Item -LiteralPath (Join-Path $d7 'embed\privacy.b64')
Set-FmpAssetRoot -Path $d7
$h7 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'arquivo vazio e arquivo ausente caem no fallback sem excecao' -Condition ((Get-IssueText) -eq 'startup:length_mismatch,privacy:file_missing' -or (Get-IssueText) -eq 'startup:unreadable,privacy:file_missing' -and $h7 -match 'id="startup"' -and $h7 -match 'id="privacy"')

$d8 = New-AssetCopy -Name 'assets-badmanifest'
[System.IO.File]::WriteAllText((Join-Path $d8 'manifest.json'), '{ not json')
Set-FmpAssetRoot -Path $d8
$h8 = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpTrue -Name 'manifesto invalido: fallback total' -Condition ((Get-IssueText) -eq 'manifest_invalid' -and $h8 -notmatch '<img ')
Set-DefaultAssetRoot
$hBack = Get-VisualHtml -Doc $docPt -Lang 'pt-BR'
Assert-FmpEqual -Name 'assets reais voltam a ser embutidos apos os testes de falha' -Expected 9 -Actual (Get-Count $hBack '<img ')

# =====================================================================
Start-FmpSuite 'V10. CSS: impressao A4, responsividade e seguranca'
Assert-FmpTrue -Name 'CSS sem <, @import, url() ou expression()' -Condition ($cssText -notmatch '<|@import|url\s*\(|expression\s*\(')
Assert-FmpTrue -Name 'CSS: @page A4 com margens e rodape' -Condition ($cssText -match '@page \{[^}]*size: A4' -and $cssText -match '@bottom-right')
Assert-FmpTrue -Name 'CSS: impressao evita cortar achados, cartoes e linhas de tabela' -Condition ($cssText -match '\.finding[^{]*\{\s*break-inside: avoid' -or $cssText -match '\.finding, \.kv-card[^{]*\{\s*break-inside: avoid')
Assert-FmpTrue -Name 'CSS: cabecalho de tabela repete e titulos nao ficam orfaos' -Condition ($cssText -match 'thead \{ display: table-header-group' -and $cssText -match 'h3 \{ break-after: avoid')
Assert-FmpTrue -Name 'CSS: barras e selos mantem cor na impressao' -Condition ($cssText -match 'print-color-adjust: exact')
Assert-FmpTrue -Name 'CSS: banner grande oculto na impressao, logo compacto exibido' -Condition ($cssText -match '\.hero-banner, \.hero-fallback, nav\.toc, \.skip, \.print-action \{ display: none' -and $cssText -match '\.print-brand')
Assert-FmpTrue -Name 'HTML: logo de impressao embutido' -Condition ($htmlPt -match '<div class="print-only print-brand"><img ')
Assert-FmpTrue -Name 'CSS: pontos de quebra 900, 640 e 360 px' -Condition ($cssText -match '@media \(max-width: 900px\)' -and $cssText -match '@media \(max-width: 640px\)' -and $cssText -match '@media \(max-width: 360px\)')
Assert-FmpTrue -Name 'CSS: tabelas empilham no celular com rotulo da coluna' -Condition ($cssText -match 'table\.data\.stack td::before \{ content: attr\(data-label\)')
Assert-FmpTrue -Name 'CSS: imagens nunca deformam' -Condition ($cssText -match 'img \{ max-width: 100%; height: auto; \}' -and $cssText -match 'aspect-ratio: 3 / 1')
Assert-FmpTrue -Name 'HTML: viewport responsivo' -Condition ($htmlPt -match '<meta name="viewport" content="width=device-width, initial-scale=1">')
Assert-FmpTrue -Name 'CSS: sem animacoes nem transicoes' -Condition ($cssText -notmatch '@keyframes|animation:|transition:')
Assert-FmpTrue -Name 'CSS: paleta ancorada (navy, ciano/teal) e verde so para estados positivos' -Condition ($cssText -match '--navy: #0b2545' -and $cssText -match '--teal:' -and (Get-Count $cssText 'var\(--ok\)') -le 4)
Assert-FmpTrue -Name 'CSS: forced-colors usa cores de sistema nas barras e bordas nos selos' -Condition ($cssText -match '@media \(forced-colors: active\)' -and $cssText -match 'background: Highlight' -and $cssText -match 'border: 1px solid CanvasText')
Assert-FmpTrue -Name 'CSS: lista de categorias da nota vira coluna unica no celular (sem rolagem horizontal a 320 px)' -Condition ($cssText -match '\.kv-grid, \.usage-list, \.cat-list \{ grid-template-columns: 1fr')
Assert-FmpTrue -Name 'hierarquia de titulos: sem h4 e titulo de achado em h3 dentro do painel h2' -Condition ($htmlPt -notmatch '<h4' -and $htmlPt -match '<div class="finding-head">.{0,400}?<h3 id=')
Assert-FmpTrue -Name 'rodape de impressao localizado (PT-BR e EN) e nao fixo no CSS estatico' -Condition ($cssText -notmatch '@bottom-left' -and $htmlPt -match '@bottom-left \{ content: "FIX MY PC \\00B7  Ferramenta independente' -and $htmlEn -match '@bottom-left \{ content: "FIX MY PC \\00B7  Independent tool, not affiliated with Microsoft"')
Assert-FmpTrue -Name 'aviso de nao afiliacao a Microsoft no rodape (PT-BR e EN)' -Condition ($htmlPt -match 'class="disclaimer">[^<]*Sem afilia[^<]*Microsoft' -and $htmlEn -match 'class="disclaimer">[^<]*Not affiliated with, endorsed by or sponsored by Microsoft')

# =====================================================================
Start-FmpSuite 'V11. Internacionalizacao (paridade e cobertura do redesign)'
$kPt = @($locPt.PSObject.Properties.Name)
$kEn = @($locEn.PSObject.Properties.Name)
Assert-FmpEqual -Name 'paridade de chaves PT-BR/EN' -Expected 0 -Actual @(Compare-Object $kPt $kEn).Count
$redesign = @('report.brand.product', 'report.brand.bannerAlt', 'report.brand.logoAlt', 'report.a11y.skip', 'report.nav.label', 'report.section.storagePerf', 'report.section.privacyNext',
    'report.meta.version', 'report.value.unavailable', 'report.summary.score', 'report.summary.coverage', 'report.summary.coverage.note', 'report.summary.confidence', 'report.summary.bySeverity',
    'report.summary.analysisOnlyCount', 'report.summary.observations', 'report.summary.observation.more', 'report.score.noGauge', 'report.score.scale', 'report.score.of.short',
    'report.findings.lead', 'report.field.explanation', 'report.finding.noLimitations', 'report.storage.used', 'report.storage.usedOf', 'report.storage.usedPct', 'report.perf.ramUsed',
    'report.perf.sampling', 'report.startup.counts', 'report.startup.unknownNote', 'report.events.historicalNote', 'report.events.truncatedNote', 'report.privacy.points',
    'report.table.empty', 'report.score.col.penalty', 'report.score.byCategory', 'report.score.cat.points', 'report.score.cat.none', 'report.score.cat.noEvidence', 'table.bus', 'table.pid')
$allThere = $true
foreach ($k in $redesign) { if ($kPt -notcontains $k -or $kEn -notcontains $k) { $allThere = $false; Write-Host ('    missing: ' + $k) } }
Assert-FmpTrue -Name 'todos os rotulos do redesign existem nos dois idiomas' -Condition $allThere
Assert-FmpTrue -Name 'privacidade: lista com 6 itens e aviso de sanitizacao nao absoluta' -Condition ((@($locPt.'report.privacy.points').Count -eq 6) -and (@($locEn.'report.privacy.points').Count -eq 6) -and ($locEn.'report.privacy.points' -join ' ') -match 'cannot guarantee' -and ($locPt.'report.privacy.points' -join ' ') -match 'n.o garante')
$priv = [regex]::Match($htmlEn, '<ul class="privacy-points">.*?</ul>').Value
Assert-FmpEqual -Name 'privacidade renderiza um <li> por item (lista nao fundida)' -Expected 6 -Actual (Get-Count $priv '<li>')
Assert-FmpTrue -Name 'privacidade: nao modifica o Windows, JSON sanitizado, confirmacao e correcao separada' -Condition ($htmlEn -match 'does not change Windows' -and $htmlEn -match 'sanitized JSON' -and $htmlEn -match 'need confirmation by a person' -and $htmlEn -match 'separate decision')
$allFixtures = @('win11-healthy.json', 'win10-outdated.json', 'low-disk.json', 'cpu-ram-spike.json', 'events-mixed.json', 'startup-full.json', 'advanced-mixed.json', 'limited-access.json', 'degenerate.json', 'demo-synthetic.json', 'critical-disk.json')
$totalMissing = 0
foreach ($fx in $allFixtures) {
    foreach ($lang in @('pt-BR', 'en')) {
        $null = Get-VisualHtml -Doc (New-VisualDoc -Fixture $fx -Mode 'full' -Lang $lang) -Lang $lang
        $totalMissing += @(Get-FmpMissingLocaleKeys | ForEach-Object { $_ }).Count
    }
}
Assert-FmpEqual -Name 'todas as fixtures em PT-BR e EN renderizam sem chave faltando' -Expected 0 -Actual $totalMissing

# =====================================================================
Start-FmpSuite 'V12. Identidade visual v2 (FMP-10): fontes, hashes, embutidos, tamanho, CSP e revisao de marca'
# SHA-256 of the approved v2 sources (FIX-MY-PC-v2-assets.zip). Changing the art means changing this list on purpose.
$v2Pins = [ordered]@{
    'assets\branding\fixmypc-logo-v2.png'        = 'ce2ba790104d18a58e55996e49ce902fbee5cad26549439c742e9b435819b351'
    'assets\branding\fixmypc-icon-v2.png'        = 'edd82d4738abb496b196add3b52d947ebeec99a2e9888c24b61727b558c23c72'
    'assets\report\fixmypc-report-banner-v2.png' = '70b2b0a1dce3d7d7eefc454861c2d8bb68078a3edf46c9389a4ff67107a27663'
    'assets\report\fixmypc-overview-v2.png'      = '021f74bc0c30288a0344c914b47e53190b9700483b055d6d75d7846fd1274021'
    'assets\report\fixmypc-hardware-v2.png'      = 'bc8a36d59d354b64ff23843b6fd69e7e94856d7f0ce5a5cbcbff244300ce2121'
    'assets\report\fixmypc-findings-v2.png'      = 'c70099d1fc632ae03a4351e5d4b9d3538bf61f43d807e114a1f88e80a5b64ab4'
    'assets\report\fixmypc-startup-v2.png'       = '5d59a4616a94439e4564cb0c207e50b6e0778646ebcd71df5f926a9017dbce74'
    'assets\report\fixmypc-storage-v2.png'       = 'c0565aeb5fe18d7f6484ca81d0f12f126e83b6d3dcf3b210dadd723c7176917c'
    'assets\report\fixmypc-privacy-v2.png'       = 'bfabf3651d6daddec242733717eeab004fa5ab0597a18954bc76aba404acc523'
}
# Hashes of the retired art (Windows logo + approval shields, FMP-10). None of it may come back, as source or as embedded payload.
$retiredSha = @(
    '17228418bc711e046db20bf59ea7fe175cfac34cc5e42df1d68e5dd8caf58033', '08588b99dd31dd17db90969cc3ced973aed18aa918029c176b13730fbc72d349', 'b2f566ec6c715c43ba3b9251ce9831931d9955658d04fc954808c6d4c22ab269',
    '474b585dfd567df08789392631fec43c1e4161434ebebaa20f516f4b574c0bf3', '61b6bffc37b992590bad2e90b8e4f98b2ddad3fbfb37a072d424a524546debf4', '95f68548171f331049d6af706847bc3215788806f84cc38859331cc2adf0535a',
    '43ae816d34dd52e1d2ac1671746c84a013caa3bf857a9c200b40d2dc96a1682c', '99b604c6653d2d8275bec0362dcbfd5b7727c7773629c72238c2f4808affd4fc', 'd2ee9512d461a63a56b39b887618d4a86541a0eafaf3727d793ebe921a97f374',
    '55be2da96b8c644526b1577effa4da03c0ddb587464c76b77a7c3936e5745950', 'dae917ec066c3cd2b991fe5ef3ff00d462941b20f4dd1375366d699e895bb0fb', '65b604a0b41d76193b3b6237f507556b5cbb8c952a767cb355e0042bd4c810ee',
    '6a5f38eb42b50205e212555b72fd6a4fbe256c89b7df27ab101225cccb68ddea', '3bca4f5d1a5199866cef867012883a7bad98d389967e91db00dedc8c089c6c1e', '6ac432c3d0bab7f490d3ac6a374baa81d0f9d9000339e2aac8b9b4572ef2f09b',
    'f3d88487983c0b5a191c50ef44da18be96f42b63b002d501d6a16019e9972521', '43e7b1853f7ce0eef96bdc134fc3ee6177f093a7a80f79aae2957e5e9e63b1a8', '3c429aefd135510e55a182fb206cbe817dbc86cdadfb32edec2c31084782932c'
)
foreach ($rel in $v2Pins.Keys) {
    $actual = ''
    $pp = Join-Path $root $rel
    if (Test-Path -LiteralPath $pp) { $actual = (Get-FileHash -LiteralPath $pp -Algorithm SHA256).Hash.ToLowerInvariant() }
    Assert-FmpEqual -Name ('fonte v2 com SHA-256 fixado: ' + $rel) -Expected $v2Pins[$rel] -Actual $actual
}
$staleFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'assets') -Recurse -File | Where-Object { $_.Name -match '^fixmypc-' -and $_.Name -notmatch '-v2\.' })
Assert-FmpEqual -Name 'nenhum arquivo de arte antiga (sem -v2) restou em assets/' -Expected 0 -Actual $staleFiles.Count
$optScript = [System.IO.File]::ReadAllText((Join-Path $root 'tools\Optimize-Assets.ps1'))
Assert-FmpTrue -Name 'Optimize-Assets.ps1 so aponta para fontes v2' -Condition ((@([regex]::Matches($optScript, "src = 'assets\\[a-z]+\\fixmypc-[a-z0-9-]+\.png'")).Count -eq 9) -and (@([regex]::Matches($optScript, "src = 'assets\\[a-z]+\\fixmypc-[a-z-]+-v2\.png'")).Count -eq 9))
$rendererText = [System.IO.File]::ReadAllText((Join-Path $root 'src\reports\HtmlRenderer.ps1'))
Assert-FmpTrue -Name 'renderizador e CSS nao citam nomes de arte antiga' -Condition ($rendererText -notmatch 'fixmypc-(logo|icon|overview|hardware|findings|startup|storage|privacy|report-banner)\.png' -and $cssText -notmatch 'fixmypc-')
foreach ($k in $keys) {
    $m = Get-FmpValue -Data $manifest -Path ('assets.' + $k)
    $srcRel = ([string](Get-FmpValue -Data $m -Path 'source')).Replace('/', '\')
    Assert-FmpTrue -Name ($k + ': manifesto aponta para fonte v2 fixada') -Condition ($v2Pins.Contains($srcRel))
    $srcPath = Join-Path $root $srcRel
    $srcSha = ''
    $srcLen = -1
    if (Test-Path -LiteralPath $srcPath) { $srcSha = (Get-FileHash -LiteralPath $srcPath -Algorithm SHA256).Hash.ToLowerInvariant(); $srcLen = (Get-Item -LiteralPath $srcPath).Length }
    Assert-FmpEqual -Name ($k + ': sourceSha256 do manifesto = fonte atual (embed nao esta defasado)') -Expected $srcSha -Actual ([string](Get-FmpValue -Data $m -Path 'sourceSha256'))
    Assert-FmpEqual -Name ($k + ': sourceBytes do manifesto = fonte atual') -Expected $srcLen -Actual (Get-FmpValue -Data $m -Path 'sourceBytes')
    Assert-FmpTrue -Name ($k + ': variante otimizada existe e tem nome v2') -Condition (((Join-Path $root ([string]$m.file).Replace('/', '\')) | Test-Path) -and ([string]$m.file) -match '-v2\.(png|jpg)$')
    Assert-FmpTrue -Name ($k + ': payload embutido nao e arte retirada') -Condition (($retiredSha -notcontains [string]$m.sha256) -and ($retiredSha -notcontains [string](Get-FmpValue -Data $m -Path 'sourceSha256')))
    $b64 = [System.IO.File]::ReadAllText((Join-Path $root ('assets\optimized\' + ([string]$m.b64).Replace('/', '\')))).Trim()
    Assert-FmpTrue -Name ($k + ': Base64 do manifesto esta dentro do HTML PT-BR e EN') -Condition ($htmlPt.Contains($b64) -and $htmlEn.Contains($b64))
}
$docCrit = New-VisualDoc -Fixture 'critical-disk.json' -Lang 'en'
$htmlCrit = Get-VisualHtml -Doc $docCrit -Lang 'en'
$docNone = New-VisualDoc -Fixture 'win11-healthy.json' -Lang 'pt-BR'
$htmlNone = Get-VisualHtml -Doc $docNone -Lang 'pt-BR'
$expectedCsp = "default-src 'none'; script-src 'sha256-" + $script:PrintHash + "'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
foreach ($pair in @(@('PT-BR', $htmlPt), @('EN', $htmlEn), @('critico', $htmlCrit), @('sem risco', $htmlNone))) {
    $h = $pair[1]
    $cspNow = ([regex]::Match($h, 'Content-Security-Policy" content="([^"]*)"').Groups[1].Value).Replace('&#39;', "'")
    Assert-FmpEqual -Name ($pair[0] + ': CSP exata e restritiva') -Expected $expectedCsp -Actual $cspNow
    $noData = [regex]::Replace($h, 'data:image/[a-z]+;base64,[A-Za-z0-9+/=]+', 'DATA')
    Assert-FmpEqual -Name ($pair[0] + ': nenhuma URL externa fora dos data: de imagem') -Expected 0 -Actual @([regex]::Matches($noData, '(?i)(https?:)?//[a-z0-9-]+\.[a-z]{2,}')).Count
    Assert-FmpTrue -Name ($pair[0] + ': abaixo de 8 MiB e sem script alem do de impressao') -Condition (([System.Text.Encoding]::UTF8.GetByteCount($h) -lt 8MB) -and ((Remove-FmpPrintTag $h) -notmatch '(?i)<script'))
}
Assert-FmpTrue -Name 'risco critico: cartao de nota tingido, aviso em tom de erro e texto de risco' -Condition ($htmlCrit -match 'class="score-card tone-[a-z]+ risk-critical"' -and $htmlCrit -match 'class="callout bad"' -and $htmlCrit -match 'class="risk critical"' -and $htmlCrit -match 'Score capped at 49')
Assert-FmpTrue -Name 'sem risco detectado: cartao sem tinta de risco e texto que nao garante saude' -Condition ($htmlNone -notmatch 'class="score-card[^"]* risk-' -and $htmlNone -match 'class="risk none_detected"' -and $htmlNone -match 'nem garante sa(&#250;|.)de perfeita')
Assert-FmpTrue -Name 'risco elevado: cartao tingido de ambar' -Condition ($htmlPt -match 'class="score-card tone-[a-z]+ risk-elevated"')
Assert-FmpTrue -Name 'CSS: tintas de risco e callout.bad nao usam o verde de sucesso' -Condition ($cssText -match '\.score-card\.risk-critical' -and $cssText -match '\.callout\.bad' -and $cssText -notmatch '\.(score-card\.risk-[a-z]+|callout\.bad)[^{}]*\{[^}]*var\(--ok')
# FMP-10 gate: every source needs a brand-review record for ITS CURRENT hash, with all four problems absent.
$review = (Read-FmpJsonFile -Path (Join-Path $root 'assets\brand-review.json')).Data
$reviewOk = ($null -ne $review)
foreach ($k in $keys) {
    $m = Get-FmpValue -Data $manifest -Path ('assets.' + $k)
    $r = $null
    if ($reviewOk) { $r = @($review.assets | Where-Object { $_.key -eq $k })[0] }
    $good = $false
    if ($null -ne $r) {
        $good = (([string]$r.sourceSha256 -eq [string](Get-FmpValue -Data $m -Path 'sourceSha256')) -and ($r.windowsLogo -eq $false) -and ($r.thirdPartyMarks -eq $false) -and ($r.approvalChecksOrShields -eq $false) -and ($r.fixedHealthGauges -eq $false))
    }
    Assert-FmpTrue -Name ('FMP-10 ' + $k + ': revisao de marca registrada para o hash atual, sem logotipo/check/medidor') -Condition $good
}
$dist = (Read-FmpJsonFile -Path (Join-Path $root 'distribution-manifest.json')).Data
$blockerIds = @($dist.releaseBlockers | ForEach-Object { $_.id })
Assert-FmpTrue -Name 'FMP-10 e LICENSE-PENDING resolvidos: nao constam mais em releaseBlockers (revisao juridica continua)' -Condition (($blockerIds -notcontains 'FMP-10') -and ($blockerIds -notcontains 'LICENSE-PENDING') -and ($blockerIds -contains 'LEGAL-REVIEW'))

# =====================================================================
Start-FmpSuite 'V13. Botao Imprimir / Salvar em PDF (Stage 10): texto, acessibilidade, script por hash, CSS'
$btnRe = '<button type="button" id="fmp-print" class="print-btn" hidden><svg [^>]*aria-hidden="true"[^>]*>.*?</svg><span>([^<]+)</span></button>'
$btnPt = [regex]::Match($htmlPt, $btnRe)
$btnEn = [regex]::Match($htmlEn, $btnRe)
Assert-FmpEqual -Name 'PT-BR: botao presente com texto exato' -Expected 'Imprimir / Salvar em PDF' -Actual ([System.Net.WebUtility]::HtmlDecode($btnPt.Groups[1].Value))
Assert-FmpEqual -Name 'EN: botao presente com texto exato' -Expected 'Print / Save as PDF' -Actual $btnEn.Groups[1].Value
Assert-FmpTrue -Name 'fallback Ctrl+P localizado nos dois idiomas' -Condition ($htmlPt.Contains('<p class="print-hint">Voc&#234; tamb&#233;m pode usar Ctrl+P.</p>') -and $htmlEn.Contains('<p class="print-hint">You can also press Ctrl+P.</p>'))
Assert-FmpTrue -Name 'botao unico, nativo (focavel por teclado), no cabecalho e antes do h1' -Condition ((Get-Count $htmlPt 'id="fmp-print"') -eq 1 -and $htmlPt.IndexOf('id="fmp-print"') -gt $htmlPt.IndexOf('<header class="hero">') -and $htmlPt.IndexOf('id="fmp-print"') -lt $htmlPt.IndexOf('<h1>') -and $htmlPt -notmatch '<button[^>]*tabindex="-')
Assert-FmpTrue -Name 'botao oculto ate o script autorizado rodar (sem controle morto se a CSP bloquear)' -Condition ($btnPt.Success -and $btnEn.Success)
$ps = $script:FmpPrintScript
Assert-FmpTrue -Name 'script: window.print somente dentro do handler de clique' -Condition ((Get-Count $ps 'window\.print') -eq 1 -and $ps.Contains('addEventListener("click",function(){window.print();})'))
Assert-FmpTrue -Name 'script: sem rede, armazenamento, cookies, eval, timers ou acesso a dados do laudo' -Condition ($ps -notmatch '(?i)fetch|xmlhttp|websocket|sendbeacon|eventsource|import|storage|indexeddb|cookie|eval|new function|settimeout|setinterval|innerhtml|textcontent|queryselector|location|navigator|open\(|postmessage|https?:|//')
Assert-FmpTrue -Name 'script: le somente o elemento do botao' -Condition ((Get-Count $ps 'document\.') -eq 1 -and $ps.Contains('document.getElementById("fmp-print")'))
Assert-FmpTrue -Name 'script no fim do body, depois do botao' -Condition ($htmlPt.EndsWith($script:PrintTag + '</body></html>'))
Assert-FmpTrue -Name 'sem onclick nem javascript: no botao' -Condition ($btnPt.Value -notmatch '(?i)\son[a-z]+=|javascript:')
$tampered = $script:FmpPrintScript.Replace('window.print();', 'window.print( );')
$tamperedHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($tampered)))
Assert-FmpTrue -Name 'script adulterado tem outro hash e nao e autorizado pela CSP' -Condition ($tamperedHash -ne $script:PrintHash -and -not $htmlPt.Contains("'sha256-" + $tamperedHash) -and -not $htmlPt.Contains('&#39;sha256-' + $tamperedHash))
Assert-FmpEqual -Name 'hash do renderer igual ao recalculado pelo teste' -Expected $script:PrintHash -Actual (Get-FmpPrintScriptHash)
Assert-FmpTrue -Name 'CSS: botao some na impressao' -Condition ($cssText -match '@media print \{[\s\S]*\.print-action \{ display: none; \}|@media print \{[\s\S]*, \.print-action \{ display: none; \}')
Assert-FmpTrue -Name 'CSS: [hidden] vence o display do botao' -Condition ($cssText.Contains('.print-btn[hidden] { display: none; }'))
Assert-FmpTrue -Name 'CSS: foco visivel, hover e alvo de toque >= 40px' -Condition ($cssText -match '\.print-btn:focus-visible \{ outline: 2px' -and $cssText -match '\.print-btn:hover' -and $cssText -match '\.print-btn \{[^}]*min-height: 40px')
Assert-FmpTrue -Name 'CSS: no celular o botao ocupa a largura e nao sobrepoe' -Condition ($cssText -match '@media \(max-width: 640px\) \{[\s\S]*\.print-action \{ width: 100%; align-items: stretch; margin-left: 0; \}')
Assert-FmpTrue -Name 'CSS: alto contraste mantem borda e foco do botao' -Condition ($cssText -match '@media \(forced-colors: active\) \{[\s\S]*\.print-btn \{ border: 1px solid ButtonText; \}')

# Scratch folder holds only synthetic output of this run; remove it so repeated runs do not accumulate.
Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue

# =====================================================================
Write-Host ''
Write-Host ('==== RESUMO VISUAL: ' + $script:PassCount + ' passaram, ' + $script:FailCount + ' falharam ====')
if ($script:FailCount -gt 0) {
    foreach ($f in $script:Failures) { Write-Host ('  FAIL: ' + $f) -ForegroundColor Red }
    exit 1
}
exit 0
