# =====================================================================
# FIX MY PC - tools/Render-Samples.ps1   (DEVELOPMENT ONLY)
#
# Renders the synthetic demonstration reports from tests/fixtures/*.json
# through the real analysis + HTML pipeline. It reads ONLY the project's
# own fixtures: no collector is loaded, nothing about the host is queried
# and no consent flag is involved. Output goes to -OutDir (default samples\).
#
# Run:  powershell -NoProfile -File tools\Render-Samples.ps1
# =====================================================================
param([string]$OutDir = '')
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
if ($OutDir -eq '') { $OutDir = Join-Path $root 'samples\visual' }
New-FmpOutputDirectory $OutDir

$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data
$ruleConfig = Get-FmpRuleConfig -Root $root

function New-FmpSampleDocument {
    param([string]$Fixture, [string]$Mode, [string]$Lang)
    $fx = Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $Fixture))
    if (-not $fx.Ok) { throw ('fixture load failed: ' + $Fixture + ' :: ' + $fx.Error) }
    $diag = ConvertTo-FmpSerializable -Value $fx.Data
    $diag['run']['language'] = $Lang
    $analysis = Invoke-FmpRules -Diagnostic $diag -RuleConfig $ruleConfig -Mode $Mode
    $diag['analysis'] = $analysis
    $diag['healthScore'] = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue -Data $diag -Path 'modules')
    return (ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diag)
}

# name -> fixture, mode
$plan = @(
    @{ n = 'demo';       f = 'demo-synthetic.json'; m = 'full' },
    @{ n = 'none-detected'; f = 'win11-healthy.json'; m = 'full' },
    @{ n = 'critical';   f = 'critical-disk.json';  m = 'full' },
    @{ n = 'access-denied'; f = 'advanced-mixed.json'; m = 'full' },
    @{ n = 'provisional'; f = 'limited-access.json'; m = 'simple' },
    @{ n = 'unavailable'; f = 'degenerate.json';     m = 'simple' }
)
foreach ($p in $plan) {
    foreach ($lang in @('pt-BR', 'en')) {
        Reset-FmpMissingLocaleKeys
        if ($lang -eq 'en') { Set-FmpRenderLocale -Primary $locEn -Fallback $locPt -Language 'en' }
        else { Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR' }
        $doc = New-FmpSampleDocument -Fixture $p.f -Mode $p.m -Lang $lang
        $target = Join-Path $OutDir ($p.n + '.' + $lang + '.html')
        if (Test-Path -LiteralPath $target) { throw ('Refusing to overwrite: ' + $target) }
        Write-FmpHtmlReport -Diagnostic $doc -OutPath $target -Synthetic:$true -RedactionCount 3
        $size = (Get-Item -LiteralPath $target).Length
        $missing = ((Get-FmpMissingLocaleKeys) -join ',')
        Write-Host ('{0,-26} {1,10:N0} B  score={2}/{3}  missingKeys={4}' -f ($p.n + '.' + $lang), $size, $doc['healthScore']['score'], $doc['healthScore']['status'], $missing)
    }
}
