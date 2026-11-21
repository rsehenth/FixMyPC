# =====================================================================
# FIX MY PC: Windows Diagnostic & Audit Skill - v0.1.0
# Entry point. Read-only Windows audit producing HTML + JSON reports.
#
# Usage examples:
#   powershell -NoProfile -File fixmypc.ps1
#   powershell -NoProfile -File fixmypc.ps1 -Mode full -Language pt-BR -OutDir "$env:LOCALAPPDATA\FixMyPC\auditoria-1" -AcceptReadOnlyPolicy
#   powershell -NoProfile -NonInteractive -File fixmypc.ps1 -Fixture tests\fixtures\demo-synthetic.json -Mode full -Language pt-BR -Yes
#   powershell -NoProfile -NonInteractive -File fixmypc.ps1 -ValidateOnly
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet('simple', 'full')]
    [string]$Mode = '',
    [ValidateSet('pt-BR', 'en')]
    [string]$Language = '',
    [string]$OutDir = '',
    [string]$Fixture = '',
    [switch]$AcceptReadOnlyPolicy,
    [switch]$Yes,
    [switch]$IncludeInternalJson,
    [switch]$ValidateOnly,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$script:FmpRoot = $PSScriptRoot

. (Join-Path $script:FmpRoot 'src\security\ReadOnlyPolicy.ps1')

function Get-FmpLocaleObject {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Language)
    $file = Join-Path (Join-Path $Root 'locales') ($Language + '.json')
    $res = Read-FmpJsonFile -Path $file
    if (-not $res.Ok) { throw "locale file could not be loaded: $file ($($res.Error))" }
    return $res.Data
}

function Show-FmpHelp {
    Write-Host 'FIX MY PC: Windows Diagnostic & Audit Skill v' $script:FmpToolVersion
    Write-Host ''
    Write-Host '  -Mode <simple|full>            audit mode (default: simple)'
    Write-Host '  -Language <pt-BR|en>           report language (default: pt-BR)'
    Write-Host '  -OutDir <path>                 new output folder, must not exist (default: %LOCALAPPDATA%\FixMyPC\fixmypc-<timestamp>-<id>)'
    Write-Host '  -Fixture <path>                run the pipeline on a synthetic JSON fixture (no collection)'
    Write-Host '  -AcceptReadOnlyPolicy          record explicit read-only policy consent (non-interactive runs)'
    Write-Host '  -Yes                           non-interactive defaults for remaining choices'
    Write-Host '  -IncludeInternalJson           explicitly request a local, unredacted JSON artifact'
    Write-Host '  -ValidateOnly                  run the read-only compliance scan + integrity checks and exit'
    Write-Host '  -Help                          show this help'
    Write-Host ''
    Write-Host 'The audit is strictly read-only. Only the output directory receives files.'
}

try {
    # The entry point and scanner are the bootstrap trust base.
    $comp = Test-FmpReadOnlyCompliance -Root $script:FmpRoot -IncludeTests:$ValidateOnly
    if (-not $comp.Ok) {
        foreach ($f in $comp.Results) {
            foreach ($v in $f.Violations) {
                Write-Host ('  ' + $f.Path + ' [' + $v.type + '] line ' + $v.line + ': ' + $v.detail) -ForegroundColor Red
            }
        }
        exit 2
    }
    . (Join-Path $script:FmpRoot 'src\common\Common.ps1')
    . (Join-Path $script:FmpRoot 'src\security\Privacy.ps1')
    . (Join-Path $script:FmpRoot 'src\analysis\Evidence.ps1')
    . (Join-Path $script:FmpRoot 'src\analysis\Rules.ps1')
    . (Join-Path $script:FmpRoot 'src\analysis\HealthScore.ps1')
    . (Join-Path $script:FmpRoot 'src\reports\HtmlRenderer.ps1')
    if ($Help) { Show-FmpHelp; exit 0 }

    # ---- Locales (needed for every message) ----
    $primaryLang = $Language
    if ($primaryLang -eq '') { $primaryLang = 'pt-BR' }
    $locPrimary = Get-FmpLocaleObject -Root $script:FmpRoot -Language $primaryLang
    $fallbackLang = 'en'
    if ($primaryLang -eq 'en') { $fallbackLang = 'pt-BR' }
    $locFallback = Get-FmpLocaleObject -Root $script:FmpRoot -Language $fallbackLang

    function Get-FmpCliText {
        param([string]$Key, [object[]]$Vals = @())
        return Get-FmpLocaleString -Locales @($locPrimary, $locFallback) -Key $Key -Values $Vals
    }

    if ($ValidateOnly) {
        Write-Host (Get-FmpCliText 'cli.compliance.scanning')
        Write-Host ((Get-FmpCliText 'cli.compliance.ok' -Vals @($comp.FilesScanned)))
        foreach ($lang in @('pt-BR', 'en')) {
            $l = Get-FmpLocaleObject -Root $script:FmpRoot -Language $lang
            Reset-FmpMissingLocaleKeys
            # Touch every key present so missing-key tracking only reports referenced keys later.
            Write-Host ('  locale ' + $lang + ': ' + (@($l.PSObject.Properties).Count) + ' keys loaded')
        }
        $null = Get-FmpRuleConfig -Root $script:FmpRoot
        Write-Host 'rules.json: OK'
        Write-Host 'ValidateOnly: PASS'
        exit 0
    }

    # ---- Read-only compliance gate (mandatory before any collection) ----
    Write-Host (Get-FmpCliText 'cli.compliance.scanning')
    Write-Host ((Get-FmpCliText 'cli.compliance.ok' -Vals @($comp.FilesScanned)))

    $synthetic = $PSBoundParameters.ContainsKey('Fixture')
    if ($synthetic -and [string]::IsNullOrWhiteSpace($Fixture)) { exit 3 }
    $nonInteractiveHost = $false
    foreach ($arg in [Environment]::GetCommandLineArgs()) {
        if ($arg -in @('-File', '-f', '-Command', '-c')) { break }
        if ($arg -like '-NonI*') { $nonInteractiveHost = $true; break }
    }
    $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not $nonInteractiveHost -and -not $Yes -and -not $synthetic

    # ---- 1-3. Presentation, language, mode ----
    Write-Host ''
    Write-Host ('== ' + (Get-FmpCliText 'cli.banner.title') + ' ==')
    Write-Host ((Get-FmpCliText 'cli.banner.version' -Vals @($script:FmpToolVersion)))
    Write-Host ''
    Write-Host (Get-FmpCliText 'cli.policy.intro')
    foreach ($p in (Get-FmpCliText 'cli.policy.points' -Vals @())) {
        Write-Host (' - ' + $p)
    }
    Write-Host ''

    if ($Language -eq '' -and $interactive) {
        $ans = ''
        try { $ans = Read-Host (Get-FmpCliText 'cli.choose.language') }
        catch { $interactive = $false }
        if ($ans.Trim() -eq '2') { $primaryLang = 'en'; $fallbackLang = 'pt-BR' }
        else { $primaryLang = 'pt-BR'; $fallbackLang = 'en' }
        $locPrimary = Get-FmpLocaleObject -Root $script:FmpRoot -Language $primaryLang
        $locFallback = Get-FmpLocaleObject -Root $script:FmpRoot -Language $fallbackLang
    }
    elseif ($Language -eq '') { $primaryLang = 'pt-BR' }
    Write-Host ((Get-FmpCliText 'cli.language.selected' -Vals @($primaryLang)))

    if ($Mode -eq '' -and $interactive) {
        $ans = ''
        try { $ans = Read-Host (Get-FmpCliText 'cli.choose.mode') }
        catch { $interactive = $false }
        if ($ans.Trim() -eq '2') { $Mode = 'full' } else { $Mode = 'simple' }
    }
    elseif ($Mode -eq '') { $Mode = 'simple' }
    Write-Host ((Get-FmpCliText 'cli.mode.selected' -Vals @((Get-FmpCliText ('mode.' + $Mode)))))

    # ---- 4. Output directory (the only authorized write location) ----
    $runId = New-FmpRunId
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    # Default output: a new, randomly named folder under %LOCALAPPDATA%\FixMyPC, never the install folder. Privacy comes
    # from the protected ACL New-FmpOutputDirectory sets on creation, not from the parent's ACL (S11-01).
    $localAppData = [string]$env:LOCALAPPDATA
    if ($OutDir -eq '') {
        if ($localAppData -notmatch '^[A-Za-z]:\\') { Write-Host (Get-FmpCliText 'cli.error.noLocalAppData') -ForegroundColor Red; exit 3 }
        $OutDir = Join-Path $localAppData ('FixMyPC\fixmypc-' + $stamp + '-' + $runId)
    }
    $fullOut = $OutDir
    Write-Host ((Get-FmpCliText 'cli.data.explain' -Vals @($fullOut)))
    # The output folder is created new with a private ACL. That cannot protect files on drives without NTFS/ReFS
    # permissions, nor copies made by cloud sync, so both cases are flagged before consent is asked.
    $outNormalized = ''
    try { $outNormalized = [System.IO.Path]::GetFullPath($OutDir) + '\' } catch { $outNormalized = '' }
    $driveFormat = ''
    try { $driveFormat = [string][System.IO.DriveInfo]::new($outNormalized.Substring(0, 3)).DriveFormat } catch { $driveFormat = '' }
    if ($driveFormat -notin @('NTFS', 'ReFS')) { Write-Host (Get-FmpCliText 'cli.outdir.notPrivate') -ForegroundColor Yellow }
    foreach ($syncRoot in @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer)) {
        if ([string]$syncRoot -match '^[A-Za-z]:\\' -and $outNormalized.StartsWith(([string]$syncRoot).TrimEnd('\') + '\', 'OrdinalIgnoreCase')) {
            Write-Host (Get-FmpCliText 'cli.outdir.synced') -ForegroundColor Yellow
            break
        }
    }

    # ---- 5. Consent ----
    # Real collection requires explicit consent (-AcceptReadOnlyPolicy or an
    # interactive "yes"). Fixture runs never touch the system, so -Yes is
    # enough for them. -Yes alone NEVER authorizes a real collection.
    $ans = ''
    if (-not $synthetic -and -not $AcceptReadOnlyPolicy -and $interactive) {
        try { $ans = Read-Host (Get-FmpCliText 'cli.consent.prompt') }
        catch { $interactive = $false }
    }
    if (-not $synthetic -and -not (Test-FmpCollectionConsent -Explicit:$AcceptReadOnlyPolicy -Interactive:$interactive -Answer $ans)) {
        Write-Host (Get-FmpCliText 'cli.error.consent') -ForegroundColor Yellow
        exit 3
    }
    if (-not $synthetic) { Write-Host (Get-FmpCliText 'cli.consent.granted') }

    try {
        $fullOut = (Get-FmpCheckedPath $OutDir).TrimEnd('\')
        # An existing folder keeps whatever ACL it has; only a folder this run creates is known to be private.
        if (Test-Path -LiteralPath $fullOut) { throw (Get-FmpCliText 'cli.error.outDirExists') }
        Set-FmpAllowedWriteRoot $fullOut
        $internalPath = Join-Path $fullOut 'diagnostic-internal.json'
        $sanitizedPath = Join-Path $fullOut 'diagnostic-sanitized.json'
        $reportPath = Join-Path $fullOut 'report.html'
        foreach ($path in @($sanitizedPath, $reportPath, $internalPath)) {
            $null = Assert-FmpOutputPath $path
            if (Test-Path -LiteralPath $path) { throw 'Output already contains an artifact. Choose a fresh output directory.' }
        }
    }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 3 }

    $startedAt = Get-FmpTimestamp
    $modules = @()

    if ($synthetic) {
        # ---- Synthetic pipeline: no collection, no system access ----
        $fixturePath = $Fixture
        if ($Fixture -notmatch '^(?:[A-Za-z]:|[\\/])' -and $PWD.Provider.Name -eq 'FileSystem') {
            $fixturePath = Join-Path $PWD.ProviderPath $Fixture
        }
        $fx = Read-FmpJsonFile -Path $fixturePath
        if (-not $fx.Ok -or -not (Test-FmpDiagnosticDocument $fx.Data)) {
            Write-Host (Get-FmpCliText 'cli.error.fixture' -Vals @($Fixture)) -ForegroundColor Red
            exit 3
        }
        $fxRun = Get-FmpValue -Data $fx.Data -Path 'run'
        $meta = @{
            Id         = $runId
            Mode       = $Mode
            Language   = $primaryLang
            Synthetic  = $true
            StartedAt  = $(if ($null -ne $fxRun) { Get-FmpValue -Data $fxRun -Path 'startedAt' } else { $startedAt })
            FinishedAt = $(if ($null -ne $fxRun) { Get-FmpValue -Data $fxRun -Path 'finishedAt' } else { Get-FmpTimestamp })
        }
        $diag = ConvertTo-FmpSerializable -Value $fx.Data
        # Ensure the embedded run matches this invocation.
        $diag['run'] = [ordered]@{
            id = $meta.Id; tool = 'FIX MY PC: Windows Diagnostic & Audit Skill'
            toolVersion = $script:FmpToolVersion; mode = $meta.Mode
            language = $meta.Language; synthetic = $true
            startedAt = $meta.StartedAt; finishedAt = $meta.FinishedAt
            readOnlyPolicy = Get-FmpReadOnlyPolicySummary
        }
        $modules = @(Get-FmpValue -Data $diag -Path 'modules')
    }
    else {
        . (Join-Path $script:FmpRoot 'src\collectors\System.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Events.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Startup.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Performance.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Storage.ps1')
        if ($Mode -eq 'full') { . (Join-Path $script:FmpRoot 'src\collectors\Advanced.ps1') }
        # ---- 6. Authorized collection with per-module progress ----
        # Each module's command inventory comes from the same static AST scan
        # used by the compliance gate (audit trail for the report).
        $invSrc = Join-Path $script:FmpRoot 'src\collectors'
        Write-Host ((Get-FmpCliText 'cli.run.starting' -Vals @((Get-FmpCliText ('mode.' + $Mode)))))
        $full = ($Mode -eq 'full')

        $modSystem = Get-FmpSystemData
        $modSystem['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'System.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modSystem.id, $modSystem.status, $modSystem.durationMs)))

        $modEvents = Get-FmpEventData -WindowDays 7 -Full:$full
        $modEvents['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Events.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modEvents.id, $modEvents.status, $modEvents.durationMs)))

        $modStartup = Get-FmpStartupData
        $modStartup['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Startup.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modStartup.id, $modStartup.status, $modStartup.durationMs)))

        $modPerf = Get-FmpPerformanceData
        $modPerf['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Performance.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modPerf.id, $modPerf.status, $modPerf.durationMs)))

        $modStorage = Get-FmpStorageData
        $modStorage['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Storage.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modStorage.id, $modStorage.status, $modStorage.durationMs)))

        if ($full) {
            $modAdvanced = Get-FmpAdvancedData
            $modAdvanced['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Advanced.ps1')
            Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modAdvanced.id, $modAdvanced.status, $modAdvanced.durationMs)))
            $modules = @($modSystem, $modEvents, $modStartup, $modPerf, $modStorage, $modAdvanced)
        }
        else {
            $modules = @($modSystem, $modEvents, $modStartup, $modPerf, $modStorage)
        }
        Write-Host (Get-FmpCliText 'cli.run.done')

        $meta = @{
            Id = $runId; Mode = $Mode; Language = $primaryLang
            Synthetic = $false; StartedAt = $startedAt; FinishedAt = Get-FmpTimestamp
        }
        $diag = Merge-FmpDiagnostics -Modules $modules -RunMeta $meta
    }

    # ---- 7-8. Deterministic analysis + score ----
    $ruleConfig = Get-FmpRuleConfig -Root $script:FmpRoot
    $analysis = Invoke-FmpRules -Diagnostic $diag -RuleConfig $ruleConfig -Mode $Mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules $modules
    Write-Host ((Get-FmpCliText 'cli.analysis.done' -Vals @(@($analysis.checks).Count, @($analysis.findings).Count)))

    # ---- Artifact writes (only inside the authorized directory) ----
    $diag['analysis'] = $analysis
    $diag['healthScore'] = $score
    $privateIdentifiers = @()
    if (-not $synthetic) {
        $privateIdentifiers = @(@($env:COMPUTERNAME, $env:USERNAME, $env:USERDOMAIN, $env:USERDNSDOMAIN) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $sanitized = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diag -PrivateIdentifiers $privateIdentifiers
    if (-not (Test-FmpDiagnosticDocument $diag) -or -not (Test-FmpDiagnosticDocument $sanitized)) {
        throw 'Diagnostic document failed structural validation.'
    }
    Reset-FmpMissingLocaleKeys
    Set-FmpRenderLocale -Primary $locPrimary -Fallback $locFallback -Language $primaryLang
    $sanitizedText = ConvertTo-FmpJsonText -Data $sanitized
    $internalText = $null
    if ($IncludeInternalJson) { $internalText = ConvertTo-FmpJsonText -Data $diag }
    $htmlText = Get-FmpHtmlReportText -Diagnostic $sanitized -Synthetic:$synthetic -RedactionCount (Get-FmpRedactionCount)
    $utf8Check = [System.Text.UTF8Encoding]::new($false, $true)
    foreach ($payload in @($sanitizedText, $internalText, $htmlText)) {
        if ($null -ne $payload -and $utf8Check.GetBytes($payload).Length -gt 8MB) {
            throw 'Artifact exceeds the 8 MiB limit.'
        }
    }

    # Re-checked here: the folder must still not exist when this run creates it with its private ACL.
    if (Test-Path -LiteralPath $fullOut) { throw (Get-FmpCliText 'cli.error.outDirExists') }
    New-FmpOutputDirectory $fullOut
    Write-FmpUtf8File -Path $sanitizedPath -Text $sanitizedText
    if ($IncludeInternalJson) { Write-FmpUtf8File -Path $internalPath -Text $internalText }
    Write-FmpUtf8File -Path $reportPath -Text $htmlText
    $missing = Get-FmpMissingLocaleKeys
    if ($missing.Count -gt 0) {
        Write-Host ('locale keys missing: ' + ($missing -join ', ')) -ForegroundColor Yellow
    }

    # ---- 9-10. Paths + review guidance ----
    Write-Host ''
    Write-Host ('== ' + (Get-FmpCliText 'cli.done.title') + ' ==')
    Write-Host ((Get-FmpCliText 'cli.done.report' -Vals @($reportPath)))
    Write-Host ((Get-FmpCliText 'cli.done.sanitized' -Vals @($sanitizedPath)))
    if ($IncludeInternalJson) {
        Write-Host ((Get-FmpCliText 'cli.done.internal' -Vals @($internalPath)))
        Write-Host (Get-FmpCliText 'cli.internal.notice')
    }
    $scoreStatus = Get-FmpCliText ('score.status.' + $score.status)
    if ($null -eq $score.score) { Write-Host $scoreStatus }
    else { Write-Host (Get-FmpCliText 'cli.done.score' -Vals @([string]$score.score, $scoreStatus)) }
    Write-Host ''
    Write-Host (Get-FmpCliText 'cli.review.title')
    foreach ($s in (Get-FmpCliText 'cli.review.steps' -Vals @())) {
        Write-Host (' - ' + $s)
    }
    exit 0
}
catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    exit 4
}
