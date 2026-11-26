# =====================================================================
# FIX MY PC: PC Diagnostic & Audit Skill - v0.2.0-preview
# Entry point. Read-only Windows audit producing HTML + JSON reports.
#
# Usage examples:
#   powershell -NoProfile -File fixmypc.ps1
#   powershell -NoProfile -File fixmypc.ps1 -Mode full -Language pt-BR -OutDir "$env:LOCALAPPDATA\FixMyPC\auditoria-1" -AcceptReadOnlyPolicy
#   powershell -NoProfile -NonInteractive -File fixmypc.ps1 -Fixture tests\fixtures\demo-synthetic.json -Mode full -Language pt-BR -Yes
#   powershell -NoProfile -NonInteractive -File fixmypc.ps1 -ValidateOnly
#   powershell -NoProfile -NonInteractive -File fixmypc.ps1 -Plan -Mode full -Symptom slow -Language pt-BR
#     (prints the consent request and the exact command with a one-run -ConsentToken; collects nothing)
# =====================================================================
[CmdletBinding()]
param(
    [ValidateSet('simple', 'full')]
    [string]$Mode = '',
    [ValidateSet('pt-BR', 'en')]
    [string]$Language = '',
    [string]$OutDir = '',
    [string]$Fixture = '',
    [ValidateSet('general', 'boot', 'slow', 'crash')]
    [string]$Symptom = '',
    [ValidateRange(15, 300)]
    [int]$ObserveSeconds = 0,
    [ValidateSet('yes', 'no', 'unknown')]
    [string]$DuringProblem = 'unknown',
    [string]$IncidentAt = '',
    [ValidateRange(1, 720)]
    [int]$IncidentToleranceMinutes = 30,
    [ValidateSet('standard', 'deep')]
    [string]$Depth = '',
    [switch]$Plan,
    [string]$ConsentToken = '',
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
    Write-Host 'FIX MY PC: PC Diagnostic & Audit Skill v' $script:FmpToolVersion
    Write-Host ''
    Write-Host '  -Mode <simple|full>            audit mode (default: simple)'
    Write-Host '  -Language <pt-BR|en>           report language (default: pt-BR)'
    Write-Host '  -OutDir <path>                 new output folder, must not exist (default: %LOCALAPPDATA%\FixMyPC\fixmypc-<timestamp>-<id>)'
    Write-Host '  -Symptom <general|boot|slow|crash>  problem to investigate (default: general)'
    Write-Host '  -ObserveSeconds <15-300>       Full audit observation window (default by symptom: slow 60, general 45, boot/crash 30)'
    Write-Host '  -DuringProblem <yes|no|unknown> whether the problem is happening during the measurement'
    Write-Host '  -IncidentAt <time>             when the problem happened: yyyy-MM-ddTHH:mm[:ss][Z|+hh:mm|-hh:mm] (no offset = this PC''s local time), during-run or unknown'
    Write-Host '  -IncidentToleranceMinutes <1-720>  how far around that time to look (default 30)'
    Write-Host '  -Depth <standard|deep>         Full audit only: how far complementary investigations may go (default standard)'
    Write-Host '  -Fixture <path>                run the pipeline on a synthetic JSON fixture (no collection)'
    Write-Host '  -Plan                          print the consent request and the exact command (with -ConsentToken); collects nothing'
    Write-Host '  -AcceptReadOnlyPolicy          non-interactive consent; needs the -ConsentToken printed by -Plan for this exact run'
    Write-Host '  -ConsentToken <token>          one-run token from -Plan (bound to mode, symptom, language, window, folder; 30 min)'
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
    . (Join-Path $script:FmpRoot 'src\analysis\Diagnosis.ps1')
    . (Join-Path $script:FmpRoot 'src\analysis\Correlation.ps1')
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

    $ruleConfig = Get-FmpRuleConfig -Root $script:FmpRoot
    $runId = New-FmpRunId
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $localAppData = [string]$env:LOCALAPPDATA

    # ---- Incident time: structured value only, validated before consent because it is part of the approved scope ----
    # A fixture has its own timeline, so "now" does not bound its incident time.
    $incidentNow = [DateTime]::UtcNow
    if ($PSBoundParameters.ContainsKey('Fixture')) { $incidentNow = $null }
    $incident = ConvertTo-FmpIncidentAnchor -Value $IncidentAt -ToleranceMinutes $IncidentToleranceMinutes -NowUtc $incidentNow
    if (-not $incident.ok) { Write-Host (Get-FmpCliText 'cli.error.incident' -Vals @($incident.reason)) -ForegroundColor Red; exit 3 }
    if ($incident.anchor.kind -eq 'during_run' -and $DuringProblem -eq 'no') { Write-Host (Get-FmpCliText 'cli.error.incidentConflict') -ForegroundColor Red; exit 3 }
    if ($Depth -eq 'deep' -and $Mode -eq 'simple') { Write-Host (Get-FmpCliText 'cli.error.depthMode') -ForegroundColor Red; exit 3 }

    # ---- -Plan: the consent request for an agent run. Prints, collects nothing, writes nothing. ----
    if ($Plan) {
        if ($PSBoundParameters.ContainsKey('Fixture')) { Write-Host '-Plan applies to real runs only.' -ForegroundColor Red; exit 3 }
        $pMode = $Mode; if ($pMode -eq '') { $pMode = 'simple' }
        $pSym = $Symptom; if ($pSym -eq '') { $pSym = 'general' }
        if ($Depth -eq 'deep' -and $pMode -ne 'full') { Write-Host (Get-FmpCliText 'cli.error.depthMode') -ForegroundColor Red; exit 3 }
        $pDepth = ''
        if ($pMode -eq 'full') { $pDepth = 'standard'; if ($Depth -ne '') { $pDepth = $Depth } }
        $pObs =Get-FmpObserveSeconds -Config $ruleConfig -Mode $pMode -Symptom $pSym -Requested $ObserveSeconds
        $pOut = $OutDir
        if ($pOut -eq '') {
            if ($localAppData -notmatch '^[A-Za-z]:\\') { Write-Host (Get-FmpCliText 'cli.error.noLocalAppData') -ForegroundColor Red; exit 3 }
            $pOut = Join-Path $localAppData ('FixMyPC\fixmypc-' + $stamp + '-' + $runId)
        }
        try { $pOut = (Get-FmpCheckedPath $pOut).TrimEnd('\') }
        catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 3 }
        if (Test-Path -LiteralPath $pOut) { Write-Host (Get-FmpCliText 'cli.error.outDirExists') -ForegroundColor Red; exit 3 }
        $selfPath = Join-Path $script:FmpRoot 'fixmypc.ps1'
        # The printed command quotes paths with single quotes (same meaning in PowerShell and POSIX shells).
        if ($pOut -match "['`$``]" -or $selfPath -match "['`$``]") { Write-Host 'Paths with quotes, $ or backticks are not supported by -Plan; choose another folder.' -ForegroundColor Red; exit 3 }
        $issued = [DateTime]::UtcNow
        $scope = Get-FmpConsentScope -Mode $pMode -Symptom $pSym -Language $primaryLang -ObserveSeconds $pObs -DuringProblem $DuringProblem -IncludeInternal ([bool]$IncludeInternalJson) -OutDir $pOut -Incident $incident.scope -Depth $pDepth
        $token = New-FmpConsentToken -Scope $scope -IssuedUtc $issued
        $cmd = 'powershell -NoProfile -NonInteractive -File ''' + $selfPath + ''' -Mode ' + $pMode + ' -Symptom ' + $pSym + ' -Language ' + $primaryLang
        if ($pMode -eq 'full') { $cmd += ' -ObserveSeconds ' + $pObs }
        $cmd += ' -DuringProblem ' + $DuringProblem
        if ($incident.anchor.kind -eq 'during_run') { $cmd += ' -IncidentAt during-run' }
        elseif ($incident.anchor.kind -eq 'at') { $cmd += ' -IncidentAt ''' + $incident.anchor.input + ''' -IncidentToleranceMinutes ' + $IncidentToleranceMinutes }
        if ($pDepth -eq 'deep') { $cmd += ' -Depth deep' }
        $cmd += ' -OutDir ''' + $pOut + ''''
        if ($IncludeInternalJson) { $cmd += ' -IncludeInternalJson' }
        $cmd += ' -AcceptReadOnlyPolicy -ConsentToken ' + $token
        Write-Host ('== ' + (Get-FmpCliText 'cli.plan.title') + ' ==')
        Write-Host (Get-FmpCliText 'cli.plan.mode' -Vals @((Get-FmpCliText ('cli.plan.modeName.' + $pMode))))
        Write-Host (Get-FmpCliText 'cli.plan.language' -Vals @((Get-FmpCliText ('cli.plan.langName.' + $primaryLang))))
        Write-Host (Get-FmpCliText 'cli.plan.goal' -Vals @((Get-FmpCliText ('diag.symptom.' + $pSym))))
        Write-Host (Get-FmpCliText 'cli.plan.during' -Vals @((Get-FmpCliText ('cli.plan.duringValue.' + $DuringProblem))))
        if ($incident.anchor.kind -eq 'during_run') { Write-Host (Get-FmpCliText 'cli.plan.incidentDuring') }
        elseif ($incident.anchor.kind -eq 'at') { Write-Host (Get-FmpCliText 'cli.plan.incident' -Vals @($incident.anchor.input, $incident.anchor.effectiveToleranceMinutes)) }
        if ($pMode -eq 'full') {
            Write-Host (Get-FmpCliText 'cli.plan.data.full' -Vals @($pObs, (Get-FmpValue $ruleConfig 'diagnosis.bootHistoryDays' -Default 60), (Get-FmpEventWindowDays -Config $ruleConfig -Mode $pMode -Symptom $pSym)))
            Write-Host (Get-FmpCliText 'cli.plan.catalog' -Vals @((Get-FmpEventCatalogDays -Config $ruleConfig -Mode $pMode -Symptom $pSym -Incident $incident.anchor -NowUtc $issued -Depth $pDepth), (Get-FmpValue $ruleConfig 'diagnosis.eventCatalog.maxPerProvider' -Default 300)))
            Write-Host (Get-FmpCliText 'cli.plan.depth' -Vals @((Get-FmpCliText ('cli.plan.depthName.' + $pDepth))))
            Write-Host (Get-FmpCliText ('cli.plan.investigations.' + $pDepth) -Vals @([int]((Get-FmpValue $ruleConfig ('diagnosis.budgets.' + $pDepth + 'Ms') -Default 45000) / 1000)))
            Write-Host (Get-FmpCliText 'cli.plan.investigationsNever')
            Write-Host (Get-FmpCliText 'cli.plan.duration.full' -Vals @($pObs, ($pObs + 20), ($pObs + 120), ($pObs + 45)))
        }
        else {
            Write-Host (Get-FmpCliText 'cli.plan.data.simple')
            Write-Host (Get-FmpCliText 'cli.plan.duration.simple')
        }
        Write-Host (Get-FmpCliText 'cli.plan.outdir' -Vals @($pOut))
        Write-Host (Get-FmpCliText 'cli.plan.ai')
        Write-Host (Get-FmpCliText 'cli.plan.noRepair')
        Write-Host (Get-FmpCliText 'cli.plan.command')
        Write-Host ('  ' + $cmd)
        Write-Host (Get-FmpCliText 'cli.plan.validity' -Vals @(($issued.AddDays(30 / 1440.0).ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC')))
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

    # The Full audit is steered by the reported symptom: it changes the observation window, event history and priorities.
    if ($Symptom -eq '' -and $Mode -eq 'full' -and $interactive) {
        $ans = ''
        try { $ans = Read-Host (Get-FmpCliText 'cli.choose.symptom') }
        catch { $interactive = $false }
        $symptomMap = @{ '1' = 'boot'; '2' = 'slow'; '3' = 'crash' }
        if ($symptomMap.ContainsKey($ans.Trim())) { $Symptom = $symptomMap[$ans.Trim()] } else { $Symptom = 'general' }
    }
    elseif ($Symptom -eq '') { $Symptom = 'general' }
    Write-Host ((Get-FmpCliText 'cli.symptom.selected' -Vals @((Get-FmpCliText ('diag.symptom.' + $Symptom)))))
    $observeResolved = Get-FmpObserveSeconds -Config $ruleConfig -Mode $Mode -Symptom $Symptom -Requested $ObserveSeconds
    if ($Depth -eq 'deep' -and $Mode -ne 'full') { Write-Host (Get-FmpCliText 'cli.error.depthMode') -ForegroundColor Red; exit 3 }
    $depthResolved = ''
    if ($Mode -eq 'full') { $depthResolved = 'standard'; if ($Depth -ne '') { $depthResolved = $Depth } }
    $eventDays =Get-FmpEventWindowDays -Config $ruleConfig -Mode $Mode -Symptom $Symptom

    # ---- 4. Output directory (the only authorized write location) ----
    # Default output: a new, randomly named folder under %LOCALAPPDATA%\FixMyPC, never the install folder. Privacy comes
    # from the protected ACL New-FmpOutputDirectory sets on creation, not from the parent's ACL (S11-01).
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
    # Real collection requires either a typed "yes" in an interactive terminal, or -AcceptReadOnlyPolicy together with
    # the -ConsentToken that -Plan printed for this exact run (mode, symptom, language, window, folder; 30 min). The
    # flag alone is a caller's declaration and is refused. Fixture runs never touch the system, so -Yes is enough for
    # them. -Yes alone NEVER authorizes a real collection.
    if ($depthResolved -ne '' -and -not $synthetic) {
        Write-Host (Get-FmpCliText 'cli.plan.depth' -Vals @((Get-FmpCliText ('cli.plan.depthName.' + $depthResolved))))
        Write-Host (Get-FmpCliText ('cli.plan.investigations.' + $depthResolved) -Vals @([int]((Get-FmpValue $ruleConfig ('diagnosis.budgets.' + $depthResolved + 'Ms') -Default 45000) / 1000)))
        Write-Host (Get-FmpCliText 'cli.plan.investigationsNever')
    }
    $ans = ''
    $tokenState = 'missing'
    if (-not $synthetic -and $AcceptReadOnlyPolicy) {
        $scopeOut = ''
        try { $scopeOut = (Get-FmpCheckedPath $OutDir).TrimEnd('\') } catch { $scopeOut = '' }
        $scope = Get-FmpConsentScope -Mode $Mode -Symptom $Symptom -Language $primaryLang -ObserveSeconds $observeResolved -DuringProblem $DuringProblem -IncludeInternal ([bool]$IncludeInternalJson) -OutDir $scopeOut -Incident $incident.scope -Depth $depthResolved
        $tokenState = Test-FmpConsentToken -Token $ConsentToken -Scope $scope -NowUtc ([DateTime]::UtcNow)
    }
    if (-not $synthetic -and $tokenState -ne 'valid' -and $interactive) {
        try { $ans = Read-Host (Get-FmpCliText 'cli.consent.prompt') }
        catch { $interactive = $false }
    }
    if (-not $synthetic -and -not (Test-FmpCollectionConsent -Explicit:$AcceptReadOnlyPolicy -Interactive:$interactive -Answer $ans -TokenState $tokenState)) {
        if ($AcceptReadOnlyPolicy) { Write-Host (Get-FmpCliText 'cli.error.token' -Vals @($tokenState)) -ForegroundColor Yellow }
        else { Write-Host (Get-FmpCliText 'cli.error.consent') -ForegroundColor Yellow }
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

    # ---- C1: consume the authorization BEFORE any collector is loaded ----
    # The existence check above is not atomic. The run that creates the reservation file (exclusive create) in the
    # approved folder is the only one that collects; a concurrent or later run with the same command is refused here.
    # The folder and that file stay even if the run fails or is interrupted, so the approval is never usable twice.
    if (-not $synthetic) {
        $reserved = $false
        try { $reserved = New-FmpRunReservation -Root $fullOut -RunId $runId }
        catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 3 }
        if (-not $reserved) { Write-Host (Get-FmpCliText 'cli.error.reservation') -ForegroundColor Red; exit 3 }
    }

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
            id = $meta.Id; tool = 'FIX MY PC: PC Diagnostic & Audit Skill'
            toolVersion = $script:FmpToolVersion; mode = $meta.Mode
            language = $meta.Language; synthetic = $true
            startedAt = $meta.StartedAt; finishedAt = $meta.FinishedAt
            readOnlyPolicy = Get-FmpReadOnlyPolicySummary
        }
        $modules = @(Get-FmpValue -Data $diag -Path 'modules')
    }
    else {
        . (Join-Path $script:FmpRoot 'src\collectors\Observation.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\System.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Events.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Startup.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Performance.ps1')
        . (Join-Path $script:FmpRoot 'src\collectors\Storage.ps1')
        if ($Mode -eq 'full') {
            . (Join-Path $script:FmpRoot 'src\collectors\Advanced.ps1')
            . (Join-Path $script:FmpRoot 'src\collectors\Investigations.ps1')
        }
        # ---- 6. Authorized collection with per-module progress ----
        # Each module's command inventory comes from the same static AST scan
        # used by the compliance gate (audit trail for the report).
        $invSrc = Join-Path $script:FmpRoot 'src\collectors'
        Write-Host ((Get-FmpCliText 'cli.run.starting' -Vals @((Get-FmpCliText ('mode.' + $Mode)))))
        $full = ($Mode -eq 'full')

        # Observation runs first, before the heavier inventory queries, so the audit's own load does not dominate it.
        $modObservation = $null
        if ($full) {
            Write-Host ((Get-FmpCliText 'cli.run.observing' -Vals @($observeResolved)))
            $obsCfg = Get-FmpValue $ruleConfig 'diagnosis.observation'
            $modObservation = Get-FmpObservationData -DurationSec $observeResolved -IntervalSec ([int](Get-FmpValue $obsCfg 'intervalSeconds' -Default 5)) -MaxSamples ([int](Get-FmpValue $obsCfg 'maxSamples' -Default 61)) -CpuHighPct ([double](Get-FmpValue $ruleConfig 'diagnosis.thresholds.cpuHighPct' -Default 85))
            $modObservation['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'Observation.ps1')
            Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modObservation.id, $modObservation.status, $modObservation.durationMs)))
        }

        $modSystem = Get-FmpSystemData
        $modSystem['commands'] = Get-FmpCommandInventory -Path (Join-Path $invSrc 'System.ps1')
        Write-Host ((Get-FmpCliText 'cli.run.module' -Vals @($modSystem.id, $modSystem.status, $modSystem.durationMs)))

        $catalogDays = Get-FmpEventCatalogDays -Config $ruleConfig -Mode $Mode -Symptom $Symptom -Incident $incident.anchor -NowUtc ([DateTime]::UtcNow) -Depth $depthResolved
        $modEvents = Get-FmpEventData -WindowDays $eventDays -Full:$full -BootHistory:$full -BootDays ([int](Get-FmpValue $ruleConfig 'diagnosis.bootHistoryDays' -Default 60)) -CatalogDays $catalogDays -CatalogMaxPerProvider ([int](Get-FmpValue $ruleConfig 'diagnosis.eventCatalog.maxPerProvider' -Default 300))
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
            $modules = @($modObservation, $modSystem, $modEvents, $modStartup, $modPerf, $modStorage, $modAdvanced)
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

    # ---- 7-8. Deterministic analysis + score + symptom-oriented diagnosis ----
    $diag['run']['symptom'] = $Symptom
    $diag['run']['duringProblem'] = $DuringProblem
    $diag['run']['observeSeconds'] = $observeResolved
    if ($incident.anchor.kind -ne 'unknown') { $diag['run']['incident'] = $incident.anchor }
    $analysis = Invoke-FmpRules -Diagnostic $diag -RuleConfig $ruleConfig -Mode $Mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules $modules
    # Complementary investigations run after triage and never feed the score. A fixture only replays what it already holds.
    if (-not $synthetic -and $Mode -eq 'full') {
        $diag['run']['depth'] = $depthResolved
        Write-Host (Get-FmpCliText 'cli.run.investigating')
        $investigations = Invoke-FmpInvestigationPlan -Diagnostic $diag -Analysis $analysis -RuleConfig $ruleConfig -Symptom $Symptom -DuringProblem $DuringProblem -Depth $depthResolved
        $diag['investigations'] = $investigations
        Write-Host (Get-FmpCliText 'cli.run.investigated' -Vals @(@(@(Get-FmpValue $investigations 'runs') | Where-Object { [string](Get-FmpValue $_ 'state') -notin @('not_triggered', 'not_authorized', 'budget', 'limit') }).Count, [Math]::Round([double](Get-FmpValue $investigations 'elapsedMs') / 1000, 0)))
    }
    $diagnosis = Get-FmpDiagnosis -Diagnostic $diag -Analysis $analysis -RuleConfig $ruleConfig -Symptom $Symptom -DuringProblem $DuringProblem
    Add-FmpDiagnosisText -Diagnosis $diagnosis -Locales @($locPrimary, $locFallback) -Language $primaryLang
    Write-Host ((Get-FmpCliText 'cli.analysis.done' -Vals @(@($analysis.checks).Count, @($analysis.findings).Count)))

    # ---- Artifact writes (only inside the authorized directory) ----
    $diag['analysis'] = $analysis
    $diag['healthScore'] = $score
    $diag['diagnosis'] = $diagnosis
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

    # Real runs created their private folder at the reservation. Fixture runs (no system access, no consent) create it
    # here; the folder must still not exist.
    if ($synthetic) {
        if (Test-Path -LiteralPath $fullOut) { throw (Get-FmpCliText 'cli.error.outDirExists') }
        New-FmpOutputDirectory $fullOut
    }
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
    # Investigation result first; the score is printed after it, as a secondary figure.
    Write-Host ''
    Write-Host (Get-FmpCliText 'cli.diag.title')
    Write-Host (' ' + [string]$diagnosis['symptomText'] + ': ' + [string]$diagnosis['conclusionText'])
    if (@($diagnosis['keyFindings']).Count -gt 0) {
        Write-Host (Get-FmpCliText 'cli.diag.findings')
        foreach ($kf in @($diagnosis['keyFindings'])) { Write-Host (' - ' + [string]$kf['title'] + ': ' + [string]$kf['observed']) }
    }
    $nvLabels = @(@($diagnosis['questions']) | Where-Object { $_['answer'] -notin @('yes', 'no', 'partial') -and $_['relevance'] -ne 'low' } | ForEach-Object { [string]$_['text'] })
    if ($nvLabels.Count -gt 0) {
        Write-Host (Get-FmpCliText 'cli.diag.notVerified')
        foreach ($nvl in $nvLabels) { Write-Host (' - ' + $nvl) }
    }
    Write-Host (Get-FmpCliText 'cli.diag.next')
    foreach ($ns in @($diagnosis['nextStepsText'])) { Write-Host (' - ' + [string]$ns) }
    $scoreStatus = Get-FmpCliText ('score.status.' + $score.status)
    if ($null -eq $score.score) { Write-Host $scoreStatus }
    else { Write-Host (Get-FmpCliText 'cli.diag.scoreSecondary' -Vals @([string]$score.score, (Get-FmpCliText ('confidence.' + $score.confidence)))) }
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
