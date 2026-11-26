# =====================================================================
# FIX MY PC - Diagnosis.Tests.ps1 (2.0)
# Offline suite for the symptom-oriented diagnosis, the chat consent
# token, the two-layer HTML report and contract compatibility. Uses ONLY
# synthetic fixtures and mocked collectors - never touches the real
# system (no CIM, no event log, no registry). Run:
#   powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\Diagnosis.Tests.ps1
# =====================================================================
param([switch]$ConsentReplayGate)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\common\Common.ps1')
. (Join-Path $root 'src\security\ReadOnlyPolicy.ps1')
. (Join-Path $root 'src\security\Privacy.ps1')
. (Join-Path $root 'src\analysis\Evidence.ps1')
. (Join-Path $root 'src\analysis\Rules.ps1')
. (Join-Path $root 'src\analysis\HealthScore.ps1')
. (Join-Path $root 'src\analysis\Diagnosis.ps1')
. (Join-Path $root 'src\reports\HtmlRenderer.ps1')

$script:PassCount = 0
$script:FailCount = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:CurrentSuite = ''
$script:Metrics = New-Object System.Collections.Generic.List[string]

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
function Start-FmpSuite { param([string]$Name) $script:CurrentSuite = $Name; Write-Host ('== ' + $Name + ' ==') }

$scratch = Join-Path $root ('out\fmp-dx-tests-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $scratch
$ruleConfig = Get-FmpRuleConfig -Root $root
$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data

function Get-FmpFixtureDoc {
    param([string]$Name)
    $fx = Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $Name))
    if (-not $fx.Ok) { throw ('fixture load failed: ' + $Name) }
    return (ConvertTo-FmpSerializable -Value $fx.Data)
}

function Invoke-FmpDx {
    # Same pipeline as fixmypc.ps1 after collection: rules -> score -> diagnosis -> text -> sanitize.
    param([System.Collections.IDictionary]$Doc, [string]$Symptom, [string]$During = 'unknown', [string]$Lang = 'pt-BR')
    $mode = [string]$Doc['run']['mode']
    $analysis = Invoke-FmpRules -Diagnostic $Doc -RuleConfig $ruleConfig -Mode $mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue $Doc 'modules')
    $dx = Get-FmpDiagnosis -Diagnostic $Doc -Analysis $analysis -RuleConfig $ruleConfig -Symptom $Symptom -DuringProblem $During
    $locs = @($locPt, $locEn)
    if ($Lang -eq 'en') { $locs = @($locEn, $locPt) }
    Add-FmpDiagnosisText -Diagnosis $dx -Locales $locs -Language $Lang
    $Doc['run']['language'] = $Lang
    $Doc['analysis'] = $analysis
    $Doc['healthScore'] = $score
    $Doc['diagnosis'] = $dx
    $san = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $Doc
    return @{ Dx = $dx; Score = $score; Analysis = $analysis; Sanitized = $san; Doc = $Doc }
}
function Get-FmpQ { param($Dx, [string]$Id) foreach ($q in @($Dx['questions'])) { if ($q['id'] -eq $Id) { return $q } } return $null }
function Get-FmpKeyIds { param($Dx) return @(@($Dx['keyFindings']) | ForEach-Object { [string]$_['id'] }) }
function Get-FmpRenderHtml {
    param($Sanitized, [string]$Lang = 'pt-BR')
    if ($Lang -eq 'en') { Set-FmpRenderLocale -Primary $locEn -Fallback $locPt -Language 'en' } else { Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR' }
    return Get-FmpHtmlReportText -Diagnostic $Sanitized -Synthetic:$true
}

# =====================================================================
Start-FmpSuite 'A. Token de consentimento (escopo, validade, adulteracao)'
$now = [DateTime]::UtcNow
$scopeArgs = @{ Mode = 'full'; Symptom = 'slow'; Language = 'pt-BR'; ObserveSeconds = 60; DuringProblem = 'unknown'; IncludeInternal = $false; OutDir = 'C:\Users\Example\AppData\Local\FixMyPC\run-1' }
$scope = Get-FmpConsentScope @scopeArgs
$tok = New-FmpConsentToken -Scope $scope -IssuedUtc $now
Assert-FmpTrue -Name 'formato fmpc1-<data>-<16 hex>' -Condition ($tok -cmatch '^fmpc1-\d{14}-[0-9a-f]{16}$')
Assert-FmpEqual -Name 'token do mesmo escopo e valido' -Expected 'valid' -Actual (Test-FmpConsentToken -Token $tok -Scope $scope -NowUtc $now)
Assert-FmpEqual -Name 'sem token: missing' -Expected 'missing' -Actual (Test-FmpConsentToken -Token '' -Scope $scope -NowUtc $now)
Assert-FmpEqual -Name 'texto qualquer: malformed' -Expected 'malformed' -Actual (Test-FmpConsentToken -Token 'yes' -Scope $scope -NowUtc $now)
$tampered = $tok.Substring(0, $tok.Length - 1) + $(if ($tok.EndsWith('0')) { '1' } else { '0' })
Assert-FmpEqual -Name 'digest adulterado: scope_mismatch' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tampered -Scope $scope -NowUtc $now)
foreach ($change in @(@('Mode', 'simple'), @('Symptom', 'crash'), @('Language', 'en'), @('ObserveSeconds', 120), @('DuringProblem', 'yes'), @('IncludeInternal', $true), @('OutDir', 'C:\Users\Example\AppData\Local\FixMyPC\run-2'))) {
    $alt = @{} + $scopeArgs
    $alt[$change[0]] = $change[1]
    Assert-FmpEqual -Name ('mudar ' + $change[0] + ' invalida a autorizacao') -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tok -Scope (Get-FmpConsentScope @alt) -NowUtc $now)
}
$old = New-FmpConsentToken -Scope $scope -IssuedUtc $now.AddMinutes(-31)
Assert-FmpEqual -Name 'token com mais de 30 min: expired' -Expected 'expired' -Actual (Test-FmpConsentToken -Token $old -Scope $scope -NowUtc $now)
$future = New-FmpConsentToken -Scope $scope -IssuedUtc $now.AddMinutes(10)
Assert-FmpEqual -Name 'token emitido no futuro: future' -Expected 'future' -Actual (Test-FmpConsentToken -Token $future -Scope $scope -NowUtc $now)
Assert-FmpTrue -Name 'flag sem token valido nunca autoriza' -Condition (-not (Test-FmpCollectionConsent $true $false '' 'missing') -and -not (Test-FmpCollectionConsent $true $false '' 'expired') -and (Test-FmpCollectionConsent $true $false '' 'valid'))
Assert-FmpTrue -Name 'token valido sem a flag nao autoriza' -Condition (-not (Test-FmpCollectionConsent $false $false '' 'valid'))

# =====================================================================
Start-FmpSuite 'B. CLI: -Plan, execucao sem autorizacao, autorizacao invalida e reutilizacao'
# Project copy whose collectors throw at load: reaching them proves consent passed; nothing real is ever queried.
$stubEntry = @{
    'System.ps1' = 'Get-FmpSystemData'; 'Events.ps1' = 'Get-FmpEventData'; 'Startup.ps1' = 'Get-FmpStartupData'; 'Performance.ps1' = 'Get-FmpPerformanceData'
    'Storage.ps1' = 'Get-FmpStorageData'; 'Advanced.ps1' = 'Get-FmpAdvancedData'; 'Observation.ps1' = 'Get-FmpObservationData'
    'Investigations.ps1' = 'Invoke-FmpInvestigationPlan'
}
function New-FmpMockProject {
    # $Prelude runs when a collector file is loaded (before the sentinel throw). 'Start-Sleep -Seconds 120' keeps the run
    # inside the collection stage so the test can interrupt it; no stub ever queries the system.
    param([string]$Dir, [string]$Prelude = '')
    New-FmpOutputDirectory $Dir
    foreach ($relative in $script:FmpSourceFiles) {
        $target = Join-Path $Dir $relative
        New-FmpOutputDirectory (Split-Path -Parent $target)
        if ($relative -like 'src\collectors\*') { Write-FmpUtf8File $target ($Prelude + [Environment]::NewLine + "throw 'SYNTHETIC_COLLECTOR_REACHED'" + [Environment]::NewLine + 'function ' + $stubEntry[(Split-Path -Path $target -Leaf)] + " { throw 'SYNTHETIC_COLLECTOR_REACHED' }") }
        else { Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative))) }
    }
    foreach ($relative in @('locales\pt-BR.json', 'locales\en.json', 'rules\rules.json', 'templates\style.css')) {
        $target = Join-Path $Dir $relative
        New-FmpOutputDirectory (Split-Path -Parent $target)
        Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative)))
    }
    Set-FmpAllowedWriteRoot $scratch
}
$mockRoot = Join-Path $scratch 'mock-project'
New-FmpMockProject -Dir $mockRoot
$slowMockRoot = Join-Path $scratch 'mock-project-slow'
New-FmpMockProject -Dir $slowMockRoot -Prelude 'Start-Sleep -Seconds 120'
$mockCli = Join-Path $mockRoot 'fixmypc.ps1'
$slowMockCli = Join-Path $slowMockRoot 'fixmypc.ps1'
function Invoke-FmpCli {
    param([string[]]$CliArgs, [string]$Cli = $mockCli)
    $out = & powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli @CliArgs 2>&1 | Out-String
    return @{ Exit = $LASTEXITCODE; Out = $out }
}
$script:ProcSeq = 0
function Start-FmpCliProcess {
    # Separate OS process (true parallelism, can be killed). Output goes to files inside the test scratch.
    param([string[]]$CliArgs, [string]$Cli = $mockCli)
    $script:ProcSeq++
    $so = Join-Path $scratch ('proc-' + $script:ProcSeq + '.out')
    $se = Join-Path $scratch ('proc-' + $script:ProcSeq + '.err')
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' + $Cli + '" ' + ((@($CliArgs) | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -NoNewWindow -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
    $null = $proc.Handle
    return @{ P = $proc; So = $so; Se = $se }
}
function Complete-FmpCliProcess {
    param($H, [int]$TimeoutMs = 180000)
    if (-not $H.P.WaitForExit($TimeoutMs)) { $H.P.Kill() }
    $H.P.WaitForExit()
    $txt = ''
    foreach ($f in @($H.So, $H.Se)) { if (Test-Path -LiteralPath $f) { $txt += [System.IO.File]::ReadAllText($f) } }
    return @{ Exit = $H.P.ExitCode; Out = $txt }
}
function Get-FmpPlanToken {
    param([string]$OutDir, [string]$Cli = $mockCli)
    $pl = Invoke-FmpCli -CliArgs @('-Plan', '-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-OutDir', $OutDir) -Cli $Cli
    return [regex]::Match($pl.Out, 'fmpc1-\d{14}-[0-9a-f]{16}').Value
}
function Get-FmpRunArgs {
    param([string]$OutDir, [string]$Token)
    return @('-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-ObserveSeconds', '60', '-DuringProblem', 'unknown', '-OutDir', $OutDir, '-AcceptReadOnlyPolicy', '-ConsentToken', $Token)
}
$planOut = Join-Path $scratch 'plan-run'
$p = Invoke-FmpCli @('-Plan', '-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-OutDir', $planOut)
Assert-FmpEqual -Name '-Plan termina com 0' -Expected 0 -Actual $p.Exit
Assert-FmpTrue -Name '-Plan nao cria a pasta nem coleta' -Condition (-not (Test-Path -LiteralPath $planOut) -and $p.Out -notmatch 'SYNTHETIC_COLLECTOR_REACHED')
foreach ($needle in @('PEDIDO DE AUTORIZA', 'Auditoria Completa', 'O computador fica lento', '60 s', $planOut, 'diagnostic-sanitized.json', 'Reparos: nenhum', '-ConsentToken fmpc1-', 'uma única execução')) {
    Assert-FmpTrue -Name ('-Plan informa: ' + $needle) -Condition ($p.Out.Contains($needle))
}
$cmdLine = @($p.Out -split "`r?`n" | Where-Object { $_ -match '^\s+powershell ' })[0].Trim()
$approvedToken = [regex]::Match($cmdLine, 'fmpc1-\d{14}-[0-9a-f]{16}').Value
$base = @('-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-ObserveSeconds', '60', '-DuringProblem', 'unknown', '-OutDir', $planOut, '-AcceptReadOnlyPolicy')
$r = Invoke-FmpCli ($base + @('-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'comando aprovado passa pelo consentimento (chega ao coletor sintetico)' -Condition ($r.Exit -eq 4 -and $r.Out -match 'SYNTHETIC_COLLECTOR_REACHED') -Detail ('exit=' + $r.Exit)
# C1 (always on since Phase 0; -ConsentReplayGate is kept as a no-op switch for old command lines).
$reservationFile = Join-Path $planOut 'run-reservation.json'
Assert-FmpTrue -Name 'C1: a execucao autorizada deixou a reserva na pasta aprovada' -Condition (Test-Path -LiteralPath $reservationFile)
Assert-FmpTrue -Name 'C1: a reserva nao contem o token nem caminhos' -Condition ((Test-Path -LiteralPath $reservationFile) -and ([System.IO.File]::ReadAllText($reservationFile) -notmatch 'fmpc1-|[A-Za-z]:\\'))
$retry = Invoke-FmpCli ($base + @('-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'C1: mesmo token apos falha do coletor e recusado (exit 3, nada coletado)' -Condition ($retry.Exit -eq 3 -and $retry.Out -notmatch 'SYNTHETIC_COLLECTOR_REACHED') -Detail ('exit=' + $retry.Exit)
$r = Invoke-FmpCli $base
Assert-FmpTrue -Name 'flag sem token: exit 3, nada coletado' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC' -and $r.Out -match 'missing')
$r = Invoke-FmpCli ($base + @('-ConsentToken', 'sim'))
Assert-FmpTrue -Name 'token invalido: exit 3' -Condition ($r.Exit -eq 3 -and $r.Out -match 'malformed')
$r = Invoke-FmpCli (@('-Mode', 'simple') + $base[2..($base.Count - 1)] + @('-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'mesmo token com outro modo: exit 3 (scope_mismatch)' -Condition ($r.Exit -eq 3 -and $r.Out -match 'scope_mismatch')
$otherOut = Join-Path $scratch 'plan-other'
$r = Invoke-FmpCli (@('-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-ObserveSeconds', '60', '-DuringProblem', 'unknown', '-OutDir', $otherOut, '-AcceptReadOnlyPolicy', '-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'mesmo token com outra pasta: exit 3' -Condition ($r.Exit -eq 3 -and $r.Out -match 'scope_mismatch')
$r = Invoke-FmpCli (@('-Mode', 'full', '-Symptom', 'crash') + $base[4..($base.Count - 1)] + @('-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'mesmo token com outro sintoma: exit 3' -Condition ($r.Exit -eq 3 -and $r.Out -match 'scope_mismatch')
# Reuse after a completed run: the approved folder now exists, so the same command is refused before any collection.
New-FmpOutputDirectory $planOut
Set-FmpAllowedWriteRoot $scratch
$r = Invoke-FmpCli ($base + @('-ConsentToken', $approvedToken))
Assert-FmpTrue -Name 'reutilizar a autorizacao apos a execucao: exit 3, nada coletado' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC')
$expiredTok = New-FmpConsentToken -Scope (Get-FmpConsentScope -Mode 'full' -Symptom 'slow' -Language 'pt-BR' -ObserveSeconds 60 -DuringProblem 'unknown' -IncludeInternal $false -OutDir $otherOut) -IssuedUtc ([DateTime]::UtcNow.AddMinutes(-45))
$r = Invoke-FmpCli (@('-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-ObserveSeconds', '60', '-DuringProblem', 'unknown', '-OutDir', $otherOut, '-AcceptReadOnlyPolicy', '-ConsentToken', $expiredTok))
Assert-FmpTrue -Name 'autorizacao expirada: exit 3' -Condition ($r.Exit -eq 3 -and $r.Out -match 'expired')
$r = Invoke-FmpCli @('-Plan', '-Fixture', (Join-Path $root 'tests\fixtures\diag-slow-use.json'))
Assert-FmpEqual -Name '-Plan recusa fixture' -Expected 3 -Actual $r.Exit
$r = Invoke-FmpCli @('-Plan', '-Mode', 'simple', '-Language', 'en', '-OutDir', (Join-Path $scratch 'plan-en'))
Assert-FmpTrue -Name '-Plan em ingles, modo Rapido' -Condition ($r.Exit -eq 0 -and $r.Out.Contains('AUTHORIZATION REQUEST') -and $r.Out.Contains('Quick audit') -and $r.Out -notmatch '-ObserveSeconds')

# =====================================================================
Start-FmpSuite 'B2. C1: reserva exclusiva da autorizacao antes de qualquer coletor (coletores simulados)'
# Primitive, deterministic: the second reservation of the same folder loses even when the folder already exists
# (the state a concurrent run sees after passing the non-atomic existence check).
$resDir = Join-Path $scratch 'reserve-unit'
Assert-FmpTrue -Name 'C1: primeira reserva vence' -Condition (New-FmpRunReservation -Root $resDir -RunId 'unit-1')
Assert-FmpTrue -Name 'C1: segunda reserva da mesma pasta perde' -Condition (-not (New-FmpRunReservation -Root $resDir -RunId 'unit-2'))
Assert-FmpTrue -Name 'C1: a reserva vencedora nao e sobrescrita' -Condition ([System.IO.File]::ReadAllText((Join-Path $resDir 'run-reservation.json')).Contains('unit-1'))
$foreignDir = Join-Path $scratch 'reserve-foreign'
$null = [System.IO.Directory]::CreateDirectory($foreignDir)   # inherited ACL: not created privately by a run
Assert-FmpTrue -Name 'C1: pasta preexistente sem ACL privada nao e reservada' -Condition (-not (New-FmpRunReservation -Root $foreignDir -RunId 'unit-3') -and -not (Test-Path -LiteralPath (Join-Path $foreignDir 'run-reservation.json')))
Set-FmpAllowedWriteRoot $scratch

# Invalid consent never reserves: the folder is not created, so a wrong command cannot burn the approved one.
$c1Fresh = Join-Path $scratch 'c1-fresh'
$c1Tok = Get-FmpPlanToken -OutDir $c1Fresh
foreach ($bad in @(@('ausente', ''), @('malformado', 'sim'), @('expirado', (New-FmpConsentToken -Scope (Get-FmpConsentScope -Mode 'full' -Symptom 'slow' -Language 'pt-BR' -ObserveSeconds 60 -DuringProblem 'unknown' -IncludeInternal $false -OutDir $c1Fresh) -IssuedUtc ([DateTime]::UtcNow.AddMinutes(-45)))))) {
    $argsBad = Get-FmpRunArgs -OutDir $c1Fresh -Token $bad[1]
    if ($bad[1] -eq '') { $argsBad = $argsBad[0..($argsBad.Count - 3)] }
    $r = Invoke-FmpCli $argsBad
    Assert-FmpTrue -Name ('C1: consentimento ' + $bad[0] + ' -> exit 3, nenhum coletor, pasta nao criada') -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC' -and -not (Test-Path -LiteralPath $c1Fresh)) -Detail ('exit=' + $r.Exit)
}
$r = Invoke-FmpCli (Get-FmpRunArgs -OutDir (Join-Path $scratch 'c1-other-dest') -Token $c1Tok)
Assert-FmpTrue -Name 'C1: destino alterado -> exit 3 (scope_mismatch), nada criado' -Condition ($r.Exit -eq 3 -and $r.Out -match 'scope_mismatch' -and -not (Test-Path -LiteralPath (Join-Path $scratch 'c1-other-dest')))
$r = Invoke-FmpCli (@('-Mode', 'full', '-Symptom', 'slow', '-Language', 'en') + (Get-FmpRunArgs -OutDir $c1Fresh -Token $c1Tok)[6..14])
Assert-FmpTrue -Name 'C1: escopo modificado (idioma) -> exit 3, nada criado' -Condition ($r.Exit -eq 3 -and $r.Out -match 'scope_mismatch' -and -not (Test-Path -LiteralPath $c1Fresh))
$r = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1Fresh -Token $c1Tok)
Assert-FmpTrue -Name 'C1: consentimento valido depois das tentativas invalidas chega ao coletor uma vez' -Condition ($r.Exit -eq 4 -and $r.Out -match 'SYNTHETIC_COLLECTOR_REACHED')
$r = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1Fresh -Token $c1Tok)
Assert-FmpTrue -Name 'C1: segunda execucao com o mesmo token -> exit 3, nenhum coletor' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC')

# Simultaneous runs of the same approved command: at most one reaches the (simulated) collector.
$c1Par = Join-Path $scratch 'c1-parallel'
$c1ParTok = Get-FmpPlanToken -OutDir $c1Par
$handles = @(1..4 | ForEach-Object { Start-FmpCliProcess -CliArgs (Get-FmpRunArgs -OutDir $c1Par -Token $c1ParTok) })
$results = @($handles | ForEach-Object { Complete-FmpCliProcess $_ })
$reached = @($results | Where-Object { $_.Out -match 'SYNTHETIC_COLLECTOR_REACHED' }).Count
$refused = @($results | Where-Object { $_.Exit -eq 3 -and $_.Out -notmatch 'SYNTHETIC' }).Count
Assert-FmpTrue -Name 'C1: 4 execucoes simultaneas -> exatamente 1 chega ao coletor' -Condition ($reached -eq 1) -Detail ('reached=' + $reached + ' exits=' + (($results | ForEach-Object { $_.Exit }) -join ','))
Assert-FmpTrue -Name 'C1: as outras 3 terminam com exit 3 sem coletar' -Condition ($refused -eq 3) -Detail ('refused=' + $refused)

# Interruption during collection (process killed inside the collector stage): the approval stays consumed.
$c1Kill = Join-Path $scratch 'c1-kill-during'
$c1KillTok = Get-FmpPlanToken -OutDir $c1Kill -Cli $slowMockCli
$h = Start-FmpCliProcess -CliArgs (Get-FmpRunArgs -OutDir $c1Kill -Token $c1KillTok) -Cli $slowMockCli
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path -LiteralPath (Join-Path $c1Kill 'run-reservation.json')) -and $sw.ElapsedMilliseconds -lt 60000 -and -not $h.P.HasExited) { Start-Sleep -Milliseconds 100 }
Start-Sleep -Milliseconds 500
$killedInside = -not $h.P.HasExited
if ($killedInside) { $h.P.Kill() }
$null = Complete-FmpCliProcess $h
Assert-FmpTrue -Name 'C1: processo interrompido durante a etapa de coleta' -Condition ($killedInside -and (Test-Path -LiteralPath (Join-Path $c1Kill 'run-reservation.json')))
$r = Invoke-FmpCli -CliArgs (Get-FmpRunArgs -OutDir $c1Kill -Token $c1KillTok) -Cli $slowMockCli
Assert-FmpTrue -Name 'C1: reutilizar apos interrupcao durante a coleta -> exit 3, nenhum coletor' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC') -Detail ('exit=' + $r.Exit)
$leftovers = @([System.IO.Directory]::GetFiles($c1Kill) | ForEach-Object { [System.IO.Path]::GetFileName($_) })
Assert-FmpTrue -Name 'C1: interrupcao deixa somente a reserva (nenhum dado de diagnostico)' -Condition (($leftovers -join ',') -eq 'run-reservation.json') -Detail ($leftovers -join ',')

# Interruption before collection: whatever the kill timing, the approved command reaches the collector at most once.
$c1Early = Join-Path $scratch 'c1-kill-before'
$c1EarlyTok = Get-FmpPlanToken -OutDir $c1Early
$h = Start-FmpCliProcess -CliArgs (Get-FmpRunArgs -OutDir $c1Early -Token $c1EarlyTok)
Start-Sleep -Milliseconds 300
if (-not $h.P.HasExited) { $h.P.Kill() }
$first = Complete-FmpCliProcess $h
$reservedEarly = Test-Path -LiteralPath $c1Early
$second = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1Early -Token $c1EarlyTok)
$third = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1Early -Token $c1EarlyTok)
$earlyReached = @(@($first, $second, $third) | Where-Object { $_.Out -match 'SYNTHETIC_COLLECTOR_REACHED' }).Count
Assert-FmpTrue -Name ('C1: interrupcao antes da coleta (pasta criada antes do kill: ' + $reservedEarly + ') -> no maximo 1 coleta em 3 tentativas') -Condition ($earlyReached -le 1 -and $third.Exit -eq 3 -and $third.Out -notmatch 'SYNTHETIC') -Detail ('reached=' + $earlyReached)
Assert-FmpTrue -Name 'C1: se a pasta nao chegou a ser criada, a aprovacao ainda nao foi consumida (sem coleta anterior)' -Condition ($reservedEarly -or ($second.Out -match 'SYNTHETIC_COLLECTOR_REACHED'))

# Destination creation fails (a file blocks the parent): refused before any collector, nothing reserved.
$c1Block = Join-Path $scratch 'c1-blocker'
$c1BlockOut = Join-Path $c1Block 'run'
$c1BlockTok = Get-FmpPlanToken -OutDir $c1BlockOut
Write-FmpUtf8File $c1Block 'not a folder'
$r = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1BlockOut -Token $c1BlockTok)
Assert-FmpTrue -Name 'C1: falha na criacao do destino -> exit 3, nenhum coletor' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC' -and -not (Test-Path -LiteralPath $c1BlockOut)) -Detail ('exit=' + $r.Exit)

# Reuse after a completed run: the folder holds the reservation and the artifacts.
$c1Done = Join-Path $scratch 'c1-completed'
$c1DoneTok = Get-FmpPlanToken -OutDir $c1Done
$null = New-FmpRunReservation -Root $c1Done -RunId 'done'
Write-FmpUtf8File (Join-Path $c1Done 'diagnostic-sanitized.json') '{}'
Write-FmpUtf8File (Join-Path $c1Done 'report.html') '<!doctype html>'
Set-FmpAllowedWriteRoot $scratch
$r = Invoke-FmpCli (Get-FmpRunArgs -OutDir $c1Done -Token $c1DoneTok)
Assert-FmpTrue -Name 'C1: reutilizar apos execucao concluida -> exit 3, nenhum coletor, artefatos intactos' -Condition ($r.Exit -eq 3 -and $r.Out -notmatch 'SYNTHETIC' -and [System.IO.File]::ReadAllText((Join-Path $c1Done 'report.html')) -eq '<!doctype html>')

# Fixture runs keep the old contract: no reservation file, folder created at the end.
$fxOut = Join-Path $scratch 'c1-fixture'
$r = Invoke-FmpCli -CliArgs @('-Fixture', (Join-Path $root 'tests\fixtures\diag-slow-use.json'), '-Mode', 'full', '-Symptom', 'slow', '-Language', 'pt-BR', '-OutDir', $fxOut, '-Yes') -Cli (Join-Path $root 'fixmypc.ps1')
Assert-FmpTrue -Name 'C1: execucao com fixture nao cria reserva e continua funcionando' -Condition ($r.Exit -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $fxOut 'run-reservation.json')) -and (Test-Path -LiteralPath (Join-Path $fxOut 'report.html')))

# =====================================================================
Start-FmpSuite 'C. Lentidao durante o uso (fixture diag-slow-use)'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$slow = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-use.json') -Symptom 'slow' -During 'yes'
$sw.Stop(); $script:Metrics.Add('pipeline slow-use: ' + $sw.ElapsedMilliseconds + ' ms')
Assert-FmpEqual -Name 'conclusao: evidencia encontrada' -Expected 'found' -Actual $slow.Dx['conclusion']
Assert-FmpEqual -Name 'pressao de memoria: sim' -Expected 'yes' -Actual (Get-FmpQ $slow.Dx 'memory_pressure')['answer']
Assert-FmpEqual -Name 'disco ocupado: sim' -Expected 'yes' -Actual (Get-FmpQ $slow.Dx 'storage_busy')['answer']
Assert-FmpEqual -Name 'CPU: picos isolados = parcial (nao sustentada)' -Expected 'partial' -Actual (Get-FmpQ $slow.Dx 'cpu_load')['answer']
Assert-FmpEqual -Name 'no maximo 3 achados principais' -Expected 3 -Actual @($slow.Dx['keyFindings']).Count
Assert-FmpEqual -Name 'memoria vem primeiro (ordem deterministica)' -Expected 'memory_pressure' -Actual (Get-FmpKeyIds $slow.Dx)[0]
Assert-FmpTrue -Name 'correlacao na mesma janela: paginacao pode ocupar o disco' -Condition (@((Get-FmpQ $slow.Dx 'storage_busy')['alternativeKeys']) -contains 'diag.alt.paging_io')
Assert-FmpTrue -Name 'cada achado tem evidencia, porque importa, o que fazer, fonte, janela, confianca, limitacoes e alternativas' -Condition (@(@($slow.Dx['keyFindings']) | Where-Object {
    [string]::IsNullOrEmpty($_['observed']) -or [string]::IsNullOrEmpty($_['why']) -or [string]::IsNullOrEmpty($_['whatToDo']) -or [string]::IsNullOrEmpty($_['source']) -or
    [string]::IsNullOrEmpty($_['window']) -or [string]::IsNullOrEmpty($_['confidence']) -or @($_['limitations']).Count -eq 0 -or @($_['alternatives']).Count -eq 0 }).Count -eq 0)
Assert-FmpTrue -Name 'texto nao afirma vazamento nem causa' -Condition (($slow.Dx['keyFindings'] | ForEach-Object { $_['observed'] + $_['why'] }) -join ' ' -notmatch '(?i)vazamento confirmado|a causa (é|e) |defeito confirmado')
Assert-FmpTrue -Name 'a pontuacao nao muda por causa do diagnostico' -Condition ($null -eq $slow.Score['diagnosis'] -and $slow.Score['scoreAlgorithmVersion'] -eq '2.0')
$slowAgain = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-use.json') -Symptom 'slow' -During 'yes'
Assert-FmpEqual -Name 'deterministico: mesma entrada, mesmo diagnostico' -Expected (ConvertTo-FmpJsonText -Data $slow.Dx) -Actual (ConvertTo-FmpJsonText -Data $slowAgain.Dx)

# =====================================================================
Start-FmpSuite 'D. Inicializacao lenta (com e sem evidencia historica)'
$boot = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-boot.json') -Symptom 'boot'
$bq = Get-FmpQ $boot.Dx 'boot_history'
Assert-FmpEqual -Name 'historico de boot: sim' -Expected 'yes' -Actual $bq['answer']
Assert-FmpEqual -Name 'conclusao: evidencia encontrada' -Expected 'found' -Actual $boot.Dx['conclusion']
Assert-FmpEqual -Name 'mediana dos seis tempos ate a area de trabalho: 75 s' -Expected 75.0 -Actual ([double]$bq['values']['medianMainPathSec'])
Assert-FmpTrue -Name 'componente recorrente citado; componente visto 1x nao e citado' -Condition ($bq['values']['contributors'] -match 'ExampleUpdater' -and $bq['values']['contributors'] -notmatch 'examplefilter')
Assert-FmpTrue -Name 'limitacao: contagem de programas de inicializacao nao explica a demora' -Condition (@($bq['limitationKeys']) -contains 'diag.lim.startup_count_not_cause')
Assert-FmpEqual -Name 'CPU tem relevancia baixa para boot' -Expected 'low' -Actual (Get-FmpQ $boot.Dx 'cpu_load')['relevance']
$bootDenied = Get-FmpFixtureDoc 'diag-slow-boot.json'
$bootDenied['events']['bootPerformance'] = [ordered]@{ status = 'access_denied'; windowDays = 60; boots = @(); contributors = @() }
$bd = Invoke-FmpDx -Doc $bootDenied -Symptom 'boot'
Assert-FmpEqual -Name 'sem acesso ao log: resposta access_denied (nao saudavel)' -Expected 'access_denied' -Actual (Get-FmpQ $bd.Dx 'boot_history')['answer']
Assert-FmpEqual -Name 'sem evidencia relevante: conclusao insuficiente' -Expected 'insufficient' -Actual $bd.Dx['conclusion']
Assert-FmpTrue -Name 'proximo passo explica como um administrador pode consultar (somente leitura)' -Condition (@($bd.Dx['nextSteps']) -contains 'diag.next.boot_admin')
$bootFast = Get-FmpFixtureDoc 'diag-slow-boot.json'
foreach ($b in @($bootFast['events']['bootPerformance']['boots'])) { $b['mainPathMs'] = 21000; $b['bootMs'] = 30000; $b['degraded'] = $false }
$bf = Invoke-FmpDx -Doc $bootFast -Symptom 'boot'
Assert-FmpTrue -Name 'boots rapidos e sem degradacao: nao, sem achado' -Condition ((Get-FmpQ $bf.Dx 'boot_history')['answer'] -eq 'no' -and $bf.Dx['conclusion'] -eq 'none')
foreach ($b in @($bootFast['events']['bootPerformance']['boots'])) { $b['mainPathMs'] = $null; $b['bootMs'] = 100000 }
Assert-FmpEqual -Name 'boot total longo sem medicao do caminho principal: desconhecido' -Expected 'unknown' -Actual (Get-FmpDiagBootQuestion $bootFast $ruleConfig)['answer']

# =====================================================================
Start-FmpSuite 'E. Travamentos recorrentes e eventos isolados'
$cr = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-crash-recurring.json') -Symptom 'crash'
$cq = Get-FmpQ $cr.Dx 'crash_history'
Assert-FmpEqual -Name 'reinicios recorrentes: sim' -Expected 'yes' -Actual $cq['answer']
Assert-FmpTrue -Name '4 reinicios em 3 dias, 2 telas azuis, contexto de 41 lido' -Condition ($cq['values']['restarts'] -eq 4 -and $cq['values']['restartDays'] -eq 3 -and $cq['values']['bugchecks'] -eq 2 -and $cq['values']['withBugcheck'] -eq 2 -and $cq['values']['withPowerButton'] -eq 1)
Assert-FmpTrue -Name 'Kernel-Power 41 nao e tratado como defeito de fonte' -Condition (@($cq['limitationKeys']) -contains 'diag.lim.kp41_not_psu')
Assert-FmpTrue -Name 'hipoteses alternativas registradas' -Condition (@($cq['alternativeKeys']) -contains 'diag.alt.power_loss')
$iso = Get-FmpFixtureDoc 'diag-crash-recurring.json'
$iso['events']['logs']['System']['groups'] = @($iso['events']['logs']['System']['groups'][0])
$iso['events']['logs']['System']['groups'][0]['occurrences'] = @($iso['events']['logs']['System']['groups'][0]['occurrences'][0])
$iso['events']['logs']['Application']['groups'] = @()
$ci = Invoke-FmpDx -Doc $iso -Symptom 'crash'
Assert-FmpEqual -Name 'um reinicio isolado: parcial' -Expected 'partial' -Actual (Get-FmpQ $ci.Dx 'crash_history')['answer']
Assert-FmpEqual -Name 'evento isolado nao vira conclusao forte' -Expected 'weak' -Actual $ci.Dx['conclusion']
$crGeneral = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-crash-recurring.json') -Symptom 'slow'
Assert-FmpEqual -Name 'para lentidao, estabilidade tem relevancia media' -Expected 'medium' -Actual (Get-FmpQ $crGeneral.Dx 'crash_history')['relevance']

# =====================================================================
Start-FmpSuite 'F. CPU sustentada x pico, memoria pressionada x cache normal, disco ocupado x erro'
$cpuDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
$cpuDoc['observation']['cpu']['stats']['highShare'] = 0.83; $cpuDoc['observation']['cpu']['stats']['avg'] = 91.0; $cpuDoc['observation']['cpu']['stats']['max'] = 99.0
$cpuDoc['observation']['processes']['topCpu'] = @([ordered]@{ name = 'ExampleCompiler'; avgCores = 6.1; avgPctOfMachine = 76.3; maxCores = 7.8; activeShare = 0.92; intervals = 12; privateMB = 900.0; privateGrowth = 3.0 })
$cs = Invoke-FmpDx -Doc $cpuDoc -Symptom 'slow'
Assert-FmpTrue -Name 'CPU sustentada: sim, com o processo de consumo sustentado' -Condition ((Get-FmpQ $cs.Dx 'cpu_load')['answer'] -eq 'yes' -and (Get-FmpQ $cs.Dx 'cpu_load')['values']['processes'] -match 'ExampleCompiler')
Assert-FmpTrue -Name 'CPU alta traz hipoteses de carga legitima' -Condition (@((Get-FmpQ $cs.Dx 'cpu_load')['alternativeKeys']) -contains 'diag.alt.legit_load')
$spikeDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
$spikeDoc['observation']['cpu']['stats']['highShare'] = 0.08; $spikeDoc['observation']['cpu']['stats']['max'] = 97.0
Assert-FmpEqual -Name 'pico isolado de CPU: parcial' -Expected 'partial' -Actual (Get-FmpQ (Invoke-FmpDx -Doc $spikeDoc -Symptom 'slow').Dx 'cpu_load')['answer']
$cacheDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
$cacheDoc['performance']['memory']['availablePct'] = 55.0
Assert-FmpEqual -Name 'memoria com cache e disponibilidade alta: nao' -Expected 'no' -Actual (Get-FmpQ (Invoke-FmpDx -Doc $cacheDoc -Symptom 'slow').Dx 'memory_pressure')['answer']
$busyDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
$busyDoc['observation']['disks']['items'][0]['avgQueue'] = [ordered]@{ count = 12; avg = 2.4; min = 1.1; max = 5.0; p90 = 4.0 }
$bu = Invoke-FmpDx -Doc $busyDoc -Symptom 'slow'
Assert-FmpTrue -Name 'disco ocupado com resposta rapida: ocupado=sim, lento=nao, erro=nao' -Condition ((Get-FmpQ $bu.Dx 'storage_busy')['answer'] -eq 'yes' -and (Get-FmpQ $bu.Dx 'storage_slow')['answer'] -eq 'no' -and (Get-FmpQ $bu.Dx 'storage_errors')['answer'] -eq 'no')
$errDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
$errDoc['events']['logs']['System']['groups'] = @([ordered]@{ provider = 'disk'; eventId = 7; count = 2; firstSeen = '2026-11-19T08:00:00.000Z'; lastSeen = '2026-11-19T10:00:00.000Z'; maxLevel = 2
    occurrences = @([ordered]@{ at = '2026-11-19T08:00:00.000Z'; level = 2 }, [ordered]@{ at = '2026-11-19T10:00:00.000Z'; level = 2 }) })
$er = Invoke-FmpDx -Doc $errDoc -Symptom 'slow'
Assert-FmpTrue -Name 'erro historico de disco: erros=sim, ocupado=nao (sao coisas diferentes)' -Condition ((Get-FmpQ $er.Dx 'storage_errors')['answer'] -eq 'yes' -and (Get-FmpQ $er.Dx 'storage_busy')['answer'] -eq 'no')
Assert-FmpTrue -Name 'erro de disco sugere backup primeiro' -Condition (@($er.Dx['nextSteps']) -contains 'diag.next.backup')

# =====================================================================
Start-FmpSuite 'G. Sem problemas, inventario normal, dados ausentes, provedores indisponiveis, modo Rapido'
$ok = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-healthy-full.json') -Symptom 'slow' -During 'no'
Assert-FmpEqual -Name 'sem problemas: conclusao none' -Expected 'none' -Actual $ok.Dx['conclusion']
Assert-FmpEqual -Name 'sem problemas: nenhum achado principal inventado' -Expected 0 -Actual @($ok.Dx['keyFindings']).Count
Assert-FmpTrue -Name 'inventario (apps, antivirus, servicos) nao vira achado' -Condition (@(@($ok.Analysis['findings']) | Where-Object { $_['id'] -match 'third_party_av|installed|startup.high' }).Count -eq 0)
Assert-FmpTrue -Name 'medido fora do problema: sugere repetir durante a lentidao' -Condition (@($ok.Dx['nextSteps']) -contains 'diag.next.reproduce')
Assert-FmpEqual -Name 'SMART inacessivel: saude parcialmente desconhecida (nao "saudavel")' -Expected 'partial_unknown' -Actual (Get-FmpQ $ok.Dx 'storage_health')['answer']
$deniedDoc = Get-FmpFixtureDoc 'diag-healthy-full.json'
foreach ($fam in @('cpu', 'memory', 'disks', 'processes')) { $deniedDoc['observation'][$fam]['state'] = 'access_denied' }
$dn = Invoke-FmpDx -Doc $deniedDoc -Symptom 'slow'
Assert-FmpTrue -Name 'provedores negados: CPU/memoria/disco nunca viram "nao"' -Condition (@('cpu_load', 'memory_pressure', 'storage_busy', 'storage_slow' | Where-Object { (Get-FmpQ $dn.Dx $_)['answer'] -eq 'no' }).Count -eq 0)
Assert-FmpTrue -Name 'provedores negados: listados como nao verificados' -Condition (@($dn.Dx['notVerified']).Count -ge 2)
$quickDoc = Get-FmpFixtureDoc 'win11-healthy.json'
$quickDoc['run']['mode'] = 'simple'
$qk = Invoke-FmpDx -Doc $quickDoc -Symptom 'slow'
Assert-FmpTrue -Name 'Rapida: CPU vem da leitura pontual, com confianca baixa' -Condition ((Get-FmpQ $qk.Dx 'cpu_load')['window'] -eq 'snapshot' -and (Get-FmpQ $qk.Dx 'cpu_load')['confidence'] -eq 'low')
Assert-FmpEqual -Name 'Rapida: disco ao longo do tempo nao coletado' -Expected 'not_collected' -Actual (Get-FmpQ $qk.Dx 'storage_busy')['answer']
Assert-FmpTrue -Name 'Rapida com sintoma: sugere a Auditoria Completa' -Condition (@($qk.Dx['nextSteps']) -contains 'diag.next.full_audit')
Assert-FmpEqual -Name 'Rapida: observacao indisponivel no resumo' -Expected $false -Actual $qk.Dx['observation']['available']
$emptyDoc = Get-FmpFixtureDoc 'degenerate.json'
$em = Invoke-FmpDx -Doc $emptyDoc -Symptom 'general'
Assert-FmpTrue -Name 'documento degenerado: nenhuma resposta "nao" sem dados' -Condition (@(@($em.Dx['questions']) | Where-Object { $_['answer'] -eq 'no' -and $_['window'] -eq 'none' }).Count -eq 0)

$edges = Get-FmpFixtureDoc 'diag-healthy-full.json'
$disk = $edges['observation']['disks']['items'][0]
foreach ($field in @('avgQueue', 'readLatencyMs', 'writeLatencyMs', 'readBytesPerSec', 'writeBytesPerSec')) {
    $disk[$field] = [ordered]@{ count = 0; avg = $null; max = $null; p90 = $null }
}
$disk['activeIntervals'] = 0
$edges['observation']['memory']['pagesInputPerSec']['avg'] = $null
$edges['observation']['memory']['commitPct']['max'] = $null
$edges['events']['logs']['Application']['status'] = 'access_denied'
$edgeDx = (Invoke-FmpDx -Doc $edges -Symptom 'slow').Dx
foreach ($q in @('memory_pressure', 'storage_busy', 'storage_slow', 'crash_history')) {
    Assert-FmpEqual -Name ('medicao incompleta: ' + $q) -Expected 'unknown' -Actual (Get-FmpQ $edgeDx $q)['answer']
}
$disk['avgQueue'] = [ordered]@{ count = 12; avg = 2; max = 20 }
$disk['readLatencyMs'] = [ordered]@{ count = 1; avg = 80; max = 80; p90 = 80 }
$disk['activeIntervals'] = 1
$edges['observation']['memory']['availableMB']['avg'] = 350
$edges['observation']['memory']['commitPct']['max'] = 95
$edgeDx = (Invoke-FmpDx -Doc $edges -Symptom 'slow').Dx
Assert-FmpEqual -Name 'um intervalo de latencia alta e sinal parcial' -Expected 'partial' -Actual (Get-FmpQ $edgeDx 'storage_slow')['answer']
Assert-FmpTrue -Name 'commit alto sem paginacao medida nao sustenta hipotese de I/O por paginacao' -Condition ((Get-FmpQ $edgeDx 'memory_pressure')['answer'] -eq 'yes' -and (Get-FmpQ $edgeDx 'storage_busy')['alternativeKeys'] -notcontains 'diag.alt.paging_io')
$oldEvent = [ordered]@{ provider = 'Kernel-Power'; eventId = 41; count = 2; firstSeen = '2026-09-01T00:00:00Z'; lastSeen = '2026-09-02T00:00:00Z' }
$edges['events']['logs']['System']['groups'] = @($oldEvent)
$outside = Get-FmpDiagEventStats $edges 'System' 'Kernel-Power' @(41) '2026-11-21T00:00:00Z' 168
Assert-FmpEqual -Name 'grupo legado inteiramente fora da janela nao conta' -Expected 0 -Actual $outside.count
$edges['events']['logs']['Application']['status'] = 'ok'
$edges['events']['logs']['Application']['groups'] = @([ordered]@{ provider = 'Application Hang'; eventId = 1002
    occurrences = @(@{at = '2026-11-17T08:00:00Z'}, @{at = '2026-11-18T08:00:00Z'}, @{at = '2026-11-19T08:00:00Z'}) })
$edges['run']['finishedAt'] = '2026-11-21T00:00:00Z'
Assert-FmpEqual -Name 'travamentos registrados em aplicativo sao indicio parcial' -Expected 'partial' -Actual (Get-FmpDiagCrashQuestion $edges $ruleConfig)['answer']

# =====================================================================
Start-FmpSuite 'H. Localizacao PT-BR e EN (sem chaves faltando, sem placeholders)'
foreach ($lang in @('pt-BR', 'en')) {
    foreach ($case in @(@('diag-slow-use.json', 'slow'), @('diag-slow-boot.json', 'boot'), @('diag-crash-recurring.json', 'crash'), @('diag-healthy-full.json', 'general'), @('win11-healthy.json', 'slow'))) {
        Reset-FmpMissingLocaleKeys
        $res = Invoke-FmpDx -Doc (Get-FmpFixtureDoc $case[0]) -Symptom $case[1] -Lang $lang
        $null = Get-FmpRenderHtml -Sanitized $res.Sanitized -Lang $lang
        [string[]]$missing = Get-FmpMissingLocaleKeys
        Assert-FmpTrue -Name ($lang + ' ' + $case[0] + ': nenhuma chave faltando') -Condition ($missing.Count -eq 0) -Detail ((@($missing | ForEach-Object { [string]$_ })) -join ', ')
        $allText = (@($res.Dx['questions']) | ForEach-Object { $_['text'] }) + @($res.Dx['nextStepsText']) + @($res.Dx['conclusionText']) + (@($res.Dx['keyFindings']) | ForEach-Object { $_['why'] + ' ' + $_['whatToDo'] })
        Assert-FmpTrue -Name ($lang + ' ' + $case[0] + ': nenhum {placeholder} sobrando') -Condition ((($allText -join ' ') -notmatch '\{[A-Za-z0-9]+\}'))
    }
}
Assert-FmpTrue -Name 'PT e EN geram textos diferentes' -Condition ((Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-use.json') -Symptom 'slow' -Lang 'en').Dx['conclusionText'] -ne $slow.Dx['conclusionText'])
foreach ($k in @($locPt.PSObject.Properties | Where-Object { $_.Name -like 'diag.*' -or $_.Name -like 'report.diag.*' -or $_.Name -like 'report.obs.*' -or $_.Name -like 'cli.plan.*' })) {
    if ($null -eq $locEn.PSObject.Properties[$k.Name]) { Assert-FmpTrue -Name ('EN tem ' + $k.Name) -Condition $false }
}
Assert-FmpTrue -Name 'chaves 2.0 presentes nos dois idiomas' -Condition $true

# =====================================================================
Start-FmpSuite 'I. HTML em duas camadas, impressao, CSP, escaping, privacidade'
# The renderer encodes accents as numeric entities; text checks run on the decoded page.
$htmlPt = [System.Net.WebUtility]::HtmlDecode((Get-FmpRenderHtml -Sanitized $slow.Sanitized -Lang 'pt-BR'))
$htmlEn = [System.Net.WebUtility]::HtmlDecode((Get-FmpRenderHtml -Sanitized (Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-use.json') -Symptom 'slow' -Lang 'en').Sanitized -Lang 'en'))
Assert-FmpTrue -Name 'camada 1 (resultado) vem antes da pontuacao' -Condition ($htmlPt.IndexOf('id="diagnosis"') -gt 0 -and $htmlPt.IndexOf('id="diagnosis"') -lt $htmlPt.IndexOf('id="summary"'))
Assert-FmpTrue -Name 'separador de detalhes tecnicos antes dos achados das regras' -Condition ($htmlPt.IndexOf('class="layer-sep"') -gt $htmlPt.IndexOf('id="summary"') -and $htmlPt.IndexOf('class="layer-sep"') -lt $htmlPt.IndexOf('id="findings"'))
Assert-FmpTrue -Name 'camada 2 com medicoes e historico' -Condition ($htmlPt.Contains('id="observation"') -and $htmlPt.Contains('Medições e histórico'))
Assert-FmpTrue -Name 'cada achado mostra O que observamos / Por que importa / O que voce pode fazer' -Condition ($htmlPt.Contains('Por que isso importa') -and $htmlPt.Contains('O que você pode fazer') -and $htmlEn.Contains('Why it matters') -and $htmlEn.Contains('What you can do'))
$dxSection = $htmlPt.Substring($htmlPt.IndexOf('id="diagnosis"'), $htmlPt.IndexOf('id="summary"') - $htmlPt.IndexOf('id="diagnosis"'))
Assert-FmpTrue -Name 'nenhum campo do resumo foi apagado pela sanitizacao' -Condition ($dxSection -notmatch '<Redacted>')
Assert-FmpTrue -Name 'botao Imprimir / Salvar em PDF preservado' -Condition ($htmlPt -match 'id="fmp-print"' -and @([regex]::Matches($htmlPt, '<script')).Count -eq 1)
Assert-FmpTrue -Name 'CSP restritiva preservada' -Condition ($htmlPt -match "default-src 'none'; script-src 'sha256-[A-Za-z0-9+/=]+'; style-src 'unsafe-inline';")
Assert-FmpTrue -Name 'sem recursos externos' -Condition ($htmlPt -notmatch '(?i)(src|href)="https?:')
Assert-FmpTrue -Name 'aviso de pontuacao secundaria' -Condition ($htmlPt.Contains('A pontuação a seguir é secundária'))
$evilDoc = Get-FmpFixtureDoc 'diag-slow-use.json'
$evilDoc['observation']['processes']['topCpu'][0]['name'] = '<img src=x onerror=alert(1)>'
$evilDoc['observation']['processes']['topCpu'][0]['activeShare'] = 0.9
$evil = Get-FmpRenderHtml -Sanitized (Invoke-FmpDx -Doc $evilDoc -Symptom 'slow').Sanitized
Assert-FmpTrue -Name 'nome de processo hostil e escapado' -Condition ($evil -notmatch '<img src=x' -and $evil -match '&lt;img src=x')
$legacy = Get-FmpFixtureDoc 'win11-healthy.json'
$legAnalysis = Invoke-FmpRules -Diagnostic $legacy -RuleConfig $ruleConfig -Mode 'full'
$legacy['analysis'] = $legAnalysis
$legacy['healthScore'] = Get-FmpHealthScore -Analysis $legAnalysis -RuleConfig $ruleConfig -Modules (Get-FmpValue $legacy 'modules')
$legHtml = Get-FmpRenderHtml -Sanitized (ConvertTo-FmpSanitizedDiagnostic -Diagnostic $legacy)
Assert-FmpTrue -Name 'documento 1.0 sem diagnostico ainda renderiza (sem painel novo)' -Condition ($legHtml -notmatch 'id="diagnosis"' -and $legHtml -match 'id="summary"')
$sizePt = [System.Text.UTF8Encoding]::new($false).GetBytes($htmlPt).Length
$script:Metrics.Add('report.html slow-use: ' + $sizePt + ' bytes')
Assert-FmpTrue -Name ('tamanho do relatorio dentro do limite (' + $sizePt + ' bytes < 8 MiB)') -Condition ($sizePt -lt 8MB)
Write-FmpUtf8File -Path (Join-Path $scratch 'slow-use.pt-BR.html') -Text $htmlPt
Write-FmpUtf8File -Path (Join-Path $scratch 'slow-use.en.html') -Text $htmlEn

# =====================================================================
Start-FmpSuite 'J. Compatibilidade do contrato JSON e adaptadores'
foreach ($r in @($slow, $boot, $cr, $ok, $qk)) {
    Assert-FmpTrue -Name ('documento sanitizado valido: ' + $r.Doc['run']['id']) -Condition (Test-FmpDiagnosticDocument $r.Sanitized)
}
Assert-FmpEqual -Name 'schemaVersion inalterado (mudanca aditiva)' -Expected '1.0.0' -Actual $slow.Sanitized['schemaVersion']
Assert-FmpEqual -Name 'diagnosis.version presente' -Expected '1' -Actual $slow.Sanitized['diagnosis']['version']
Assert-FmpTrue -Name 'healthScore mantem o algoritmo 2.0 e seus campos' -Condition ($slow.Sanitized['healthScore']['scoreAlgorithmVersion'] -eq '2.0' -and $slow.Sanitized['healthScore'].Contains('coveragePct') -and $slow.Sanitized['healthScore'].Contains('riskLevel'))
$schema = [System.IO.File]::ReadAllText((Join-Path $root 'schemas\diagnostic.schema.json'))
Assert-FmpTrue -Name 'schema documenta observation e diagnosis' -Condition ($schema.Contains('"observation"') -and $schema.Contains('"diagnosis"'))
foreach ($fx in @('win11-healthy.json', 'events-mixed.json', 'demo-synthetic.json', 'critical-disk.json', 'limited-access.json')) {
    $legacyRes = Invoke-FmpDx -Doc (Get-FmpFixtureDoc $fx) -Symptom 'general'
    Assert-FmpTrue -Name ('fixture 1.0 continua valida com o diagnostico: ' + $fx) -Condition (Test-FmpDiagnosticDocument $legacyRes.Sanitized)
}
$crit = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'critical-disk.json') -Symptom 'slow'
Assert-FmpTrue -Name 'falha comprovada de disco nunca fica escondida (achado principal mesmo fora do sintoma)' -Condition (@(@($crit.Dx['keyFindings']) | Where-Object { $_['kind'] -eq 'rule' }).Count -ge 1)
$skill = [System.IO.File]::ReadAllText((Join-Path $root 'SKILL.md'))
foreach ($needle in @('-Plan', '-ConsentToken', 'audit', 'Auditoria Rápida', 'Auditoria Completa', 'does not prove that a human', 'every real run')) {
    Assert-FmpTrue -Name ('SKILL.md descreve: ' + $needle) -Condition ($skill.Contains($needle))
}
$codex = [System.IO.File]::ReadAllText((Join-Path $root 'adapters\codex\AGENTS.md'))
Assert-FmpTrue -Name 'Codex: $fixmypc nativo, sem anunciar /fixmypc audit como comando do Codex' -Condition ($codex.Contains('$fixmypc') -and $codex.Contains('-Plan') -and $codex -notmatch 'In Codex,? (type|run|use) /fixmypc')
$claude = [System.IO.File]::ReadAllText((Join-Path $root 'adapters\claude\README.md'))
Assert-FmpTrue -Name 'Claude Code: /fixmypc audit e -Plan documentados' -Condition ($claude.Contains('/fixmypc audit') -and $claude.Contains('-Plan'))

# =====================================================================
Start-FmpSuite 'K. Custo (medido com fixtures)'
$swAll = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($i in 1..5) { $null = Invoke-FmpDx -Doc (Get-FmpFixtureDoc 'diag-slow-use.json') -Symptom 'slow' }
$swAll.Stop()
$avgMs = [Math]::Round($swAll.ElapsedMilliseconds / 5, 0)
$script:Metrics.Add('analise+diagnostico+sanitizacao por execucao: ' + $avgMs + ' ms (media de 5)')
$jsonBytes = [System.Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-FmpJsonText -Data $slow.Sanitized)).Length
$script:Metrics.Add('diagnostic-sanitized.json slow-use: ' + $jsonBytes + ' bytes')
Assert-FmpTrue -Name ('analise do diagnostico e leve (' + $avgMs + ' ms)') -Condition ($avgMs -lt 5000)
Assert-FmpTrue -Name ('JSON sanitizado pequeno (' + $jsonBytes + ' bytes)') -Condition ($jsonBytes -lt 1MB)

# =====================================================================
Write-Host ''
Write-Host '-- Metricas --'
foreach ($m in $script:Metrics) { Write-Host ('  ' + $m) }
Write-Host ('==== DIAGNOSIS RESUMO: ' + $script:PassCount + ' passaram, ' + $script:FailCount + ' falharam ====')
try { Remove-Item -LiteralPath $mockRoot -Recurse -Force -ErrorAction Stop } catch { }
if ($script:FailCount -gt 0) {
    foreach ($f in $script:Failures) { Write-Host ('  FAIL: ' + $f) -ForegroundColor Red }
    exit 1
}
exit 0
