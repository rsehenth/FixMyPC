# =====================================================================
# FIX MY PC - Run.Tests.ps1
# Offline test suite. Uses ONLY synthetic fixtures - never touches the
# real system (no CIM, no event log, no registry). Run:
#   powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\Run.Tests.ps1
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
    if ($Condition) {
        $script:PassCount++
        Write-Host ('  [PASS] ' + $Name)
    }
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
    $ok = ($Expected -eq $Actual)
    if ($Expected -is [double] -and $Actual -is [double]) { $ok = ([Math]::Abs($Expected - $Actual) -lt 0.01) }
    Assert-FmpTrue -Name $Name -Condition $ok -Detail ('expected=' + $Expected + ' actual=' + $Actual)
}

function Start-FmpSuite {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentSuite = $Name
    Write-Host ('== ' + $Name + ' ==')
}

# ---- Scratch output dir ----
$scratch = Join-Path $root ('out\fmp-tests-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $scratch
Set-FmpAllowedWriteRoot -Root $scratch

$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data
$ruleConfig = Get-FmpRuleConfig -Root $root

function Invoke-FmpFixture {
    param([Parameter(Mandatory)][string]$Fixture, [string]$Mode = 'simple')
    $fx = Read-FmpJsonFile -Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') $Fixture)
    if (-not $fx.Ok) { throw ('fixture load failed: ' + $Fixture + ' :: ' + $fx.Error) }
    $diag = ConvertTo-FmpSerializable -Value $fx.Data
    $analysis = Invoke-FmpRules -Diagnostic $diag -RuleConfig $ruleConfig -Mode $Mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue -Data $diag -Path 'modules')
    $diag['analysis'] = $analysis
    $diag['healthScore'] = $score
    # Production renders from the SANITIZED document; tests do the same.
    $sanitized = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diag
    return @{ Diag = $diag; Sanitized = $sanitized; Analysis = $analysis; Score = $score }
}

function Get-FmpFinding {
    param([object]$Result, [string]$RuleId)
    foreach ($f in $Result.Analysis.findings) {
        if (([string](Get-FmpValue -Data $f -Path 'id')) -eq $RuleId) { return $f }
    }
    return $null
}

function Get-FmpCheck {
    param([object]$Result, [string]$RuleId)
    foreach ($c in $Result.Analysis.checks) {
        if (([string](Get-FmpValue -Data $c -Path 'id')) -eq $RuleId) { return $c }
    }
    return $null
}

# =====================================================================
Start-FmpSuite 'A. Politica somente leitura (codigo-fonte do projeto)'
$comp = Test-FmpReadOnlyCompliance -Root $root -IncludeTests
Assert-FmpTrue -Name 'projeto inteiro passa na verificacao AST' -Condition ([bool]$comp.Ok) -Detail ('violations=' + $comp.ViolationCount)
if (-not $comp.Ok) {
    foreach ($f in $comp.Results) {
        foreach ($v in $f.Violations) {
            Write-Host ('    ' + $f.Path + ' [' + $v.type + '] line ' + $v.line + ': ' + $v.detail) -ForegroundColor Yellow
        }
    }
}

$badFile = Join-Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'bad-scripts') 'forbidden-commands.ps1.txt'
$raw = [System.IO.File]::ReadAllText($badFile)
$snippets = @(
    @($raw -split '# --- snippet ---') |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' } |
        Where-Object { @($_ -split "`n" | Where-Object { $_.TrimStart() -ne '' -and -not $_.TrimStart().StartsWith('#') }).Count -gt 0 }
)
Assert-FmpEqual -Name 'snippets proibidos carregados' -Expected 13 -Actual $snippets.Count
$expectedTypes = @(
    'hard_banned_command',      # 1 Set-ItemProperty
    'hard_banned_command',      # 2 Stop/Start-Service
    'hard_banned_command',      # 3 Invoke-Expression / Invoke-RestMethod
    'text_win32_product',       # 4 Win32_Product
    'text_native_write_cmd',    # 5 reg add / net stop
    'hard_banned_command',      # 6 Start-Process
    'hard_banned_command',      # 7 Set-ExecutionPolicy
    'text_registry_dotnet',     # 8 Registry.CreateSubKey
    'banned_method',            # 9 .Kill()
    'dynamic_invocation',       # 10 & $var
    'hard_banned_command',      # 11 Remove-Computer
    'text_native_write_cmd',    # 12 powercfg /energy
    'text_network_api'          # 13 WebClient
)
$i = 0
foreach ($snip in $snippets) {
    $i++
    $tmp = Join-Path $scratch ('bad-' + $i + '.ps1')
    Write-FmpUtf8File $tmp $snip
    $r = Test-FmpScriptCompliance -Path $tmp -Role 'collector'
    Assert-FmpTrue -Name ('snippet ' + $i + ' detectado como violacao (' + $expectedTypes[$i - 1] + ')') -Condition (-not $r.Ok)
}
$dynSnippet = $null
foreach ($snip in $snippets) { if ($snip -match '&\s*\$unknownCommand') { $dynSnippet = $snip } }
$tmpDynamic = Join-Path $scratch 'bad-dynamic.ps1'
Write-FmpUtf8File $tmpDynamic $dynSnippet
$r = Test-FmpScriptCompliance -Path $tmpDynamic -Role 'collector'
$hasDynamic = $false
foreach ($v in $r.Violations) { if ($v.type -eq 'dynamic_invocation') { $hasDynamic = $true } }
Assert-FmpTrue -Name 'invocacao dinamica (& $var) rejeitada' -Condition $hasDynamic

Start-FmpSuite 'B. Utilitarios comuns'
$v = Get-FmpValue -Data @{ a = @{ b = @(10, 20, 30) } } -Path 'a.b[1]' -Default 'x'
Assert-FmpEqual -Name 'Get-FmpValue array index' -Expected 20 -Actual $v
$v = Get-FmpValue -Data @{ a = 1 } -Path 'a.b.c' -Default 'fallback'
Assert-FmpEqual -Name 'Get-FmpValue default em caminho ausente' -Expected 'fallback' -Actual $v
$obj = ConvertFrom-Json -InputObject '{"x":{"y":"z"}}'
$v = Get-FmpValue -Data $obj -Path 'x.y'
Assert-FmpEqual -Name 'Get-FmpValue PSCustomObject' -Expected 'z' -Actual $v
Assert-FmpEqual -Name 'escape HTML de script tag' -Expected '&lt;script&gt;' -Actual (ConvertTo-FmpHtmlText -Value '<script>')
Assert-FmpEqual -Name 'Format-FmpBytes GB' -Expected '10 GB' -Actual (Format-FmpBytes -Bytes 10737418240 -Language 'en')
Assert-FmpEqual -Name 'Format-FmpNumber pt-BR virgula' -Expected '12,5' -Actual (Format-FmpNumber -Value 12.5 -Decimals 1 -Language 'pt-BR')
Assert-FmpEqual -Name 'Format-FmpTemplate' -Expected 'Ola Joao, 3 itens' -Actual (Format-FmpTemplate -Template 'Ola {0}, {1} itens' -Values @('Joao', 3))
$bad = Read-FmpJsonFile -Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'malformed.json')
Assert-FmpTrue -Name 'JSON malformado retorna Ok=false sem lancar' -Condition (-not $bad.Ok)
$good = Read-FmpJsonFile -Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'malformed.json')
Assert-FmpTrue -Name 'erro do JSON malformado registrado' -Condition ($null -ne $good.Error)

Start-FmpSuite 'C. Privacidade e sanitizacao'
Assert-FmpEqual -Name 'perfil de usuario e subpastas redigidos' -Expected '<Path>' -Actual (Hide-FmpSensitiveValue -Value 'C:\Users\Joao da Silva\AppData\prog.exe')
Assert-FmpEqual -Name 'identificador sintetico redigido sem diferenciar caixa' -Expected '<Identifier> login' -Actual (Hide-FmpSensitiveValue 'TestUser login' -PrivateIdentifiers 'testuser')
Assert-FmpEqual -Name 'IP redigido' -Expected 'conectado a <IP> ok' -Actual (Hide-FmpSensitiveValue -Value 'conectado a 192.168.0.14 ok')
Assert-FmpEqual -Name 'e-mail redigido' -Expected 'contato <Email>' -Actual (Hide-FmpSensitiveValue -Value 'contato maria@empresa.com.br')
Assert-FmpEqual -Name 'GUID redigido' -Expected 'id <Guid> fim' -Actual (Hide-FmpSensitiveValue -Value 'id 0f8fad5b-d9cb-469f-a165-70867728950e fim')
Assert-FmpEqual -Name 'credencial redigida' -Expected 'password=<Redacted> restante' -Actual (Hide-FmpSensitiveValue -Value 'password=Secret#1 restante')
Assert-FmpEqual -Name 'campo account substituido' -Expected '<Account>' -Actual (Hide-FmpSensitiveValue -Value 'DESKTOP-X\maria' -FieldName 'account')
Assert-FmpEqual -Name 'LocalSystem preservado' -Expected 'LocalSystem' -Actual (Hide-FmpSensitiveValue -Value 'LocalSystem' -FieldName 'account')
Assert-FmpEqual -Name 'deviceId substituido' -Expected '<DeviceId>' -Actual (Hide-FmpSensitiveValue -Value 'PCI\VEN_8086&DEV_1234&SUBSYS_0' -FieldName 'deviceId')

$mini = [ordered]@{
    startup = [ordered]@{ items = @([ordered]@{ name = 'T'; command = 'C:\Users\Segredo\User\tool.exe --token=xyz'; origin = 'registry' }) }
    advanced = [ordered]@{ problemDevices = [ordered]@{ items = @([ordered]@{ name = 'Dev'; deviceId = 'PCI\VEN_1' }) } }
}
$miniCopy = ConvertTo-FmpSerializable -Value $mini
$san = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $miniCopy
$sanCmd = Get-FmpValue -Data $san -Path 'startup.items[0].command'
Assert-FmpTrue -Name 'caminho de usuario redigido no sanitizado' -Condition ($sanCmd -notlike '*\Segredo\*')
Assert-FmpTrue -Name 'token redigido no sanitizado' -Condition ($sanCmd -notlike '*xyz*')
Assert-FmpEqual -Name 'deviceId no sanitizado' -Expected '<DeviceId>' -Actual (Get-FmpValue -Data $san -Path 'advanced.problemDevices.items[0].deviceId')
$origCmd = Get-FmpValue -Data $miniCopy -Path 'startup.items[0].command'
Assert-FmpTrue -Name 'documento interno NAO e alterado pela sanitizacao' -Condition ($origCmd -like '*Segredo*')

# =====================================================================
Start-FmpSuite 'D. Analise e pontuacao - fixtures'

$healthy = Invoke-FmpFixture -Fixture 'win11-healthy.json' -Mode 'full'
Assert-FmpEqual -Name 'win11 saudavel: pontuacao 100' -Expected 100 -Actual $healthy.Score.score
Assert-FmpEqual -Name 'win11 saudavel: status ok' -Expected 'ok' -Actual $healthy.Score.status
Assert-FmpEqual -Name 'win11 saudavel: confianca alta' -Expected 'high' -Actual $healthy.Score.confidence
Assert-FmpEqual -Name 'win11 saudavel: zero achados' -Expected 0 -Actual @($healthy.Analysis.findings).Count
Assert-FmpEqual -Name 'win11 saudavel: cobertura 100' -Expected 100 -Actual $healthy.Score.coveragePct

$w10 = Invoke-FmpFixture -Fixture 'win10-outdated.json' -Mode 'simple'
$eolF = Get-FmpFinding -Result $w10 -RuleId 'os.w10_eol'
Assert-FmpTrue -Name 'win10: achado de fim de suporte presente' -Condition ($null -ne $eolF)
Assert-FmpEqual -Name 'win10: penalidade 6' -Expected 6 -Actual $w10.Score.totalDeduction
# FMP-01: events have no evidence -> excluded; eligible 30+20+10 = 60; round(100*(60-6)/60) = 90.
Assert-FmpEqual -Name 'win10: pontuacao 90 (eventos sem evidencia fora da nota)' -Expected 90 -Actual $w10.Score.score
Assert-FmpEqual -Name 'win10: peso elegivel 60' -Expected 60 -Actual $w10.Score.eligibleWeight
Assert-FmpEqual -Name 'win10: status provisorio (eventos ausentes)' -Expected 'provisional' -Actual $w10.Score.status
$evCheck = Get-FmpCheck -Result $w10 -RuleId 'events.critical_recurring'
Assert-FmpEqual -Name 'win10: eventos ausentes -> state unknown' -Expected 'unknown' -Actual $evCheck.state

$low = Invoke-FmpFixture -Fixture 'low-disk.json' -Mode 'simple'
$catStorage = $null
foreach ($c in $low.Score.categories) { if ($c.category -eq 'storage') { $catStorage = $c } }
Assert-FmpEqual -Name 'low-disk: dedupe de storage aplicado (max por grupo)' -Expected 18 -Actual $catStorage.deduction
# Storage deducts 18. Level 2 disk errors are not recurring critical events.
# FMP-01: SMART PredictFailure is a proven critical failure: round(100*(85-18)/85) = 79, capped at 49.
Assert-FmpEqual -Name 'low-disk: nota sem limite 79' -Expected 79 -Actual $low.Score.uncappedScore
Assert-FmpEqual -Name 'low-disk: nota limitada a 49 (SMART prevendo falha)' -Expected 49 -Actual $low.Score.score
Assert-FmpEqual -Name 'low-disk: risco critico' -Expected 'critical' -Actual $low.Score.riskLevel
$lowCritical = Get-FmpFinding -Result $low -RuleId 'storage.disk_space_critical'
Assert-FmpTrue -Name 'low-disk: achado critico presente' -Condition ($null -ne $lowCritical)
# FMP-05: <5% livre passa de attention para review_recommended (a condicao mais grave nao pode ficar abaixo de <10% livre).
Assert-FmpEqual -Name 'low-disk: severidade review_recommended (FMP-05)' -Expected 'review_recommended' -Actual $lowCritical.severity
Assert-FmpTrue -Name 'low-disk: SMART prevendo falha' -Condition ($null -ne (Get-FmpFinding -Result $low -RuleId 'storage.smart_predict_failure'))
Assert-FmpTrue -Name 'low-disk: erros de disco recentes' -Condition ($null -ne (Get-FmpFinding -Result $low -RuleId 'storage.disk_event_errors'))

$spike = Invoke-FmpFixture -Fixture 'cpu-ram-spike.json' -Mode 'simple'
$catPerf = $null
foreach ($c in $spike.Score.categories) { if ($c.category -eq 'performance') { $catPerf = $c } }
# FMP-07: CPU de ~4 s e observacao informativa (0); so a pressao de commit penaliza (4).
Assert-FmpEqual -Name 'spike: deducao de desempenho = 4 (cpu 0 + commit 4)' -Expected 4 -Actual $catPerf.deduction
# FMP-01: round(100*(85-8)/85) = round(90.59) = 91.
Assert-FmpEqual -Name 'spike: pontuacao 95 = round(100*(85-4)/85)' -Expected 95 -Actual $spike.Score.score
Assert-FmpEqual -Name 'spike: risco elevado (achados com penalidade)' -Expected 'elevated' -Actual $spike.Score.riskLevel
$ramF = Get-FmpFinding -Result $spike -RuleId 'perf.ram_pressure'
Assert-FmpTrue -Name 'spike: achado de RAM presente' -Condition ($null -ne $ramF)
Assert-FmpEqual -Name 'spike: RAM e informativo (penalidade 0)' -Expected 'info' -Actual $ramF.severity
Assert-FmpTrue -Name 'spike: limitacao de leitura pontual registrada' -Condition (@($ramF.limitations).Count -gt 0)
Assert-FmpTrue -Name 'spike: sem linguagem de problema cronico no titulo RAM' -Condition ((Get-FmpLocaleString -Locales @($locPt) -Key 'rules.perf.ram_pressure.title') -notmatch 'cronico')

$evm = Invoke-FmpFixture -Fixture 'events-mixed.json' -Mode 'simple'
$catEvents = $null
foreach ($c in $evm.Score.categories) { if ($c.category -eq 'events') { $catEvents = $c } }
Assert-FmpEqual -Name 'events-mixed: deducao de 16 com dedupe de estabilidade' -Expected 16 -Actual $catEvents.deduction
# FMP-01: round(100*(85-16)/85) = round(81.18) = 81.
Assert-FmpEqual -Name 'events-mixed: pontuacao 81' -Expected 81 -Actual $evm.Score.score
$shutF = Get-FmpFinding -Result $evm -RuleId 'events.unexpected_shutdown'
Assert-FmpEqual -Name 'events-mixed: 3 desligamentos -> attention' -Expected 'attention' -Actual $shutF.severity
Assert-FmpTrue -Name 'events-mixed: BSOD achado' -Condition ($null -ne (Get-FmpFinding -Result $evm -RuleId 'events.bsod'))
Assert-FmpTrue -Name 'events-mixed: WHEA achado' -Condition ($null -ne (Get-FmpFinding -Result $evm -RuleId 'events.whea_hardware'))
Assert-FmpTrue -Name 'events-mixed: erro de nivel 2 nao e critico recorrente' -Condition ($null -eq (Get-FmpFinding -Result $evm -RuleId 'events.critical_recurring'))

$lim = Invoke-FmpFixture -Fixture 'limited-access.json' -Mode 'full'
Assert-FmpEqual -Name 'limited: nenhuma penalidade por acesso negado' -Expected 100 -Actual $lim.Score.score
Assert-FmpEqual -Name 'limited: status PROVISORIO (dados insuficientes nao tranquilizam)' -Expected 'provisional' -Actual $lim.Score.status
Assert-FmpEqual -Name 'limited: confianca media' -Expected 'medium' -Actual $lim.Score.confidence
Assert-FmpEqual -Name 'limited: zero itens de penalidade' -Expected 0 -Actual @($lim.Score.penaltyItems).Count
$smartCheck = Get-FmpCheck -Result $lim -RuleId 'storage.smart_predict_failure'
Assert-FmpEqual -Name 'limited: SMART -> access_denied' -Expected 'access_denied' -Actual $smartCheck.state
Assert-FmpTrue -Name 'limited: cobertura menor que 100' -Condition ($lim.Score.coveragePct -lt 100)

$stf = Invoke-FmpFixture -Fixture 'startup-full.json' -Mode 'full'
$unsignedF = Get-FmpFinding -Result $stf -RuleId 'startup.unsigned_autostart'
Assert-FmpTrue -Name 'startup: sem assinatura presente' -Condition ($null -ne $unsignedF)
Assert-FmpEqual -Name 'startup: sem assinatura e informativo' -Expected 'info' -Actual $unsignedF.severity
Assert-FmpEqual -Name 'startup: pontuacao 100 (volume nao penaliza)' -Expected 100 -Actual $stf.Score.score
Assert-FmpTrue -Name 'startup: humanCheck nega prova de malware' -Condition ((Get-FmpLocaleString -Locales @($locPt) -Key 'rules.startup.unsigned_autostart.humanCheck') -match 'N[AÃOO]{2}O?|not')

# high_count via dados sinteticos gerados em memoria (35 itens).
$manyItems = @(0..34 | ForEach-Object {
    [ordered]@{ kind = 'run'; name = ('App' + $_); command = ('C:\Program Files\App\App' + $_ + '.exe'); source = 'HKLM'; view = '64'; origin = 'registry' }
})
$manyDiag = ConvertTo-FmpSerializable -Value ([ordered]@{
    run = [ordered]@{ id = 'x'; finishedAt = '2026-11-19T12:00:00.000Z' }
    startup = [ordered]@{ items = $manyItems; logonTasks = @(); autoServices = @() }
})
$manyAnalysis = Invoke-FmpRules -Diagnostic $manyDiag -RuleConfig $ruleConfig -Mode 'full'
$manyF = $null
foreach ($f in $manyAnalysis.findings) { if ($f.id -eq 'startup.high_count') { $manyF = $f } }
Assert-FmpTrue -Name 'startup: contagem alta presente (35 itens)' -Condition ($null -ne $manyF)
if ($null -ne $manyF) {
    Assert-FmpEqual -Name 'startup: contagem alta e informativa' -Expected 'info' -Actual $manyF.severity
    Assert-FmpEqual -Name 'startup: contagem alta penalidade 0' -Expected 0 -Actual $manyF.penalty
}

$adv = Invoke-FmpFixture -Fixture 'advanced-mixed.json' -Mode 'full'
Assert-FmpEqual -Name 'advanced: pontuacao 100 (regras full nao penalizam)' -Expected 100 -Actual $adv.Score.score
$expectedAdvanced = @('devices.problem_codes', 'security.defender_disabled', 'os.pending_reboot', 'os.outdated_patch', 'startup.unsigned_autostart')
foreach ($rid in $expectedAdvanced) {
    $f = Get-FmpFinding -Result $adv -RuleId $rid
    Assert-FmpTrue -Name ('advanced: achado ' + $rid + ' presente') -Condition ($null -ne $f)
    if ($null -ne $f) { Assert-FmpTrue -Name ('advanced: ' + $rid + ' analysisOnly') -Condition ([bool]$f.analysisOnly) }
}

$deg = Invoke-FmpFixture -Fixture 'degenerate.json' -Mode 'simple'
Assert-FmpTrue -Name 'degenerate: pipeline sobrevive' -Condition ($null -ne $deg.Score)
Assert-FmpEqual -Name 'degenerate: status indisponivel (cobertura 0)' -Expected 'unavailable' -Actual $deg.Score.status

$demo = Invoke-FmpFixture -Fixture 'demo-synthetic.json' -Mode 'full'
# FMP-01: round(100*(85-18)/85) = round(78.82) = 79.
Assert-FmpEqual -Name 'demo: pontuacao 79' -Expected 79 -Actual $demo.Score.score
Assert-FmpEqual -Name 'demo: status ok' -Expected 'ok' -Actual $demo.Score.status
Assert-FmpTrue -Name 'demo: achado EOL presente' -Condition ($null -ne (Get-FmpFinding -Result $demo -RuleId 'os.w10_eol'))
Assert-FmpTrue -Name 'demo: achado de espaco presente' -Condition ($null -ne (Get-FmpFinding -Result $demo -RuleId 'storage.low_free_space'))
Assert-FmpTrue -Name 'demo: recorrencia historica nao demonstra evento critico recente' -Condition ($null -eq (Get-FmpFinding -Result $demo -RuleId 'events.critical_recurring'))

# Score floor: everything redlines at once -> positive, bounded score.
$worst = [ordered]@{
    run = [ordered]@{ id = 'x'; finishedAt = '2026-11-19T12:00:00.000Z' }
    system = [ordered]@{ os = [ordered]@{ caption = 'Windows 10 Pro'; displayVersion = '22H2'; uptimeHours = 100 } }
    events = [ordered]@{ windowDays = 7; logs = [ordered]@{ System = [ordered]@{ status = 'ok'; totalEvents = 100; groups = @(
        [ordered]@{ provider = 'WHEA-Logger'; eventId = 18; count = 4; firstSeen = '2026-11-18T00:00:00.000Z'; lastSeen = '2026-11-19T00:00:00.000Z' },
        [ordered]@{ provider = 'Microsoft-Windows-Kernel-Power'; eventId = 41; count = 10; firstSeen = '2026-11-18T00:00:00.000Z'; lastSeen = '2026-11-19T00:00:00.000Z' },
        [ordered]@{ provider = 'Microsoft-Windows-WER-SystemErrorReporting'; eventId = 1001; count = 3; firstSeen = '2026-11-18T00:00:00.000Z'; lastSeen = '2026-11-19T00:00:00.000Z' },
        [ordered]@{ provider = 'Noisy'; eventId = 7031; count = 60; firstSeen = '2026-11-18T00:00:00.000Z'; lastSeen = '2026-11-19T00:00:00.000Z' }
    ) } } }
    performance = [ordered]@{ memory = [ordered]@{ totalBytes = 8GB; freeBytes = 100MB; availablePct = 1.2; commitPct = 99.0 }; cpu = [ordered]@{ sampleCount = 3; avgPercent = 99.0; maxPercent = 100.0; minPercent = 98.0 } }
    storage = [ordered]@{
        volumes = @([ordered]@{ driveLetter = 'C:'; freePct = 1.0; isSystem = $true })
        physicalDisks = @([ordered]@{ friendlyName = 'Disk0'; healthStatus = 'Unhealthy' })
        smart = [ordered]@{ status = 'ok'; checked = 1; items = @([ordered]@{ predictFailure = $true; reason = 5 }) }
    }
}
$worstDiag = ConvertTo-FmpSerializable -Value $worst
$worstAnalysis = Invoke-FmpRules -Diagnostic $worstDiag -RuleConfig $ruleConfig -Mode 'simple'
$worstScore = Get-FmpHealthScore -Analysis $worstAnalysis -RuleConfig $ruleConfig
Assert-FmpTrue -Name 'tudo errado: pontuacao entre 0 e 100' -Condition ($worstScore.score -ge 0 -and $worstScore.score -le 100)
Assert-FmpTrue -Name 'tudo errado: pontuacao bem abaixo de 100' -Condition ($worstScore.score -lt 60) -Detail ('score=' + $worstScore.score)
Assert-FmpTrue -Name 'tudo errado: deducoes por categoria limitadas aos pesos' -Condition ($worstScore.totalDeduction -le 100)

# =====================================================================
Start-FmpSuite 'E. Relatorio HTML (escapamento e autonomia)'

function Invoke-FmpRenderToScratch {
    param([object]$FixtureResult, [string]$Lang, [string]$Name)
    Reset-FmpMissingLocaleKeys
    $primary = $locPt; $fallback = $locEn
    if ($Lang -eq 'en') { $primary = $locEn; $fallback = $locPt }
    Set-FmpRenderLocale -Primary $primary -Fallback $fallback -Language $Lang
    $out = Join-Path $scratch $Name
    Write-FmpHtmlReport -Diagnostic $FixtureResult.Sanitized -OutPath $out -Synthetic:$true -RedactionCount 3
    return (Get-FmpMissingLocaleKeys)
}

$missingPt = Invoke-FmpRenderToScratch -FixtureResult $demo -Lang 'pt-BR' -Name 'demo-pt.html'
Assert-FmpEqual -Name 'demo pt-BR: nenhuma chave de idioma faltando' -Expected 0 -Actual @($missingPt).Count
$demoHtml = [System.IO.File]::ReadAllText((Join-Path $scratch 'demo-pt.html'))
Assert-FmpTrue -Name 'demo HTML: doctype presente' -Condition ($demoHtml -match '^<!DOCTYPE html>')
Assert-FmpTrue -Name 'demo HTML: charset utf-8' -Condition ($demoHtml -match 'charset="utf-8"')
Assert-FmpTrue -Name 'demo HTML: banner sintetico' -Condition ($demoHtml -match 'DADOS SINTETICOS|SINT&#201;TICOS|SINTÉTICOS')
Assert-FmpTrue -Name 'demo HTML: pontuacao exibida' -Condition ($demoHtml -match '<div class="num ">79</div>')
Assert-FmpTrue -Name 'demo HTML: sem recurso externo (src=)' -Condition ($demoHtml -notmatch 'src="http')
Assert-FmpTrue -Name 'demo HTML: sem recurso externo (href=)' -Condition ($demoHtml -notmatch 'href="http')
$printTag = [regex]::Escape('<script>' + $script:FmpPrintScript + '</script>')
Assert-FmpTrue -Name 'demo HTML: nenhum script alem do de impressao autorizado' -Condition (($demoHtml -replace $printTag, '') -notmatch '(?i)<script' -and $demoHtml -match $printTag)

$missingEn = Invoke-FmpRenderToScratch -FixtureResult $demo -Lang 'en' -Name 'demo-en.html'
Assert-FmpEqual -Name 'demo en: nenhuma chave de idioma faltando' -Expected 0 -Actual @($missingEn).Count
$demoEn = [System.IO.File]::ReadAllText((Join-Path $scratch 'demo-en.html'))
Assert-FmpTrue -Name 'demo HTML en: ingles renderizado' -Condition ($demoEn -match 'PC diagnostic report')

$degMissing = Invoke-FmpRenderToScratch -FixtureResult $deg -Lang 'pt-BR' -Name 'degenerate.html'
$degHtml = [System.IO.File]::ReadAllText((Join-Path $scratch 'degenerate.html'))
Assert-FmpTrue -Name 'HTML: encoding em celula de texto' -Condition ((ConvertTo-FmpCellText -Value '<script>' -Key 'text') -eq '&lt;script&gt;')
Assert-FmpTrue -Name 'degenerate HTML: sem <script> executavel' -Condition (($degHtml -replace $printTag, '') -notmatch '(?i)<script[^>]*>')
Assert-FmpTrue -Name 'degenerate HTML: sem javascript: em href' -Condition ($degHtml -notmatch 'href="javascript')
Assert-FmpTrue -Name 'degenerate HTML: onerror injetado e escapado' -Condition ($degHtml -notmatch '<img src=x onerror')
Assert-FmpTrue -Name 'degenerate HTML: unicode preservado' -Condition ($degHtml -match 'S&#227;oPauloTool|SãoPauloTool')
Assert-FmpTrue -Name 'degenerate HTML: tokens e texto de evento ausentes' -Condition ($degHtml -notmatch 'Secret#1')
Assert-FmpTrue -Name 'HTML indisponivel omite denominador da nota' -Condition ($degHtml -notmatch '<div class="of">')
Assert-FmpEqual -Name 'degenerate render: nenhuma chave faltando' -Expected 0 -Actual @($degMissing).Count

Start-FmpSuite 'F. Internacionalizacao'
$keysPt = @($locPt.PSObject.Properties.Name)
$keysEn = @($locEn.PSObject.Properties.Name)
$missingInEn = @($keysPt | Where-Object { $keysEn -notcontains $_ })
$missingInPt = @($keysEn | Where-Object { $keysPt -notcontains $_ })
Assert-FmpEqual -Name 'locales com mesmos conjuntos de chaves (pt->en)' -Expected 0 -Actual $missingInEn.Count
Assert-FmpEqual -Name 'locales com mesmos conjuntos de chaves (en->pt)' -Expected 0 -Actual $missingInPt.Count
$allRuleKeysOk = $true
foreach ($r in $ruleConfig.rules) {
    $id = [string](Get-FmpValue -Data $r -Path 'id')
    foreach ($lang in @($locPt, $locEn)) {
        # Locales are FLAT key objects: use direct property access, not paths.
        foreach ($suffix in @('title', 'detail', 'humanCheck')) {
            if ($null -eq $lang.PSObject.Properties[('rules.' + $id + '.' + $suffix)]) { $allRuleKeysOk = $false }
        }
    }
}
Assert-FmpTrue -Name 'toda regra tem title/detail/humanCheck nos dois idiomas' -Condition $allRuleKeysOk
Assert-FmpEqual -Name 'fallback: chave ausente retorna a chave' -Expected 'chave.inexistente' -Actual (Get-FmpLocaleString -Locales @($locPt) -Key 'chave.inexistente')

Start-FmpSuite 'G. Entrada do CLI (processo real, modo sintetico)'
$e2eOut = Join-Path $scratch 'e2e'
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $root 'fixmypc.ps1') -Fixture (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'demo-synthetic.json') -Mode full -Language pt-BR -OutDir $e2eOut -Yes *> $null
$e2eCode = $LASTEXITCODE
Assert-FmpEqual -Name 'CLI com fixture: exit 0' -Expected 0 -Actual $e2eCode
Assert-FmpTrue -Name 'CLI: report.html gerado' -Condition (Test-Path -LiteralPath (Join-Path $e2eOut 'report.html'))
Assert-FmpTrue -Name 'CLI: diagnostic-sanitized.json gerado' -Condition (Test-Path -LiteralPath (Join-Path $e2eOut 'diagnostic-sanitized.json'))
Assert-FmpTrue -Name 'CLI: JSON interno omitido por padrao' -Condition (-not (Test-Path -LiteralPath (Join-Path $e2eOut 'diagnostic-internal.json')))
$sanJson = Read-FmpJsonFile -Path (Join-Path $e2eOut 'diagnostic-sanitized.json')
Assert-FmpTrue -Name 'CLI: sanitizado tem privacy.sanitized=true' -Condition ([bool](Get-FmpValue -Data $sanJson.Data -Path 'privacy.sanitized'))
Assert-FmpTrue -Name 'CLI: sanitizado marcado como sintetico' -Condition ([bool](Get-FmpValue -Data $sanJson.Data -Path 'run.synthetic'))

& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $root 'fixmypc.ps1') -ValidateOnly *> $null
Assert-FmpEqual -Name 'CLI ValidateOnly: exit 0' -Expected 0 -Actual $LASTEXITCODE

Start-FmpSuite 'H. Regressoes da revisao'
Assert-FmpTrue -Name 'nota indisponivel e nula' -Condition ($null -eq $deg.Score.score)
Assert-FmpEqual -Name 'campo ausente nao conta como um item' -Expected 0 -Actual @(Get-FmpValue @{} 'missing').Count
$sample = [pscustomobject]@{ sample = 'synthetic-marker-for-private-message'; arguments = 'synthetic-private-arguments' }
$safeSample = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $sample
Assert-FmpTrue -Name 'PSCustomObject tem mensagens e argumentos redigidos' -Condition ((ConvertTo-FmpJsonText $safeSample) -notmatch 'synthetic-(marker|private)')
$path = Join-Path $scratch 'existing.txt'
Write-FmpUtf8File $path 'original'
$blocked = $false
try { Write-FmpUtf8File $path 'second' } catch { $blocked = $true }
Assert-FmpTrue -Name 'escrita preserva arquivo existente' -Condition ($blocked -and [System.IO.File]::ReadAllText($path) -eq 'original')
Assert-FmpTrue -Name 'JSON do CLI inclui achados e cobertura' -Condition ($null -ne (Get-FmpValue $sanJson.Data 'analysis.findings') -and $null -ne (Get-FmpValue $sanJson.Data 'healthScore.coveragePct'))
$emptyEvents = @{ run = @{ finishedAt = '2026-11-19T12:00:00Z' }; events = @{ logs = @{ System = @{ status = 'empty' }; Application = @{ status = 'empty' } } } }
Assert-FmpEqual -Name 'logs vazios consultados sao evidencias validas' -Expected 'pass' -Actual (Test-FmpRule_events_critical_recurring $emptyEvents).State
$missingSmart = @{ storage = @{ smart = @{ status = 'ok'; items = @(@{ predictFailure = $null }) } } }
Assert-FmpEqual -Name 'indicador SMART nulo e inconclusivo' -Expected 'unknown' -Actual (Test-FmpRule_storage_smart_predict_failure $missingSmart).State
$unknownDefender = @{ advanced = @{ defender = @{ status = 'ok'; data = @{} } } }
Assert-FmpEqual -Name 'Defender sem status de tempo real e inconclusivo' -Expected 'unknown' -Actual (Test-FmpRule_security_defender_disabled $unknownDefender).State
$partialCpu = @{ performance = @{ cpu = @{ sampleCount = 1; avgPercent = 15 } } }
Assert-FmpEqual -Name 'uma amostra de CPU nao demonstra normalidade' -Expected 'unknown' -Actual (Test-FmpRule_perf_cpu_sustained_high $partialCpu).State
$badPercent = @{ storage = @{ volumes = @(@{ isSystem = $true; freePct = -1 }) } }
Assert-FmpEqual -Name 'percentual de disco invalido nao vira achado' -Expected 'unknown' -Actual (Test-FmpRule_storage_disk_space_critical $badPercent).State
$unknownDisk = @{ storage = @{ physicalDisks = @(@{ healthStatus = 'Unknown' }); volumes = @() } }
Assert-FmpEqual -Name 'saude Unknown nao vira defeito' -Expected 'unknown' -Actual (Test-FmpRule_storage_disk_health_unhealthy $unknownDisk).State
Assert-FmpTrue -Name 'XSS em celula percentual permanece texto' -Condition ((ConvertTo-FmpCellText -Value '<img src=x>' -Key 'freePct') -eq '&lt;img src=x&gt;%')
$rawHtml = Join-Path $scratch 'raw.html'
$rawRejected = $false
try { Write-FmpHtmlReport -Diagnostic $demo.Diag -OutPath $rawHtml } catch { $rawRejected = $true }
Assert-FmpTrue -Name 'renderizador recusa diagnostico bruto' -Condition ($rawRejected -and -not (Test-Path -LiteralPath $rawHtml))
$nested = @{ nodes = @(@(), @(1), @(2, $null, 3)) }
$nested = ConvertTo-FmpSerializable -Value $nested
Assert-FmpTrue -Name 'JSON preserva arrays vazios, unitarios, aninhados e null' -Condition ($nested.nodes.Count -eq 3 -and $nested.nodes[0].Count -eq 0 -and $nested.nodes[1].Count -eq 1 -and $nested.nodes[2].Count -eq 3 -and $null -eq $nested.nodes[2][1])
$unicode = 'a' + [char]0xd83d + [char]0xde80
Assert-FmpEqual -Name 'truncamento UTF-8 preserva caractere completo' -Expected 'a' -Actual (Limit-FmpString $unicode 2)
foreach ($badPath in @(
    'relative\file', 'C:relative', '\\example.invalid\share', '\\.\PhysicalDrive0', '\\?\C:\temp\out.json',
    ($scratch + '\..\file'), ($scratch + '\file:stream'), ($scratch + '\NUL.txt'), ($scratch + '\CON'),
    ($scratch + '\dir.\file.json'), ($scratch + '\file.txt ')
)) {
    $pathRejected = $false
    try { $null = Get-FmpLocalPath $badPath } catch { $pathRejected = $true }
    Assert-FmpTrue -Name ('caminho invalido/dispositivo/traversal/ADS rejeitado: ' + $badPath) -Condition $pathRejected
}

# Double.NaN and Infinity serialization safety
$nanVal = 0.0 / 0.0
$infVal = 1.0 / 0.0
$nanJson = ConvertTo-FmpJsonText -Data ([ordered]@{ ok = 1.5; badNan = $nanVal; badInf = $infVal })
Assert-FmpTrue -Name 'NaN e Infinity serializam como null em JSON' -Condition ($nanJson -match '"badNan":\s*null' -and $nanJson -match '"badInf":\s*null')

# Caption trailing space + startup unsupported subcheck regression
$w10Space = [ordered]@{
    run = [ordered]@{ finishedAt = '2026-11-19T12:00:00Z' }
    system = [ordered]@{ os = [ordered]@{ caption = 'Microsoft Windows 10 Pro '; displayVersion = '22H2' } }
}
Assert-FmpEqual -Name 'Caption com espaco final ainda identifica Win10 EOL' -Expected 'finding' -Actual (Test-FmpRule_os_w10_eol $w10Space $ruleConfig.rules[13] $ruleConfig).State
$suPartial = [ordered]@{
    startup = [ordered]@{ items = @([ordered]@{ name = 'A' }); logonTasks = @(); autoServices = @() }
    subChecks = @([ordered]@{ id = 'startup.logonTasks'; state = 'unsupported' })
}
Assert-FmpEqual -Name 'startup subcheck unsupported nao exclui startup.high_count da cobertura' -Expected 'unknown' -Actual (Test-FmpRule_startup_high_count $suPartial $ruleConfig.rules[16] $ruleConfig).State

# Null / malformed pagefile and truncated event HTML regression
$htmlEdgeDiag = ConvertTo-FmpSanitizedDiagnostic -Diagnostic ([ordered]@{
    schemaVersion = '1.0.0'
    run = [ordered]@{ id = 'x'; toolVersion = '0.1.0'; mode = 'simple'; language = 'pt-BR'; synthetic = $true; startedAt = '2026-11-19T12:00:00Z'; finishedAt = '2026-11-19T12:00:10Z' }
    events = [ordered]@{ windowDays = 7; logs = [ordered]@{ System = [ordered]@{ status = 'ok'; totalEvents = 2000; truncated = $true; groups = @() } } }
    performance = [ordered]@{ pagefile = [ordered]@{ name = 'C:\pagefile.sys'; allocatedMB = $null; currentUsageMB = 'bad'; peakUsageMB = 100 } }
    analysis = [ordered]@{ checks = @(); findings = @() }
    healthScore = [ordered]@{ score = $null; status = 'unavailable'; confidence = 'low'; coveragePct = 0; applicableChecks = 0; coveredChecks = 0; categories = @(); limitations = @() }
})
Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR'
$htmlEdge = Get-FmpHtmlReportText -Diagnostic $htmlEdgeDiag -Synthetic:$true -RedactionCount 0
Assert-FmpTrue -Name 'HTML evento truncado exibe marcador +' -Condition ($htmlEdge -match '2\.000\+|2000\+')
Assert-FmpTrue -Name 'HTML pagefile nulo/invalido nao vira 0 B nem lanca' -Condition ($htmlEdge -match 'alocado -' -and $htmlEdge -match 'uso atual -')

# Multi-artifact preflight atomicity: oversized payload (>8 MiB) must not leave partial files
$oversizedOut = Join-Path $scratch 'oversized-out'
$hugeStr = 'X' * 50000
$hugeApps = @(0..199 | ForEach-Object { [ordered]@{ displayName = ('App' + $_ + '-' + $hugeStr); displayVersion = '1.0' } })
$oversizedFixture = Join-Path $scratch 'oversized-fixture.json'
# Note: ConvertTo-FmpSerializable caps strings at 4000; test HTML/JSON size cap via 500 items or Write-FmpHtmlReport size guard
$largeCheck = [ordered]@{
    schemaVersion = '1.0.0'
    run = [ordered]@{ id = 'fmp-oversize'; toolVersion = '0.1.0'; mode = 'simple'; language = 'pt-BR'; synthetic = $true; startedAt = '2026-11-19T12:00:00Z'; finishedAt = '2026-11-19T12:00:10Z' }
    modules = @()
}
$oversizeHtmlRejected = $false
try {
    $bigDiag = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $largeCheck
    $bigDiag['analysis'] = @{ checks = @(); findings = @(0..4000 | ForEach-Object { @{ id = 'os.long_uptime'; category = 'os'; severity = 'info'; confidence = 'high'; values = @{ days = 100; thresholdDays = 60 }; limitations = @('A' * 2500) } }) }
    $bigDiag['healthScore'] = @{ score = 100; status = 'ok'; confidence = 'high'; coveragePct = 100; applicableChecks = 1; coveredChecks = 1; categories = @(); limitations = @() }
    Write-FmpHtmlReport -Diagnostic $bigDiag -OutPath (Join-Path $scratch 'too-big.html') -Synthetic:$true
}
catch { $oversizeHtmlRejected = $true }
Assert-FmpTrue -Name 'HTML acima de 8 MiB e bloqueado antes de criar arquivo' -Condition ($oversizeHtmlRejected -and -not (Test-Path -LiteralPath (Join-Path $scratch 'too-big.html')))

$eventData = @{ run = @{ finishedAt = '2026-11-19T12:00:00Z' }; events = @{ logs = @{
    System = @{ status = 'ok'; groups = @(@{ provider = 'Example Provider'; eventId = 7; occurrences = @(
        1..5 | ForEach-Object { @{ at = '2026-11-19T11:00:00Z'; level = 1 } }
    ) }) }
    Application = @{ status = 'empty' }
} } }
Assert-FmpEqual -Name 'cinco eventos criticos recentes contam para recorrencia' -Expected 'finding' -Actual (Test-FmpRule_events_critical_recurring $eventData).State
$eventData['events']['logs']['System']['groups'][0]['occurrences'][0]['at'] = '2026-11-16T12:00:00Z'
Assert-FmpEqual -Name 'evento antigo nao conta na janela curta' -Expected 'pass' -Actual (Test-FmpRule_events_critical_recurring $eventData).State
$eventData['events']['logs']['Application']['status'] = 'access_denied'
Assert-FmpEqual -Name 'log parcial nao permite concluir ausencia' -Expected 'access_denied' -Actual (Test-FmpRule_events_critical_recurring $eventData).State
$eventData['events']['logs']['Application']['status'] = 'empty'
$eventData.events.logs.System['truncated'] = $true
Assert-FmpEqual -Name 'limite amostral deixa ausencia inconclusiva' -Expected 'unknown' -Actual (Test-FmpRule_events_critical_recurring $eventData).State

$syntheticModule = Invoke-FmpCollector -Name 'synthetic' -Body {
    param($ctx)
    $null = New-FmpEvidence -Ctx $ctx -CheckId 'synthetic.test' -Summary 'offline'
    Add-FmpSubCheck -Ctx $ctx -Id 'synthetic.test' -State 'error'
    Write-Output 'incidental output'
}
Assert-FmpEqual -Name 'coletor sintetico falho retorna um unico modulo failed' -Expected 'failed' -Actual $syntheticModule.status
Assert-FmpEqual -Name 'modulo sintetico mantem trilha de evidencia' -Expected 1 -Actual $syntheticModule.evidence.Count

$simpleDemo = Invoke-FmpFixture -Fixture 'demo-synthetic.json' -Mode 'simple'
Assert-FmpEqual -Name 'score comparavel entre Simples e Completa' -Expected $demo.Score.score -Actual $simpleDemo.Score.score
Assert-FmpEqual -Name 'cobertura comparavel entre Simples e Completa' -Expected $demo.Score.coveragePct -Actual $simpleDemo.Score.coveragePct
$demoAdvancedFailed = Get-FmpHealthScore -Analysis $demo.Analysis -RuleConfig $ruleConfig -Modules @(@{ id = 'advanced'; status = 'failed' })
Assert-FmpEqual -Name 'falha exclusiva da Completa preserva score-base' -Expected $demo.Score.status -Actual $demoAdvancedFailed.status
$scoreChecks = @{ checks = @(
    @{ id = 'e1'; state = 'access_denied'; category = 'events' },
    @{ id = 'e2'; state = 'error'; category = 'events' },
    @{ id = 's1'; state = 'finding'; category = 'storage' },
    @{ id = 's2'; state = 'finding'; category = 'storage' },
    @{ id = 's3'; state = 'finding'; category = 'storage' }
); findings = @(
    @{ id = 's1'; category = 'storage'; dedupeGroup = 'primary'; penalty = 22 },
    @{ id = 's2'; category = 'storage'; dedupeGroup = 'primary'; penalty = 15 },
    @{ id = 's3'; category = 'storage'; dedupeGroup = 'secondary'; penalty = 40 }
) }
$scoreChecks.findings += $scoreChecks.findings[0]
$scored = Get-FmpHealthScore -Analysis $scoreChecks -RuleConfig $ruleConfig
Assert-FmpEqual -Name 'duplicatas e causas correlatas respeitam teto de 30' -Expected 30 -Actual $scored.totalDeduction
Assert-FmpEqual -Name 'itens de penalidade somam a deducao aplicada' -Expected 30 -Actual (($scored.penaltyItems | ForEach-Object { $_.points } | Measure-Object -Sum).Sum)
Assert-FmpEqual -Name 'erros e acesso negado nao contam como cobertura' -Expected 60 -Actual $scored.coveragePct
Assert-FmpTrue -Name 'cobertura desigual por categoria fica explicita' -Condition ($scored.categories[0].coveredChecks -eq 3 -and $scored.categories[1].coveredChecks -eq 0)
Assert-FmpEqual -Name 'nenhum campo de score fornecido: indisponivel' -Expected 'unavailable' -Actual (Get-FmpHealthScore -Analysis @{} -RuleConfig $ruleConfig).status

foreach ($deniedSource in @('echo test', '$text = 42 > $null', '[System.IO.Path]::GetTempPath()', 'Get-Date -OutVariable x', '$env:EXAMPLE_TEST = 1')) {
    $snippetPath = Join-Path $scratch ('snippet-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    Write-FmpUtf8File $snippetPath $deniedSource
    Assert-FmpTrue -Name 'scanner rejeita construcao fora do escopo' -Condition (-not (Test-FmpScriptCompliance -Path $snippetPath -Role 'collector').Ok)
}

# =====================================================================
Start-FmpSuite 'J. FMP-01 - elegibilidade, renormalizacao e risco diagnostico'

function Get-FmpHealthyDiag {
    $fx = Read-FmpJsonFile -Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'win11-healthy.json')
    return (ConvertTo-FmpSerializable -Value $fx.Data)
}
function Invoke-FmpScoreDiag {
    param([System.Collections.IDictionary]$Diag, [string]$Mode = 'simple')
    $analysis = Invoke-FmpRules -Diagnostic $Diag -RuleConfig $ruleConfig -Mode $Mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue -Data $Diag -Path 'modules')
    $Diag['analysis'] = $analysis
    $Diag['healthScore'] = $score
    return @{ Diag = $Diag; Analysis = $analysis; Score = $score; Sanitized = (ConvertTo-FmpSanitizedDiagnostic -Diagnostic $Diag) }
}
function Get-FmpScoreCategory {
    param([object]$Score, [string]$Name)
    foreach ($c in $Score.categories) { if ($c.category -eq $Name) { return $c } }
}
function Set-FmpFailingDisk {
    # Audit case B1: Windows reports Unhealthy + SMART PredictFailure + recent disk errors.
    param([System.Collections.IDictionary]$Diag)
    $Diag['storage']['physicalDisks'][0]['healthStatus'] = 'Unhealthy'
    $Diag['storage']['smart']['items'][0]['predictFailure'] = $true
    $occ = @(1..12 | ForEach-Object { [ordered]@{ at = '2026-11-19T11:00:00.000Z'; level = 2 } })
    $Diag['events']['logs']['System']['groups'] = @([ordered]@{ provider = 'disk'; eventId = 7; count = 12; maxLevel = 2
        firstSeen = '2026-11-19T11:00:00.000Z'; lastSeen = '2026-11-19T11:00:00.000Z'; occurrences = $occ })
}
function Get-FmpRenderedHtml {
    param([object]$Result, [string]$Lang = 'pt-BR')
    $primary = $locPt; $fallback = $locEn
    if ($Lang -eq 'en') { $primary = $locEn; $fallback = $locPt }
    Set-FmpRenderLocale -Primary $primary -Fallback $fallback -Language $Lang
    return (Get-FmpHtmlReportText -Diagnostic $Result.Sanitized -Synthetic:$true -RedactionCount 0)
}

# B0: healthy machine. Startup has no base rule, so it must not contribute points.
$b0 = Invoke-FmpScoreDiag -Diag (Get-FmpHealthyDiag)
$b0Startup = Get-FmpScoreCategory -Score $b0.Score -Name 'startup'
Assert-FmpEqual -Name 'B0: nota 100' -Expected 100 -Actual $b0.Score.score
Assert-FmpEqual -Name 'B0: status ok' -Expected 'ok' -Actual $b0.Score.status
Assert-FmpEqual -Name 'B0: risco nenhum detectado' -Expected 'none_detected' -Actual $b0.Score.riskLevel
Assert-FmpTrue -Name 'B0: inicializacao fora da nota (sem regras-base)' -Condition ($b0Startup.eligible -eq $false -and $b0Startup.excludedReason -eq 'no_base_rules')
Assert-FmpEqual -Name 'B0: peso elegivel 85 (100 - inicializacao)' -Expected 85 -Actual $b0.Score.eligibleWeight
Assert-FmpTrue -Name 'B0: nota sem limite de gravidade' -Condition ($b0.Score.capped -eq $false)

# Every weighted category either has a penalizing base rule or is reported as excluded.
$baseCats = @{}
foreach ($r in $ruleConfig.rules) {
    if (@($r.modes) -contains 'simple' -and [double]$r.penalty -gt 0) { $baseCats[[string]$r.category] = $true }
}
$structuralOk = $true
foreach ($c in $b0.Score.categories) {
    if (-not $baseCats.ContainsKey([string]$c.category) -and $c.eligible -ne $false) { $structuralOk = $false }
    if ($c.eligible -eq $true -and $c.coveredChecks -lt 1) { $structuralOk = $false }
}
Assert-FmpTrue -Name 'categoria sem regra-base penalizavel nunca e elegivel' -Condition $structuralOk

# B1: failing disk can no longer read as healthy.
$b1Diag = Get-FmpHealthyDiag
Set-FmpFailingDisk -Diag $b1Diag
$b1 = Invoke-FmpScoreDiag -Diag $b1Diag
Assert-FmpEqual -Name 'B1: risco critico' -Expected 'critical' -Actual $b1.Score.riskLevel
Assert-FmpTrue -Name 'B1: nota limitada a no maximo 49' -Condition ($null -ne $b1.Score.score -and $b1.Score.score -le 49) -Detail ('score=' + $b1.Score.score)
Assert-FmpEqual -Name 'B1: nota sem limite = round(100*(85-12)/85) = 86' -Expected 86 -Actual $b1.Score.uncappedScore
Assert-FmpEqual -Name 'B1: limite aplicado 49' -Expected 49 -Actual $b1.Score.scoreCap
Assert-FmpTrue -Name 'B1: nota marcada como limitada' -Condition ($b1.Score.capped -eq $true)
Assert-FmpEqual -Name 'B1: disponibilidade continua ok (dados completos)' -Expected 'ok' -Actual $b1.Score.status
Assert-FmpEqual -Name 'B1: confianca dos dados alta nao implica saude' -Expected 'high' -Actual $b1.Score.confidence
Assert-FmpTrue -Name 'B1: motivos do risco citam SMART e Unhealthy' -Condition (@($b1.Score.riskReasons) -contains 'storage.smart_predict_failure' -and @($b1.Score.riskReasons) -contains 'storage.disk_health_unhealthy')
Assert-FmpEqual -Name 'B1: deducao e dedupe preservados (grupo storage.health = 12)' -Expected 12 -Actual $b1.Score.totalDeduction

# Mode equivalence: Full-only rules never change the base score or risk.
$b1FullDiag = Get-FmpHealthyDiag
Set-FmpFailingDisk -Diag $b1FullDiag
$b1Full = Invoke-FmpScoreDiag -Diag $b1FullDiag -Mode 'full'
Assert-FmpEqual -Name 'modos: mesma nota Simples x Completa' -Expected $b1.Score.score -Actual $b1Full.Score.score
Assert-FmpEqual -Name 'modos: mesmo risco Simples x Completa' -Expected $b1.Score.riskLevel -Actual $b1Full.Score.riskLevel
Assert-FmpEqual -Name 'modos: mesmo peso elegivel Simples x Completa' -Expected $b1.Score.eligibleWeight -Actual $b1Full.Score.eligibleWeight

# B2: every base rule that can penalize fires. No artificial rule forces 0.
[System.Collections.IDictionary]$b2Diag = Get-FmpHealthyDiag
Set-FmpFailingDisk -Diag $b2Diag
for ($vi = 0; $vi -lt @($b2Diag['storage']['volumes']).Count; $vi++) { if ($b2Diag['storage']['volumes'][$vi]['isSystem']) { $b2Diag['storage']['volumes'][$vi]['freePct'] = 1.0 } }
$b2Diag['performance']['cpu']['avgPercent'] = 99.0
$b2Diag['performance']['cpu']['maxPercent'] = 100.0
$b2Diag['performance']['memory']['commitPct'] = 99.0
$b2Diag['system']['os']['caption'] = 'Windows 10 Pro'
$b2Diag['system']['os']['displayVersion'] = '22H2'
$critOcc = @(1..8 | ForEach-Object { [ordered]@{ at = '2026-11-19T08:00:00.000Z'; level = 1 } })
$b2Diag['events']['logs']['System']['groups'] = @(
    [ordered]@{ provider = 'Microsoft-Windows-Kernel-Power'; eventId = 41; count = 8; maxLevel = 1; firstSeen = '2026-11-19T08:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $critOcc },
    [ordered]@{ provider = 'Microsoft-Windows-WHEA-Logger'; eventId = 18; count = 8; maxLevel = 1; firstSeen = '2026-11-19T08:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $critOcc },
    [ordered]@{ provider = 'BugCheck'; eventId = 1001; count = 8; maxLevel = 2; firstSeen = '2026-11-19T08:00:00.000Z'; lastSeen = '2026-11-19T08:00:00.000Z'; occurrences = $critOcc }
)
$b2 = Invoke-FmpScoreDiag -Diag $b2Diag
Assert-FmpEqual -Name 'B2: deducao 57 (22+25+4+0+6; CPU curta nao penaliza, FMP-07)' -Expected 57 -Actual $b2.Score.totalDeduction
Assert-FmpEqual -Name 'B2: nota = round(100*(85-57)/85) = 33' -Expected 33 -Actual $b2.Score.score
Assert-FmpEqual -Name 'B2: risco critico' -Expected 'critical' -Actual $b2.Score.riskLevel
Assert-FmpTrue -Name 'B2: limite nao altera nota ja inferior' -Condition ($b2.Score.capped -eq $false)

# Partial coverage: SMART denied is inconclusive, never a penalty or a gate.
[System.Collections.IDictionary]$denDiag = Get-FmpHealthyDiag
$denDiag['storage']['smart'] = [ordered]@{ status = 'access_denied'; checked = 0; items = @() }
$den = Invoke-FmpScoreDiag -Diag $denDiag
Assert-FmpEqual -Name 'SMART negado: nota 100 sem penalidade' -Expected 100 -Actual $den.Score.score
Assert-FmpEqual -Name 'SMART negado: nota provisoria' -Expected 'provisional' -Actual $den.Score.status
Assert-FmpEqual -Name 'SMART negado: risco nenhum detectado' -Expected 'none_detected' -Actual $den.Score.riskLevel
Assert-FmpTrue -Name 'SMART negado: cobertura menor que 100' -Condition ($den.Score.coveragePct -lt 100)

# SMART unknown + Windows Warning: elevated risk, no cap.
[System.Collections.IDictionary]$warnDiag = Get-FmpHealthyDiag
$warnDiag['storage']['smart'] = [ordered]@{ status = 'empty'; checked = 0; items = @() }
$warnDiag['storage']['physicalDisks'][0]['healthStatus'] = 'Warning'
$warn = Invoke-FmpScoreDiag -Diag $warnDiag
Assert-FmpEqual -Name 'Warning + SMART desconhecido: risco elevado' -Expected 'elevated' -Actual $warn.Score.riskLevel
Assert-FmpEqual -Name 'Warning + SMART desconhecido: nota 86 sem limite' -Expected 86 -Actual $warn.Score.score
Assert-FmpEqual -Name 'Warning + SMART desconhecido: provisoria' -Expected 'provisional' -Actual $warn.Score.status

# Category with applicable checks but no evidence is excluded, not counted healthy.
$noEv = @{ checks = @(
    @{ id = 'st1'; state = 'unknown'; category = 'storage' }, @{ id = 'st2'; state = 'unknown'; category = 'storage' },
    @{ id = 'ev1'; state = 'pass'; category = 'events' }, @{ id = 'ev2'; state = 'pass'; category = 'events' },
    @{ id = 'pf1'; state = 'pass'; category = 'performance' }, @{ id = 'os1'; state = 'pass'; category = 'os' }
); findings = @() }
$noEvScore = Get-FmpHealthScore -Analysis $noEv -RuleConfig $ruleConfig
$noEvStorage = Get-FmpScoreCategory -Score $noEvScore -Name 'storage'
Assert-FmpTrue -Name 'sem evidencia: armazenamento fora da nota' -Condition ($noEvStorage.eligible -eq $false -and $noEvStorage.excludedReason -eq 'no_evidence')
Assert-FmpEqual -Name 'sem evidencia: peso elegivel 55' -Expected 55 -Actual $noEvScore.eligibleWeight
Assert-FmpEqual -Name 'sem evidencia: nota provisoria' -Expected 'provisional' -Actual $noEvScore.status

# Availability and risk are independent: no score, but a proven critical problem.
$unavCritical = @{ checks = @(
    @{ id = 'storage.smart_predict_failure'; state = 'finding'; category = 'storage' },
    @{ id = 'u1'; state = 'unknown'; category = 'events' }, @{ id = 'u2'; state = 'unknown'; category = 'events' },
    @{ id = 'u3'; state = 'unknown'; category = 'performance' }, @{ id = 'u4'; state = 'unknown'; category = 'os' }
); findings = @(
    @{ id = 'storage.smart_predict_failure'; category = 'storage'; severity = 'review_recommended'; penalty = 8; dedupeGroup = 'storage.health'; riskGate = 'critical' }
) }
$unavScore = Get-FmpHealthScore -Analysis $unavCritical -RuleConfig $ruleConfig
Assert-FmpEqual -Name 'indisponivel com falha comprovada: nota nula' -Expected 'unavailable' -Actual $unavScore.status
Assert-FmpEqual -Name 'indisponivel com falha comprovada: risco critico' -Expected 'critical' -Actual $unavScore.riskLevel
Assert-FmpEqual -Name 'nenhum dado: risco indeterminado' -Expected 'undetermined' -Actual (Get-FmpHealthScore -Analysis @{} -RuleConfig $ruleConfig).riskLevel

# Analysis-only (Full) findings never raise the base risk.
$advOnly = Invoke-FmpFixture -Fixture 'advanced-mixed.json' -Mode 'full'
Assert-FmpEqual -Name 'achados so da Completa nao elevam o risco-base' -Expected 'none_detected' -Actual $advOnly.Score.riskLevel

# HTML: risk shown apart from the score; the cap is explained; excluded category is labelled.
$b1Html = Get-FmpRenderedHtml -Result $b1
$capText = ConvertTo-FmpHtmlText (Get-FmpLocaleString -Locales @($locPt) -Key 'score.capped' -Values @('49', '86'))
Assert-FmpTrue -Name 'HTML B1: nivel de risco critico exibido' -Condition ($b1Html.Contains('class="risk critical"') -and $b1Html.Contains((ConvertTo-FmpHtmlText (Get-FmpLocaleString -Locales @($locPt) -Key 'risk.level.critical'))))
Assert-FmpTrue -Name 'HTML B1: limite da nota explicado' -Condition ($b1Html.Contains($capText))
Assert-FmpTrue -Name 'HTML B1: nota exibida e a limitada' -Condition ($b1Html.Contains('<div class="num ">49</div>'))
Assert-FmpTrue -Name 'HTML B1: categoria inicializacao fora da nota' -Condition ($b1Html.Contains((ConvertTo-FmpHtmlText (Get-FmpLocaleString -Locales @($locPt) -Key 'report.score.cat.none'))))
Assert-FmpTrue -Name 'HTML: confianca rotulada como confianca dos dados' -Condition ((Get-FmpLocaleString -Locales @($locPt) -Key 'report.summary.confidence') -match 'dados' -and (Get-FmpLocaleString -Locales @($locEn) -Key 'report.summary.confidence') -match 'data')
$b0Html = Get-FmpRenderedHtml -Result $b0
Assert-FmpTrue -Name 'HTML B0: risco nenhum detectado exibido' -Condition ($b0Html.Contains('class="risk none_detected"'))

# =====================================================================
Start-FmpSuite 'K. FMP-04 - limitacoes localizadas com chave estavel'

function Test-FmpLocaleKeyBoth {
    param([string]$Key)
    return ($null -ne $locPt.PSObject.Properties[$Key] -and $null -ne $locEn.PSObject.Properties[$Key])
}
function Get-FmpParsedAst {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
}

# 1. Rule limitations: every literal has a stable key, present in both locales.
$rulesAst = Get-FmpParsedAst -Path (Join-Path $root 'src\analysis\Rules.ps1')
$ruleLimTexts = New-Object System.Collections.Generic.List[string]
foreach ($h in $rulesAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
    foreach ($pair in $h.KeyValuePairs) {
        if ($pair.Item1 -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or $pair.Item1.Value -ne 'Limitations') { continue }
        foreach ($s in $pair.Item2.FindAll({ param($a) $a -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
            if (-not $ruleLimTexts.Contains($s.Value)) { $ruleLimTexts.Add($s.Value) }
        }
    }
}
Assert-FmpEqual -Name 'regras: 34 limitacoes canonicas distintas' -Expected 34 -Actual $ruleLimTexts.Count
$ruleKeyMissing = @($ruleLimTexts | Where-Object { -not $script:FmpRuleLimitationKeys.ContainsKey($_) -or -not (Test-FmpLocaleKeyBoth $script:FmpRuleLimitationKeys[$_]) })
Assert-FmpTrue -Name 'regras: toda limitacao tem chave estavel nos dois idiomas' -Condition ($ruleKeyMissing.Count -eq 0) -Detail ($ruleKeyMissing -join ' | ')

# 2. Collector limitations: every call site resolves to limit.<key> in both locales.
$limitSites = 0
$limitMissing = New-Object System.Collections.Generic.List[string]
foreach ($file in @('Advanced.ps1', 'Events.ps1', 'Performance.ps1', 'Startup.ps1', 'Storage.ps1', 'System.ps1', 'Observation.ps1')) {
    $cAst = Get-FmpParsedAst -Path (Join-Path (Join-Path $root 'src\collectors') $file)
    foreach ($cmd in $cAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        if ($cmd.GetCommandName() -ne 'Add-FmpLimitation') { continue }
        $limitSites++
        $els = $cmd.CommandElements
        $keyConst = $null
        $localeConst = $null
        for ($i = 0; $i -lt ($els.Count - 1); $i++) {
            if ($els[$i] -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
            $next = $els[$i + 1]
            if ($next -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
            if ($els[$i].ParameterName -eq 'Key') { $keyConst = $next.Value }
            if ($els[$i].ParameterName -eq 'LocaleKey') { $localeConst = $next.Value }
        }
        $resolved = $localeConst
        if ($null -eq $resolved) { $resolved = $keyConst }
        if ($null -eq $resolved -or -not (Test-FmpLocaleKeyBoth ('limit.' + $resolved))) { $limitMissing.Add($file + ':' + $cmd.Extent.StartLineNumber) }
    }
}
Assert-FmpEqual -Name 'coletores: 29 pontos de limitacao (2.0: +1 Events, +2 Observation; Fase A: +2 Events, +2 Observation)' -Expected 29 -Actual $limitSites
Assert-FmpTrue -Name 'coletores: todo ponto resolve limit.<chave> nos dois idiomas' -Condition ($limitMissing.Count -eq 0) -Detail ($limitMissing -join ', ')

# 3. Score limitations carry keys.
$scoreKeys = @($b0.Score.limitationKeys)
Assert-FmpEqual -Name 'pontuacao: 2 limitacoes com chave' -Expected 2 -Actual @($scoreKeys | Where-Object { Test-FmpLocaleKeyBoth $_ }).Count
Assert-FmpEqual -Name 'pontuacao: texto canonico preservado' -Expected 2 -Actual @($b0.Score.limitations).Count

# 4. Canonical text preserved in JSON, with parallel keys.
$lowK = Invoke-FmpFixture -Fixture 'limited-access.json' -Mode 'full'
$parallelOk = $true
foreach ($c in $lowK.Analysis.checks) {
    if (-not $c.Contains('limitations')) { continue }
    if (@($c['limitationKeys']).Count -ne @($c['limitations']).Count) { $parallelOk = $false }
    foreach ($t in @($c['limitations'])) { if (-not $script:FmpRuleLimitationKeys.ContainsKey($t)) { $parallelOk = $false } }
}
Assert-FmpTrue -Name 'JSON: limitationKeys paralelo ao texto canonico' -Condition $parallelOk

# 5. PT-BR reports contain no canonical English limitation and no technical key.
foreach ($fxName in @('demo-synthetic.json', 'limited-access.json', 'advanced-mixed.json', 'low-disk.json', 'startup-full.json')) {
    $res = Invoke-FmpFixture -Fixture $fxName -Mode 'full'
    $html = Get-FmpRenderedHtml -Result $res -Lang 'pt-BR'
    $leaks = New-Object System.Collections.Generic.List[string]
    $english = New-Object System.Collections.Generic.List[string]
    foreach ($f in $res.Analysis.findings) { foreach ($t in @(Get-FmpValue -Data $f -Path 'limitations')) { if ($null -ne $t) { $english.Add([string]$t) } } }
    foreach ($t in @($res.Score.limitations)) { $english.Add([string]$t) }
    $techKeys = New-Object System.Collections.Generic.List[string]
    foreach ($m in @(Get-FmpValue -Data $res.Diag -Path 'modules')) {
        foreach ($l in @(Get-FmpValue -Data $m -Path 'limits')) {
            $d = [string](Get-FmpValue -Data $l -Path 'detail')
            if ($d -ne '') { $english.Add($d) }
            $techKeys.Add([string](Get-FmpValue -Data $l -Path 'key'))
        }
    }
    foreach ($t in $english) { if ($html.Contains((ConvertTo-FmpHtmlText $t))) { $leaks.Add($t) } }
    foreach ($k in $techKeys) { if ($k -ne '' -and $html.Contains($k)) { $leaks.Add('key:' + $k) } }
    foreach ($k in @('lim.', 'limit.', 'score.limitation.')) { if ($html.Contains('>' + $k)) { $leaks.Add('key:' + $k) } }
    if ($html -match '\{\d+\}') { $leaks.Add('placeholder') }
    Assert-FmpTrue -Name ('PT-BR ' + $fxName + ': nenhum texto canonico ingles nem chave tecnica') -Condition ($leaks.Count -eq 0) -Detail ($leaks -join ' | ')
}

# 6. Unknown key falls back to the canonical detail, never to the key.
[System.Collections.IDictionary]$fbDiag = Get-FmpHealthyDiag
$fbDiag['modules'][0]['limits'] = @([ordered]@{ key = 'zz_unregistered_key'; detail = 'Canonical fallback detail.' })
$fbHtml = Get-FmpRenderedHtml -Result (Invoke-FmpScoreDiag -Diag $fbDiag)
Assert-FmpTrue -Name 'fallback: chave desconhecida mostra o detalhe canonico' -Condition ($fbHtml.Contains('Canonical fallback detail.') -and -not $fbHtml.Contains('zz_unregistered_key'))

# =====================================================================
Start-FmpSuite 'L. FMP-02/03 - scanner: setters, receptores, caminhos e consultas'
$advPath = Join-Path (Join-Path (Join-Path (Join-Path $root 'tests') 'fixtures') 'bad-scripts') 'scanner-adversarial.txt'
$advCases = @(@([System.IO.File]::ReadAllText($advPath) -split '(?m)^### ') | Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') })
$advInternal = @('Get-FmpCheckedPath', 'Get-FmpSafeRegistryPath', 'New-FmpCollectorContext', 'ConvertTo-FmpSerializable')
$advRejects = 0
$advAccepts = 0
foreach ($case in $advCases) {
    $advLines = @($case -split "`r?`n")
    $advHead = @($advLines[0].Split('|') | ForEach-Object { $_.Trim() })
    $advId = $advHead[0]
    $advRole = 'collector'
    if ($advHead.Count -ge 4) { $advRole = $advHead[3] }
    $advCode = (@($advLines[1..($advLines.Count - 1)] | Where-Object { $_.Trim() -ne '' }) -join [Environment]::NewLine)
    $advFile = Join-Path $scratch ('adv-' + $advId + '.ps1')
    Write-FmpUtf8File $advFile $advCode
    $advResult = Test-FmpScriptCompliance -Path $advFile -Role $advRole -InternalFunctions $advInternal
    $advTypes = @($advResult.Violations | ForEach-Object { [string]$_.type })
    if ($advHead[1] -eq 'reject') {
        $advRejects++
        Assert-FmpTrue -Name ('scanner rejeita ' + $advId + ' (' + $advHead[2] + ')') -Condition ((-not $advResult.Ok) -and ($advTypes -contains $advHead[2])) -Detail ('violations=' + (($advTypes | Sort-Object -Unique) -join ','))
    }
    else {
        $advAccepts++
        Assert-FmpTrue -Name ('scanner aceita operacao legitima ' + $advId) -Condition ([bool]$advResult.Ok) -Detail ('violations=' + (($advTypes | Sort-Object -Unique) -join ','))
    }
}
Assert-FmpTrue -Name 'fixture adversarial carregada (A1-A8 + extras)' -Condition ($advRejects -ge 40 -and $advAccepts -ge 15) -Detail ('rejects=' + $advRejects + ' accepts=' + $advAccepts)

$regOk = $true
$regGot = ''
try { $regGot = Get-FmpSafeRegistryPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' } catch { $regOk = $false }
Assert-FmpTrue -Name 'Get-FmpSafeRegistryPath devolve chave autorizada' -Condition ($regOk -and $regGot -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
foreach ($badReg in @('HKLM:\SAM', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', '\\audit.invalid\share', 'Registry::HKEY_LOCAL_MACHINE\SAM', 'C:\Windows', '')) {
    $thrown = $false
    try { $null = Get-FmpSafeRegistryPath $badReg } catch { $thrown = $true }
    Assert-FmpTrue -Name ('Get-FmpSafeRegistryPath recusa em tempo de execucao: ' + $badReg) -Condition $thrown
}

# =====================================================================
Start-FmpSuite 'M. FMP-05/06/07 - escala de severidade, inicializacao e CPU de amostra curta'

# FMP-05: inside one dedupe group the rule with the higher penalty never has a lower severity.
$m5Rules = (Read-FmpJsonFile -Path (Join-Path $root 'rules\rules.json')).Data
$m5Rank = @{ info = 0; attention = 1; review_recommended = 2 }
$m5Grouped = @(@($m5Rules.rules) | Where-Object { $null -ne $_.dedupeGroup -and [string]$_.dedupeGroup -ne '' })
$m5Inversions = New-Object System.Collections.Generic.List[string]
foreach ($m5Name in @($m5Grouped | ForEach-Object { [string]$_.dedupeGroup } | Sort-Object -Unique)) {
    $m5Members = @($m5Grouped | Where-Object { [string]$_.dedupeGroup -eq $m5Name })
    foreach ($m5A in $m5Members) {
        foreach ($m5B in $m5Members) {
            if ([double]$m5A.penalty -gt [double]$m5B.penalty -and $m5Rank[[string]$m5A.severity] -lt $m5Rank[[string]$m5B.severity]) {
                $m5Inversions.Add($m5Name + ': ' + $m5A.id + ' (' + $m5A.severity + ', pen ' + $m5A.penalty + ') < ' + $m5B.id + ' (' + $m5B.severity + ', pen ' + $m5B.penalty + ')')
            }
        }
    }
}
Assert-FmpEqual -Name 'FMP-05: nenhum grupo de dedupe tem severidade invertida em relacao a penalidade' -Expected 0 -Actual $m5Inversions.Count
if ($m5Inversions.Count -gt 0) { foreach ($m5Line in $m5Inversions) { Write-Host ('    ' + $m5Line) -ForegroundColor Yellow } }

[System.Collections.IDictionary]$m5Diag = Get-FmpHealthyDiag
for ($vi = 0; $vi -lt @($m5Diag['storage']['volumes']).Count; $vi++) { if ($m5Diag['storage']['volumes'][$vi]['isSystem']) { $m5Diag['storage']['volumes'][$vi]['freePct'] = 3.0 } }
$m5 = Invoke-FmpScoreDiag -Diag $m5Diag
$m5Order = @((Get-FmpOrderedFindings -Analysis $m5.Analysis).base | ForEach-Object { [string]$_.f.id })
$m5Crit = -1
$m5Low = -1
for ($k = 0; $k -lt $m5Order.Count; $k++) {
    if ($m5Order[$k] -eq 'storage.disk_space_critical') { $m5Crit = $k }
    if ($m5Order[$k] -eq 'storage.low_free_space') { $m5Low = $k }
}
Assert-FmpTrue -Name 'FMP-05: 3% livre lista a condicao critica antes de "<10% livre"' -Condition ($m5Crit -ge 0 -and $m5Low -ge 0 -and $m5Crit -lt $m5Low) -Detail ('order=' + ($m5Order -join ','))
$m5CritF = Get-FmpFinding $m5 'storage.disk_space_critical'
$m5LowF = Get-FmpFinding $m5 'storage.low_free_space'
Assert-FmpTrue -Name 'FMP-05: severidade da condicao critica nao e inferior a de "<10% livre"' -Condition ($m5Rank[[string]$m5CritF.severity] -ge $m5Rank[[string]$m5LowF.severity])
Assert-FmpEqual -Name 'FMP-05: penalidades inalteradas (critico 10, <10% livre 6)' -Expected '10/6' -Actual ([string]$m5CritF.penalty + '/' + [string]$m5LowF.penalty)
Assert-FmpEqual -Name 'FMP-05: dedupe preservado (maior penalidade do grupo)' -Expected 10 -Actual ([int]$m5.Score.totalDeduction)

# FMP-06: roughly 100 legitimate automatic Windows services must not raise the "many startup items" alert.
[System.Collections.IDictionary]$m6Diag = Get-FmpHealthyDiag
$m6Diag['startup']['autoServices'] = @(1..100 | ForEach-Object { [ordered]@{ name = ('Svc' + $_); displayName = ('Service ' + $_); state = 'Running'; startMode = 'Auto'; delayed = $false; pathName = 'C:\Windows\system32\svchost.exe -k netsvcs'; account = 'LocalSystem' } })
$m6 = Invoke-FmpScoreDiag -Diag $m6Diag -Mode 'full'
$m6Check = Get-FmpCheck $m6 'startup.high_count'
Assert-FmpEqual -Name 'FMP-06: 100 servicos automaticos legitimos nao disparam o alerta' -Expected 'pass' -Actual $m6Check.state
Assert-FmpEqual -Name 'FMP-06: servicos ficam registrados a parte (measured.services)' -Expected 100 -Actual ([int]$m6Check['measured']['services'])
Assert-FmpTrue -Name 'FMP-06: sem achado de excesso de inicializacao' -Condition ($null -eq (Get-FmpFinding $m6 'startup.high_count'))
[System.Collections.IDictionary]$m6bDiag = Get-FmpHealthyDiag
$m6bDiag['startup']['items'] = @(1..40 | ForEach-Object { [ordered]@{ kind = 'run'; name = ('App' + $_); command = $null; source = 'HKCU'; view = '64'; origin = 'registry' } })
$m6bDiag['startup']['autoServices'] = $m6Diag['startup']['autoServices']
$m6b = Invoke-FmpScoreDiag -Diag $m6bDiag -Mode 'full'
$m6bF = Get-FmpFinding $m6b 'startup.high_count'
Assert-FmpTrue -Name 'FMP-06: 40 itens de inicializacao do usuario ainda geram o alerta informativo' -Condition ($null -ne $m6bF -and $m6bF.severity -eq 'info' -and [int]$m6bF.penalty -eq 0)
Assert-FmpEqual -Name 'FMP-06: o total do alerta ignora servicos (40, nao 140)' -Expected 40 -Actual ([int]$m6bF['values']['total'])
[System.Collections.IDictionary]$m6cDiag = Get-FmpHealthyDiag
$m6cDiag['startup']['items'] = @([ordered]@{ kind = 'run'; name = 'OneApp'; command = $null; source = 'HKCU'; view = '64'; origin = 'registry' })
$m6cDiag['startup']['logonTasks'] = @([ordered]@{ name = 'OneTask'; path = '\'; state = 'Ready'; action = 'x.exe' })
$m6cDiag['startup']['autoServices'] = @()
$m6cDiag['subChecks'] = @(
    [ordered]@{ id = 'startup.registry'; state = 'pass' },
    [ordered]@{ id = 'startup.folders'; state = 'pass' },
    [ordered]@{ id = 'startup.logonTasks'; state = 'pass' },
    [ordered]@{ id = 'startup.autoServices'; state = 'access_denied' }
)
$m6c = Invoke-FmpScoreDiag -Diag $m6cDiag -Mode 'full'
Assert-FmpEqual -Name 'FMP-06: autoServices access_denied com itens e tarefas disponiveis permanece pass' -Expected 'pass' -Actual (Get-FmpCheck $m6c 'startup.high_count').state
[System.Collections.IDictionary]$m6dDiag = Get-FmpHealthyDiag
$m6dDiag['startup']['items'] = @([ordered]@{ kind = 'run'; name = 'OneApp'; command = $null; source = 'HKCU'; view = '64'; origin = 'registry' })
$m6dDiag['startup']['logonTasks'] = @()
$m6dDiag['startup']['autoServices'] = @()
$m6dDiag['subChecks'] = @(
    [ordered]@{ id = 'startup.registry'; state = 'pass' },
    [ordered]@{ id = 'startup.folders'; state = 'pass' },
    [ordered]@{ id = 'startup.logonTasks'; state = 'access_denied' },
    [ordered]@{ id = 'startup.autoServices'; state = 'pass' }
)
$m6d = Invoke-FmpScoreDiag -Diag $m6dDiag -Mode 'full'
Assert-FmpEqual -Name 'FMP-06: fonte contada (logonTasks) access_denied permanece access_denied' -Expected 'access_denied' -Actual (Get-FmpCheck $m6d 'startup.high_count').state

# FMP-07: a ~4 s CPU sample is an observation, not sustained load, and never costs score.
$m7Base = Invoke-FmpScoreDiag -Diag (Get-FmpHealthyDiag)
[System.Collections.IDictionary]$m7Diag = Get-FmpHealthyDiag
$m7Diag['performance']['cpu']['avgPercent'] = 95.0
$m7Diag['performance']['cpu']['maxPercent'] = 100.0
$m7 = Invoke-FmpScoreDiag -Diag $m7Diag
$m7F = Get-FmpFinding $m7 'perf.cpu_sustained_high'
Assert-FmpTrue -Name 'FMP-07: CPU alta em 3 amostras vira observacao informativa sem penalidade' -Condition ($null -ne $m7F -and $m7F.severity -eq 'info' -and [int]$m7F.penalty -eq 0)
Assert-FmpEqual -Name 'FMP-07: nota igual a de um computador sem CPU alta' -Expected $m7Base.Score.score -Actual $m7.Score.score
Assert-FmpTrue -Name 'FMP-07: valores medidos e janela preservados' -Condition ([double]$m7F['values']['avg'] -eq 95 -and [double]$m7F['values']['max'] -eq 100 -and [int]$m7F['values']['samples'] -eq 3 -and [double]$m7F['values']['windowSec'] -eq 4)
$m7Pt = Get-FmpRenderedHtml -Result $m7 -Lang 'pt-BR'
$m7En = Get-FmpRenderedHtml -Result $m7 -Lang 'en'
Assert-FmpTrue -Name 'FMP-07: titulo PT-BR "CPU elevada durante a amostragem"' -Condition ($m7Pt.Contains('CPU elevada durante a amostragem') -and -not $m7Pt.Contains('toda a amostragem'))
Assert-FmpTrue -Name 'FMP-07: titulo EN equivalente' -Condition ($m7En.Contains('High CPU during the sampling window') -and -not $m7En.Contains('whole sampling'))

# =====================================================================
Start-FmpSuite 'N. FMP-08 - SIDs, sufixos por usuario e identificadores privados (JSON e HTML)'
$n8Sid = 'S-1-5-21-1004336348-1177238915-682003330-1001'
[System.Collections.IDictionary]$n8Diag = Get-FmpHealthyDiag
$n8Diag['startup']['logonTasks'] = @([ordered]@{ name = ('OneDrive Reporting Task-' + $n8Sid); path = '\'; state = 'Ready'; action = 'C:\x.exe'
    futureField = 'runs as DESKTOP-AUDIT01 account jsilva'; owner = 'S-1-5-18' })
$n8Diag['startup']['autoServices'] = @(
    [ordered]@{ name = 'CDPUserSvc_4a7f3c'; displayName = 'Connected Devices Platform User Service_4a7f3c'; state = 'Running'; startMode = 'Auto'; delayed = $false; pathName = 'C:\Windows\system32\svchost.exe -k UnistackSvcGroup'; account = 'LocalSystem' },
    [ordered]@{ name = 'wuauserv'; displayName = 'Windows Update'; state = 'Running'; startMode = 'Auto'; delayed = $true; pathName = 'C:\Windows\system32\svchost.exe -k netsvcs'; account = 'LocalSystem' },
    [ordered]@{ name = 'Svc_12'; displayName = 'Short suffix kept'; state = 'Running'; startMode = 'Auto'; delayed = $false; pathName = 'C:\x.exe'; account = 'LocalSystem' })
$n8Diag['system']['cpu']['name'] = 'CPU at host DESKTOP-AUDIT01 user jsilva'
$n8Diag['system']['vendorNote'] = ('owner ' + $n8Sid + ' / jsilva')
$n8Diag['advanced']['installedApps']['items'][0]['comments'] = ('Agent for DESKTOP-AUDIT01 ' + $n8Sid)
$n8Run = Invoke-FmpScoreDiag -Diag $n8Diag -Mode 'full'
$n8San = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $n8Run.Diag -PrivateIdentifiers @('DESKTOP-AUDIT01', 'jsilva')
$n8Json = ConvertTo-FmpJsonText -Data $n8San
$n8Html = Get-FmpRenderedHtml -Result @{ Sanitized = $n8San } -Lang 'en'
$n8HtmlPt = Get-FmpRenderedHtml -Result @{ Sanitized = $n8San } -Lang 'pt-BR'
foreach ($n8Needle in @('S-1-5-21-1004336348', '1177238915', '682003330', 'CDPUserSvc_4a7f3c', 'Service_4a7f3c', 'DESKTOP-AUDIT01', 'jsilva')) {
    Assert-FmpTrue -Name ('FMP-08: JSON compartilhavel nao contem ' + $n8Needle) -Condition (-not $n8Json.Contains($n8Needle))
    Assert-FmpTrue -Name ('FMP-08: HTML (EN e PT-BR) nao contem ' + $n8Needle) -Condition (-not $n8Html.Contains($n8Needle) -and -not $n8HtmlPt.Contains($n8Needle))
}
Assert-FmpTrue -Name 'FMP-08: dados diagnosticos legitimos preservados (servico, SID bem-conhecido, sufixo curto)' -Condition ($n8Json.Contains('wuauserv') -and $n8Json.Contains('S-1-5-18') -and $n8Json.Contains('Svc_12') -and $n8Json.Contains('OneDrive Reporting Task') -and $n8Json.Contains('CDPUserSvc_'))
Assert-FmpTrue -Name 'FMP-08: marcadores de substituicao no lugar dos identificadores' -Condition (($n8Json -match '(<|\\u003c)SID(>|\\u003e)') -and ($n8Json -match '_(<|\\u003c)LUID(>|\\u003e)') -and ($n8Json -match '(<|\\u003c)Identifier(>|\\u003e)'))
Assert-FmpTrue -Name 'FMP-08: HTML mostra o nome do servico sem o sufixo por usuario' -Condition ($n8Html.Contains('CDPUserSvc_&lt;LUID&gt;'))
# Unexpected-field coverage does not depend on field-name lists: the same text in a brand-new field is scrubbed too.
$n8San2 = ConvertTo-FmpSanitizedDiagnostic -Diagnostic @{ brandNewSection = @{ anyField = ('x ' + $n8Sid + ' y'); other = 'svc CaptureService_9f2e1a on DESKTOP-AUDIT01' } } -PrivateIdentifiers @('DESKTOP-AUDIT01')
$n8Json2 = ConvertTo-FmpJsonText -Data $n8San2
Assert-FmpTrue -Name 'FMP-08: campo nao previsto tambem e sanitizado (SID, LUID, computador)' -Condition (-not $n8Json2.Contains('1004336348') -and -not $n8Json2.Contains('9f2e1a') -and -not $n8Json2.Contains('DESKTOP-AUDIT01') -and ($n8Json2 -match 'CaptureService_(<|\\u003c)LUID(>|\\u003e)'))
# Short private identifiers (2 chars) are only applied to the original field list, so they cannot shred unrelated text.
$n8San3 = ConvertTo-FmpSanitizedDiagnostic -Diagnostic @{ brandNewSection = @{ anyField = 'Realtek jo audio driver' } } -PrivateIdentifiers @('jo')
Assert-FmpTrue -Name 'FMP-08: identificador de 2 caracteres nao destroi texto em campos nao listados' -Condition ((ConvertTo-FmpJsonText -Data $n8San3).Contains('Realtek jo audio driver'))

# Stage 8.1 FMP-08 regressions: correlated service displayName LUID, non-Svc prefix, varying lengths, benign preservation, XSS + LUID.
[System.Collections.IDictionary]$n8LuidDiag = Get-FmpHealthyDiag
$n8LuidDiag['startup']['autoServices'] = @(
    [ordered]@{ name = 'OneSyncSvc_1a2b3'; displayName = 'Sync Host_1a2b3'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'UserBroker_9e8d7c6b'; displayName = 'User Broker_9e8d7c6b'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'CustomAgent_a1b2c3d4e5f6'; displayName = 'Custom Agent_a1b2c3d4e5f6'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'OneSyncSvc_f0e1'; displayName = 'Short Hex_f0e1'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'XssSvc_1a2b3'; displayName = 'Sync Host_1a2b3<script>alert(1)</script>'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'Spooler'; displayName = 'Print Spooler'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'App_2024_x64'; displayName = 'App 2024 (x64)'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'Service_v2'; displayName = 'Service v2'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'Diff_dead'; displayName = 'Diff_beef'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' }
)
$n8LuidDiag['system']['vendorNote'] = 'App_2024 and Sync Host 1a2b3'
$n8LuidRun = Invoke-FmpScoreDiag -Diag $n8LuidDiag -Mode 'full'
$n8LuidSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $n8LuidRun.Diag
$n8LuidJson = ConvertTo-FmpJsonText -Data $n8LuidSan
$n8LuidHtmlEn = Get-FmpRenderedHtml -Result @{ Sanitized = $n8LuidSan } -Lang 'en'
$n8LuidHtmlPt = Get-FmpRenderedHtml -Result @{ Sanitized = $n8LuidSan } -Lang 'pt-BR'
foreach ($luidLeak in @('_1a2b3', '_9e8d7c6b', '_a1b2c3d4e5f6', '_f0e1')) {
    Assert-FmpTrue -Name ('FMP-08: JSON sanitizado nao vaza sufixo LUID ' + $luidLeak) -Condition (-not $n8LuidJson.Contains($luidLeak))
    Assert-FmpTrue -Name ('FMP-08: HTML EN/PT-BR nao vaza sufixo LUID ' + $luidLeak) -Condition (-not $n8LuidHtmlEn.Contains($luidLeak) -and -not $n8LuidHtmlPt.Contains($luidLeak))
}
Assert-FmpTrue -Name 'FMP-08: displayName com sufixo LUID compartilhado mascarado como Sync Host_<LUID>' -Condition ($n8LuidHtmlEn.Contains('Sync Host_&lt;LUID&gt;') -and $n8LuidHtmlPt.Contains('Sync Host_&lt;LUID&gt;'))
Assert-FmpTrue -Name 'FMP-08: strings legitimas e semelhantes preservadas sem falso positivo' -Condition (
    $n8LuidJson.Contains('Print Spooler') -and $n8LuidJson.Contains('App_2024_x64') -and
    $n8LuidJson.Contains('Service_v2') -and $n8LuidJson.Contains('Diff_dead') -and $n8LuidJson.Contains('Diff_beef') -and
    $n8LuidJson.Contains('App_2024 and Sync Host 1a2b3'))
Assert-FmpTrue -Name 'FMP-08: XSS com LUID escapado e sem tag script ativa' -Condition ($n8LuidHtmlEn.Contains('&lt;LUID&gt;&lt;script&gt;alert(1)&lt;/script&gt;') -and -not ($n8LuidHtmlEn -replace $printTag, '').Contains('<script>'))

# =====================================================================
Start-FmpSuite 'Q. Etapa 8.1 - truncamento de colecoes (0/1/149/150/151/300, coleta vs sanitizacao, aninhadas)'
foreach ($qCount in @(0, 1, 149, 150)) {
    [System.Collections.IDictionary]$qDiag = Get-FmpHealthyDiag
    $qItems = @(if ($qCount -gt 0) { 1..$qCount | ForEach-Object { [ordered]@{ displayName = ('App ' + $_); displayVersion = '1.0'; publisher = 'Pub'; source = 'hklm64' } } })
    $qDiag['advanced']['installedApps'] = [ordered]@{ status = 'ok'; totalCount = $qCount; truncated = $false; items = $qItems }
    $qSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $qDiag
    $qApps = $qSan['advanced']['installedApps']
    Assert-FmpTrue -Name ('Truncamento (' + $qCount + ' itens): sem falso truncamento nem aviso') -Condition (
        $qApps['truncated'] -eq $false -and $qApps['collectionTruncated'] -eq $false -and $qApps['sanitizedTruncated'] -eq $false -and
        [int]$qApps['totalCount'] -eq $qCount -and [int]$qApps['presentedCount'] -eq $qCount -and @($qApps['items']).Count -eq $qCount -and
        $qSan['privacy']['truncated'] -eq $false -and @($qSan['privacy']['truncatedCollections']).Count -eq 0)
    if ($qCount -eq 150) {
        $q150Html = Get-FmpRenderedHtml -Result @{ Sanitized = $qSan } -Lang 'pt-BR'
        Assert-FmpTrue -Name 'Truncamento (150 itens): HTML nao exibe aviso de truncamento na sanitizacao' -Condition (-not $q150Html.Contains('sanitizada limitada'))
    }
}
foreach ($qCount in @(151, 300)) {
    [System.Collections.IDictionary]$qDiag = Get-FmpHealthyDiag
    $qItems = @(1..$qCount | ForEach-Object { [ordered]@{ displayName = ('App ' + $_); displayVersion = '1.0'; publisher = 'Pub'; source = 'hklm64' } })
    $qDiag['advanced']['installedApps'] = [ordered]@{ status = 'ok'; totalCount = $qCount; truncated = $false; items = $qItems }
    $qSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $qDiag
    $qApps = $qSan['advanced']['installedApps']
    Assert-FmpTrue -Name ('Truncamento (' + $qCount + ' itens): sinaliza corte na sanitizacao sem perder totalCount') -Condition (
        $qApps['truncated'] -eq $true -and $qApps['collectionTruncated'] -eq $false -and $qApps['sanitizedTruncated'] -eq $true -and
        [int]$qApps['totalCount'] -eq $qCount -and [int]$qApps['presentedCount'] -eq 150 -and @($qApps['items']).Count -eq 150 -and
        $qSan['privacy']['truncated'] -eq $true -and @($qSan['privacy']['truncatedCollections']).Count -ge 1)
    $qEntry = @($qSan['privacy']['truncatedCollections'] | Where-Object { $_['path'] -eq 'advanced.installedApps.items' })[0]
    Assert-FmpTrue -Name ('Truncamento (' + $qCount + ' itens): registro em privacy.truncatedCollections com contagens exatas') -Condition ($null -ne $qEntry -and [int]$qEntry['originalCount'] -eq $qCount -and [int]$qEntry['retainedCount'] -eq 150)
}
# Originally truncated collection (350 total, 300 collected -> 150 sanitized; and 200 total, 120 collected -> 120 sanitized).
[System.Collections.IDictionary]$qOrigBoth = Get-FmpHealthyDiag
$qOrigBoth['advanced']['installedApps'] = [ordered]@{ status = 'ok'; totalCount = 350; truncated = $true; items = @(1..300 | ForEach-Object { [ordered]@{ displayName = ('App ' + $_) } }) }
$qOrigBothSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $qOrigBoth
$qObApps = $qOrigBothSan['advanced']['installedApps']
Assert-FmpTrue -Name 'Truncamento duplo (coleta 350->300 + sanitizacao 300->150): preserva ambos os sinais' -Condition (
    $qObApps['truncated'] -eq $true -and $qObApps['collectionTruncated'] -eq $true -and $qObApps['sanitizedTruncated'] -eq $true -and
    [int]$qObApps['totalCount'] -eq 350 -and [int]$qObApps['presentedCount'] -eq 150)
[System.Collections.IDictionary]$qOrigOnly = Get-FmpHealthyDiag
$qOrigOnly['advanced']['installedApps'] = [ordered]@{ status = 'ok'; totalCount = 200; truncated = $true; items = @(1..120 | ForEach-Object { [ordered]@{ displayName = ('App ' + $_) } }) }
$qOrigOnlySan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $qOrigOnly
$qOoApps = $qOrigOnlySan['advanced']['installedApps']
Assert-FmpTrue -Name 'Truncamento apenas na coleta (200->120): preserva collectionTruncated=true e sanitizedTruncated=false' -Condition (
    $qOoApps['truncated'] -eq $true -and $qOoApps['collectionTruncated'] -eq $true -and $qOoApps['sanitizedTruncated'] -eq $false -and
    [int]$qOoApps['totalCount'] -eq 200 -and [int]$qOoApps['presentedCount'] -eq 120 -and $qOrigOnlySan['privacy']['truncated'] -eq $false)

# Nested collections truncated during sanitization.
$qNested = [ordered]@{
    schemaVersion = '1.0.0'
    run = [ordered]@{ id = 'n'; toolVersion = '0.1.0'; mode = 'simple'; language = 'pt-BR'; synthetic = $true; startedAt = '2026-11-19T12:00:00Z'; finishedAt = '2026-11-19T12:00:10Z' }
    nested = [ordered]@{
        wrapper = [ordered]@{ truncated = $false; items = @(1..151) }
        rawList = @(1..152)
    }
}
$qNestedSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $qNested
Assert-FmpTrue -Name 'Colecoes aninhadas: wrapper e lista interna sinalizam truncamento' -Condition (
    $qNestedSan['privacy']['truncated'] -eq $true -and
    $qNestedSan['nested']['wrapper']['truncated'] -eq $true -and
    $qNestedSan['nested']['wrapper']['sanitizedTruncated'] -eq $true -and
    $qNestedSan['nested']['wrapper']['collectionTruncated'] -eq $false -and
    [int]$qNestedSan['nested']['wrapper']['presentedCount'] -eq 150 -and
    @($qNestedSan['privacy']['truncatedCollections'] | Where-Object { $_['path'] -eq 'nested.wrapper.items' }).Count -eq 1 -and
    @($qNestedSan['privacy']['truncatedCollections'] | Where-Object { $_['path'] -eq 'nested.rawList' }).Count -eq 1)

# =====================================================================
Start-FmpSuite 'O. Pontuacao - versao do algoritmo, nota provisoria honesta e falha de modulo fora da nota'
$o0 = Invoke-FmpScoreDiag -Diag (Get-FmpHealthyDiag)
Assert-FmpEqual -Name 'scoreAlgorithmVersion identifica o algoritmo (2.0 = FMP-01)' -Expected '2.0' -Actual ([string]$o0.Score.scoreAlgorithmVersion)
Assert-FmpEqual -Name 'scoreAlgorithmVersion chega ao JSON compartilhavel' -Expected '2.0' -Actual ([string]$o0.Sanitized['healthScore']['scoreAlgorithmVersion'])

# A provisional 100 (partial coverage) must not read as proven health.
$oLim = Invoke-FmpFixture -Fixture 'limited-access.json'
Assert-FmpTrue -Name 'limited-access: nota 100 provisoria com cobertura parcial' -Condition ($oLim.Score.status -eq 'provisional' -and [int]$oLim.Score.score -eq 100 -and [double]$oLim.Score.coveragePct -lt 100)
$oLimPt = Get-FmpRenderedHtml -Result $oLim -Lang 'pt-BR'
$oLimEn = Get-FmpRenderedHtml -Result $oLim -Lang 'en'
$null = $oLimPt -match '(?s)<div class="score-card tone-provisional">(.*?)</div><div class="exec-side">'
$oCardPt = [string]$Matches[1]
$null = $oLimEn -match '(?s)<div class="score-card tone-provisional">(.*?)</div><div class="exec-side">'
$oCardEn = [string]$Matches[1]
Assert-FmpTrue -Name 'nota provisoria PT-BR: o cartao diz que nao ha prova de saude e mostra a cobertura' -Condition ($oCardPt.Contains('Nenhum problema encontrado') -and $oCardPt.Contains('prova que') -and $oCardPt -match 'cobertura \d+')
Assert-FmpTrue -Name 'nota provisoria EN: o cartao diz que nao ha prova de saude e mostra a cobertura' -Condition ($oCardEn.Contains('No problem was found') -and $oCardEn.Contains('does not prove') -and $oCardEn -match 'coverage \d+')
$oOkHtml = Get-FmpRenderedHtml -Result $o0 -Lang 'en'
Assert-FmpTrue -Name 'nota completa (ok): sem o aviso de cobertura parcial no cartao' -Condition (-not $oOkHtml.Contains('does not prove'))
Assert-FmpTrue -Name 'nota provisoria mantem o numero no JSON (contrato) e o rotulo provisorio' -Condition ($oCardEn.Contains('Provisional score') -and $oCardEn.Contains('>100<'))

# A failed module that feeds no scored category cannot invalidate the score (FMP-01 excluded Startup: no base rule).
[System.Collections.IDictionary]$oStartDiag = Get-FmpHealthyDiag
for ($mi = 0; $mi -lt @($oStartDiag['modules']).Count; $mi++) { if ($oStartDiag['modules'][$mi]['id'] -eq 'startup') { $oStartDiag['modules'][$mi]['status'] = 'failed' } }
$oStart = Invoke-FmpScoreDiag -Diag $oStartDiag
$oStartCat = Get-FmpScoreCategory -Score $oStart.Score -Name 'startup'
Assert-FmpTrue -Name 'inicializacao falhou: categoria segue fora da nota (no_base_rules)' -Condition ($oStartCat.eligible -eq $false -and $oStartCat.excludedReason -eq 'no_base_rules')
Assert-FmpTrue -Name 'inicializacao falhou: a nota das categorias elegiveis continua disponivel' -Condition ($oStart.Score.status -ne 'unavailable' -and [int]$oStart.Score.score -eq [int]$o0.Score.score -and [int]$oStart.Score.eligibleWeight -eq [int]$o0.Score.eligibleWeight)
[System.Collections.IDictionary]$oStorDiag = Get-FmpHealthyDiag
for ($mi = 0; $mi -lt @($oStorDiag['modules']).Count; $mi++) { if ($oStorDiag['modules'][$mi]['id'] -eq 'storage') { $oStorDiag['modules'][$mi]['status'] = 'failed' } }
$oStor = Invoke-FmpScoreDiag -Diag $oStorDiag
Assert-FmpTrue -Name 'armazenamento falhou: nota continua indisponivel (contrato dos modulos-base preservado)' -Condition ($oStor.Score.status -eq 'unavailable' -and $null -eq $oStor.Score.score)

# =====================================================================
Start-FmpSuite 'P. FMP-09 - a flag de consentimento nao prova autorizacao humana (documentacao e adaptadores)'
foreach ($p9Rel in @('SKILL.md', 'adapters\claude\README.md', 'adapters\codex\AGENTS.md', 'README.md')) {
    $p9Text = [System.IO.File]::ReadAllText((Join-Path $root $p9Rel))
    Assert-FmpTrue -Name ('FMP-09: ' + $p9Rel + ' diz que -AcceptReadOnlyPolicy nao prova autorizacao humana') -Condition ($p9Text -match 'does not prove (that )?a human')
    Assert-FmpTrue -Name ('FMP-09: ' + $p9Rel + ' exige consentimento a cada execucao real') -Condition ($p9Text -match 'every real run')
}
foreach ($p9Rel in @('README.pt-BR.md', 'docs\readonly-policy.md')) {
    $p9Text = [System.IO.File]::ReadAllText((Join-Path $root $p9Rel))
    Assert-FmpTrue -Name ('FMP-09: ' + $p9Rel + ' diz que a flag nao prova autorizacao humana') -Condition ($p9Text -match 'n.o prova que um humano')
    Assert-FmpTrue -Name ('FMP-09: ' + $p9Rel + ' exige consentimento a cada execucao real') -Condition ($p9Text -match 'cada execu..o real')
}
$p9Policy = [System.IO.File]::ReadAllText((Join-Path $root 'docs\readonly-policy.md'))
Assert-FmpTrue -Name 'FMP-09: politica registra a avaliacao do token de consentimento e a razao de nao implementa-lo' -Condition ($p9Policy.Contains('-IssueConsentToken') -and $p9Policy -match 'N.o implementado')
# The existing gate is unchanged: no flag and no interactive answer means no collection.
Assert-FmpTrue -Name 'FMP-09: fluxo atual nao foi enfraquecido (sem flag e sem resposta nao ha consentimento)' -Condition (-not (Test-FmpCollectionConsent $false $false '') -and -not (Test-FmpCollectionConsent $false $true '') -and (Test-FmpCollectionConsent $true $false '' 'valid'))
# 2.0: the flag alone is only a declaration; it needs the -Plan token bound to this run.
Assert-FmpTrue -Name '2.0: -AcceptReadOnlyPolicy sozinho nao autoriza (token ausente, invalido ou expirado)' -Condition (-not (Test-FmpCollectionConsent $true $false '') -and -not (Test-FmpCollectionConsent $true $false '' 'scope_mismatch') -and -not (Test-FmpCollectionConsent $true $false '' 'expired'))

Start-FmpSuite 'I. Entrada do CLI com coletores isolados'
$mockRoot = Join-Path $scratch 'mock-project'
New-FmpOutputDirectory $mockRoot
$mockCollectors = @{
    'System.ps1' = 'Get-FmpSystemData'; 'Events.ps1' = 'Get-FmpEventData'; 'Startup.ps1' = 'Get-FmpStartupData'
    'Performance.ps1' = 'Get-FmpPerformanceData'; 'Storage.ps1' = 'Get-FmpStorageData'; 'Advanced.ps1' = 'Get-FmpAdvancedData'
    'Observation.ps1' = 'Get-FmpObservationData'; 'Investigations.ps1' = 'Invoke-FmpInvestigationPlan'
}
foreach ($relative in $script:FmpSourceFiles) {
    $target = Join-Path $mockRoot $relative
    New-FmpOutputDirectory (Split-Path -Parent $target)
    if ($relative -like 'src\collectors\*') {
        $entryPoint = $mockCollectors[(Split-Path -Path $target -Leaf)]
        Write-FmpUtf8File $target ("throw 'SYNTHETIC_COLLECTOR_REACHED'" + [Environment]::NewLine + 'function ' + $entryPoint + " { throw 'SYNTHETIC_COLLECTOR_REACHED' }")
    }
    else { Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative))) }
}
foreach ($relative in @('locales\pt-BR.json', 'locales\en.json', 'rules\rules.json', 'templates\style.css')) {
    $target = Join-Path $mockRoot $relative
    New-FmpOutputDirectory (Split-Path -Parent $target)
    Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative)))
}
Set-FmpAllowedWriteRoot $scratch
$mockCli = Join-Path $mockRoot 'fixmypc.ps1'
$deniedOut = Join-Path $scratch 'denied'
$invalidJson = Join-Path $scratch 'invalid-document.json'
Write-FmpUtf8File $invalidJson '{}'
$validFixture = Join-Path $root 'tests\fixtures\demo-synthetic.json'

& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Yes -OutDir $deniedOut *> $null
Assert-FmpEqual -Name '-Yes sozinho falha antes de carregar qualquer coletor' -Expected 3 -Actual $LASTEXITCODE
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -OutDir $deniedOut *> $null
Assert-FmpEqual -Name 'sem flags, host nao interativo exige consentimento' -Expected 3 -Actual $LASTEXITCODE
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture $invalidJson -AcceptReadOnlyPolicy -OutDir $deniedOut *> $null
Assert-FmpEqual -Name 'fixture invalida falha mesmo com consentimento' -Expected 3 -Actual $LASTEXITCODE
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture ' ' -AcceptReadOnlyPolicy -OutDir $deniedOut *> $null
Assert-FmpEqual -Name 'fixture vazia nao ativa coleta real' -Expected 3 -Actual $LASTEXITCODE
$previousPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Mode invalid -AcceptReadOnlyPolicy -OutDir $deniedOut *> $null
    $bindingExit = $LASTEXITCODE
}
finally { $ErrorActionPreference = $previousPreference }
Assert-FmpEqual -Name 'erro de binding falha antes de carregar coletores' -Expected 1 -Actual $bindingExit
Assert-FmpTrue -Name 'consentimento negado e fixture invalida nao criam saida' -Condition (-not (Test-Path -LiteralPath $deniedOut))
Assert-FmpTrue -Name 'respostas que comecam com Y ou 1 nao valem consentimento' -Condition (-not (Test-FmpCollectionConsent $false $true 'yesterday') -and -not (Test-FmpCollectionConsent $false $true '10'))
Assert-FmpTrue -Name 'resposta explicita ou flag com token valido valem consentimento' -Condition ((Test-FmpCollectionConsent $false $true ' SIM ') -and (Test-FmpCollectionConsent $true $false '' 'valid'))
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture $validFixture -Mode full -OutDir $deniedOut -IncludeInternalJson *> $null
Assert-FmpEqual -Name 'fixture Completa roda mesmo quando todo coletor interromperia a execucao' -Expected 0 -Actual $LASTEXITCODE
Assert-FmpTrue -Name 'JSON interno gerado somente com pedido explicito' -Condition (Test-Path -LiteralPath (Join-Path $deniedOut 'diagnostic-internal.json'))
$originalJson = [System.IO.File]::ReadAllText((Join-Path $deniedOut 'diagnostic-sanitized.json'))
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture $validFixture -OutDir $deniedOut *> $null
Assert-FmpEqual -Name 'CLI recusa diretorio com artefato anterior' -Expected 3 -Actual $LASTEXITCODE
Assert-FmpEqual -Name 'CLI preserva conteudo original' -Expected $originalJson -Actual ([System.IO.File]::ReadAllText((Join-Path $deniedOut 'diagnostic-sanitized.json')))

# Stage 8.1 E2E CLI regression in fixture mode for both blockers (LUID leak + 151->150 truncation).
$e2eFixturePath = Join-Path $scratch 'e2e-stage81-fixture.json'
$e2eOutPt = Join-Path $scratch 'e2e-stage81-pt'
$e2eOutEn = Join-Path $scratch 'e2e-stage81-en'
$e2eObj = (Read-FmpJsonFile -Path $validFixture).Data
$e2eSerializable = ConvertTo-FmpSerializable -Value $e2eObj
$e2eSerializable['startup']['autoServices'] = @(
    [ordered]@{ name = 'OneSyncSvc_1a2b3'; displayName = 'Sync Host_1a2b3'; state = 'Running'; startMode = 'Auto'; delayed = $false; account = 'LocalSystem' },
    [ordered]@{ name = 'wuauserv'; displayName = 'Windows Update'; state = 'Running'; startMode = 'Auto'; delayed = $true; account = 'LocalSystem' }
)
$e2eSerializable['advanced']['installedApps'] = [ordered]@{
    status = 'ok'
    totalCount = 151
    truncated = $false
    items = @(1..151 | ForEach-Object { [ordered]@{ displayName = ('Synthetic App ' + $_); displayVersion = '1.0'; publisher = 'FMP'; source = 'hklm64' } })
}
Write-FmpUtf8File -Path $e2eFixturePath -Text (ConvertTo-FmpJsonText -Data $e2eSerializable)
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture $e2eFixturePath -Mode full -Language pt-BR -OutDir $e2eOutPt -IncludeInternalJson *> $null
Assert-FmpEqual -Name 'E2E Etapa 8.1 PT-BR: CLI fixture exit 0' -Expected 0 -Actual $LASTEXITCODE
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -Fixture $e2eFixturePath -Mode full -Language en -OutDir $e2eOutEn *> $null
Assert-FmpEqual -Name 'E2E Etapa 8.1 EN: CLI fixture exit 0' -Expected 0 -Actual $LASTEXITCODE
$e2eSanPtText = [System.IO.File]::ReadAllText((Join-Path $e2eOutPt 'diagnostic-sanitized.json'))
$e2eIntPtText = [System.IO.File]::ReadAllText((Join-Path $e2eOutPt 'diagnostic-internal.json'))
$e2eHtmlPtText = [System.IO.File]::ReadAllText((Join-Path $e2eOutPt 'report.html'))
$e2eHtmlEnText = [System.IO.File]::ReadAllText((Join-Path $e2eOutEn 'report.html'))
$e2eSanPt = (Read-FmpJsonFile -Path (Join-Path $e2eOutPt 'diagnostic-sanitized.json')).Data
Assert-FmpTrue -Name 'E2E Etapa 8.1: JSON e HTML sanitizados sem vazamento de LUID' -Condition (
    -not $e2eSanPtText.Contains('1a2b3') -and -not $e2eHtmlPtText.Contains('1a2b3') -and -not $e2eHtmlEnText.Contains('1a2b3') -and
    $e2eHtmlPtText.Contains('Sync Host_&lt;LUID&gt;') -and $e2eHtmlEnText.Contains('Sync Host_&lt;LUID&gt;') -and
    $e2eIntPtText.Contains('OneSyncSvc_1a2b3') -and $e2eIntPtText.Contains('Sync Host_1a2b3'))
Assert-FmpTrue -Name 'E2E Etapa 8.1: JSON e HTML indicam truncamento de 151 para 150' -Condition (
    $e2eSanPt.advanced.installedApps.truncated -eq $true -and
    $e2eSanPt.advanced.installedApps.collectionTruncated -eq $false -and
    $e2eSanPt.advanced.installedApps.sanitizedTruncated -eq $true -and
    [int]$e2eSanPt.advanced.installedApps.totalCount -eq 151 -and
    [int]$e2eSanPt.advanced.installedApps.presentedCount -eq 150 -and
    @($e2eSanPt.advanced.installedApps.items).Count -eq 150 -and
    $e2eSanPt.privacy.truncated -eq $true -and
    $e2eHtmlPtText.Contains('150') -and $e2eHtmlPtText.Contains('151') -and
    $e2eHtmlEnText.Contains('150') -and $e2eHtmlEnText.Contains('151'))

# =====================================================================
Start-FmpSuite 'R. Etapa 10 - mensagens coerentes, unidades, SMART, eventos, privacidade e saida padrao'
# Stage 9 scenario: provisional coverage AND one Volsnap #36 finding. The card must not say "no problem found".
$r10 = Read-FmpJsonFile -Path (Join-Path $root 'tests\fixtures\limited-access.json')
$r10Diag = ConvertTo-FmpSerializable -Value $r10.Data
$r10Diag['events']['logs']['System']['groups'] = @([ordered]@{ provider = 'Volsnap'; eventId = 36; count = 1; maxLevel = 2
    firstSeen = '2026-11-19T11:00:00.000Z'; lastSeen = '2026-11-19T11:00:00.000Z'; occurrences = @([ordered]@{ at = '2026-11-19T11:00:00.000Z'; level = 2 }) })
$r10Res = Invoke-FmpScoreDiag -Diag $r10Diag -Mode 'simple'
Assert-FmpTrue -Name 'R1 cenario Etapa 9: nota provisoria com um achado Volsnap' -Condition ($r10Res.Score.status -eq 'provisional' -and @($r10Res.Analysis.findings | Where-Object { $_.id -eq 'storage.disk_event_errors' }).Count -eq 1)
$r10Pt = Get-FmpRenderedHtml -Result $r10Res -Lang 'pt-BR'
$r10En = Get-FmpRenderedHtml -Result $r10Res -Lang 'en'
$null = $r10Pt -match '(?s)<div class="score-card tone-provisional[^"]*">(.*?)</div><div class="exec-side">'
$r10CardPt = [string]$Matches[1]
$null = $r10En -match '(?s)<div class="score-card tone-provisional[^"]*">(.*?)</div><div class="exec-side">'
$r10CardEn = [string]$Matches[1]
Assert-FmpTrue -Name 'R1 PT-BR: cartao nao diz "nenhum problema" quando ha achado' -Condition (-not $r10CardPt.Contains('Nenhum problema') -and $r10CardPt.Contains('1 achado nas verifica') -and $r10CardPt.Contains('incompleta'))
Assert-FmpTrue -Name 'R1 EN: cartao nao diz "no problem" quando ha achado' -Condition (-not $r10CardEn.Contains('No problem') -and $r10CardEn.Contains('1 finding in the checks') -and $r10CardEn.Contains('incomplete'))
Assert-FmpTrue -Name 'R2 PT-BR: singular "1 achado" e unidade de segundos no resumo' -Condition ($r10Pt -match '<p class="lead">[^<]* em [0-9,]+ segundos\. [^<]*: 1 achado, ' -and $r10Pt -notmatch '1 achados')
Assert-FmpTrue -Name 'R2 EN: singular "1 finding" e unidade de segundos no resumo' -Condition ($r10En -match '<p class="lead">[^<]* in [0-9.]+ seconds\. [^<]*: 1 finding, ' -and $r10En -notmatch '1 findings')
Assert-FmpTrue -Name 'R2 tempo por modulo com unidade ms e coluna Duracao' -Condition ($r10En.Contains('<th scope="col">Duration</th>') -and $r10En -match '>\d[\d,.]* ms<' -and $r10Pt.Contains('Dura&#231;&#227;o'))
Assert-FmpTrue -Name 'R3 SMART inacessivel: estado do provedor nao certifica integridade fisica' -Condition ($r10Pt.Contains('n&#227;o certifica a integridade f&#237;sica') -and $r10En.Contains('does not certify the physical integrity') -and $locEn.'table.health' -eq 'Health (reported by Windows)' -and $locPt.'table.health' -match 'informada pelo Windows')
Assert-FmpTrue -Name 'R4 log com status ok aparece como consulta concluida, nao como OK' -Condition ($r10Pt.Contains('<span class="st ok">Consulta conclu&#237;da</span>') -and $r10En.Contains('<span class="st ok">Query completed</span>'))
Assert-FmpTrue -Name 'R5 Volsnap: texto nao afirma defeito fisico' -Condition ($r10Pt.Contains('n&#227;o comprova defeito f&#237;sico') -and $r10En.Contains('does not prove a physical defect'))
Assert-FmpTrue -Name 'R6 compartilhamento com IA e opcional, revisado e sem envio automatico (PT/EN)' -Condition (
    $r10Pt.Contains('Compartilhar &#233; opcional, nada &#233; enviado automaticamente e a anonimiza&#231;&#227;o n&#227;o &#233; perfeita') -and
    $r10En.Contains('Sharing is optional, nothing is sent automatically and anonymization is not perfect') -and
    $r10Pt -notmatch 'anexe-o' -and $r10En -notmatch 'attach it to your AI')
$r10Stage9Shape = Get-FmpFinding -Result $r10Res -RuleId 'storage.disk_event_errors'
Assert-FmpEqual -Name 'R5 Volsnap: peso diagnostico inalterado (6 pontos, review_recommended)' -Expected '6|review_recommended' -Actual ([string]$r10Stage9Shape.penalty + '|' + [string]$r10Stage9Shape.severity)
# Healthy, complete coverage, two inconclusive vs one: plural forms.
Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR'
Assert-FmpTrue -Name 'R2 plural PT-BR: 1 modulo / 2 modulos / 1 inconclusiva / 0 inconclusivas' -Condition ((Get-FmpCountText -Key 'count.modules' -N 1) -eq ('1 m' + [char]0x00F3 + 'dulo') -and (Get-FmpCountText -Key 'count.modules' -N 2) -eq ('2 m' + [char]0x00F3 + 'dulos') -and (Get-FmpCountText -Key 'count.inconclusive' -N 1) -eq '1 inconclusiva' -and (Get-FmpCountText -Key 'count.inconclusive' -N 0) -eq '0 inconclusivas')
# Sanitizer: dictionary keys, IPv6, domains - synthetic values only.
$r10Priv = [ordered]@{ schemaVersion = '1.0.0'
    system = [ordered]@{ hosts = [ordered]@{ 'WORKPC-7731' = 'seen' }
        note = 'peer fe80::1c2b:3a4d:5e6f:7081%12 and 2001:db8:85a3::8a2e:370:7334 and 2001:0db8:0000:0000:0000:ff00:0042:8329 at 2026-11-21T11:54:00Z'
        detail = 'joined CORPDOM / corp.example.local'; keep = 'std::vector at 11:54:00 build 10.0.26300' } }
$r10PrivSan = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $r10Priv -PrivateIdentifiers @('WORKPC-7731', 'CORPDOM', 'corp.example.local')
$r10PrivText = ConvertTo-Json $r10PrivSan -Depth 6
Assert-FmpTrue -Name 'R7 chave de dicionario com nome do computador e mascarada' -Condition (-not $r10PrivText.Contains('WORKPC-7731') -and $r10PrivSan['system']['hosts'].Contains('<Identifier>'))
Assert-FmpTrue -Name 'R7 IPv6 (comprimido, com zona e completo) mascarado' -Condition (-not $r10PrivText.Contains('fe80') -and -not $r10PrivText.Contains('2001:') -and $r10PrivSan['system']['note'] -match '^peer <IP> and <IP> and <IP> at 2026-11-21T11:54:00Z$')
Assert-FmpTrue -Name 'R7 dominio NetBIOS e DNS mascarados quando informados como identificadores' -Condition (-not $r10PrivText.Contains('CORPDOM') -and -not $r10PrivText.Contains('corp.example.local'))
Assert-FmpEqual -Name 'R7 sem falso positivo em horas, ::, e versoes' -Expected 'std::vector at 11:54:00 build 10.0.26300' -Actual $r10PrivSan['system']['keep']
$r10Cli = [System.IO.File]::ReadAllText((Join-Path $root 'fixmypc.ps1'))
Assert-FmpTrue -Name 'R7 CLI passa USERDOMAIN e USERDNSDOMAIN ao sanitizador' -Condition ($r10Cli.Contains('$env:USERDOMAIN') -and $r10Cli.Contains('$env:USERDNSDOMAIN'))
# Default output: %LOCALAPPDATA%\FixMyPC, never the install folder. Mock project (collectors throw) + redirected LOCALAPPDATA.
$r10Lad = Join-Path $scratch 'fake-localappdata'
# The environment change happens only inside this child helper, never in the test process.
Set-FmpAllowedWriteRoot $scratch
$r10Helper = Join-Path $scratch 'default-outdir-helper.ps1'
Write-FmpUtf8File $r10Helper (@(
    'param([string]$Cli, [string]$Fixture, [string]$Lad)',
    '$env:LOCALAPPDATA = $Lad',
    '$o = (& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli -Fixture $Fixture -Mode simple -Language en -Yes *>&1) -join " "',
    '$e1 = $LASTEXITCODE',
    '$env:LOCALAPPDATA = ""',
    '& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli -Fixture $Fixture -Mode simple -Language en -Yes *> $null',
    'Write-Output ("EXIT1=" + $e1 + " EXIT2=" + $LASTEXITCODE + " OUT=" + $o)'
) -join [Environment]::NewLine)
New-FmpOutputDirectory $r10Lad
$r10Out = [string](& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $r10Helper -Cli $mockCli -Fixture $validFixture -Lad $r10Lad)
$r10Exit = -1; $r10ExitNoLad = -1
if ($r10Out -match '^EXIT1=(\d+) EXIT2=(\d+) ') { $r10Exit = [int]$Matches[1]; $r10ExitNoLad = [int]$Matches[2] }
$r10Runs = @(Get-ChildItem -LiteralPath (Join-Path $r10Lad 'FixMyPC') -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })
Assert-FmpTrue -Name 'R8 saida padrao vai para %LOCALAPPDATA%\FixMyPC\fixmypc-*' -Condition ($r10Exit -eq 0 -and $r10Runs.Count -eq 1 -and $r10Runs[0].Name -like 'fixmypc-*' -and (Test-Path -LiteralPath (Join-Path $r10Runs[0].FullName 'report.html')))
Assert-FmpTrue -Name 'R8 saida padrao nunca dentro da pasta instalada' -Condition (-not (Test-Path -LiteralPath (Join-Path $mockRoot 'out')))
Assert-FmpEqual -Name 'R8 sem LOCALAPPDATA e sem -OutDir: falha segura (exit 3)' -Expected 3 -Actual $r10ExitNoLad
Assert-FmpTrue -Name 'R8 unidade NTFS fora do OneDrive: sem aviso de permissoes nem de nuvem' -Condition (-not $r10Out.Contains('does not support Windows folder permissions') -and -not $r10Out.Contains('synchronized with the cloud'))
Assert-FmpTrue -Name 'R8 CLI nao imprime o caminho do JSON interno quando ele nao e pedido' -Condition (-not $r10Out.Contains('diagnostic-internal.json'))
# S11-01/S11-02: the output folder is created private even under a parent with inherited permissive ACEs (the test
# scratch lives in the repo's out\, which inherits drive-level grants). ACLs are only read, inside the child helper.
Set-FmpAllowedWriteRoot $scratch
$s11Helper = Join-Path $scratch 's11-acl-helper.ps1'
Write-FmpUtf8File $s11Helper (@(
    'param([string]$Cli, [string]$Fixture, [string]$Base)',
    '$out = Join-Path $Base "nested\run"',
    '& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli -Fixture $Fixture -Mode simple -Language en -Yes -OutDir $out *> $null',
    '$e1 = $LASTEXITCODE',
    '$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
    '$okSids = @($me, "S-1-5-18")',
    '$only = $true',
    'foreach ($p in @((Join-Path $Base "nested"), $out, (Join-Path $out "report.html"), (Join-Path $out "diagnostic-sanitized.json"))) {',
    '    foreach ($r in (Get-Acl -LiteralPath $p).Access) { if ($r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $okSids) { $only = $false } }',
    '}',
    '$prot = (Get-Acl -LiteralPath $out).AreAccessRulesProtected',
    '& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli -Fixture $Fixture -Mode simple -Language en -Yes -OutDir $out *> $null',
    '$e2 = $LASTEXITCODE',
    '$env:OneDrive = Join-Path $Base "sync"',
    '$o = (& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $Cli -Fixture $Fixture -Mode simple -Language en -Yes -OutDir (Join-Path $Base "sync\r") *>&1) -join " "',
    'Write-Output ("EXIT1=" + $e1 + " ONLY=" + $only + " PROT=" + $prot + " EXIT2=" + $e2 + " SYNC=" + $o.Contains("synchronized with the cloud"))'
) -join [Environment]::NewLine)
$s11Out = [string](& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $s11Helper -Cli $mockCli -Fixture $validFixture -Base (Join-Path $scratch 's11'))
Assert-FmpTrue -Name 'S11-01 pasta nova criada pela execucao (exit 0)' -Condition ($s11Out -match 'EXIT1=0 ')
Assert-FmpTrue -Name 'S11-01 pasta, pais criados e artefatos so com usuario atual e SYSTEM' -Condition ($s11Out -match ' ONLY=True ')
Assert-FmpTrue -Name 'S11-01 ACL da pasta de saida protegida (sem heranca da pasta-mae)' -Condition ($s11Out -match ' PROT=True ')
Assert-FmpTrue -Name 'S11-01 pasta de saida existente e recusada (exit 3)' -Condition ($s11Out -match ' EXIT2=3 ')
Assert-FmpTrue -Name 'S11-02 pasta dentro do OneDrive gera aviso antes do consentimento' -Condition ($s11Out -match ' SYNC=True$')
$s11Cli = [System.IO.File]::ReadAllText((Join-Path $root 'fixmypc.ps1'))
Assert-FmpTrue -Name 'S11-04 -Help e exemplo do cabecalho sem out\ nem C:\temp' -Condition (-not $s11Cli.Contains('default: out\') -and -not $s11Cli.Contains('C:\temp'))
# The runtime package ships no tests: -ValidateOnly must still pass there, while production sources stay mandatory.
Assert-FmpTrue -Name 'R9 pacote sem tests/: conformidade com IncludeTests passa' -Condition ((Test-FmpReadOnlyCompliance -Root $mockRoot -IncludeTests).Ok)
& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $mockCli -ValidateOnly *> $null
Assert-FmpEqual -Name 'R9 pacote sem tests/: -ValidateOnly exit 0' -Expected 0 -Actual $LASTEXITCODE

& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $root 'tests\Collector.Tests.ps1') *> $null
Assert-FmpEqual -Name 'Suite isolada dos 6 coletores: exit 0' -Expected 0 -Actual $LASTEXITCODE

& powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $root 'tests\Visual.Tests.ps1') *> $null
Assert-FmpEqual -Name 'Suite visual do redesign (assets, CSP, escape, estados, impressao): exit 0' -Expected 0 -Actual $LASTEXITCODE

# =====================================================================
Write-Host ''
Write-Host ('==== RESUMO: ' + $script:PassCount + ' passaram, ' + $script:FailCount + ' falharam ====')
if ($script:FailCount -gt 0) {
    foreach ($f in $script:Failures) { Write-Host ('  FAIL: ' + $f) -ForegroundColor Red }
    exit 1
}
exit 0
