# =====================================================================
# FIX MY PC - PhaseA.Tests.ps1
# Offline suite for Phase A: committed memory, per-process I/O, groups,
# event catalog, incident time and correlation. Uses ONLY synthetic data
# and mocked providers: no CIM, event log or real collection. The CLI is
# called only with -Fixture or -Plan, which never touch the system. Run:
#   powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\PhaseA.Tests.ps1
# =====================================================================
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
. (Join-Path $root 'src\collectors\Observation.ps1')
. (Join-Path $root 'src\collectors\Events.ps1')

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
function Start-FmpSuite { param([string]$Name) $script:CurrentSuite = $Name; Write-Host ('== ' + $Name + ' ==') }

$scratch = Join-Path $root ('out\fmp-phasea-tests-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $scratch
$ruleConfig = Get-FmpRuleConfig -Root $root
$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data

# ---------------------------------------------------------------------
# Mocks: these functions shadow the real cmdlets for everything below.
# ---------------------------------------------------------------------
function Start-Sleep { param([int]$Seconds) }
# Fail closed: a query the suite did not mock is an error and never a collection.
function Get-Process { throw 'UNMOCKED_SYSTEM_COMMAND: Get-Process' }
function Get-PhysicalDisk { throw 'UNMOCKED_SYSTEM_COMMAND: Get-PhysicalDisk' }
function Get-StorageReliabilityCounter { throw 'UNMOCKED_SYSTEM_COMMAND: Get-StorageReliabilityCounter' }

function New-RawProc {
    param([string]$Name, [uint64]$ProcId, [uint64]$Start, [int]$Tick, $Commit, $Ws, $WsPrivate, [uint64]$Cpu = 0, [uint64]$RB = 0, [uint64]$WB = 0, [uint64]$RO = 0, [uint64]$WO = 0)
    $stamp = [uint64](1000000000 + $Tick * 50000000)
    return [pscustomobject]@{
        Name = $Name; IDProcess = $ProcId; ElapsedTime = $Start; PercentProcessorTime = $Cpu
        WorkingSet = $Ws; WorkingSetPrivate = $WsPrivate; PrivateBytes = $Commit
        IOReadBytesPersec = $RB; IOWriteBytesPersec = $WB; IOReadOperationsPersec = $RO; IOWriteOperationsPersec = $WO
        Timestamp_Sys100NS = $stamp; Timestamp_PerfTime = $stamp; Frequency_PerfTime = [uint64]10000000
        Timestamp_Object = $stamp; Frequency_Object = [uint64]10000000
    }
}

$script:ProcTick = -1
$script:ProcTicks = @{}
foreach ($t in 0..2) {
    $l = New-Object System.Collections.Generic.List[object]
    # Commit far above the resident memory: must rank first by commit and stay low by Working Set.
    $l.Add((New-RawProc 'HiddenCommit' 100 500000000 $t (8.5 * 1GB) (350MB) (300MB) -RB ([uint64](900GB + $t * 10MB)) -RO ([uint64](1000000 + $t * 10))))
    $l.Add((New-RawProc 'BigResident' 200 500000000 $t (3GB) (3GB) (2900MB)))
    # Two instances whose individual peaks happen at different ticks: simultaneous peak 4 GB, sum of peaks 6 GB.
    $a = @(1GB, 3GB, 1GB)[$t]; $b = @(3GB, 1GB, 1GB)[$t]
    $l.Add((New-RawProc 'chrome' 301 500000000 $t $a (200MB) (150MB)))
    $l.Add((New-RawProc 'chrome#1' 302 500000000 $t $b (200MB) (150MB)))
    # Same PID, new process after tick 0: its small counters must not be subtracted from the old process's huge ones.
    if ($t -eq 0) { $l.Add((New-RawProc 'Reused' 400 500000000 $t (100MB) (50MB) (40MB) -RB ([uint64]5000000000))) }
    else { $l.Add((New-RawProc 'Reused' 400 900000000 $t (100MB) (50MB) (40MB) -RB ([uint64]($t * 1000)))) }
    if ($t -lt 2) { $l.Add((New-RawProc 'ShortLived' 500 500000000 $t (100MB) (50MB) (40MB))) }
    $l.Add((New-RawProc 'CounterReset' 600 500000000 $t (100MB) (50MB) (40MB) -RB ([uint64]@(1000, 2000, 500)[$t])))
    $l.Add((New-RawProc 'NoPrivate' 700 500000000 $t $null (100MB) (90MB)))
    # A huge lifetime counter that does not move in the window: recent activity is zero.
    $l.Add((New-RawProc 'OldCumulative' 800 500000000 $t (100MB) (50MB) (40MB) -RB ([uint64]5000000000000)))
    $script:ProcTicks[$t] = $l.ToArray()
}

function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [string[]]$Property, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_Processor' { return [pscustomobject]@{ NumberOfLogicalProcessors = 8 } }
        'Win32_OperatingSystem' { return [pscustomobject]@{ TotalVisibleMemorySize = 16777216 } }
        'Win32_PerfRawData_PerfProc_Process' { $script:ProcTick++; return $script:ProcTicks[$script:ProcTick] }
        default { return @() }
    }
}

$script:MockEvents = @()
$script:MockOldest = $null
$script:AbsentProviders = @()
function New-MockEvent {
    param([string]$Provider, [int]$Id, [int]$Level, [datetime]$At, [string]$Xml = '<Event/>')
    $e = [pscustomobject]@{ ProviderName = $Provider; Id = $Id; Level = $Level; TimeCreated = $At; RecordId = [Guid]::NewGuid().ToString() }
    $e | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Value ([scriptblock]::Create("return '" + $Xml + "'"))
    return $e
}
function Get-WinEvent {
    [CmdletBinding()]
    param([hashtable]$FilterHashtable, [int]$MaxEvents, [switch]$Oldest)
    if ($Oldest) { return $script:MockOldest }
    if (-not $FilterHashtable.ContainsKey('ProviderName')) { return @() }
    $p = [string]$FilterHashtable['ProviderName']
    if ($p -in $script:AbsentProviders) {
        $err = New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception 'no provider'), 'NoMatchingProvidersFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
        $PSCmdlet.ThrowTerminatingError($err)
    }
    # Deliberately ignores Level: the catalog must apply each pair's levels itself.
    return @($script:MockEvents | Where-Object { $_.ProviderName -ceq $p -and $_.Id -in @($FilterHashtable['Id']) } | Select-Object -First $MaxEvents)
}

function Get-FmpFixtureDoc {
    param([string]$Name)
    $fx = Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $Name))
    if (-not $fx.Ok) { throw ('fixture load failed: ' + $Name) }
    return (ConvertTo-FmpSerializable -Value $fx.Data)
}

function Invoke-FmpDx {
    param([System.Collections.IDictionary]$Doc, [string]$Symptom = 'crash', [string]$Lang = 'pt-BR', [string[]]$Ids = @())
    $mode = [string]$Doc['run']['mode']
    $analysis = Invoke-FmpRules -Diagnostic $Doc -RuleConfig $ruleConfig -Mode $mode
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue $Doc 'modules')
    $dx = Get-FmpDiagnosis -Diagnostic $Doc -Analysis $analysis -RuleConfig $ruleConfig -Symptom $Symptom
    $locs = @($locPt, $locEn)
    if ($Lang -eq 'en') { $locs = @($locEn, $locPt) }
    Add-FmpDiagnosisText -Diagnosis $dx -Locales $locs -Language $Lang
    $Doc['run']['language'] = $Lang
    $Doc['analysis'] = $analysis
    $Doc['healthScore'] = $score
    $Doc['diagnosis'] = $dx
    $san = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $Doc -PrivateIdentifiers $Ids
    return @{ Dx = $dx; Score = $score; Sanitized = $san; Doc = $Doc }
}

function Get-Q { param($Res, [string]$Id) return @(@($Res.Dx['questions']) | Where-Object { $_['id'] -eq $Id })[0] }

function New-CatalogDoc {
    # A real fixture plus a catalog built by the same pure function the collector uses.
    param([object[]]$Records = @(), [object]$OldestAt = $null, [object]$Incident = $null, [string[]]$Absent = @(), [string]$Fixture = 'diag-slow-use.json')
    $doc = Get-FmpFixtureDoc $Fixture
    $end = (Get-FmpParsedDate $doc['run']['finishedAt']).ToUniversalTime()
    $catalog = @(Get-FmpEventCatalog)
    $state = @{}
    foreach ($c in $catalog) {
        $st = 'empty'
        if ($c.provider -in $Absent) { $st = 'provider_absent' }
        elseif (@($Records | Where-Object { $_['provider'] -ceq $c.provider }).Count -gt 0) { $st = 'ok' }
        $state[$c.provider] = @{ status = $st; truncated = $false }
    }
    if ($null -eq $OldestAt) { $OldestAt = $end.AddDays(-60) }
    $since = $end.AddDays(-30)
    $doc['events']['catalog'] = [ordered]@{
        version = '1'; state = 'pass'; channel = 'System'; windowDays = 30; since = $since.ToString('yyyy-MM-ddTHH:mm:ssZ'); maxPerProvider = 300; anyTruncated = $false
        retention = [ordered]@{ status = 'ok'; oldestAt = ([datetime]$OldestAt).ToString('yyyy-MM-ddTHH:mm:ssZ'); coversWindow = (([datetime]$OldestAt) -le $since) }
        entries = @(ConvertTo-FmpCatalogEntries -Catalog $catalog -ProviderState $state -Records $Records)
    }
    if ($null -ne $Incident) { $doc['run']['incident'] = $Incident }
    return $doc
}

function New-Rec { param([string]$Provider, [int]$Id, [int]$Level, [datetime]$At, $StepSec = $null) return @{ provider = $Provider; id = $Id; level = $Level; at = $At; stepSec = $StepSec } }

$refDoc = Get-FmpFixtureDoc 'diag-slow-use.json'
$refEnd = (Get-FmpParsedDate $refDoc['run']['finishedAt']).ToUniversalTime()

# =====================================================================
Start-FmpSuite 'A1. Memoria: Private Bytes versus Working Set'
$obsMod = Get-FmpObservationData -DurationSec 10 -IntervalSec 5 -TopProcesses 20
$procs = $obsMod['data']['processes']
Assert-FmpEqual -Name 'coleta sintetica de processos concluida' -Expected 'pass' -Actual $procs['state']
$topC = @($procs['topCommit'])
Assert-FmpEqual -Name 'commit alto com Working Set baixo fica em 1o por memoria comprometida' -Expected 'HiddenCommit' -Actual $topC[0]['name']
Assert-FmpEqual -Name 'commitPrivateMB vem de PrivateBytes' -Expected 8704 -Actual $topC[0]['commitPrivateMB']
Assert-FmpEqual -Name 'workingSetMB vem de WorkingSet' -Expected 350 -Actual $topC[0]['workingSetMB']
Assert-FmpEqual -Name 'workingSetPrivateMB vem de WorkingSetPrivate' -Expected 300 -Actual $topC[0]['workingSetPrivateMB']
Assert-FmpEqual -Name 'privateMB legado preserva o significado antigo' -Expected 300 -Actual $topC[0]['privateMB']
Assert-FmpEqual -Name 'topMemory legado continua ordenado por Working Set privado' -Expected 'BigResident' -Actual @($procs['topMemory'])[0]['name']
$noPriv = @(@($procs['topMemory']) | Where-Object { $_['name'] -eq 'NoPrivate' })[0]
Assert-FmpTrue -Name 'PrivateBytes ausente vira null, nunca 0' -Condition ($null -eq $noPriv['commitPrivateMB'])
Assert-FmpTrue -Name 'processo sem PrivateBytes nao entra no ranking de commit' -Condition (@($topC | Where-Object { $_['name'] -eq 'NoPrivate' }).Count -eq 0)
Assert-FmpEqual -Name 'crescimento usa primeira e ultima leitura' -Expected 0 -Actual $topC[0]['commitGrowthMB']
Assert-FmpTrue -Name 'PID e horario de inicio identificam a instancia' -Condition ($topC[0]['pid'] -eq 100 -and [string]$topC[0]['startedAt'] -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

# =====================================================================
Start-FmpSuite 'A2. I/O por processo e agregacao'
$rows = @($procs['topMemory'])
$hid = @($rows | Where-Object { $_['name'] -eq 'HiddenCommit' })[0]
Assert-FmpEqual -Name 'taxa de leitura = delta / tempo real, nao o acumulado de 900 GB' -Expected 2097152 -Actual $hid['readBytesPerSec']
Assert-FmpEqual -Name 'operacoes de leitura por segundo' -Expected 2 -Actual $hid['readOpsPerSec']
$old = @($rows | Where-Object { $_['name'] -eq 'OldCumulative' })[0]
Assert-FmpEqual -Name 'contador cumulativo parado = atividade recente 0' -Expected 0 -Actual $old['readBytesPerSec']
Assert-FmpTrue -Name 'processo sem atividade recente nao aparece em topIo' -Condition (@(@($procs['topIo']) | Where-Object { $_['name'] -eq 'OldCumulative' }).Count -eq 0)
$reused = @($rows | Where-Object { $_['pid'] -eq 400 })
Assert-FmpEqual -Name 'PID reutilizado gera duas instancias separadas' -Expected 2 -Actual $reused.Count
$new = @($reused | Where-Object { $_['ioIntervals'] -eq 1 })[0]
Assert-FmpEqual -Name 'instancia nova calcula taxa so com seus proprios contadores' -Expected 200 -Actual $new['readBytesPerSec']
Assert-FmpTrue -Name 'instancia antiga do PID reutilizado marcada como encerrada' -Condition (@($reused | Where-Object { $_['exited'] -eq $true }).Count -eq 1)
$short = @($rows | Where-Object { $_['name'] -eq 'ShortLived' })[0]
Assert-FmpTrue -Name 'processo encerrado na janela marcado' -Condition ($short['exited'] -eq $true)
Assert-FmpEqual -Name 'contagem de encerrados na janela' -Expected 2 -Actual $procs['exitedDuringWindow']
$reset = @($rows | Where-Object { $_['name'] -eq 'CounterReset' })[0]
Assert-FmpEqual -Name 'contador reiniciado invalida so aquele intervalo' -Expected 1 -Actual $reset['ioInvalidIntervals']
Assert-FmpEqual -Name 'taxa ignora o intervalo com contador reiniciado' -Expected 200 -Actual $reset['readBytesPerSec']
$bad = Get-FmpProcessIoInterval ([pscustomobject]@{ Timestamp_PerfTime = 10; Frequency_PerfTime = 10; IOReadBytesPersec = 5; IOWriteBytesPersec = 5; IOReadOperationsPersec = 5; IOWriteOperationsPersec = 5 }) ([pscustomobject]@{ Timestamp_PerfTime = 10; Frequency_PerfTime = 10; IOReadBytesPersec = 9; IOWriteBytesPersec = 9; IOReadOperationsPersec = 9; IOWriteOperationsPersec = 9 })
Assert-FmpTrue -Name 'intervalo de duracao zero nao gera taxa' -Condition ($null -eq $bad['seconds'] -and $null -eq $bad['readBytes'])
$miss = Get-FmpProcessIoInterval ([pscustomobject]@{ Timestamp_PerfTime = 10; Frequency_PerfTime = 10 }) ([pscustomobject]@{ Timestamp_PerfTime = 20; Frequency_PerfTime = 10 })
Assert-FmpTrue -Name 'contador indisponivel fica null, nunca 0' -Condition ($null -eq $miss['readBytes'] -and $null -eq $miss['writeOps'])
$shareSum = 0.0
foreach ($r in $rows) { if ($null -ne $r['ioSharePct']) { $shareSum += $r['ioSharePct'] } }
Assert-FmpTrue -Name 'participacao de I/O soma cerca de 100%' -Condition ([Math]::Abs($shareSum - 100) -le 0.5) -Detail ('soma=' + $shareSum)
$groups = @($procs['appGroups'])
$chrome = @($groups | Where-Object { $_['name'] -eq 'chrome' })[0]
Assert-FmpEqual -Name 'sufixo #n removido e instancias agregadas' -Expected 2 -Actual $chrome['instancesMax']
Assert-FmpEqual -Name 'pico do grupo e soma simultanea (4 GB), nao soma de maximos (6 GB)' -Expected 4096 -Actual $chrome['commitPeakMB']
Assert-FmpEqual -Name 'media do grupo usa o total de cada leitura' -Expected 3413.3 -Actual $chrome['commitAvgMB']
Assert-FmpEqual -Name 'base do agrupamento declarada como nome do executavel' -Expected 'executable_name' -Actual $procs['appGroupBasis']
Assert-FmpTrue -Name 'grupo com PrivateBytes ausente marcado como incompleto' -Condition (@($groups | Where-Object { $_['name'] -eq 'NoPrivate' })[0]['commitIncomplete'] -eq $true)
$lim = @($obsMod['limits'] | ForEach-Object { $_['key'] })
Assert-FmpTrue -Name 'limitacoes de I/O e de agrupamento registradas' -Condition ('process_io_scope' -in $lim -and 'process_group_basis' -in $lim)

# =====================================================================
Start-FmpSuite 'A3. Catalogo de eventos: provedor + ID + nivel'
$t0 = [DateTime]::UtcNow.AddDays(-2)
$script:AbsentProviders = @('stornvme')
$script:MockOldest = [pscustomobject]@{ TimeCreated = [DateTime]::UtcNow.AddDays(-5) }
$script:MockEvents = @(
    (New-MockEvent 'nvlddmkm' 153 2 $t0)
    (New-MockEvent 'Display' 4101 3 $t0.AddDays(16 / 86400))
    (New-MockEvent 'disk' 153 3 $t0.AddDays(-1))
    (New-MockEvent 'disk' 153 4 $t0.AddDays(-1))
    (New-MockEvent 'Tcpip' 4266 3 $t0)
    (New-MockEvent 'User32' 1074 4 $t0)
    (New-MockEvent 'Microsoft-Windows-Kernel-General' 1 4 $t0 "<Data Name=`"TimeDeltaInMs`">15</Data>")
    (New-MockEvent 'Microsoft-Windows-Kernel-General' 1 4 $t0 "<Data Name=`"TimeDeltaInMs`">3600000</Data>")
)
$evMod = Get-FmpEventData -WindowDays 7 -CatalogDays 30
$cat = $evMod['data']['catalog']
$byKey = @{}
foreach ($e in @($cat['entries'])) { $byKey[[string]$e['key']] = $e }
Assert-FmpEqual -Name 'nvlddmkm 153 classificado como grafico' -Expected 'graphics' -Actual $byKey['nvlddmkm|153']['family']
Assert-FmpEqual -Name 'disk 153 classificado como armazenamento' -Expected 'storage' -Actual $byKey['disk|153']['family']
Assert-FmpEqual -Name 'nvlddmkm 153 nao soma os eventos do disk 153' -Expected 1 -Actual $byKey['nvlddmkm|153']['count']
Assert-FmpEqual -Name 'nivel fora do catalogo e descartado (disk 153 Informacao)' -Expected 1 -Actual $byKey['disk|153']['count']
Assert-FmpEqual -Name 'Aviso coletado (Display 4101)' -Expected 1 -Actual $byKey['Display|4101']['levels']['warning']
Assert-FmpEqual -Name 'Aviso coletado (Tcpip 4266)' -Expected 1 -Actual $byKey['Tcpip|4266']['count']
Assert-FmpEqual -Name 'Informacao relevante coletada (User32 1074)' -Expected 1 -Actual $byKey['User32|1074']['levels']['information']
Assert-FmpEqual -Name 'provedor nao registrado vira provider_absent' -Expected 'provider_absent' -Actual $byKey['stornvme|129']['status']
Assert-FmpEqual -Name 'provedor ausente nao derruba os demais' -Expected 'pass' -Actual $cat['state']
Assert-FmpEqual -Name 'ajuste pequeno de relogio ignorado; salto grande mantido' -Expected 1 -Actual $byKey['Microsoft-Windows-Kernel-General|1']['count']
Assert-FmpEqual -Name 'tamanho do salto de relogio' -Expected 3600 -Actual @($byKey['Microsoft-Windows-Kernel-General|1']['occurrences'])[0]['stepSec']
Assert-FmpTrue -Name 'retencao menor que a janela detectada' -Condition ($cat['retention']['coversWindow'] -eq $false)
Assert-FmpTrue -Name 'limitacao de retencao registrada' -Condition ('events_retention' -in @($evMod['limits'] | ForEach-Object { $_['key'] }))
$occKeys = @(@($byKey['nvlddmkm|153']['occurrences'])[0].Keys)
Assert-FmpTrue -Name 'ocorrencia guarda so horario e nivel, sem mensagem' -Condition ($occKeys.Count -eq 2 -and 'at' -in $occKeys -and 'level' -in $occKeys)
$pairsSeen = @{}
foreach ($c in @(Get-FmpEventCatalog)) { $pairsSeen[([string]$c.provider + '|' + $c.id)] = $true }
Assert-FmpEqual -Name 'catalogo nao tem par provedor+ID repetido' -Expected @(Get-FmpEventCatalog).Count -Actual $pairsSeen.Count
$provs = @(Get-FmpEventCatalog | ForEach-Object { [string]$_.provider } | Sort-Object -Unique)
Assert-FmpTrue -Name 'todo provedor do catalogo esta na allowlist do scanner' -Condition (@($provs | Where-Object { $_ -cnotin $script:FmpAllowedEventProviders }).Count -eq 0)

# =====================================================================
Start-FmpSuite 'A4. Horario do incidente'
$anyNow = [datetime]'2026-11-23T12:00:00Z'
$now = $anyNow.ToUniversalTime()
$z = ConvertTo-FmpIncidentAnchor -Value '2026-11-23T10:00Z' -NowUtc $now
Assert-FmpTrue -Name 'horario com Z aceito' -Condition ($z.ok -and $z.anchor.atUtc -eq '2026-11-23T10:00:00Z' -and $z.anchor.offsetKnown)
$o = ConvertTo-FmpIncidentAnchor -Value '2026-11-23 07:00:00-03:00' -NowUtc $now
Assert-FmpEqual -Name 'deslocamento convertido para UTC' -Expected '2026-11-23T10:00:00Z' -Actual $o.anchor.atUtc
foreach ($badV in @('ontem a noite', 'hoje as 14h', '2026-13-40T10:00', '2026-11-23', '2026-11-23T25:00', '2026-11-23T10:00+15:00', "2026-11-23T10:00'; x")) {
    $res = ConvertTo-FmpIncidentAnchor -Value $badV -NowUtc $now
    Assert-FmpTrue -Name ('valor recusado sem interpretar linguagem natural: ' + $badV) -Condition (-not $res.ok -and $res.reason -eq 'malformed')
}
Assert-FmpEqual -Name 'data futura recusada' -Expected 'future' -Actual (ConvertTo-FmpIncidentAnchor -Value '2026-11-23T13:00Z' -NowUtc $now).reason
Assert-FmpEqual -Name 'data com mais de 60 dias recusada' -Expected 'too_old' -Actual (ConvertTo-FmpIncidentAnchor -Value '2026-08-01T10:00Z' -NowUtc $now).reason
Assert-FmpEqual -Name 'tolerancia fora da faixa recusada' -Expected 'tolerance' -Actual (ConvertTo-FmpIncidentAnchor -Value '2026-11-23T10:00Z' -ToleranceMinutes 721 -NowUtc $now).reason
Assert-FmpEqual -Name 'unknown nao cria ancora' -Expected 'unknown' -Actual (ConvertTo-FmpIncidentAnchor -Value 'unknown').anchor.kind
Assert-FmpEqual -Name 'during-run aceito' -Expected 'during_run' -Actual (ConvertTo-FmpIncidentAnchor -Value 'during-run').anchor.kind
$gapZone = [pscustomobject]@{}
$gapZone | Add-Member -MemberType ScriptMethod -Name IsInvalidTime -Value { param($d) return $true }
$gapZone | Add-Member -MemberType ScriptMethod -Name IsAmbiguousTime -Value { param($d) return $false }
Assert-FmpEqual -Name 'hora local inexistente (inicio do horario de verao) recusada' -Expected 'nonexistent_local' -Actual (ConvertTo-FmpIncidentAnchor -Value '2026-03-08T02:30' -Zone $gapZone).reason
$dupZone = [pscustomobject]@{}
$dupZone | Add-Member -MemberType ScriptMethod -Name IsInvalidTime -Value { param($d) return $false }
$dupZone | Add-Member -MemberType ScriptMethod -Name IsAmbiguousTime -Value { param($d) return $true }
$amb = ConvertTo-FmpIncidentAnchor -Value '2026-11-01T01:30' -ToleranceMinutes 30 -Zone $dupZone
Assert-FmpTrue -Name 'hora local repetida amplia a busca em 60 min e fica marcada' -Condition ($amb.ok -and $amb.anchor.ambiguousLocal -and $amb.anchor.effectiveToleranceMinutes -eq 90)

$scopeArgs = @{ Mode = 'full'; Symptom = 'crash'; Language = 'pt-BR'; ObserveSeconds = 30; DuringProblem = 'unknown'; IncludeInternal = $false; OutDir = 'C:\x' }
$legacyScope = Get-FmpConsentScope @scopeArgs
Assert-FmpEqual -Name 'escopo sem incidente identico ao contrato anterior' -Expected 'fmpc1|full|crash|pt-BR|30|unknown|False|C:\x' -Actual $legacyScope
$scopeA = Get-FmpConsentScope @scopeArgs -Incident $z.scope
$scopeB = Get-FmpConsentScope @scopeArgs -Incident (ConvertTo-FmpIncidentAnchor -Value '2026-11-23T10:05Z' -NowUtc $now).scope
$scopeC = Get-FmpConsentScope @scopeArgs -Incident (ConvertTo-FmpIncidentAnchor -Value '2026-11-23T10:00Z' -ToleranceMinutes 45 -NowUtc $now).scope
$tok = New-FmpConsentToken -Scope $scopeA -IssuedUtc $now
Assert-FmpEqual -Name 'token vale para o mesmo incidente' -Expected 'valid' -Actual (Test-FmpConsentToken -Token $tok -Scope $scopeA -NowUtc $now)
Assert-FmpEqual -Name 'token invalido se o horario mudar' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tok -Scope $scopeB -NowUtc $now)
Assert-FmpEqual -Name 'token invalido se a tolerancia mudar' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tok -Scope $scopeC -NowUtc $now)
Assert-FmpEqual -Name 'token invalido se o incidente for removido' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tok -Scope $legacyScope -NowUtc $now)
Assert-FmpEqual -Name 'incidente antigo amplia a janela do catalogo' -Expected 48 -Actual (Get-FmpEventCatalogDays -Config $ruleConfig -Mode 'full' -Symptom 'slow' -Incident (ConvertTo-FmpIncidentAnchor -Value '2026-10-08T12:00Z' -NowUtc $now).anchor -NowUtc $now)
Assert-FmpEqual -Name 'auditoria rapida nao coleta catalogo' -Expected 0 -Actual (Get-FmpEventCatalogDays -Config $ruleConfig -Mode 'simple' -Symptom 'slow')

function New-At { param([datetime]$At, [int]$Tol = 30) return (ConvertTo-FmpIncidentAnchor -Value ($At.ToString('yyyy-MM-ddTHH:mm:ss') + 'Z') -ToleranceMinutes $Tol).anchor }
$tEv = $refEnd.AddHours(-20)
$gpuRecs = @((New-Rec 'nvlddmkm' 153 2 $tEv), (New-Rec 'Display' 4101 3 $tEv.AddDays(16 / 86400)))
$near = Invoke-FmpDx -Doc (New-CatalogDoc -Records $gpuRecs -Incident (New-At $tEv.AddDays(10 / 1440)))
$qNear = Get-Q $near 'incident_correlation'
Assert-FmpEqual -Name 'evento dentro da tolerancia correlacionado' -Expected 'yes' -Actual $qNear['answer']
Assert-FmpEqual -Name 'pergunta do incidente vem primeiro' -Expected 'incident_correlation' -Actual @($near.Dx['questions'])[0]['id']
Assert-FmpTrue -Name 'diferenca temporal mostrada com sinal' -Condition ([string]$near.Dx['incident']['closest'] -match '\(-\d+ min\)') -Detail ([string]$near.Dx['incident']['closest'])
Assert-FmpTrue -Name 'proximidade nao e apresentada como causa' -Condition (@($qNear['limitations']) -join ' ' -match 'não demonstra causa')
$far = Invoke-FmpDx -Doc (New-CatalogDoc -Records $gpuRecs -Incident (New-At $tEv.AddDays(-3 / 24)))
Assert-FmpEqual -Name 'evento fora da tolerancia nao correlaciona' -Expected 'no' -Actual (Get-Q $far 'incident_correlation')['answer']
$routine = Invoke-FmpDx -Doc (New-CatalogDoc -Records @((New-Rec 'User32' 1074 4 $tEv)) -Incident (New-At $tEv))
Assert-FmpEqual -Name 'so desligamento rotineiro perto = parcial' -Expected 'partial' -Actual (Get-Q $routine 'incident_correlation')['answer']
$stepRecs = $gpuRecs + @(, (New-Rec 'Microsoft-Windows-Kernel-General' 1 4 $tEv.AddDays(-5 / 1440) 3600))
$step = Invoke-FmpDx -Doc (New-CatalogDoc -Records $stepRecs -Incident (New-At $tEv))
Assert-FmpEqual -Name 'salto de relogio perto do incidente impede correlacao' -Expected 'clock_step' -Actual $step.Dx['incident']['reliability']
Assert-FmpEqual -Name 'relogio inconsistente = inconclusivo' -Expected 'unknown' -Actual (Get-Q $step 'incident_correlation')['answer']
$futureRecs = $gpuRecs + @(, (New-Rec 'Display' 4101 3 $refEnd.AddDays(2)))
$fut = Invoke-FmpDx -Doc (New-CatalogDoc -Records $futureRecs -Incident (New-At $tEv))
Assert-FmpEqual -Name 'evento com data futura indica relogio inconsistente' -Expected 'clock_future' -Actual $fut.Dx['incident']['reliability']
$before = Invoke-FmpDx -Doc (New-CatalogDoc -Records @() -OldestAt $refEnd.AddHours(-1) -Incident (New-At $tEv))
Assert-FmpEqual -Name 'incidente anterior a retencao' -Expected 'before_retention' -Actual $before.Dx['incident']['reliability']
Assert-FmpEqual -Name 'sem log naquele horario nao vira "nao"' -Expected 'unknown' -Actual (Get-Q $before 'incident_correlation')['answer']
$partRet = Invoke-FmpDx -Doc (New-CatalogDoc -Records @() -OldestAt $tEv -Incident (New-At $tEv))
Assert-FmpEqual -Name 'retencao parcial da janela do incidente' -Expected 'partial_retention' -Actual $partRet.Dx['incident']['reliability']
Assert-FmpEqual -Name 'retencao parcial sem eventos fica inconclusiva' -Expected 'unknown' -Actual (Get-Q $partRet 'incident_correlation')['answer']
$dr = Get-FmpFixtureDoc 'diag-slow-use.json'
$dr['run']['incident'] = [ordered]@{ kind = 'during_run' }
$drRes = Invoke-FmpDx -Doc $dr
Assert-FmpEqual -Name 'durante a execucao sem catalogo = no_catalog' -Expected 'no_catalog' -Actual $drRes.Dx['incident']['reliability']

# =====================================================================
Start-FmpSuite 'A4. Conclusoes diagnosticas'
$gpu = Invoke-FmpDx -Doc (New-CatalogDoc -Records $gpuRecs)
$qGpu = Get-Q $gpu 'graphics_events'
Assert-FmpEqual -Name 'par grafico em 16 s = sim' -Expected 'yes' -Actual $qGpu['answer']
$pair = @(@($gpu.Dx['correlations']) | Where-Object { $_['id'] -eq 'graphics_timeout' })[0]
Assert-FmpEqual -Name 'par correlacionado com a distancia real' -Expected 16 -Actual $pair['closestSec']
Assert-FmpTrue -Name 'falha grafica nao afirma defeito fisico' -Condition ((@($qGpu['limitations']) -join ' ') -match 'não comprovam defeito físico')
$diskOnly = Invoke-FmpDx -Doc (New-CatalogDoc -Records @((New-Rec 'disk' 153 3 $tEv)))
Assert-FmpEqual -Name 'disk 153 nao vira evento grafico' -Expected 'no' -Actual (Get-Q $diskOnly 'graphics_events')['answer']
Assert-FmpEqual -Name 'disk 153 isolado = sinal parcial de armazenamento' -Expected 'partial' -Actual (Get-Q $diskOnly 'storage_signals')['answer']
Assert-FmpTrue -Name 'sinal de disco nao conclui falha fisica' -Condition ((@((Get-Q $diskOnly 'storage_signals')['limitations']) -join ' ') -match 'não comprovam falha física')
$nvOnly = Invoke-FmpDx -Doc (New-CatalogDoc -Records @((New-Rec 'nvlddmkm' 153 2 $tEv)))
Assert-FmpEqual -Name 'nvlddmkm 153 nao vira sinal de armazenamento' -Expected 'no' -Actual (Get-Q $nvOnly 'storage_signals')['answer']
$ports = @()
foreach ($d in 1..3) { $ports += , (New-Rec 'Tcpip' 4231 2 $refEnd.AddDays(-$d)) }
$ports += , (New-Rec 'Tcpip' 4266 3 $refEnd.AddDays(-1))
$net = Invoke-FmpDx -Doc (New-CatalogDoc -Records $ports)
$qNet = Get-Q $net 'network_ports'
Assert-FmpEqual -Name 'portas em dias distintos = historico recorrente' -Expected 'yes' -Actual $qNet['answer']
Assert-FmpEqual -Name 'portas ficam na janela historica' -Expected 'history' -Actual $qNet['window']
Assert-FmpTrue -Name 'portas: texto separa historico de estado atual' -Condition ([string]$qNet['text'] -match 'uso atual de portas não foi medido')
$short = Invoke-FmpDx -Doc (New-CatalogDoc -Records @() -OldestAt $refEnd.AddDays(-3))
Assert-FmpEqual -Name 'sem eventos e com retencao curta = inconclusivo, nunca "nao"' -Expected 'unknown' -Actual (Get-Q $short 'graphics_events')['answer']
$clean = Invoke-FmpDx -Doc (New-CatalogDoc -Records @() -Absent @('nvlddmkm'))
Assert-FmpEqual -Name 'janela coberta, sem eventos = nao' -Expected 'no' -Actual (Get-Q $clean 'graphics_events')['answer']

function Add-ProcessMetrics {
    param([System.Collections.IDictionary]$Doc, [double]$CommitMB = 8704, [double]$WsMB = 358)
    $p = $Doc['observation']['processes']
    $p['appGroupBasis'] = 'executable_name'
    $p['topCommit'] = @(
        [ordered]@{ name = 'ExampleHiddenApp'; pid = 4242; startedAt = '2026-01-01T00:00:00Z'; exited = $false; commitPrivateMB = $CommitMB; workingSetMB = $WsMB; workingSetPrivateMB = 300.0; commitGrowthMB = 12.5 },
        [ordered]@{ name = 'ExampleBrowser'; pid = 77; startedAt = '2026-01-01T00:00:00Z'; exited = $false; commitPrivateMB = 3000.0; workingSetMB = 2900.0; workingSetPrivateMB = 2800.0; commitGrowthMB = 1.0 }
    )
    $p['topIo'] = @([ordered]@{ name = 'ExampleIndexer'; pid = 9; readBytesPerSec = 20971520.0; writeBytesPerSec = 1048576.0; readOpsPerSec = 100.0; writeOpsPerSec = 5.0; ioSharePct = 80.0 })
    $p['appGroups'] = @([ordered]@{ name = 'ExampleHiddenApp'; basis = 'executable_name'; instancesMax = 1; commitAvgMB = $CommitMB; commitPeakMB = $CommitMB; commitIncomplete = $false; workingSetAvgMB = $WsMB; workingSetPeakMB = $WsMB; avgCores = 0.1; peakCores = 0.2; readBytesPerSec = 0.0; writeBytesPerSec = 0.0; ioSharePct = 0.0 })
}
$memDoc = New-CatalogDoc -Records @((New-Rec 'disk' 153 3 $tEv))
Add-ProcessMetrics -Doc $memDoc
$mem = Invoke-FmpDx -Doc $memDoc -Symptom 'slow'
$qC = Get-Q $mem 'process_commit'
Assert-FmpTrue -Name 'processo com commit alto destacado mesmo com Working Set baixo' -Condition ($qC['answer'] -in @('yes', 'partial') -and $qC['values']['name'] -eq 'ExampleHiddenApp' -and $qC['values']['hidden'] -eq $true)
Assert-FmpTrue -Name 'uma leitura nao conclui vazamento' -Condition ((@($qC['limitations']) -join ' ') -match 'não demonstra vazamento' -and [string]$qC['text'] -notmatch 'vazamento')
$lowDoc = New-CatalogDoc
Add-ProcessMetrics -Doc $lowDoc -CommitMB 1000 -WsMB 900
Assert-FmpEqual -Name 'commit abaixo do limite = nao' -Expected 'no' -Actual (Get-Q (Invoke-FmpDx -Doc $lowDoc -Symptom 'slow') 'process_commit')['answer']
$qIo = Get-Q $mem 'process_io'
Assert-FmpTrue -Name 'I/O e tratado como coincidencia, com ressalva de rede e cache' -Condition ((@($qIo['limitations']) -join ' ') -match 'rede')
foreach ($k in @($mem.Dx['keyFindings'])) {
    if ($k['kind'] -ne 'question') { continue }
    Assert-FmpTrue -Name ('achado separa hipotese do observado: ' + $k['id']) -Condition (-not [string]::IsNullOrWhiteSpace([string]$k['hypothesis']) -and [string]$k['hypothesis'] -ne [string]$k['observed'])
}
$supported = @(@($mem.Dx['questions']) | Where-Object { $_.Contains('supporting') })
Assert-FmpTrue -Name 'evidencia complementar fica separada' -Condition ($supported.Count -ge 1 -and @($supported | Where-Object { $_.Contains('supportItems') }).Count -eq 0)

# =====================================================================
Start-FmpSuite 'Compatibilidade com o diagnostico anterior'
foreach ($fx in @('diag-slow-use.json', 'diag-crash-recurring.json', 'diag-slow-boot.json', 'diag-healthy-full.json')) {
    $r1 = Invoke-FmpDx -Doc (Get-FmpFixtureDoc $fx) -Symptom 'general'
    $ids = @(@($r1.Dx['questions']) | ForEach-Object { $_['id'] }) -join ','
    Assert-FmpEqual -Name ('documento 2.0 mantem as 8 perguntas: ' + $fx) -Expected 'cpu_load,memory_pressure,storage_busy,storage_slow,storage_errors,storage_health,boot_history,crash_history' -Actual $ids
    Assert-FmpTrue -Name ('documento 2.0 nao ganha linha do tempo: ' + $fx) -Condition (-not $r1.Dx.Contains('timeline') -and -not $r1.Dx.Contains('incident'))
    $r2 = Invoke-FmpDx -Doc (New-CatalogDoc -Records $gpuRecs -Fixture $fx) -Symptom 'general'
    Assert-FmpEqual -Name ('catalogo nao altera a nota: ' + $fx) -Expected $r1.Score['score'] -Actual $r2.Score['score']
    Assert-FmpEqual -Name ('catalogo nao altera a cobertura da nota: ' + $fx) -Expected $r1.Score['coveragePct'] -Actual $r2.Score['coveragePct']
}

# =====================================================================
Start-FmpSuite 'Seguranca: scanner com teste negativo'
$neg = @(
    @('ProviderName variavel', 'function Get-FmpX { param([string]$p) Get-WinEvent -FilterHashtable @{ LogName = ''System''; ProviderName = $p } -MaxEvents 1 -ErrorAction Stop }'),
    @('provedor fora da lista', 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; ProviderName = ''Microsoft-Windows-Security-Auditing'' } -MaxEvents 1 -ErrorAction Stop'),
    @('provedor com curinga', 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; ProviderName = ''*'' } -MaxEvents 1 -ErrorAction Stop'),
    @('ProviderName sem LogName', 'Get-WinEvent -FilterHashtable @{ ProviderName = ''disk'' } -MaxEvents 1 -ErrorAction Stop'),
    @('-Oldest sem MaxEvents', 'Get-WinEvent -FilterHashtable @{ LogName = ''System'' } -Oldest -ErrorAction Stop'),
    @('-Oldest percorrendo o log', 'Get-WinEvent -FilterHashtable @{ LogName = ''System'' } -Oldest -MaxEvents 1000 -ErrorAction Stop'),
    @('-Oldest com MaxEvents variavel', 'function Get-FmpX { param([int]$n) Get-WinEvent -FilterHashtable @{ LogName = ''System'' } -Oldest -MaxEvents $n -ErrorAction Stop }'),
    @('-Oldest com outro filtro', 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; Id = 1 } -Oldest -MaxEvents 1 -ErrorAction Stop'),
    @('log nao autorizado', 'Get-WinEvent -FilterHashtable @{ LogName = ''Microsoft-Windows-PowerShell/Operational''; ProviderName = ''disk'' } -MaxEvents 1 -ErrorAction Stop'),
    @('TimeZoneInfo fora de Common', '$z = [TimeZoneInfo]::Local'),
    @('IsInvalidTime fora de Common', 'function Get-FmpX { param([object]$z, [datetime]$d) return $z.IsInvalidTime($d) }'),
    @('Add-Type continua proibido', 'Add-Type -TypeDefinition ''public class X {}'''),
    @('ferramenta externa continua proibida', 'nvidia-smi')
)
$i = 0
foreach ($n in $neg) {
    $i++
    $tmp = Join-Path $scratch ('neg-' + $i + '.ps1')
    Write-FmpUtf8File $tmp $n[1]
    Assert-FmpTrue -Name ('scanner recusa: ' + $n[0]) -Condition (-not (Test-FmpScriptCompliance -Path $tmp -Role 'collector').Ok)
}
$okSnip = "function Get-FmpX {`n  foreach (`$prov in @('disk', 'Display')) { Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = `$prov; Id = 153 } -MaxEvents 5 -ErrorAction Stop }`n  Get-WinEvent -FilterHashtable @{ LogName = 'System' } -Oldest -MaxEvents 1 -ErrorAction Stop`n}"
$okPath = Join-Path $scratch 'ok.ps1'
Write-FmpUtf8File $okPath $okSnip
$okRes = Test-FmpScriptCompliance -Path $okPath -Role 'collector' -InternalFunctions @('Get-FmpX')
Assert-FmpTrue -Name 'scanner aceita a forma fechada usada pelo catalogo' -Condition $okRes.Ok -Detail (@($okRes.Violations | ForEach-Object { $_.detail }) -join '; ')
Assert-FmpTrue -Name 'projeto inteiro passa no scanner' -Condition (Test-FmpReadOnlyCompliance -Root $root -IncludeTests).Ok
foreach ($src in @('src\collectors\Observation.ps1', 'src\collectors\Events.ps1')) {
    $txt = [System.IO.File]::ReadAllText((Join-Path $root $src))
    Assert-FmpTrue -Name ('sem Add-Type, WPR ou nvidia-smi: ' + $src) -Condition ($txt -notmatch '(?i)Add-Type|\bwpr\b|nvidia-smi')
    Assert-FmpTrue -Name ('sem linha de comando, caminho ou assinatura novos: ' + $src) -Condition ($txt -notmatch '(?i)\bCommandLine\b|ExecutablePath|Get-AuthenticodeSignature')
}

# =====================================================================
Start-FmpSuite 'Regressao de JSON, HTML e privacidade'
$canaryDoc = New-CatalogDoc -Records ($gpuRecs + @(, (New-Rec 'disk' 153 3 $tEv.AddDays(30 / 86400)))) -Incident (New-At $tEv.AddDays(1 / 1440))
Add-ProcessMetrics -Doc $canaryDoc
$canaryDoc['observation']['processes']['topCommit'][1]['name'] = 'C:\Users\alice\AppData\secret.exe'
$canaryDoc['observation']['processes']['appGroups'][0]['name'] = 'HOST-PRIVATE-77'
$canaryDoc['observation']['processes']['topIo'][0]['name'] = 'app 192.168.10.44 token=abc123'
foreach ($lang in @('pt-BR', 'en')) {
    $res = Invoke-FmpDx -Doc $canaryDoc -Symptom 'crash' -Lang $lang -Ids @('HOST-PRIVATE-77')
    Assert-FmpTrue -Name ('documento sanitizado valido: ' + $lang) -Condition (Test-FmpDiagnosticDocument $res.Sanitized)
    $json = ConvertTo-FmpJsonText -Data $res.Sanitized
    Reset-FmpMissingLocaleKeys
    if ($lang -eq 'en') { Set-FmpRenderLocale -Primary $locEn -Fallback $locPt -Language 'en' } else { Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR' }
    $html = Get-FmpHtmlReportText -Diagnostic $res.Sanitized -Synthetic:$true -RedactionCount 0
    $missing = Get-FmpMissingLocaleKeys
    Assert-FmpEqual -Name ('nenhuma chave de traducao faltando: ' + $lang) -Expected 0 -Actual $missing.Count
    if ($missing.Count -gt 0) { Write-Host ('    faltando: ' + ($missing -join ', ')) }
    foreach ($canary in @('alice', 'HOST-PRIVATE-77', '192.168.10.44', 'abc123')) {
        Assert-FmpTrue -Name ('JSON sanitizado sem ' + $canary + ' (' + $lang + ')') -Condition (-not $json.Contains($canary))
        Assert-FmpTrue -Name ('HTML sem ' + $canary + ' (' + $lang + ')') -Condition (-not $html.Contains($canary))
    }
    Assert-FmpTrue -Name ('JSON nao tem mensagem nem linha de comando: ' + $lang) -Condition ($json -notmatch '"(commandLine|executablePath|message)"\s*:\s*"[^<]')
    Assert-FmpTrue -Name ('CSP preservada: ' + $lang) -Condition ($html.Contains('Content-Security-Policy'))
    Assert-FmpTrue -Name ('offline, sem recurso externo: ' + $lang) -Condition ($html -notmatch '(?i)<(script|link|img)[^>]+(src|href)="https?://')
    Assert-FmpTrue -Name ('sem grafico novo com falsa precisao: ' + $lang) -Condition ($html -notmatch '(?i)<canvas')
    $needles = @('Display 4101', 'nvlddmkm', 'ExampleHiddenApp')
    if ($lang -eq 'pt-BR') { $needles += @('Maiores consumidores de memória comprometida', 'Maiores consumidores de I/O', 'Consumo por aplicativo', 'Eventos diagnósticos do Windows', 'Linha do tempo dos incidentes', 'Evidências correlacionadas', 'Hipótese provável') }
    else { $needles += @('Top committed memory consumers', 'Top I/O consumers', 'Usage by application', 'Windows diagnostic events', 'Incident timeline', 'Evidence correlated in time', 'Likely hypothesis') }
    $htmlText = [System.Net.WebUtility]::HtmlDecode($html)
    foreach ($needle in $needles) { Assert-FmpTrue -Name ('HTML mostra "' + $needle + '" (' + $lang + ')') -Condition ($htmlText.Contains($needle)) }
    Assert-FmpTrue -Name ('relatorio dentro do limite de 8 MiB: ' + $lang) -Condition ([System.Text.UTF8Encoding]::new($false).GetBytes($html).Length -lt 8MB)
}

# =====================================================================
Start-FmpSuite 'CLI somente com -Fixture e -Plan'
function Invoke-FmpCli {
    param([string[]]$CliArgs)
    $out = & powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $root 'fixmypc.ps1') @CliArgs 2>&1 | ForEach-Object { [string]$_ }
    return @{ Code = $LASTEXITCODE; Text = ($out -join "`n") }
}
$fxDoc = New-CatalogDoc -Records $gpuRecs
Add-ProcessMetrics -Doc $fxDoc
$fxPath = Join-Path $scratch 'phase-a-fixture.json'
Write-FmpUtf8File -Path $fxPath -Text (ConvertTo-FmpJsonText -Data $fxDoc)
$goodAt = $tEv.AddDays(10 / 1440).ToString('yyyy-MM-ddTHH:mm:ss') + 'Z'
$outOk = Join-Path $scratch 'cli-ok'
$cli = Invoke-FmpCli @('-Fixture', $fxPath, '-Mode', 'full', '-Symptom', 'crash', '-Language', 'pt-BR', '-IncidentAt', $goodAt, '-IncidentToleranceMinutes', '30', '-Yes', '-OutDir', $outOk)
Assert-FmpEqual -Name 'CLI com fixture e horario: exit 0' -Expected 0 -Actual $cli.Code
$sanPath = Join-Path $outOk 'diagnostic-sanitized.json'
if (Test-Path -LiteralPath $sanPath) {
    $sanDoc = (Read-FmpJsonFile -Path $sanPath).Data
    Assert-FmpEqual -Name 'JSON gravado traz a confiabilidade do incidente' -Expected 'ok' -Actual (Get-FmpValue $sanDoc 'diagnosis.incident.reliability')
    Assert-FmpEqual -Name 'JSON gravado traz o horario normalizado' -Expected $goodAt -Actual (Get-FmpValue $sanDoc 'run.incident.atUtc')
    Assert-FmpTrue -Name 'relatorio gravado' -Condition (Test-Path -LiteralPath (Join-Path $outOk 'report.html'))
}
else { Assert-FmpTrue -Name 'JSON sanitizado gravado' -Condition $false -Detail $cli.Text }
$outBad = Join-Path $scratch 'cli-bad'
$cliBad = Invoke-FmpCli @('-Fixture', $fxPath, '-Mode', 'full', '-IncidentAt', 'ontem a noite', '-Yes', '-OutDir', $outBad)
Assert-FmpEqual -Name 'linguagem natural recusada com codigo 3' -Expected 3 -Actual $cliBad.Code
Assert-FmpTrue -Name 'valor recusado nao cria saida' -Condition (-not (Test-Path -LiteralPath $outBad))
$outConf = Join-Path $scratch 'cli-conflict'
$cliConf = Invoke-FmpCli @('-Fixture', $fxPath, '-Mode', 'full', '-IncidentAt', 'during-run', '-DuringProblem', 'no', '-Yes', '-OutDir', $outConf)
Assert-FmpEqual -Name 'during-run com DuringProblem no recusado' -Expected 3 -Actual $cliConf.Code
$planAt = [DateTime]::UtcNow.AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ss') + 'Z'
$outPlan = Join-Path $scratch 'cli-plan'
$plan = Invoke-FmpCli @('-Plan', '-Mode', 'full', '-Symptom', 'crash', '-Language', 'pt-BR', '-IncidentAt', $planAt, '-IncidentToleranceMinutes', '45', '-OutDir', $outPlan)
Assert-FmpEqual -Name '-Plan com horario: exit 0' -Expected 0 -Actual $plan.Code
Assert-FmpTrue -Name '-Plan imprime o horario e a tolerancia no comando aprovado' -Condition ($plan.Text.Contains("-IncidentAt '" + $planAt + "' -IncidentToleranceMinutes 45") -and $plan.Text.Contains('-ConsentToken fmpc1-'))
Assert-FmpTrue -Name '-Plan descreve o catalogo de eventos' -Condition ($plan.Text.Contains('sem mensagens'))
Assert-FmpTrue -Name '-Plan nao cria a pasta' -Condition (-not (Test-Path -LiteralPath $outPlan))

Remove-Item -LiteralPath $scratch -Recurse -Force
Write-Host ''
Write-Host ('PhaseA: ' + $script:PassCount + ' passed, ' + $script:FailCount + ' failed')
foreach ($f in $script:Failures) { Write-Host ('  ' + $f) -ForegroundColor Red }
if ($script:FailCount -gt 0) { exit 1 }
exit 0
