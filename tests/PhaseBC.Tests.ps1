# =====================================================================
# FIX MY PC - PhaseBC.Tests.ps1
# Offline suite for Phases B and C: WER, GPU, ports, services, disk map,
# adaptive selection, budgets, hypotheses, depth consent and privacy.
# Synthetic data and mocked providers only. Written for the consolidated
# validation after Phase C. Run:
#   powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File tests\PhaseBC.Tests.ps1
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
. (Join-Path $root 'src\analysis\Correlation.ps1')
. (Join-Path $root 'src\reports\HtmlRenderer.ps1')
. (Join-Path $root 'src\collectors\Observation.ps1')
. (Join-Path $root 'src\collectors\Events.ps1')
. (Join-Path $root 'src\collectors\Investigations.ps1')

# Fail closed: these shadow the real cmdlets, so a query the suite did not mock is an error and never a collection.
function Get-CimInstance { throw 'UNMOCKED_SYSTEM_COMMAND: Get-CimInstance' }
function Get-WinEvent { throw 'UNMOCKED_SYSTEM_COMMAND: Get-WinEvent' }
function Get-Process { throw 'UNMOCKED_SYSTEM_COMMAND: Get-Process' }
function Get-PhysicalDisk { throw 'UNMOCKED_SYSTEM_COMMAND: Get-PhysicalDisk' }
function Get-StorageReliabilityCounter { throw 'UNMOCKED_SYSTEM_COMMAND: Get-StorageReliabilityCounter' }
function Start-Sleep { param([int]$Seconds) }

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

$scratch = Join-Path $root ('out\fmp-phasebc-tests-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $scratch
$ruleConfig = Get-FmpRuleConfig -Root $root
$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data
$guidA = '11111111-2222-4333-8444-555555555555'

function New-WerXml {
    # Unnamed <Data> in template order, as WER 1001 may be written.
    param([string]$EventName, [string]$P1, [string]$ReportId)
    $v = @('BucketSecret', '5', $EventName, 'Not available', '0', $P1, 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9', 'P10', 'C:\Users\alice\attached.dmp', 'C:\ProgramData\Store', '', '0', $ReportId, '0', 'hash', 'cab')
    return '<Event><EventData>' + ((@($v | ForEach-Object { if ($_ -eq '') { '<Data/>' } else { '<Data>' + $_ + '</Data>' } })) -join '') + '</EventData></Event>'
}

# =====================================================================
Start-FmpSuite 'B2. WER: interpretacao'
$p = ConvertFrom-FmpWerEventXml (New-WerXml 'LiveKernelEvent' '141' $guidA)
Assert-FmpTrue -Name 'layout posicional lido' -Condition ($p['ok'] -and $p['kind'] -eq 'live_kernel' -and $p['code'] -eq '141' -and $p['reportId'] -eq $guidA)
$n = ConvertFrom-FmpWerEventXml ("<Event><EventData><Data Name='EventName'>BlueScreen</Data><Data Name='P1'>0x00000116</Data><Data Name='ReportId'>" + $guidA + "</Data></EventData></Event>")
Assert-FmpTrue -Name 'layout nomeado lido e codigo normalizado' -Condition ($n['kind'] -eq 'blue_screen' -and $n['code'] -eq '116')
$app = ConvertFrom-FmpWerEventXml (New-WerXml 'APPCRASH' 'secret-app.exe' $guidA)
Assert-FmpTrue -Name 'P1 de aplicativo nao e mantido' -Condition ($app['kind'] -eq 'app_crash' -and $null -eq $app['code'])
$masked = ConvertFrom-FmpWerEventXml (New-WerXml 'LiveKernelEvent' 'aaaaaaaa' $guidA)
Assert-FmpTrue -Name 'codigo mascarado nao vira codigo' -Condition ($null -eq $masked['code'])
$bad = ConvertFrom-FmpWerEventXml '<Event><EventData><Data>a</Data><Data>b</Data></EventData></Event>'
Assert-FmpTrue -Name 'layout desconhecido nao e adivinhado' -Condition (-not $bad['ok'])
Assert-FmpTrue -Name 'parser nao devolve caminho nem bucket' -Condition ((($p.Values | ForEach-Object { [string]$_ }) -join ' ') -notmatch 'alice|BucketSecret|Store')

Start-FmpSuite 'B2. WER: deduplicacao e reenvio'
$now = [datetime]'2026-11-23T12:00:00Z'
$now = $now.ToUniversalTime()
$records = New-Object System.Collections.Generic.List[object]
foreach ($i in 1..8) {
    $ref = 'report' + $i
    foreach ($j in 0..311) { $records.Add(@{ at = $now.AddDays(-10 - $i).AddDays($j / 1440); kind = 'live_kernel'; code = '141'; ref = $ref }) }
}
foreach ($i in 1..8) { $records.Add(@{ at = $now.AddDays(-0.5); kind = 'live_kernel'; code = '141'; ref = ('report' + $i) }) }
$records.Add(@{ at = $now.AddDays(-0.1); kind = 'app_crash'; code = $null; ref = 'fresh' })
$records.Add(@{ at = $now.AddDays(-0.1); kind = 'app_crash'; code = $null; ref = '' })
$s = Get-FmpWerSummary -Records $records.ToArray() -NowUtc $now
Assert-FmpEqual -Name 'muitos registros viram relatorios unicos' -Expected 9 -Actual $s['reports']
Assert-FmpEqual -Name 'reenvios de hoje nao sao falha nova' -Expected 8 -Actual $s['resendRecent']
Assert-FmpEqual -Name 'so o relatorio inedito e novo' -Expected 1 -Actual $s['newRecent']
Assert-FmpEqual -Name 'registro sem id fica como nao identificado' -Expected 1 -Actual $s['unidentified']
$cut = Get-FmpWerSummary -Records @(@{ at = $now.AddDays(-0.1); kind = 'app_crash'; code = $null; ref = 'x' }) -NowUtc $now -Truncated $true
Assert-FmpTrue -Name 'leitura truncada nao declara falha nova' -Condition ($cut['newRecent'] -eq 0 -and $cut['indeterminateRecent'] -eq 1)

# =====================================================================
Start-FmpSuite 'B1. GPU'
$name = 'pid_1234_luid_0x00000000_0x0000C2A1_phys_0_eng_3_engtype_3D'
$i0 = ConvertFrom-FmpGpuEngineName $name
Assert-FmpTrue -Name 'instancia de motor interpretada' -Condition ($i0['pid'] -eq 1234 -and $i0['engine'] -eq 3 -and $i0['type'] -eq '3D')
Assert-FmpTrue -Name 'nome fora do formato e ignorado' -Condition ($null -eq (ConvertFrom-FmpGpuEngineName 'x'))
$prevRow = [pscustomobject]@{ Name = $name; UtilizationPercentage = [uint64]1000; Timestamp_Sys100NS = [uint64]10000 }
$currRow = [pscustomobject]@{ Name = $name; UtilizationPercentage = [uint64]1500; Timestamp_Sys100NS = [uint64]11000 }
$use = Get-FmpGpuIntervalUsage -Prev @{ $name = $prevRow } -Curr @($currRow)
Assert-FmpEqual -Name 'uso = delta de tempo ocupado / delta de tempo' -Expected 50 -Actual @($use['engines'].Values)[0]
$reset = [pscustomobject]@{ Name = $name; UtilizationPercentage = [uint64]10; Timestamp_Sys100NS = [uint64]12000 }
Assert-FmpEqual -Name 'contador reiniciado nao gera uso' -Expected 0 -Actual (Get-FmpGpuIntervalUsage -Prev @{ $name = $currRow } -Curr @($reset))['engines'].Count

Start-FmpSuite 'B3. Rede'
$t = Get-FmpPortTrend -Totals @(1000, 1400, 1800) -RangeSize 16384
Assert-FmpTrue -Name 'crescimento monotono = em alta' -Condition ($t['trend'] -eq 'rising' -and $t['risk'] -eq 'normal')
Assert-FmpEqual -Name 'uso alto = risco alto' -Expected 'high' -Actual (Get-FmpPortTrend -Totals @(14000, 14000, 14000) -RangeSize 16384)['risk']
Assert-FmpEqual -Name 'oscilacao = estavel' -Expected 'stable' -Actual (Get-FmpPortTrend -Totals @(1000, 1200, 1000) -RangeSize 16384)['trend']
Assert-FmpEqual -Name 'faixa invalida = desconhecido' -Expected 'unknown' -Actual (Get-FmpPortTrend -Totals @(1, 2) -RangeSize 0)['risk']
Assert-FmpEqual -Name 'estado TCP documentado' -Expected 'time_wait' -Actual (Get-FmpTcpStateName 11)
Assert-FmpEqual -Name 'estado fora da lista = other' -Expected 'other' -Actual (Get-FmpTcpStateName 77)

# =====================================================================
function New-InvDoc {
    param([object[]]$Records = @(), [hashtable]$Results = @{}, [string]$Depth = 'standard', [string]$Fixture = 'diag-slow-use.json')
    $fx = Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $Fixture))
    $doc = ConvertTo-FmpSerializable -Value $fx.Data
    $end = (Get-FmpParsedDate $doc['run']['finishedAt']).ToUniversalTime()
    $catalog = @(Get-FmpEventCatalog)
    $state = @{}
    foreach ($c in $catalog) { $state[$c.provider] = @{ status = 'empty'; truncated = $false } }
    foreach ($r in $Records) { $state[[string]$r['provider']] = @{ status = 'ok'; truncated = $false } }
    $doc['events']['catalog'] = [ordered]@{ version = '1'; state = 'pass'; channel = 'System'; windowDays = 30; since = $end.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'); maxPerProvider = 300; anyTruncated = $false
        retention = [ordered]@{ status = 'ok'; oldestAt = $end.AddDays(-60).ToString('yyyy-MM-ddTHH:mm:ssZ'); coversWindow = $true }
        entries = @(ConvertTo-FmpCatalogEntries -Catalog $catalog -ProviderState $state -Records $Records) }
    $res = [ordered]@{}
    foreach ($k in $Results.Keys) { $res[$k] = $Results[$k] }
    $doc['investigations'] = [ordered]@{ version = '1'; depth = $Depth; categories = @('H', 'P', 'N'); budgetMs = 45000; elapsedMs = 1000; budgetExceeded = $false; runs = @(); results = $res }
    return $doc
}
function Invoke-FmpDx {
    param([System.Collections.IDictionary]$Doc, [string]$Symptom = 'crash', [string]$Lang = 'pt-BR')
    $analysis = Invoke-FmpRules -Diagnostic $Doc -RuleConfig $ruleConfig -Mode ([string]$Doc['run']['mode'])
    $score = Get-FmpHealthScore -Analysis $analysis -RuleConfig $ruleConfig -Modules (Get-FmpValue $Doc 'modules')
    $dx = Get-FmpDiagnosis -Diagnostic $Doc -Analysis $analysis -RuleConfig $ruleConfig -Symptom $Symptom
    $locs = @($locPt, $locEn)
    if ($Lang -eq 'en') { $locs = @($locEn, $locPt) }
    Add-FmpDiagnosisText -Diagnosis $dx -Locales $locs -Language $Lang
    $Doc['run']['language'] = $Lang
    $Doc['analysis'] = $analysis; $Doc['healthScore'] = $score; $Doc['diagnosis'] = $dx
    return @{ Dx = $dx; Score = $score; Doc = $Doc; Analysis = $analysis }
}
function Get-Q { param($Res, [string]$Id) return @(@($Res.Dx['questions']) | Where-Object { $_['id'] -eq $Id })[0] }
function Get-H { param($Res, [string]$Id) return @(@($Res.Dx['hypotheses']) | Where-Object { $_['id'] -eq $Id })[0] }

$refFx = Read-FmpJsonFile -Path (Join-Path $root 'tests\fixtures\diag-slow-use.json')
$refEnd = (Get-FmpParsedDate (Get-FmpValue $refFx.Data 'run.finishedAt')).ToUniversalTime()
$tGpu = $refEnd.AddHours(-20)
function New-Rec { param([string]$Provider, [int]$Id, [int]$Level, [datetime]$At, $Disk = $null) return @{ provider = $Provider; id = $Id; level = $Level; at = $At; stepSec = $null; diskNumber = $Disk } }
function New-WerResult {
    param([object[]]$Records, [object]$NowUtc)
    return [ordered]@{ state = 'ok'; truncated = $false; summary = (Get-FmpWerSummary -Records $Records -NowUtc $NowUtc) }
}

Start-FmpSuite 'B1/B6. Timeout grafico'
$codexRecs = @((New-Rec 'nvlddmkm' 153 2 $tGpu), (New-Rec 'disk' 153 3 $tGpu.AddDays(-3) 4))
$codexWer = New-WerResult -Records @(@{ at = $tGpu.AddDays(16 / 86400); kind = 'live_kernel'; code = '141'; ref = 'a' }) -NowUtc $refEnd
$codex = Invoke-FmpDx -Doc (New-InvDoc -Records $codexRecs -Results @{ wer_events = $codexWer; gpu_events = [ordered]@{ state = 'empty'; truncated = $false; absentProviders = 5; providers = @() } })
$qg = Get-Q $codex 'graphics_timeout'
Assert-FmpEqual -Name 'driver + LiveKernel 141 a 16 s = sim' -Expected 'yes' -Actual $qg['answer']
Assert-FmpEqual -Name 'distancia real registrada' -Expected '16' -Actual $qg['values']['closestSec']
Assert-FmpEqual -Name 'hipotese grafica sustentada' -Expected 'supported' -Actual (Get-H $codex 'graphics_driver_instability')['state']
$diskOnly = Invoke-FmpDx -Doc (New-InvDoc -Records @((New-Rec 'disk' 153 3 $tGpu 4)) -Results @{ wer_events = (New-WerResult -Records @() -NowUtc $refEnd) })
Assert-FmpEqual -Name 'disk 153 nao vira timeout grafico' -Expected 'no' -Actual (Get-Q $diskOnly 'graphics_timeout')['answer']
$noWer = Invoke-FmpDx -Doc (New-InvDoc -Records @((New-Rec 'Display' 4101 3 $tGpu)) -Results @{ wer_events = [ordered]@{ state = 'access_denied'; truncated = $false } })
Assert-FmpEqual -Name 'sem WER, evento do driver fica parcial' -Expected 'partial' -Actual (Get-Q $noWer 'graphics_timeout')['answer']

Start-FmpSuite 'B3/B6. Portas: historico versus atual'
$portRecs = @()
foreach ($d in 1..3) { $portRecs += , (New-Rec 'Tcpip' 4231 2 $refEnd.AddDays(-$d)) }
$netOk = [ordered]@{ state = 'ok'; truncated = $false; rangeStart = 49152; rangeSize = 16384; rangeVaries = $false; samples = @([ordered]@{ total = 120; inUse = 100; timeWait = 5 }); byState = [ordered]@{ established = 95; time_wait = 5 }
    udpEndpoints = 10; topOwners = @([ordered]@{ pid = 9; name = 'ExampleBrowser'; connections = 40 }); usagePct = 0.6; growthPctOfRange = 0; trend = 'stable'; risk = 'normal' }
$net = Invoke-FmpDx -Doc (New-InvDoc -Records $portRecs -Results @{ net_ports = $netOk })
Assert-FmpEqual -Name 'historico de portas sustentado' -Expected 'supported' -Actual (Get-H $net 'port_exhaustion_history')['state']
Assert-FmpEqual -Name 'uso atual normal nao sustenta esgotamento agora' -Expected 'not_supported' -Actual (Get-H $net 'port_exhaustion_active')['state']
Assert-FmpTrue -Name 'dono atual nao vira culpado historico' -Condition ((@((Get-Q $net 'ports_current')['limitationKeys']) -join ' ') -match 'ports_owner_history')

Start-FmpSuite 'B4. Discos'
Assert-FmpEqual -Name 'HarddiskN extraido' -Expected 4 -Actual (Get-FmpHarddiskNumber '<Data>\Device\Harddisk4\DR4</Data>')
Assert-FmpTrue -Name 'sem HarddiskN = null' -Condition ($null -eq (Get-FmpHarddiskNumber '<Data>abc</Data>'))
$mapDoc = New-InvDoc -Records @((New-Rec 'disk' 153 3 $refEnd.AddHours(-1) 0), (New-Rec 'disk' 51 3 $refEnd.AddDays(-5) 1), (New-Rec 'disk' 7 2 $refEnd.AddDays(-5) 4))
$mapDoc['system']['disks'] = @([ordered]@{ index = 1; diskNumber = 0; sizeBytes = 512GB; interfaceType = 'SCSI' }, [ordered]@{ index = 2; diskNumber = 1; sizeBytes = 1TB; interfaceType = 'SCSI' })
if ($null -eq (Get-FmpValue $mapDoc 'system.os')) { $mapDoc['system']['os'] = [ordered]@{} }
$mapDoc['system']['os']['lastBootAt'] = $refEnd.AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$map = @(Get-FmpDiskEventMap $mapDoc)
Assert-FmpEqual -Name 'evento desde o boot = disco atual' -Expected 'current_boot' -Actual @($map | Where-Object { $_['diskNumber'] -eq 0 })[0]['mapping']
Assert-FmpEqual -Name 'evento antigo nao e atribuido com certeza' -Expected 'earlier_boot' -Actual @($map | Where-Object { $_['diskNumber'] -eq 1 })[0]['mapping']
Assert-FmpEqual -Name 'numero inexistente = dispositivo ausente' -Expected 'device_absent' -Actual @($map | Where-Object { $_['diskNumber'] -eq 4 })[0]['mapping']

Start-FmpSuite 'B5. Servicos em svchost'
$svcDoc = New-InvDoc
$svcDoc['observation']['processes']['topCpu'] = @([ordered]@{ name = 'svchost#3'; pid = 700; avgCores = 2.0; avgPctOfMachine = 25; activeShare = 1; maxCores = 3 })
$targets = @(Get-FmpSvchostTargets $svcDoc)
Assert-FmpTrue -Name 'svchost entre os maiores identificado pelo PID' -Condition ($targets.Count -eq 1 -and $targets[0]['pid'] -eq 700 -and $targets[0]['metric'] -eq 'cpu')
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [string[]]$Property, [int]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_Service') {
        return @([pscustomobject]@{ Name = 'Dnscache'; ProcessId = 700; State = 'Running' }, [pscustomobject]@{ Name = 'CDPUserSvc_4a7f3c'; ProcessId = 700; State = 'Running' }, [pscustomobject]@{ Name = 'Other'; ProcessId = 900; State = 'Running' })
    }
    return @()
}
$svc = Get-FmpServiceHostData -Hosts $targets
Assert-FmpTrue -Name 'servicos do PID listados e marcados como compartilhados' -Condition ($svc['state'] -eq 'ok' -and @($svc['hosts'])[0]['serviceCount'] -eq 2 -and @($svc['hosts'])[0]['shared'] -eq $true)
Assert-FmpTrue -Name 'servico de outro PID nao entra' -Condition (@(@($svc['hosts'])[0]['services']) -notcontains 'Other')
# Regressao (homologacao VM-07): Sort-Object wraps strings in PSObjects, which serialized as
# {"Length": n} in the sanitized JSON and as the type name in the HTML table.
$svcJson = ConvertTo-Json -InputObject $svc['hosts'] -Depth 4 -Compress
Assert-FmpTrue -Name 'nomes de servico serializam como strings (nao {Length=n})' -Condition ($svcJson -match 'Dnscache' -and $svcJson -notmatch '"Length"')
Assert-FmpTrue -Name 'tabela html junta os nomes de servico' -Condition ((@(@($svc['hosts'])[0]['services']) -join ', ') -eq 'CDPUserSvc_4a7f3c, Dnscache')

# =====================================================================
Start-FmpSuite 'B. Coletores com provedores simulados: GPU, rede, WER e discos'
$script:CimCalls = New-Object System.Collections.Generic.List[string]
$script:CimFail = @{}
$script:NetTick = -1; $script:GpuTick = -1; $script:CpuTick = -1; $script:MemTick = -1
function New-GpuRows {
    param([int]$T)
    $ts = [uint64](100000 + $T * 1000)
    return @(
        [pscustomobject]@{ Name = 'pid_9_luid_0x00000000_0x0000C2A1_phys_0_eng_0_engtype_3D'; UtilizationPercentage = [uint64](1000 + $T * 500); Timestamp_Sys100NS = $ts }
        [pscustomobject]@{ Name = 'pid_10_luid_0x00000000_0x0000C2A1_phys_0_eng_0_engtype_3D'; UtilizationPercentage = [uint64](1000 + $T * 200); Timestamp_Sys100NS = $ts }
        [pscustomobject]@{ Name = 'pid_9_luid_0x00000000_0x0000C2A1_phys_0_eng_1_engtype_Copy'; UtilizationPercentage = [uint64](1000 + $T * 100); Timestamp_Sys100NS = $ts }
        [pscustomobject]@{ Name = 'pid_9_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D'; UtilizationPercentage = [uint64](1000 + $T * 300); Timestamp_Sys100NS = $ts }
    )
}
function New-TcpRows {
    param([int]$T)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($i in 1..(100 + 20 * $T)) { $rows.Add([pscustomobject]@{ State = 5; OwningProcess = 9 }) }
    foreach ($i in 1..10) { $rows.Add([pscustomobject]@{ State = 11; OwningProcess = 0 }) }
    foreach ($i in 1..5) { $rows.Add([pscustomobject]@{ State = 2; OwningProcess = 4 }) }
    foreach ($i in 1..3) { $rows.Add([pscustomobject]@{ State = 100; OwningProcess = 4 }) }
    $rows.Add([pscustomobject]@{ State = 77; OwningProcess = 9 })
    return $rows.ToArray()
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [string[]]$Property, [int]$OperationTimeoutSec, $ErrorAction)
    $script:CimCalls.Add($ClassName + '|' + ($Property -join ','))
    if ($script:CimFail.ContainsKey($ClassName)) { throw $script:CimFail[$ClassName] }
    switch ($ClassName) {
        'MSFT_NetTCPSetting' { return @([pscustomobject]@{ SettingName = 'Internet'; DynamicPortRangeStartPort = 49152; DynamicPortRangeNumberOfPorts = 1000 }, [pscustomobject]@{ SettingName = 'Datacenter'; DynamicPortRangeStartPort = 49152; DynamicPortRangeNumberOfPorts = 2000 }, [pscustomobject]@{ SettingName = 'Automatic'; DynamicPortRangeStartPort = $null; DynamicPortRangeNumberOfPorts = $null }) }
        'MSFT_NetUDPSetting' { return [pscustomobject]@{ DynamicPortRangeStartPort = 49152; DynamicPortRangeNumberOfPorts = 16384 } }
        'MSFT_NetTCPConnection' { $script:NetTick++; return (New-TcpRows $script:NetTick) }
        'MSFT_NetUDPEndpoint' { return @([pscustomobject]@{ OwningProcess = 9 }, [pscustomobject]@{ OwningProcess = 10 }) }
        'Win32_PerfRawData_GPUPerformanceCounters_GPUEngine' { $script:GpuTick++; return (New-GpuRows $script:GpuTick) }
        'Win32_PerfRawData_GPUPerformanceCounters_GPUAdapterMemory' { return @([pscustomobject]@{ Name = 'luid_0x00000000_0x0000C2A1_phys_0'; DedicatedUsage = [uint64](1200MB); SharedUsage = [uint64](300MB) }) }
        'Win32_Service' { return @([pscustomobject]@{ Name = 'Dnscache'; ProcessId = 700; State = 'Running' }, [pscustomobject]@{ Name = 'CDPUserSvc_4a7f3c'; ProcessId = 700; State = 'Running' }) }
        'Win32_Processor' { return [pscustomobject]@{ NumberOfLogicalProcessors = 8 } }
        'Win32_OperatingSystem' { return [pscustomobject]@{ TotalVisibleMemorySize = 16777216 } }
        'Win32_PerfRawData_PerfOS_Processor' { $script:CpuTick++; return [pscustomobject]@{ PercentProcessorTime = [uint64](1000000 + $script:CpuTick * 2000000); Timestamp_Sys100NS = [uint64](1000000000 + $script:CpuTick * 20000000) } }
        'Win32_PerfRawData_PerfOS_Memory' { $script:MemTick++; return [pscustomobject]@{ AvailableBytes = [uint64](8GB); CommittedBytes = [uint64](4GB); CommitLimit = [uint64](16GB); PagesInputPersec = [uint64](100 + $script:MemTick); Timestamp_PerfTime = [uint64](1000000000 + $script:MemTick * 20000000); Frequency_PerfTime = [uint64]10000000 } }
    }
    return @()
}
function Get-Process { param($ErrorAction) return @([pscustomobject]@{ Id = 9; ProcessName = 'ExampleBrowser' }, [pscustomobject]@{ Id = 10; ProcessName = 'ExampleGame' }) }

$netData = Get-FmpNetPortData -IntervalSec 0
Assert-FmpEqual -Name 'rede: coleta simulada concluida' -Expected 'ok' -Actual $netData['state']
Assert-FmpTrue -Name 'rede: so pede estado e processo' -Condition (@($script:CimCalls | Where-Object { $_ -like 'MSFT_NetTCPConnection|*' -and $_ -ne 'MSFT_NetTCPConnection|State,OwningProcess' }).Count -eq 0)
Assert-FmpEqual -Name 'rede: tres leituras' -Expected 3 -Actual @($netData['samples']).Count
Assert-FmpEqual -Name 'rede: Listen e Bound nao contam como portas em uso' -Expected 111 -Actual @($netData['samples'])[0]['inUse']
Assert-FmpEqual -Name 'rede: menor faixa entre os perfis' -Expected 1000 -Actual $netData['rangeSize']
Assert-FmpTrue -Name 'rede: perfis diferentes sinalizados' -Condition ($netData['rangeVaries'] -eq $true)
Assert-FmpEqual -Name 'rede: tendencia em alta' -Expected 'rising' -Actual $netData['trend']
Assert-FmpEqual -Name 'rede: maior dono por nome' -Expected 'ExampleBrowser' -Actual @($netData['topOwners'])[0]['name']
Assert-FmpEqual -Name 'rede: estado desconhecido vira other' -Expected 1 -Actual $netData['byState']['other']
Assert-FmpEqual -Name 'rede: endpoints UDP' -Expected 2 -Actual $netData['udpEndpoints']
$script:CimFail = @{ MSFT_NetTCPSetting = [System.UnauthorizedAccessException]::new('denied') }
Assert-FmpEqual -Name 'rede: acesso negado' -Expected 'access_denied' -Actual (Get-FmpNetPortData -IntervalSec 0)['state']
$script:CimFail = @{}

$gpuData = Get-FmpGpuUseData -IntervalSec 0
Assert-FmpEqual -Name 'GPU: coleta simulada concluida' -Expected 'ok' -Actual $gpuData['state']
Assert-FmpEqual -Name 'GPU: dois adaptadores separados' -Expected 2 -Actual @($gpuData['adapters']).Count
$gpuMain = @(@($gpuData['adapters']) | Where-Object { $_['dedicatedUsedMB'] -eq 1200 })[0]
Assert-FmpEqual -Name 'GPU: motor soma os processos' -Expected '3D' -Actual @($gpuMain['engines'])[0]['type']
Assert-FmpEqual -Name 'GPU: uso do motor 3D' -Expected 70 -Actual @($gpuMain['engines'])[0]['avgPct']
Assert-FmpEqual -Name 'GPU: VRAM compartilhada' -Expected 300 -Actual $gpuMain['sharedUsedMB']
Assert-FmpEqual -Name 'GPU: maior processo pelo PID real' -Expected 9 -Actual @($gpuData['topProcesses'])[0]['pid']
Assert-FmpEqual -Name 'GPU: uso do maior processo' -Expected 50 -Actual @($gpuData['topProcesses'])[0]['avgPct']
Assert-FmpEqual -Name 'GPU: nome do maior processo' -Expected 'ExampleBrowser' -Actual @($gpuData['topProcesses'])[0]['name']
Assert-FmpTrue -Name 'GPU: identificador do adaptador nao sai do coletor' -Condition ((ConvertTo-FmpJsonText -Data $gpuData) -notmatch 'C2A1|AAAA|luid')
$script:CimFail = @{ Win32_PerfRawData_GPUPerformanceCounters_GPUEngine = 'Invalid class' }
Assert-FmpEqual -Name 'GPU: classe ausente = indisponivel' -Expected 'unsupported' -Actual (Get-FmpGpuUseData -IntervalSec 0)['state']
$script:CimFail = @{}

$script:WinEvents = @{}
$script:AbsentProv = @()
function New-MockEvent {
    param([int]$Id, [int]$Level, [datetime]$At, [string]$Xml = '<Event/>')
    $e = [pscustomobject]@{ Id = $Id; Level = $Level; TimeCreated = $At }
    $e | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Value ([scriptblock]::Create("return '" + $Xml + "'"))
    return $e
}
function Get-WinEvent {
    [CmdletBinding()]
    param([hashtable]$FilterHashtable, [int]$MaxEvents, [switch]$Oldest)
    $prov = [string]$FilterHashtable['ProviderName']
    $code = ''
    if ($prov -in $script:AbsentProv) { $code = 'NoMatchingProvidersFound,Microsoft.PowerShell.Commands.GetWinEventCommand' }
    elseif (-not $script:WinEvents.ContainsKey($prov)) { $code = 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand' }
    if ($code -ne '') { $PSCmdlet.ThrowTerminatingError((New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception 'mock'), $code, 'ObjectNotFound', $null))) }
    return @($script:WinEvents[$prov] | Select-Object -First $MaxEvents)
}
$utcNow = [DateTime]::UtcNow
$guidB = '22222222-3333-4444-8555-666666666666'
$script:WinEvents = @{ 'Windows Error Reporting' = @(
    (New-MockEvent 1001 4 $utcNow.AddHours(-1) (New-WerXml 'LiveKernelEvent' '141' $guidA)),
    (New-MockEvent 1001 4 $utcNow.AddDays(-9) (New-WerXml 'LiveKernelEvent' '141' $guidA)),
    (New-MockEvent 1001 4 $utcNow.AddDays(-10) (New-WerXml 'LiveKernelEvent' '141' $guidA)),
    (New-MockEvent 1001 4 $utcNow.AddHours(-2) (New-WerXml 'APPCRASH' 'secret-app.exe' $guidB))
) }
$werData = Get-FmpWerEvents -Since $utcNow.AddDays(-30) -NowUtc $utcNow -MaxEvents 100
Assert-FmpEqual -Name 'WER: quatro registros, dois relatorios' -Expected 2 -Actual $werData['summary']['reports']
Assert-FmpEqual -Name 'WER: reenvio recente separado' -Expected 1 -Actual $werData['summary']['resendRecent']
Assert-FmpEqual -Name 'WER: uma falha nova' -Expected 1 -Actual $werData['summary']['newRecent']
$werJson = ConvertTo-FmpJsonText -Data $werData
Assert-FmpTrue -Name 'WER: sem ReportId, bucket, caminho ou aplicativo' -Condition ($werJson -notmatch 'alice|BucketSecret|secret-app|11111111-2222|22222222-3333|Store')
Assert-FmpTrue -Name 'WER: limite de registros marcado' -Condition ((Get-FmpWerEvents -Since $utcNow.AddDays(-30) -NowUtc $utcNow -MaxEvents 2)['truncated'] -eq $true)
$script:AbsentProv = @('Windows Error Reporting')
Assert-FmpEqual -Name 'WER: provedor ausente = indisponivel' -Expected 'unsupported' -Actual (Get-FmpWerEvents -Since $utcNow.AddDays(-30) -NowUtc $utcNow)['state']
$script:AbsentProv = @()
$script:WinEvents = @{}
$werEmpty = Get-FmpWerEvents -Since $utcNow.AddDays(-30) -NowUtc $utcNow
Assert-FmpTrue -Name 'WER: sem eventos = vazio com resumo' -Condition ($werEmpty['state'] -eq 'empty' -and $werEmpty['summary']['reports'] -eq 0)

$script:AbsentProv = @('amdkmdag', 'amdkmdap', 'atikmdag', 'igfx', 'igfxn')
$script:WinEvents = @{ nvlddmkm = @((New-MockEvent 153 2 $utcNow.AddHours(-3)), (New-MockEvent 14 2 $utcNow.AddHours(-4))) }
$vendor = Get-FmpGpuVendorEvents -Since $utcNow.AddDays(-30)
Assert-FmpTrue -Name 'GPU: provedores ausentes nao derrubam a consulta' -Condition ($vendor['state'] -eq 'ok' -and $vendor['absentProviders'] -eq 5)
Assert-FmpEqual -Name 'GPU: fabricante pelo provedor' -Expected 'nvidia' -Actual @($vendor['providers'])[0]['vendor']
$script:AbsentProv = @()
$script:WinEvents = @{ amdkmdag = @((New-MockEvent 62464 2 $utcNow.AddHours(-3))); igfx = @((New-MockEvent 9 3 $utcNow.AddHours(-3))) }
$vendors2 = (@($vendor2 = Get-FmpGpuVendorEvents -Since $utcNow.AddDays(-30); $vendor2['providers']) | ForEach-Object { $_['vendor'] } | Where-Object { $_ -ne 'nvidia' }) -join ','
Assert-FmpTrue -Name 'GPU: AMD e Intel identificados' -Condition ($vendors2 -match 'amd' -and $vendors2 -match 'intel')

function Get-PhysicalDisk { param($ErrorAction) return @([pscustomobject]@{ DeviceId = '4'; SerialNumber = 'SERIALSECRET' }) }
function Get-StorageReliabilityCounter { param($PhysicalDisk, $ErrorAction) return [pscustomobject]@{ Temperature = 41; TemperatureMax = 60; ReadErrorsTotal = 2; WriteErrorsTotal = 0; ReadLatencyMax = 12; WriteLatencyMax = 8; Wear = 3; PowerOnHours = 100 } }
$relData = Get-FmpStorageReliabilityData
Assert-FmpTrue -Name 'discos: contadores lidos e ligados ao numero' -Condition ($relData['state'] -eq 'ok' -and @($relData['disks'])[0]['diskNumber'] -eq 4 -and @($relData['disks'])[0]['readErrorsTotal'] -eq 2)
Assert-FmpTrue -Name 'discos: numero de serie nao sai do coletor' -Condition ((ConvertTo-FmpJsonText -Data $relData) -notmatch 'SERIALSECRET')
function Get-StorageReliabilityCounter { param($PhysicalDisk, $ErrorAction) throw [System.UnauthorizedAccessException]::new('denied') }
Assert-FmpEqual -Name 'discos: sem administrador = acesso negado, sem elevar' -Expected 'access_denied' -Actual (Get-FmpStorageReliabilityData)['state']

$script:CimCalls = New-Object System.Collections.Generic.List[string]
$script:CpuTick = -1; $script:MemTick = -1
$conf = Get-FmpConfirmPeakData -Families @('cpu', 'memory') -Config $ruleConfig
Assert-FmpEqual -Name 'confirmacao: CPU alta continua = sustentado' -Expected 'sustained' -Actual $conf['families']['cpu']
Assert-FmpEqual -Name 'confirmacao: paginacao baixa = nao repetiu' -Expected 'isolated' -Actual $conf['families']['memory']
Assert-FmpTrue -Name 'confirmacao: so le as familias pedidas' -Condition (@($script:CimCalls | Where-Object { $_ -match 'PerfProc_Process|PhysicalDisk' }).Count -eq 0)
Assert-FmpEqual -Name 'despacho: id fora do catalogo nao executa nada' -Expected 'unsupported' -Actual (Invoke-FmpInvestigation -Id 'Invoke-Expression' -Diagnostic @{} -Config $ruleConfig -Depth 'deep' -Facts @{} -BudgetMs 1000)['state']

$script:NetTick = -1; $script:GpuTick = -1
$script:WinEvents = @{ 'Windows Error Reporting' = @((New-MockEvent 1001 4 $tGpu.AddDays(16 / 86400) (New-WerXml 'LiveKernelEvent' '141' $guidA))); nvlddmkm = @((New-MockEvent 153 2 $tGpu)) }
$script:AbsentProv = @('amdkmdag', 'amdkmdap', 'atikmdag', 'igfx', 'igfxn')
$e2eDoc = New-InvDoc -Records @((New-Rec 'nvlddmkm' 153 2 $tGpu), (New-Rec 'Tcpip' 4231 2 $tGpu))
$e2eDoc['observation']['processes']['topCpu'] = @([ordered]@{ name = 'svchost#3'; pid = 700; avgCores = 2.0; avgPctOfMachine = 25; activeShare = 1; maxCores = 3 })
$e2eDoc.Remove('investigations')
$e2eAnalysis = Invoke-FmpRules -Diagnostic $e2eDoc -RuleConfig $ruleConfig -Mode 'full'
$e2e = Invoke-FmpInvestigationPlan -Diagnostic $e2eDoc -Analysis $e2eAnalysis -RuleConfig $ruleConfig -Symptom 'crash' -Depth 'standard'
$e2eStates = @{}
foreach ($r in @($e2e['runs'])) { $e2eStates[[string]$r['id']] = [string]$r['state'] }
foreach ($id in @('gpu_events', 'wer_events', 'net_ports', 'service_hosts', 'gpu_use')) { Assert-FmpEqual -Name ('plano real com mocks: ' + $id) -Expected 'ok' -Actual $e2eStates[$id] }
Assert-FmpEqual -Name 'plano real: categoria D nao executa em standard' -Expected 'not_authorized' -Actual $e2eStates['storage_reliability']
Assert-FmpEqual -Name 'plano real: categoria C nao executa em standard' -Expected 'not_authorized' -Actual $e2eStates['confirm_peak']
Assert-FmpTrue -Name 'plano real: dentro do orcamento' -Condition ($e2e['elapsedMs'] -le $e2e['budgetMs'] -and $e2e['budgetExceeded'] -eq $false)
$script:AbsentProv = @()
$script:WinEvents = @{}
function Get-Process { throw 'UNMOCKED_SYSTEM_COMMAND: Get-Process' }
function Get-PhysicalDisk { throw 'UNMOCKED_SYSTEM_COMMAND: Get-PhysicalDisk' }
function Get-StorageReliabilityCounter { throw 'UNMOCKED_SYSTEM_COMMAND: Get-StorageReliabilityCounter' }
function Get-WinEvent { throw 'UNMOCKED_SYSTEM_COMMAND: Get-WinEvent' }

# =====================================================================
Start-FmpSuite 'C. Selecao deterministica e profundidade'
$factsCrash = @{ symptom = 'crash'; answers = @{ cpu_load = 'partial'; storage_slow = 'no' }; families = @{ graphics = 2; network = 0 }; topNames = @{ svchost = $true } }
$first = (@(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'standard' -Level 1) | ForEach-Object { $_['id'] + '=' + $_['decision'] }) -join ','
$same = $true
foreach ($i in 1..100) {
    $again = (@(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'standard' -Level 1) | ForEach-Object { $_['id'] + '=' + $_['decision'] }) -join ','
    if ($again -cne $first) { $same = $false }
}
Assert-FmpTrue -Name 'mesma entrada, mesma selecao (100 repeticoes)' -Condition $same
$std = @{}
foreach ($x in @(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'standard' -Level 1)) { $std[[string]$x['id']] = [string]$x['decision'] }
Assert-FmpEqual -Name 'gatilho falso nao roda' -Expected 'not_triggered' -Actual $std['net_ports']
Assert-FmpEqual -Name 'gatilho verdadeiro roda' -Expected 'run' -Actual $std['gpu_events']
Assert-FmpEqual -Name 'categoria D fora da profundidade padrao' -Expected 'not_authorized' -Actual $std['storage_reliability']
$deep2 = @(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'deep' -Level 2)
Assert-FmpTrue -Name 'confirmacao so no nivel 2 e na profundidade deep' -Condition ($deep2.Count -eq 1 -and $deep2[0]['id'] -eq 'confirm_peak' -and $deep2[0]['decision'] -eq 'run')
Assert-FmpEqual -Name 'confirmacao fora da profundidade padrao' -Expected 'not_authorized' -Actual @(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'standard' -Level 2)[0]['decision']
Assert-FmpEqual -Name 'investigacao ja decidida nao repete' -Expected 0 -Actual @(Select-FmpInvestigations -Config $ruleConfig -Facts $factsCrash -Depth 'deep' -Level 2 -Done @('confirm_peak')).Count
Assert-FmpTrue -Name 'gatilho com vocabulario desconhecido e falso' -Condition (-not (Test-FmpInvestigationTrigger ([pscustomobject]@{ expression = 'x' }) $factsCrash))
$tooDeep = [pscustomobject]@{ or = @([pscustomobject]@{ or = @([pscustomobject]@{ or = @([pscustomobject]@{ symptom = @('crash') }) }) }) }
Assert-FmpTrue -Name 'aninhamento acima do limite e falso' -Condition (-not (Test-FmpInvestigationTrigger $tooDeep $factsCrash))
Assert-FmpEqual -Name 'no maximo duas familias na confirmacao' -Expected 2 -Actual @(Get-FmpPeakFamilies @{ answers = @{ cpu_load = 'partial'; memory_pressure = 'partial'; storage_slow = 'partial' } }).Count
$catalogIds = @(Get-FmpValue $ruleConfig 'diagnosis.investigations' | ForEach-Object { [string]$_.id })
$invText = [System.IO.File]::ReadAllText((Join-Path $root 'src\collectors\Investigations.ps1'))
foreach ($id in $catalogIds) { Assert-FmpTrue -Name ('id do catalogo tem despacho fixo: ' + $id) -Condition ($invText.Contains("'" + $id + "' {")) }
$hypIds = @(Get-FmpValue $ruleConfig 'diagnosis.hypotheses' | ForEach-Object { [string]$_.id })
foreach ($inv in @(Get-FmpValue $ruleConfig 'diagnosis.investigations')) {
    foreach ($hid in @($inv.hypotheses)) { Assert-FmpTrue -Name ('investigacao aponta para hipotese do catalogo: ' + $inv.id + ' -> ' + $hid) -Condition ($hid -in $hypIds) }
}

Start-FmpSuite 'C. Orcamento e criterios de parada'
$script:Called = New-Object System.Collections.Generic.List[string]
$script:MockState = @{}
function Invoke-FmpInvestigation {
    param([string]$Id, [object]$Diagnostic, [object]$Config, [string]$Depth, [object]$Facts, [long]$BudgetMs)
    $script:Called.Add($Id)
    $st = 'ok'
    if ($script:MockState.ContainsKey($Id)) { $st = $script:MockState[$Id] }
    if ($st -eq 'throw') { throw 'C:\Users\alice\secret failure' }
    return [ordered]@{ state = $st; truncated = $false }
}
$planDoc = New-InvDoc -Records @((New-Rec 'Display' 4101 3 $tGpu), (New-Rec 'Tcpip' 4231 2 $tGpu))
$planDoc.Remove('investigations')
$planAnalysis = Invoke-FmpRules -Diagnostic $planDoc -RuleConfig $ruleConfig -Mode 'full'
$script:MockState = @{ wer_events = 'throw'; net_ports = 'access_denied' }
$plan = Invoke-FmpInvestigationPlan -Diagnostic $planDoc -Analysis $planAnalysis -RuleConfig $ruleConfig -Symptom 'crash' -Depth 'standard'
$byRun = @{}
foreach ($r in @($plan['runs'])) { $byRun[[string]$r['id']] = $r }
Assert-FmpEqual -Name 'cada investigacao decidida uma vez' -Expected @($plan['runs']).Count -Actual $byRun.Count
Assert-FmpEqual -Name 'falha na fonte nao e repetida' -Expected 1 -Actual @($script:Called | Where-Object { $_ -eq 'wer_events' }).Count
Assert-FmpEqual -Name 'acesso negado registrado' -Expected 'access_denied' -Actual $byRun['net_ports']['state']
Assert-FmpTrue -Name 'texto do erro nao vaza para o JSON' -Condition ((ConvertTo-FmpJsonText -Data $plan) -notmatch 'alice')
Assert-FmpEqual -Name 'profundidade padrao nao chama categoria D' -Expected 0 -Actual @($script:Called | Where-Object { $_ -eq 'storage_reliability' }).Count
$tightRules = ConvertTo-FmpSerializable -Value $ruleConfig
$tightRules['diagnosis']['budgets']['standardMs'] = 7000
$script:Called = New-Object System.Collections.Generic.List[string]
$script:MockState = @{}
$tightDoc = New-InvDoc -Records @((New-Rec 'Display' 4101 3 $tGpu), (New-Rec 'Tcpip' 4231 2 $tGpu))
$tightDoc.Remove('investigations')
$tight = Invoke-FmpInvestigationPlan -Diagnostic $tightDoc -Analysis $planAnalysis -RuleConfig $tightRules -Symptom 'crash' -Depth 'standard'
Assert-FmpTrue -Name 'o que nao cabe no orcamento fica como budget' -Condition (@(@($tight['runs']) | Where-Object { $_['state'] -eq 'budget' }).Count -ge 1 -and $tight['budgetExceeded'] -eq $true)
Assert-FmpEqual -Name 'item sem orcamento nao e chamado' -Expected 1 -Actual $script:Called.Count

Start-FmpSuite 'C. Confirmacao de picos e estados de hipotese'
Assert-FmpEqual -Name 'media acima do limite = sustentado' -Expected 'sustained' -Actual (Get-FmpConfirmVerdict 10 90 95 0.8 85)
Assert-FmpEqual -Name 'pico sem media alta = recorrente' -Expected 'recurring' -Actual (Get-FmpConfirmVerdict 10 30 90 0.1 85)
Assert-FmpEqual -Name 'sem novo pico = isolado' -Expected 'isolated' -Actual (Get-FmpConfirmVerdict 10 30 40 0 85)
Assert-FmpEqual -Name 'poucas leituras = desconhecido' -Expected 'unknown' -Actual (Get-FmpConfirmVerdict 1 90 90 1 85)
$qs = @(
    [ordered]@{ id = 'cpu_load'; answer = 'partial'; confidence = 'medium'; values = [ordered]@{} },
    [ordered]@{ id = 'memory_pressure'; answer = 'no'; confidence = 'high'; values = [ordered]@{} },
    [ordered]@{ id = 'storage_busy'; answer = 'unknown'; confidence = 'low'; values = [ordered]@{} },
    [ordered]@{ id = 'crash_history'; answer = 'no'; confidence = 'high'; values = [ordered]@{ whea = 0 } }
)
$hyp = @{}
foreach ($h in @(Get-FmpHypotheses -Questions $qs -Config $ruleConfig -Investigations ([ordered]@{ results = [ordered]@{} }))) { $hyp[[string]$h['id']] = $h }
Assert-FmpEqual -Name 'parcial = inconclusiva' -Expected 'inconclusive' -Actual $hyp['cpu_saturation']['state']
Assert-FmpEqual -Name 'fonte respondeu contra = nao sustentada' -Expected 'not_supported' -Actual $hyp['memory_pressure']['state']
Assert-FmpEqual -Name 'sem dados = nao verificada' -Expected 'untested' -Actual $hyp['port_exhaustion_active']['state']
Assert-FmpEqual -Name 'sem WHEA = nao sustentada' -Expected 'not_supported' -Actual $hyp['hardware_error_reported']['state']
Assert-FmpTrue -Name 'hipotese nao verificada tem confianca baixa' -Condition ($hyp['port_exhaustion_active']['confidence'] -eq 'low')
foreach ($loc in @($locPt, $locEn)) {
    $text = [string]$loc.'diag.hstate.untested'
    Assert-FmpTrue -Name 'texto de nao verificada nao fala em provavel' -Condition ($text -notmatch '(?i)prov|likely')
}

# =====================================================================
Start-FmpSuite 'C. Consentimento por profundidade'
$args1 = @{ Mode = 'full'; Symptom = 'crash'; Language = 'pt-BR'; ObserveSeconds = 30; DuringProblem = 'unknown'; IncludeInternal = $false; OutDir = 'C:\x' }
$plain = Get-FmpConsentScope @args1
Assert-FmpEqual -Name 'profundidade padrao mantem o escopo anterior' -Expected $plain -Actual (Get-FmpConsentScope @args1 -Depth 'standard')
$deepScope = Get-FmpConsentScope @args1 -Depth 'deep'
$tok = New-FmpConsentToken -Scope $plain -IssuedUtc $now
Assert-FmpEqual -Name 'token padrao nao autoriza deep' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tok -Scope $deepScope -NowUtc $now)
$tokDeep = New-FmpConsentToken -Scope $deepScope -IssuedUtc $now
Assert-FmpEqual -Name 'token deep vale para deep' -Expected 'valid' -Actual (Test-FmpConsentToken -Token $tokDeep -Scope $deepScope -NowUtc $now)
Assert-FmpEqual -Name 'token deep nao vale para padrao' -Expected 'scope_mismatch' -Actual (Test-FmpConsentToken -Token $tokDeep -Scope $plain -NowUtc $now)
Assert-FmpEqual -Name 'deep usa janela de 60 dias' -Expected 60 -Actual (Get-FmpEventCatalogDays -Config $ruleConfig -Mode 'full' -Symptom 'slow' -Depth 'deep')

Start-FmpSuite 'Seguranca: scanner com teste negativo'
$neg = @(
    @('endereco remoto', 'Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetTCPConnection -Property State, RemoteAddress -ErrorAction Stop'),
    @('porta local', 'Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetTCPConnection -Property LocalPort -ErrorAction Stop'),
    @('conexoes sem -Property', 'Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetTCPConnection -ErrorAction Stop'),
    @('-Property variavel', 'function Get-FmpX { param([string[]]$p) Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetTCPConnection -Property $p -ErrorAction Stop }'),
    @('endpoint UDP com porta', 'Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetUDPEndpoint -Property LocalPort -ErrorAction Stop'),
    @('outra classe do namespace', 'Get-CimInstance -Namespace ''root\StandardCimv2'' -ClassName MSFT_NetFirewallRule -ErrorAction Stop'),
    @('GPU sem -Property', 'Get-CimInstance -ClassName Win32_PerfRawData_GPUPerformanceCounters_GPUEngine -ErrorAction Stop'),
    @('Win32_Process continua proibida', 'Get-CimInstance -ClassName Win32_Process -Property CommandLine -ErrorAction Stop'),
    @('provedor WER em variavel', 'function Get-FmpX { param([string]$p) Get-WinEvent -FilterHashtable @{ LogName = ''Application''; ProviderName = $p } -MaxEvents 1 -ErrorAction Stop }'),
    @('parametro extra na confiabilidade', 'Get-StorageReliabilityCounter -Disk $null -ErrorAction Stop'),
    @('netsh continua proibido', 'netsh interface ipv4 show dynamicport tcp'),
    @('nvidia-smi continua proibido', 'nvidia-smi'),
    @('Add-Type continua proibido', 'Add-Type -TypeDefinition ''public class X {}''')
)
$i = 0
foreach ($x in $neg) {
    $i++
    $tmp = Join-Path $scratch ('neg-' + $i + '.ps1')
    Write-FmpUtf8File $tmp $x[1]
    Assert-FmpTrue -Name ('scanner recusa: ' + $x[0]) -Condition (-not (Test-FmpScriptCompliance -Path $tmp -Role 'collector').Ok)
}
Assert-FmpTrue -Name 'projeto inteiro passa no scanner' -Condition (Test-FmpReadOnlyCompliance -Root $root -IncludeTests).Ok
foreach ($src in @('src\collectors\Investigations.ps1', 'src\analysis\Correlation.ps1')) {
    Assert-FmpTrue -Name ('arquivo novo esta na lista do scanner: ' + $src) -Condition ($src -in $script:FmpSourceFiles)
    $txt = [System.IO.File]::ReadAllText((Join-Path $root $src))
    Assert-FmpTrue -Name ('sem endereco, linha de comando ou assinatura: ' + $src) -Condition ($txt -notmatch '(?i)RemoteAddress|LocalAddress|CommandLine|ExecutablePath|Get-AuthenticodeSignature|Add-Type')
}

# =====================================================================
Start-FmpSuite 'Compatibilidade, JSON, HTML e privacidade'
foreach ($fx in @('diag-slow-use.json', 'diag-crash-recurring.json')) {
    $plainDoc = ConvertTo-FmpSerializable -Value (Read-FmpJsonFile -Path (Join-Path $root ('tests\fixtures\' + $fx))).Data
    $r1 = Invoke-FmpDx -Doc $plainDoc
    Assert-FmpTrue -Name ('documento anterior nao ganha hipoteses: ' + $fx) -Condition (-not $r1.Dx.Contains('hypotheses') -and @($r1.Dx['questions']).Count -eq 8)
    $r2 = Invoke-FmpDx -Doc (New-InvDoc -Records $codexRecs -Results @{ wer_events = $codexWer } -Fixture $fx)
    Assert-FmpEqual -Name ('investigacoes nao alteram a nota: ' + $fx) -Expected $r1.Score['score'] -Actual $r2.Score['score']
}
$canaryWer = New-WerResult -Records @(@{ at = $tGpu.AddDays(16 / 86400); kind = 'live_kernel'; code = '141'; ref = 'a' }, @{ at = $tGpu; kind = 'app_crash'; code = $null; ref = 'b' }) -NowUtc $refEnd
$canaryNet = [ordered]@{ state = 'ok'; truncated = $false; rangeStart = 49152; rangeSize = 16384; rangeVaries = $true; samples = @([ordered]@{ total = 14000; inUse = 14000; timeWait = 10 }); byState = [ordered]@{ established = 14000 }
    udpEndpoints = 10; topOwners = @([ordered]@{ pid = 9; name = 'C:\Users\alice\app.exe 192.168.10.44'; connections = 4000 }); usagePct = 85.4; growthPctOfRange = 2; trend = 'rising'; risk = 'high' }
$canaryGpu = [ordered]@{ state = 'ok'; truncated = $false; intervals = 2; adapters = @([ordered]@{ adapter = 0; dedicatedUsedMB = 1200; sharedUsedMB = 300; engines = @([ordered]@{ type = '3D'; avgPct = 45.2; maxPct = 80.1 }) }); topProcesses = @() }
$canarySvc = [ordered]@{ state = 'ok'; truncated = $false; hosts = @([ordered]@{ pid = 700; serviceCount = 2; shared = $true; services = @('Dnscache', 'CDPUserSvc_4a7f3c'); metric = 'cpu' }) }
$canaryRel = [ordered]@{ state = 'ok'; truncated = $false; disks = @([ordered]@{ diskNumber = 4; temperatureC = 40; temperatureMaxC = 55; readErrorsTotal = 0; writeErrorsTotal = 0; readLatencyMaxMs = 12; writeLatencyMaxMs = 9; wearPct = 3; powerOnHours = 100 }) }
$canaryConfirm = [ordered]@{ state = 'ok'; truncated = $false; windowSec = 30; families = [ordered]@{ cpu = 'isolated' } }
foreach ($lang in @('pt-BR', 'en')) {
    $doc = New-InvDoc -Records $codexRecs -Results @{ wer_events = $canaryWer; net_ports = $canaryNet; gpu_use = $canaryGpu; service_hosts = $canarySvc; storage_reliability = $canaryRel; confirm_peak = $canaryConfirm; gpu_events = [ordered]@{ state = 'ok'; truncated = $false; absentProviders = 3; providers = @([ordered]@{ provider = 'nvlddmkm'; vendor = 'nvidia'; count = 1; truncated = $false; ids = @([ordered]@{ eventId = 153; count = 1 }); times = @() }) } }
    $doc['investigations']['runs'] = @([ordered]@{ id = 'wer_events'; level = 1; category = 'H'; hypotheses = @('application_failures'); state = 'ok'; elapsedMs = 100; truncated = $false }, [ordered]@{ id = 'storage_reliability'; level = 1; category = 'D'; hypotheses = @('storage_path_instability'); state = 'not_authorized'; elapsedMs = 0; truncated = $false })
    $res = Invoke-FmpDx -Doc $doc -Lang $lang
    $san = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $res.Doc
    Assert-FmpTrue -Name ('documento sanitizado valido: ' + $lang) -Condition (Test-FmpDiagnosticDocument $san)
    $json = ConvertTo-FmpJsonText -Data $san
    Reset-FmpMissingLocaleKeys
    if ($lang -eq 'en') { Set-FmpRenderLocale -Primary $locEn -Fallback $locPt -Language 'en' } else { Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR' }
    $html = Get-FmpHtmlReportText -Diagnostic $san -Synthetic:$true -RedactionCount 0
    $missing = Get-FmpMissingLocaleKeys
    Assert-FmpEqual -Name ('nenhuma chave de traducao faltando: ' + $lang) -Expected 0 -Actual $missing.Count
    if ($missing.Count -gt 0) { Write-Host ('    faltando: ' + ($missing -join ', ')) }
    foreach ($canary in @('alice', '192.168.10.44', '4a7f3c')) {
        Assert-FmpTrue -Name ('JSON sanitizado sem ' + $canary + ' (' + $lang + ')') -Condition (-not $json.Contains($canary))
        Assert-FmpTrue -Name ('HTML sem ' + $canary + ' (' + $lang + ')') -Condition (-not $html.Contains($canary))
    }
    Assert-FmpTrue -Name ('JSON sem campos de endereco ou comando: ' + $lang) -Condition ($json -notmatch '(?i)"(remoteAddress|localAddress|remotePort|localPort|commandLine|executablePath|storePath|attachedFiles|bucket)"')
    Assert-FmpTrue -Name ('CSP preservada: ' + $lang) -Condition ($html.Contains('Content-Security-Policy'))
    Assert-FmpTrue -Name ('offline: ' + $lang) -Condition ($html -notmatch '(?i)<(script|link|img)[^>]+(src|href)="https?://')
    $decoded = [System.Net.WebUtility]::HtmlDecode($html)
    $needles = @('nvlddmkm', 'Dnscache', '#4')
    if ($lang -eq 'pt-BR') { $needles += @('Investigacoes complementares'.Replace('coes', ([string][char]0x00E7 + [char]0x00F5 + 'es')), 'Conex') } else { $needles += @('Complementary investigations', 'Hypotheses evaluated', 'Connections and ports now', 'Disk reliability', 'Peak confirmation') }
    foreach ($needle in $needles) { Assert-FmpTrue -Name ('HTML mostra "' + $needle + '" (' + $lang + ')') -Condition ($decoded.Contains($needle)) }
}

# =====================================================================
Start-FmpSuite 'C. CLI completo com coletores simulados e consentimento por profundidade'
# A copy of the project whose collector files hold only stubs: the real branch of fixmypc.ps1 runs and nothing is queried.
$stubBody = "{ param([System.Collections.IDictionary]`$ctx) Add-FmpSubCheck -Ctx `$ctx -Id 'stub.check' -State 'pass' }"
$stubs = @{
    'Observation.ps1' = "function Get-FmpObservationData { param(`$DurationSec, `$IntervalSec, `$MaxSamples, `$CpuHighPct) return Invoke-FmpCollector -Name 'observation' -Body $stubBody }"
    'System.ps1' = "function Get-FmpSystemData { return Invoke-FmpCollector -Name 'system' -Body $stubBody }"
    'Events.ps1' = "function Get-FmpEventData { param([int]`$WindowDays, [bool]`$Full, [bool]`$BootHistory, [int]`$BootDays, [int]`$CatalogDays, [int]`$CatalogMaxPerProvider) return Invoke-FmpCollector -Name 'events' -Body $stubBody }"
    'Startup.ps1' = "function Get-FmpStartupData { return Invoke-FmpCollector -Name 'startup' -Body $stubBody }"
    'Performance.ps1' = "function Get-FmpPerformanceData { return Invoke-FmpCollector -Name 'performance' -Body $stubBody }"
    'Storage.ps1' = "function Get-FmpStorageData { return Invoke-FmpCollector -Name 'storage' -Body $stubBody }"
    'Advanced.ps1' = "function Get-FmpAdvancedData { return Invoke-FmpCollector -Name 'advanced' -Body $stubBody }"
    'Investigations.ps1' = "function Invoke-FmpInvestigationPlan { param([object]`$Diagnostic, [object]`$Analysis, [object]`$RuleConfig, [string]`$Symptom, [string]`$DuringProblem, [string]`$Depth) return [ordered]@{ version = '1'; depth = `$Depth; categories = @('H'); budgetMs = 45000; elapsedMs = 1; budgetExceeded = `$false; runs = @([ordered]@{ id = 'wer_events'; level = 1; category = 'H'; hypotheses = @('application_failures'); state = 'empty'; elapsedMs = 1; truncated = `$false }); results = [ordered]@{ wer_events = [ordered]@{ state = 'empty'; truncated = `$false; summary = [ordered]@{ records = 0; reports = 0; newRecent = 0; recentHours = 48 } } } } }"
}
$stubRoot = Join-Path $scratch 'stub-project'
New-FmpOutputDirectory $stubRoot
foreach ($relative in $script:FmpSourceFiles) {
    $target = Join-Path $stubRoot $relative
    New-FmpOutputDirectory (Split-Path -Parent $target)
    if ($relative -like 'src\collectors\*') { Write-FmpUtf8File $target $stubs[(Split-Path -Path $target -Leaf)] }
    else { Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative))) }
}
foreach ($relative in @('locales\pt-BR.json', 'locales\en.json', 'rules\rules.json', 'templates\style.css')) {
    $target = Join-Path $stubRoot $relative
    New-FmpOutputDirectory (Split-Path -Parent $target)
    Write-FmpUtf8File $target ([System.IO.File]::ReadAllText((Join-Path $root $relative)))
}
Set-FmpAllowedWriteRoot $scratch
$stubCli = Join-Path $stubRoot 'fixmypc.ps1'
function Invoke-FmpStubCli {
    param([string[]]$CliArgs)
    # A refused parameter writes to stderr, which PowerShell 5.1 would otherwise raise here as a terminating error.
    $ErrorActionPreference = 'Continue'
    $o = & powershell -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $stubCli @CliArgs 2>&1 | ForEach-Object { [string]$_ }
    return @{ Code = $LASTEXITCODE; Text = ($o -join "`n") }
}
function Get-FmpStubToken {
    param([string]$OutDir, [string[]]$Extra = @())
    $pl = Invoke-FmpStubCli (@('-Plan', '-Mode', 'full', '-Symptom', 'crash', '-Language', 'pt-BR', '-OutDir', $OutDir) + $Extra)
    if ($pl.Text -match '-ConsentToken (fmpc1-\d{14}-[0-9a-f]{16})') { return @{ Token = $Matches[1]; Text = $pl.Text; Code = $pl.Code } }
    return @{ Token = ''; Text = $pl.Text; Code = $pl.Code }
}
function Get-FmpStubRunArgs {
    param([string]$OutDir, [string]$Token, [string[]]$Extra = @())
    return @('-Mode', 'full', '-Symptom', 'crash', '-Language', 'pt-BR', '-ObserveSeconds', '30', '-DuringProblem', 'unknown') + $Extra + @('-OutDir', $OutDir, '-AcceptReadOnlyPolicy', '-ConsentToken', $Token)
}
$deepDir = Join-Path $scratch 'cli-deep'
$deepPlan = Get-FmpStubToken -OutDir $deepDir -Extra @('-Depth', 'deep')
Assert-FmpEqual -Name '-Plan deep: exit 0' -Expected 0 -Actual $deepPlan.Code
Assert-FmpTrue -Name '-Plan deep imprime a profundidade no comando' -Condition ($deepPlan.Text.Contains(' -Depth deep '))
Assert-FmpTrue -Name '-Plan descreve o que nunca e coletado' -Condition ($deepPlan.Text -match 'linhas de comando')
Assert-FmpTrue -Name '-Plan nao cria a pasta' -Condition (-not (Test-Path -LiteralPath $deepDir))
$stdDir = Join-Path $scratch 'cli-std'
$stdPlan = Get-FmpStubToken -OutDir $stdDir
Assert-FmpTrue -Name '-Plan standard nao inclui -Depth' -Condition (-not $stdPlan.Text.Contains(' -Depth '))
$mismatch = Invoke-FmpStubCli (Get-FmpStubRunArgs -OutDir $stdDir -Token $stdPlan.Token -Extra @('-Depth', 'deep'))
Assert-FmpEqual -Name 'token standard recusado em deep' -Expected 3 -Actual $mismatch.Code
Assert-FmpTrue -Name 'recusa nao cria a pasta nem coleta' -Condition (-not (Test-Path -LiteralPath $stdDir))
$mismatch2 = Invoke-FmpStubCli (Get-FmpStubRunArgs -OutDir $deepDir -Token $deepPlan.Token)
Assert-FmpEqual -Name 'token deep recusado em standard' -Expected 3 -Actual $mismatch2.Code
$deepRun = Invoke-FmpStubCli (Get-FmpStubRunArgs -OutDir $deepDir -Token $deepPlan.Token -Extra @('-Depth', 'deep'))
Assert-FmpTrue -Name 'fluxo real com stubs em deep: exit 0' -Condition ($deepRun.Code -eq 0) -Detail $deepRun.Text
$deepJson = Join-Path $deepDir 'diagnostic-sanitized.json'
if (Test-Path -LiteralPath $deepJson) {
    $dj = (Read-FmpJsonFile -Path $deepJson).Data
    Assert-FmpEqual -Name 'JSON registra a profundidade aprovada' -Expected 'deep' -Actual (Get-FmpValue $dj 'run.depth')
    Assert-FmpEqual -Name 'plano recebeu a profundidade aprovada' -Expected 'deep' -Actual (Get-FmpValue $dj 'investigations.depth')
    Assert-FmpTrue -Name 'hipoteses chegam ao JSON final' -Condition (@(Get-FmpValue $dj 'diagnosis.hypotheses').Count -ge 9)
    Assert-FmpTrue -Name 'relatorio HTML gerado no fluxo real' -Condition (Test-Path -LiteralPath (Join-Path $deepDir 'report.html'))
    Assert-FmpTrue -Name 'reserva de uso unico criada' -Condition (Test-Path -LiteralPath (Join-Path $deepDir 'run-reservation.json'))
}
else { Assert-FmpTrue -Name 'JSON do fluxo real gerado' -Condition $false -Detail $deepRun.Text }
$replay = Invoke-FmpStubCli (Get-FmpStubRunArgs -OutDir $deepDir -Token $deepPlan.Token -Extra @('-Depth', 'deep'))
Assert-FmpEqual -Name 'mesma autorizacao nao roda duas vezes' -Expected 3 -Actual $replay.Code
$stdRunPlan = Get-FmpStubToken -OutDir (Join-Path $scratch 'cli-std2')
$stdRun = Invoke-FmpStubCli (Get-FmpStubRunArgs -OutDir (Join-Path $scratch 'cli-std2') -Token $stdRunPlan.Token)
Assert-FmpEqual -Name 'fluxo real com stubs em standard: exit 0' -Expected 0 -Actual $stdRun.Code
Assert-FmpEqual -Name 'standard registrado no JSON' -Expected 'standard' -Actual (Get-FmpValue (Read-FmpJsonFile -Path (Join-Path $scratch 'cli-std2\diagnostic-sanitized.json')).Data 'run.depth')
$simpleDeep = Invoke-FmpStubCli @('-Plan', '-Mode', 'simple', '-Depth', 'deep', '-OutDir', (Join-Path $scratch 'cli-simple'))
Assert-FmpEqual -Name 'deep na Auditoria Rapida recusado' -Expected 3 -Actual $simpleDeep.Code
$badDepth = Invoke-FmpStubCli @('-Plan', '-Mode', 'full', '-Depth', 'extreme', '-OutDir', (Join-Path $scratch 'cli-bad-depth'))
Assert-FmpTrue -Name 'profundidade fora da lista recusada' -Condition ($badDepth.Code -ne 0)

Remove-Item -LiteralPath $scratch -Recurse -Force
Write-Host ''
Write-Host ('PhaseBC: ' + $script:PassCount + ' passed, ' + $script:FailCount + ' failed')
foreach ($f in $script:Failures) { Write-Host ('  ' + $f) -ForegroundColor Red }
if ($script:FailCount -gt 0) { exit 1 }
exit 0
