# =====================================================================
# FIX MY PC - Diagnosis.ps1
#
# Deterministic, symptom-oriented layer over the collected data and the
# rule results. It answers fixed questions ("did the CPU stay saturated
# during the observation?", "did Windows record degraded boots?") and,
# for each answer, records the evidence values, source, observation
# window, relevance to the reported symptom, confidence, limitations and
# alternative explanations. It never infers a cause: an answer is an
# observation, and the strongest wording it produces is "may contribute".
# Missing data is reported as unknown / not collected, never as healthy.
# Thresholds and the symptom relevance matrix live in rules.json
# ("diagnosis"); texts live in locales/*.json (diag.*).
# =====================================================================

$script:FmpDiagnosisVersion = '1'
$script:FmpSymptoms = @('general', 'boot', 'slow', 'crash')

function Get-FmpObserveSeconds {
    # Full audit observation window: explicit value (15-300) or the per-symptom default from rules.json. Quick audit: 0.
    param([object]$Config, [string]$Mode, [string]$Symptom, [int]$Requested = 0)
    if ($Mode -ne 'full') { return 0 }
    $min = [int](Get-FmpValue $Config 'diagnosis.observation.minSeconds' -Default 15)
    $max = [int](Get-FmpValue $Config 'diagnosis.observation.maxSeconds' -Default 300)
    $v = $Requested
    if ($v -le 0) { $v = [int](Get-FmpValue $Config ('diagnosis.observation.defaultSeconds.' + $Symptom) -Default 45) }
    return [int][Math]::Max($min, [Math]::Min($max, $v))
}

function Get-FmpEventWindowDays {
    param([object]$Config, [string]$Mode, [string]$Symptom)
    if ($Mode -ne 'full') { return 7 }
    $d = [int](Get-FmpValue $Config ('diagnosis.eventWindowDays.' + $Symptom) -Default 7)
    return [int][Math]::Max(1, [Math]::Min(60, $d))
}

function Get-FmpDiagNumber {
    param([object]$Data, [string]$Path)
    return ConvertTo-FmpNullableDouble (Get-FmpValue $Data $Path)
}

function Get-FmpDiagThreshold {
    param([object]$Config, [string]$Name, [double]$Default)
    $v = ConvertTo-FmpNullableDouble (Get-FmpValue $Config ('diagnosis.thresholds.' + $Name))
    if ($null -eq $v) { return $Default }
    return $v
}

function Get-FmpDiagRelevance {
    param([object]$Config, [string]$Symptom, [string]$Area)
    $r = [string](Get-FmpValue $Config ('diagnosis.relevance.' + $Symptom + '.' + $Area))
    if ($r -cin @('high', 'medium', 'low')) { return $r }
    return 'medium'
}

function Set-FmpDiagRelevance {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Question, [string]$Relevance)
    $Question['relevance'] = $Relevance
}

function Add-FmpDiagAlternative {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Question, [string]$Key)
    $Question['alternativeKeys'] = @(@($Key) + @($Question['alternativeKeys']))
}

function New-FmpDiagQuestion {
    param([string]$Id, [string]$Area, [string]$Answer, [string]$Confidence, [string]$Source, [string]$Window,
          [System.Collections.IDictionary]$Values, [string[]]$Limitations = @(), [string[]]$Alternatives = @())
    return [ordered]@{
        id = $Id; area = $Area; answer = $Answer; relevance = 'medium'; confidence = $Confidence
        source = $Source; window = $Window; values = $Values
        limitationKeys = @($Limitations); alternativeKeys = @($Alternatives)
    }
}

function Get-FmpDiagEventStats {
    # Occurrences of matching event groups inside the window: total, distinct UTC days and the latest timestamp.
    param([object]$D, [string]$Log, [string]$ProviderPattern, [int[]]$Ids, [object]$Now, [double]$Hours)
    $count = 0
    $days = @{}
    $last = $null
    foreach ($g in @(Get-FmpValue $D ('events.logs.' + $Log + '.groups'))) {
        if ($null -eq $g) { continue }
        $prov = [string](Get-FmpValue $g 'provider')
        $eid = ConvertTo-FmpNullableInt (Get-FmpValue $g 'eventId')
        if ($prov -notmatch $ProviderPattern -or $eid -notin $Ids) { continue }
        $occ = @(Get-FmpValue $g 'occurrences')
        if ($occ.Count -gt 0) {
            foreach ($o in $occ) {
                $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
                $age = Get-FmpHoursBetween (Get-FmpValue $o 'at') $Now
                if ($null -eq $at -or $null -eq $age -or $age -lt 0 -or $age -gt $Hours) { continue }
                $count++
                $days[$at.ToUniversalTime().ToString('yyyy-MM-dd')] = $true
                if ($null -eq $last -or $at -gt $last) { $last = $at }
            }
        }
        else {
            # Legacy group without timestamps per event: count it, the day span is only known from first/last.
            $n = ConvertTo-FmpNullableInt (Get-FmpValue $g 'count')
            $ls = Get-FmpParsedDate (Get-FmpValue $g 'lastSeen')
            $fs = Get-FmpParsedDate (Get-FmpValue $g 'firstSeen')
            if ($null -eq $n -or $n -lt 1) { continue }
            $lastAge = Get-FmpHoursBetween $ls $Now
            if ($null -eq $lastAge -or $lastAge -lt 0 -or $lastAge -gt $Hours) { continue }
            $firstAge = Get-FmpHoursBetween $fs $Now
            $days[$ls.ToUniversalTime().ToString('yyyy-MM-dd')] = $true
            if ($null -eq $last -or $ls -gt $last) { $last = $ls }
            if ($null -ne $firstAge -and $firstAge -ge $lastAge -and $firstAge -le $Hours) {
                $count += $n
                $days[$fs.ToUniversalTime().ToString('yyyy-MM-dd')] = $true
            }
            else { $count++ }
        }
    }
    return [ordered]@{ count = $count; days = $days.Count; last = $last }
}

# ---------------------------------------------------------------
# Questions
# ---------------------------------------------------------------
function Get-FmpDiagCpuQuestion {
    param([object]$D, [object]$Config)
    $obs = Get-FmpValue $D 'observation.cpu'
    $high = Get-FmpDiagThreshold $Config 'cpuHighPct' 85
    $sustained = Get-FmpDiagThreshold $Config 'cpuSustainedShare' 0.5
    $alts = @('diag.alt.legit_load', 'diag.alt.background_tasks')
    if ($null -ne $obs -and [string](Get-FmpValue $obs 'state') -eq 'pass' -and (Get-FmpDiagNumber $obs 'stats.count') -ge 2) {
        $avg = Get-FmpDiagNumber $obs 'stats.avg'
        $max = Get-FmpDiagNumber $obs 'stats.max'
        $share = Get-FmpDiagNumber $obs 'stats.highShare'
        if ($null -eq $share) { $share = 0 }
        $procNames = New-Object System.Collections.Generic.List[string]
        $minActive = Get-FmpDiagThreshold $Config 'procSustainedActiveShare' 0.6
        $minCores = Get-FmpDiagThreshold $Config 'procSustainedCores' 0.5
        foreach ($p in @(Get-FmpValue $D 'observation.processes.topCpu')) {
            $a = Get-FmpDiagNumber $p 'activeShare'
            $c = Get-FmpDiagNumber $p 'avgCores'
            if ($null -ne $a -and $null -ne $c -and $a -ge $minActive -and $c -ge $minCores -and $procNames.Count -lt 3) {
                $procNames.Add(([string](Get-FmpValue $p 'name')) + ' (' + (Get-FmpValue $p 'avgPctOfMachine') + '%)')
            }
        }
        $answer = 'no'
        if ($share -ge $sustained) { $answer = 'yes' }
        elseif ($null -ne $max -and $max -ge $high) { $answer = 'partial' }
        $n = Get-FmpDiagNumber $obs 'stats.count'
        $conf = 'high'
        if ($n -lt 6) { $conf = 'medium' }
        $vals = [ordered]@{ avg = $avg; max = $max; highPct = $high; highSharePct = [Math]::Round(100 * $share, 0); window = (Get-FmpValue $D 'observation.actualSec'); processes = ($procNames.ToArray() -join ', ') }
        return New-FmpDiagQuestion -Id 'cpu_load' -Area 'cpu' -Answer $answer -Confidence $conf -Source 'observation.cpu' -Window 'observation' -Values $vals -Limitations @('diag.lim.window_only') -Alternatives $alts
    }
    # Full audit whose observation failed: report that state; a 4 s snapshot must not stand in for it as "no".
    if ($null -ne $obs) {
        $st = [string](Get-FmpValue $obs 'state')
        if ($st -notin @('access_denied', 'unsupported', 'error')) { $st = 'unknown' }
        return New-FmpDiagQuestion -Id 'cpu_load' -Area 'cpu' -Answer $st -Confidence 'low' -Source 'observation.cpu' -Window 'none' -Values ([ordered]@{})
    }
    # Quick audit: only the ~4 s snapshot exists. It can show a busy moment, never a sustained load.
    $cpu = Get-FmpValue $D 'performance.cpu'
    $avgS = Get-FmpDiagNumber $cpu 'avgPercent'
    if ($null -eq $avgS) {
        $st = 'unknown'
        if ($null -ne $obs) { $st = [string](Get-FmpValue $obs 'state') }
        if ($st -notin @('access_denied', 'unsupported', 'error')) { $st = 'unknown' }
        return New-FmpDiagQuestion -Id 'cpu_load' -Area 'cpu' -Answer $st -Confidence 'low' -Source 'observation.cpu' -Window 'none' -Values ([ordered]@{})
    }
    $ansS = 'no'
    if ($avgS -ge $high) { $ansS = 'partial' }
    return New-FmpDiagQuestion -Id 'cpu_load' -Area 'cpu' -Answer $ansS -Confidence 'low' -Source 'performance.cpu' -Window 'snapshot' -Values ([ordered]@{ avg = $avgS; max = (Get-FmpDiagNumber $cpu 'maxPercent'); highPct = $high; highSharePct = $null; window = 4; processes = '' }) -Limitations @('diag.lim.snapshot_only') -Alternatives $alts
}

function Get-FmpDiagMemoryQuestion {
    param([object]$D, [object]$Config)
    $obs = Get-FmpValue $D 'observation.memory'
    $lowPct = Get-FmpDiagThreshold $Config 'memLowAvailablePct' 10
    $lowMB = Get-FmpDiagThreshold $Config 'memLowAvailableMB' 1024
    $pagingHigh = Get-FmpDiagThreshold $Config 'pagesInputHighPerSec' 100
    $commitHigh = Get-FmpDiagThreshold $Config 'commitHighPct' 90
    $alts = @('diag.alt.many_apps', 'diag.alt.short_window_leak')
    if ($null -ne $obs -and [string](Get-FmpValue $obs 'state') -eq 'pass' -and (Get-FmpDiagNumber $obs 'availableMB.count') -ge 2) {
        $total = Get-FmpDiagNumber $obs 'totalBytes'
        $availAvg = Get-FmpDiagNumber $obs 'availableMB.avg'
        $availMin = Get-FmpDiagNumber $obs 'availableMB.min'
        $availPct = $null
        if ($null -ne $total -and $total -gt 0 -and $null -ne $availAvg) { $availPct = [Math]::Round(100 * $availAvg * 1MB / $total, 1) }
        $pagesAvg = Get-FmpDiagNumber $obs 'pagesInputPerSec.avg'
        $pagesP90 = Get-FmpDiagNumber $obs 'pagesInputPerSec.p90'
        $commitMax = Get-FmpDiagNumber $obs 'commitPct.max'
        $lowAvail = ($null -ne $availAvg -and $availAvg -lt $lowMB -and ($null -eq $availPct -or $availPct -lt $lowPct))
        $paging = ($null -ne $pagesAvg -and $pagesAvg -ge $pagingHigh)
        $commit = ($null -ne $commitMax -and $commitMax -ge $commitHigh)
        $answer = 'no'
        if ($lowAvail -and ($paging -or $commit)) { $answer = 'yes' }
        elseif ($lowAvail -or $paging -or $commit) { $answer = 'partial' }
        elseif ($null -eq $pagesAvg -or $null -eq $commitMax) { $answer = 'unknown' }
        # Committed memory when collected; 2.0 documents only have the private working set.
        $top = @(Get-FmpValue $D 'observation.processes.topCommit' | Where-Object { $null -ne $_ } | Select-Object -First 3 | ForEach-Object { ([string](Get-FmpValue $_ 'name')) + ' (' + (Get-FmpValue $_ 'commitPrivateMB') + ' MB)' }) -join ', '
        if ($top -eq '') { $top = @(Get-FmpValue $D 'observation.processes.topMemory' | Select-Object -First 3 | ForEach-Object { ([string](Get-FmpValue $_ 'name')) + ' (' + (Get-FmpValue $_ 'privateMB') + ' MB)' }) -join ', ' }
        $vals = [ordered]@{ availAvgMB = $availAvg; availMinMB = $availMin; availPct = $availPct; pagesAvg = $pagesAvg; pagesP90 = $pagesP90; commitMax = $commitMax; window = (Get-FmpValue $D 'observation.actualSec'); processes = $top }
        $conf = 'high'
        if ((Get-FmpDiagNumber $obs 'availableMB.count') -lt 6) { $conf = 'medium' }
        return New-FmpDiagQuestion -Id 'memory_pressure' -Area 'memory' -Answer $answer -Confidence $conf -Source 'observation.memory' -Window 'observation' -Values $vals -Limitations @('diag.lim.standby_is_available', 'diag.lim.window_only') -Alternatives $alts
    }
    if ($null -ne $obs) {
        $st = [string](Get-FmpValue $obs 'state')
        if ($st -notin @('access_denied', 'unsupported', 'error')) { $st = 'unknown' }
        return New-FmpDiagQuestion -Id 'memory_pressure' -Area 'memory' -Answer $st -Confidence 'low' -Source 'observation.memory' -Window 'none' -Values ([ordered]@{})
    }
    $mem = Get-FmpValue $D 'performance.memory'
    $pct = Get-FmpDiagNumber $mem 'availablePct'
    $cp = Get-FmpDiagNumber $mem 'commitPct'
    if ($null -eq $pct -and $null -eq $cp) {
        return New-FmpDiagQuestion -Id 'memory_pressure' -Area 'memory' -Answer 'unknown' -Confidence 'low' -Source 'observation.memory' -Window 'none' -Values ([ordered]@{})
    }
    $ansS = 'no'
    if (($null -ne $pct -and $pct -lt $lowPct) -or ($null -ne $cp -and $cp -ge $commitHigh)) { $ansS = 'partial' }
    $availMB = Get-FmpDiagNumber $mem 'availableMB'
    return New-FmpDiagQuestion -Id 'memory_pressure' -Area 'memory' -Answer $ansS -Confidence 'low' -Source 'performance.memory' -Window 'snapshot' -Values ([ordered]@{ availAvgMB = $availMB; availMinMB = $availMB; availPct = $pct; pagesAvg = $null; pagesP90 = $null; commitMax = $cp; window = 0; processes = '' }) -Limitations @('diag.lim.snapshot_only') -Alternatives $alts
}

function Get-FmpDiagStorageQuestions {
    # Two separate observations: "busy" (requests queued most of the time) and "slow to respond" (high latency).
    param([object]$D, [object]$Config)
    $latHigh = Get-FmpDiagThreshold $Config 'diskLatencyHighMs' 50
    $latWarn = Get-FmpDiagThreshold $Config 'diskLatencyWarnMs' 20
    $qBusy = Get-FmpDiagThreshold $Config 'diskQueueBusy' 1
    $qPeak = Get-FmpDiagThreshold $Config 'diskQueuePeak' 4
    $obs = Get-FmpValue $D 'observation.disks'
    $state = [string](Get-FmpValue $obs 'state')
    $items = @(Get-FmpValue $obs 'items' | Where-Object { (Get-FmpDiagNumber $_ 'intervals') -ge 2 })
    if ($null -eq $obs -or $state -ne 'pass' -or $items.Count -eq 0) {
        $st = 'not_collected'
        if ($null -ne $obs) { $st = $state; if ($st -notin @('access_denied', 'unsupported', 'error')) { $st = 'unknown' } }
        Write-Output (New-FmpDiagQuestion -Id 'storage_busy' -Area 'storage' -Answer $st -Confidence 'low' -Source 'observation.disk' -Window 'none' -Values ([ordered]@{}))
        Write-Output (New-FmpDiagQuestion -Id 'storage_slow' -Area 'storage' -Answer $st -Confidence 'low' -Source 'observation.disk' -Window 'none' -Values ([ordered]@{}))
        return
    }
    $busy = 'unknown'; $busyVals = $null; $slow = 'unknown'; $slowVals = $null
    $queueIncomplete = $false; $latencyIncomplete = $false
    $rank = @{ unknown = 0; no = 1; partial = 2; yes = 3 }
    foreach ($it in $items) {
        $qAvg = Get-FmpDiagNumber $it 'avgQueue.avg'
        $qMax = Get-FmpDiagNumber $it 'avgQueue.max'
        $b = 'unknown'
        if ((Get-FmpDiagNumber $it 'avgQueue.count') -ge 2 -and $null -ne $qAvg -and $null -ne $qMax) {
            $b = 'no'
            if ($qAvg -ge $qBusy) { $b = 'yes' }
            elseif ($qMax -ge $qPeak) { $b = 'partial' }
        }
        if ($b -eq 'unknown') { $queueIncomplete = $true }
        $readBytes = Get-FmpDiagNumber $it 'readBytesPerSec.avg'
        $writeBytes = Get-FmpDiagNumber $it 'writeBytesPerSec.avg'
        $mb = $null
        if ($null -ne $readBytes -and $null -ne $writeBytes) { $mb = [Math]::Round(($readBytes + $writeBytes) / 1MB, 1) }
        if ($null -eq $busyVals -or $rank[$b] -gt $rank[$busy] -or ($b -eq $busy -and $qAvg -gt $busyVals['queueAvg'])) {
            $busy = $b
            $busyVals = [ordered]@{ disk = (Get-FmpValue $it 'name'); queueAvg = $qAvg; queueMax = $qMax; mbPerSec = $mb; window = (Get-FmpValue $D 'observation.actualSec') }
        }
        $rAvg = Get-FmpDiagNumber $it 'readLatencyMs.avg'
        $wAvg = Get-FmpDiagNumber $it 'writeLatencyMs.avg'
        $rP90 = Get-FmpDiagNumber $it 'readLatencyMs.p90'
        $wP90 = Get-FmpDiagNumber $it 'writeLatencyMs.p90'
        $worstAvg = [Math]::Max([double]$(if ($null -ne $rAvg) { $rAvg } else { 0 }), [double]$(if ($null -ne $wAvg) { $wAvg } else { 0 }))
        $worstP90 = [Math]::Max([double]$(if ($null -ne $rP90) { $rP90 } else { 0 }), [double]$(if ($null -ne $wP90) { $wP90 } else { 0 }))
        $readCount = Get-FmpDiagNumber $it 'readLatencyMs.count'
        $writeCount = Get-FmpDiagNumber $it 'writeLatencyMs.count'
        $s = 'unknown'
        if (($readCount -ge 2 -and $rAvg -ge $latHigh) -or ($writeCount -ge 2 -and $wAvg -ge $latHigh)) { $s = 'yes' }
        elseif ($worstAvg -ge $latWarn -or $worstP90 -ge $latHigh) { $s = 'partial' }
        elseif ((Get-FmpDiagNumber $it 'activeIntervals') -ge 2 -and ($null -ne $rAvg -or $null -ne $wAvg)) { $s = 'no' }
        if ($s -eq 'unknown') { $latencyIncomplete = $true }
        if ($null -eq $slowVals -or $rank[$s] -gt $rank[$slow]) {
            $slow = $s
            $p90 = $null
            if ($null -ne $rP90 -or $null -ne $wP90) { $p90 = $worstP90 }
            $slowVals = [ordered]@{ disk = (Get-FmpValue $it 'name'); readAvgMs = $rAvg; writeAvgMs = $wAvg; p90Ms = $p90; highMs = $latHigh; window = (Get-FmpValue $D 'observation.actualSec') }
        }
    }
    if ($queueIncomplete -and $busy -eq 'no') { $busy = 'unknown' }
    if ($latencyIncomplete -and $slow -eq 'no') { $slow = 'unknown' }
    Write-Output (New-FmpDiagQuestion -Id 'storage_busy' -Area 'storage' -Answer $busy -Confidence 'medium' -Source 'observation.disk' -Window 'observation' -Values $busyVals -Limitations @('diag.lim.busy_not_fault', 'diag.lim.window_only') -Alternatives @('diag.alt.legit_io', 'diag.alt.background_tasks'))
    Write-Output (New-FmpDiagQuestion -Id 'storage_slow' -Area 'storage' -Answer $slow -Confidence 'medium' -Source 'observation.disk' -Window 'observation' -Values $slowVals -Limitations @('diag.lim.latency_no_universal', 'diag.lim.window_only') -Alternatives @('diag.alt.heavy_io', 'diag.alt.virtual_disk'))
}

function Get-FmpDiagStorageHistoryQuestions {
    # Historical error events and the health Windows reports. "Unknown health" is its own outcome, not "healthy".
    param([object]$D, [object]$Analysis, [object]$Config)
    $checks = @{}
    foreach ($c in @(Get-FmpValue $Analysis 'checks')) { $checks[[string](Get-FmpValue $c 'id')] = $c }
    $ev = $checks['storage.disk_event_errors']
    $evState = [string](Get-FmpValue $ev 'state')
    $evAns = 'unknown'
    if ($evState -eq 'finding') { $evAns = 'yes' } elseif ($evState -eq 'pass') { $evAns = 'no' } elseif ($evState -in @('access_denied', 'unsupported', 'not_collected', 'error')) { $evAns = $evState }
    $recent = 48
    foreach ($r in @(Get-FmpValue $Config 'rules')) {
        if ((Get-FmpValue $r 'id') -eq 'storage.disk_event_errors') { $recent = [double](Get-FmpValue $r 'threshold.recentHours' -Default 48) }
    }
    $evVals = [ordered]@{ recentHours = $recent; items = '' }
    foreach ($f in @(Get-FmpValue $Analysis 'findings')) {
        if ((Get-FmpValue $f 'id') -eq 'storage.disk_event_errors') { $evVals['items'] = [string](Get-FmpValue $f 'values.items') }
    }
    Write-Output (New-FmpDiagQuestion -Id 'storage_errors' -Area 'storage_history' -Answer $evAns -Confidence 'medium' -Source 'events.System' -Window 'history' -Values $evVals -Limitations @('diag.lim.history_not_current') -Alternatives @('diag.alt.cable_or_removable'))

    $health = 'unknown'
    $hv = [ordered]@{ smart = [string](Get-FmpValue $D 'storage.smart.status') }
    $u = [string](Get-FmpValue $checks['storage.disk_health_unhealthy'] 'state')
    $p = [string](Get-FmpValue $checks['storage.smart_predict_failure'] 'state')
    if ($u -eq 'finding' -or $p -eq 'finding') { $health = 'yes' }
    elseif ($u -eq 'pass' -and $p -eq 'pass') { $health = 'no' }
    elseif ($u -eq 'pass') { $health = 'partial_unknown' }
    $lims = @('diag.lim.health_is_reported')
    if ($hv.smart -in @('access_denied', 'unsupported', 'error')) { $lims += 'diag.lim.smart_unavailable' }
    Write-Output (New-FmpDiagQuestion -Id 'storage_health' -Area 'storage_history' -Answer $health -Confidence 'medium' -Source 'storage.physicalDisks' -Window 'snapshot' -Values $hv -Limitations $lims)
}

function Get-FmpDiagMedian {
    param([object[]]$Sorted)
    if ($Sorted.Count -eq 0) { return $null }
    $lo = [int][Math]::Floor(($Sorted.Count - 1) / 2)
    $hi = [int][Math]::Floor($Sorted.Count / 2)
    return ($Sorted[$lo] + $Sorted[$hi]) / 2
}

function Get-FmpDiagBootQuestion {
    param([object]$D, [object]$Config)
    $bp = Get-FmpValue $D 'events.bootPerformance'
    if ($null -eq $bp) {
        return New-FmpDiagQuestion -Id 'boot_history' -Area 'boot' -Answer 'not_collected' -Confidence 'low' -Source 'events.bootPerformance' -Window 'none' -Values ([ordered]@{})
    }
    $st = [string](Get-FmpValue $bp 'status')
    $boots = @(Get-FmpValue $bp 'boots' | Where-Object { $null -ne (Get-FmpDiagNumber $_ 'bootMs') })
    if ($st -in @('access_denied', 'unsupported', 'error')) {
        return New-FmpDiagQuestion -Id 'boot_history' -Area 'boot' -Answer $st -Confidence 'low' -Source 'events.bootPerformance' -Window 'none' -Values ([ordered]@{}) -Limitations @('diag.lim.boot_log_admin')
    }
    if ($boots.Count -eq 0) {
        return New-FmpDiagQuestion -Id 'boot_history' -Area 'boot' -Answer 'unknown' -Confidence 'low' -Source 'events.bootPerformance' -Window 'history' -Values ([ordered]@{ windowDays = (Get-FmpValue $bp 'windowDays') }) -Limitations @('diag.lim.boot_no_events')
    }
    $slowMs = Get-FmpDiagThreshold $Config 'bootSlowMainPathMs' 60000
    $warnMs = Get-FmpDiagThreshold $Config 'bootWarnMainPathMs' 40000
    $bootMs = @($boots | ForEach-Object { Get-FmpDiagNumber $_ 'bootMs' } | Sort-Object)
    $mainMs = @($boots | ForEach-Object { Get-FmpDiagNumber $_ 'mainPathMs' } | Where-Object { $null -ne $_ } | Sort-Object)
    $postMs = @($boots | ForEach-Object { Get-FmpDiagNumber $_ 'postBootMs' } | Where-Object { $null -ne $_ } | Sort-Object)
    $medBoot = Get-FmpDiagMedian $bootMs
    $medMain = Get-FmpDiagMedian $mainMs
    $medPost = Get-FmpDiagMedian $postMs
    $degraded = @($boots | Where-Object { (Get-FmpValue $_ 'degraded') -eq $true }).Count
    $afterUpdate = @($boots | Where-Object { (Get-FmpValue $_ 'afterUpdate') -eq $true }).Count
    $answer = 'unknown'
    if ($degraded -ge 2 -or $medMain -ge $slowMs) { $answer = 'yes' }
    elseif ($degraded -eq 1 -or $medMain -ge $warnMs) { $answer = 'partial' }
    elseif ($null -ne $medMain) { $answer = 'no' }
    # A component is named only when Windows itself flagged it in more than one boot event.
    $contribs = @(Get-FmpValue $bp 'contributors' | Where-Object { (Get-FmpDiagNumber $_ 'count') -ge 2 } | Select-Object -First 3 |
        ForEach-Object { ([string](Get-FmpValue $_ 'name')) + ' (' + (Get-FmpValue $_ 'kind') + ', ' + (Get-FmpValue $_ 'count') + 'x)' }) -join ', '
    $vals = [ordered]@{
        boots = $boots.Count; windowDays = (Get-FmpValue $bp 'windowDays'); medianBootSec = [Math]::Round($medBoot / 1000, 1)
        medianMainPathSec = $(if ($null -ne $medMain) { [Math]::Round($medMain / 1000, 1) } else { $null })
        medianPostBootSec = $(if ($null -ne $medPost) { [Math]::Round($medPost / 1000, 1) } else { $null })
        degraded = $degraded; afterUpdate = $afterUpdate; minSec = [Math]::Round($bootMs[0] / 1000, 1); maxSec = [Math]::Round($bootMs[$bootMs.Count - 1] / 1000, 1)
        contributors = $contribs
    }
    $conf = 'high'
    if ($boots.Count -lt 3) { $conf = 'medium' }
    return New-FmpDiagQuestion -Id 'boot_history' -Area 'boot' -Answer $answer -Confidence $conf -Source 'events.bootPerformance' -Window 'history' -Values $vals -Limitations @('diag.lim.boot_phases', 'diag.lim.startup_count_not_cause') -Alternatives @('diag.alt.after_update', 'diag.alt.perceived_vs_measured')
}

function Get-FmpDiagCrashQuestion {
    param([object]$D, [object]$Config)
    $sysState = [string](Get-FmpValue $D 'events.logs.System.status')
    if ($sysState -notin @('ok', 'empty')) {
        $a = 'unknown'
        if ($sysState -in @('access_denied', 'unsupported', 'error')) { $a = $sysState }
        if ($null -eq (Get-FmpValue $D 'events')) { $a = 'not_collected' }
        return New-FmpDiagQuestion -Id 'crash_history' -Area 'stability' -Answer $a -Confidence 'low' -Source 'events.System' -Window 'none' -Values ([ordered]@{})
    }
    $now = Get-FmpValue $D 'run.finishedAt'
    $days = ConvertTo-FmpNullableDouble (Get-FmpValue $D 'events.windowDays')
    if ($null -eq $days -or $days -lt 1) { $days = 7 }
    $h = $days * 24
    $kp = Get-FmpDiagEventStats $D 'System' '^(Microsoft-Windows-)?Kernel-Power$' @(41) $now $h
    $ul = Get-FmpDiagEventStats $D 'System' '^EventLog$' @(6008) $now $h
    $bc = Get-FmpDiagEventStats $D 'System' '^(BugCheck|Microsoft-Windows-WER-SystemErrorReporting)$' @(1001) $now $h
    $wh = Get-FmpDiagEventStats $D 'System' '^(Microsoft-Windows-)?WHEA-Logger$' @(1, 17, 18, 19, 20, 46, 47) $now $h
    $sv = Get-FmpDiagEventStats $D 'System' '^Service Control Manager$' @(7031, 7034) $now $h
    $ac = Get-FmpDiagEventStats $D 'Application' '^Application Error$' @(1000) $now $h
    $ah = Get-FmpDiagEventStats $D 'Application' '^Application Hang$' @(1002) $now $h
    $appState = [string](Get-FmpValue $D 'events.logs.Application.status')
    $partialLogs = $appState -notin @('ok', 'empty') -or (Get-FmpValue $D 'events.logs.System.truncated') -eq $true -or (Get-FmpValue $D 'events.logs.Application.truncated') -eq $true
    $restarts = [Math]::Max($kp.count, $ul.count)
    $restartDays = [Math]::Max($kp.days, $ul.days)
    $minDays = Get-FmpDiagThreshold $Config 'crashRecurringDays' 2
    $answer = 'no'
    if (($restarts -ge 2 -and $restartDays -ge $minDays) -or $bc.count -ge 2) { $answer = 'yes' }
    elseif ($restarts -ge 1 -or $bc.count -ge 1 -or $wh.count -ge 1 -or $sv.count -ge 3 -or $ac.count -ge 3 -or $ah.count -ge 3) { $answer = 'partial' }
    elseif ($partialLogs) { $answer = 'unknown' }
    $ctx = @(Get-FmpValue $D 'events.restartContext.items')
    $withBug = @($ctx | Where-Object { (Get-FmpValue $_ 'bugcheck') -eq $true }).Count
    $withBtn = @($ctx | Where-Object { (Get-FmpValue $_ 'powerButton') -eq $true }).Count
    $last = $kp.last
    if ($null -ne $ul.last -and ($null -eq $last -or $ul.last -gt $last)) { $last = $ul.last }
    $vals = [ordered]@{
        windowDays = $days; restarts = $restarts; restartDays = $restartDays; bugchecks = $bc.count; whea = $wh.count
        serviceCrashes = $sv.count; appCrashes = $ac.count; appHangs = $ah.count; withBugcheck = $withBug; withPowerButton = $withBtn
        lastRestart = $(if ($null -ne $last) { $last.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { '' })
    }
    $conf = 'high'
    if ($partialLogs) { $conf = 'medium' }
    $limitations = @('diag.lim.kp41_not_psu', 'diag.lim.history_not_current')
    if ($partialLogs) { $limitations += 'diag.lim.history_incomplete' }
    return New-FmpDiagQuestion -Id 'crash_history' -Area 'stability' -Answer $answer -Confidence $conf -Source 'events.System+Application' -Window 'history' -Values $vals -Limitations $limitations -Alternatives @('diag.alt.power_loss', 'diag.alt.driver', 'diag.alt.thermal')
}

# ---------------------------------------------------------------
# Phase A: per-process evidence, event catalog and incident time.
# These questions exist only when their data was collected, so a 2.0
# document keeps exactly the same questions, coverage and conclusion.
# ---------------------------------------------------------------
function Get-FmpEventCatalogDays {
    # Full audit only. A reported incident older than the default window extends it, up to the 60-day cap.
    param([object]$Config, [string]$Mode, [string]$Symptom, [object]$Incident = $null, [object]$NowUtc = $null, [string]$Depth = '')
    if ($Mode -ne 'full') { return 0 }
    $d = [int](Get-FmpValue $Config ('diagnosis.eventCatalog.windowDays.' + $Symptom) -Default 30)
    if ($Depth -ceq 'deep') { $d = 60 }
    $at = Get-FmpParsedDate (Get-FmpValue $Incident 'atUtc')
    if ($null -ne $at -and $null -ne $NowUtc) {
        $tol = ConvertTo-FmpNullableDouble (Get-FmpValue $Incident 'effectiveToleranceMinutes')
        if ($null -eq $tol) { $tol = 0 }
        $need = [int][Math]::Floor((([datetime]$NowUtc).ToUniversalTime() - $at.ToUniversalTime()).TotalDays + $tol / 1440) + 2
        if ($need -gt $d) { $d = $need }
    }
    return [int][Math]::Max(1, [Math]::Min(60, $d))
}

function Format-FmpDiagUtc {
    param([object]$Value)
    $d = Get-FmpParsedDate $Value
    if ($null -eq $d) { return '' }
    return $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Format-FmpDeltaText {
    # Signed distance from the incident: + is after it, - is before it.
    param([double]$Seconds)
    $sign = '+'
    if ($Seconds -lt 0) { $sign = '-' }
    $abs = [Math]::Abs($Seconds)
    if ($abs -lt 120) { return $sign + [Math]::Round($abs, 0) + ' s' }
    if ($abs -lt 7200) { return $sign + [Math]::Round($abs / 60, 0) + ' min' }
    return $sign + [Math]::Round($abs / 3600, 1).ToString([System.Globalization.CultureInfo]::InvariantCulture) + ' h'
}

function Add-FmpDiagSupport {
    # Complementary evidence: it strengthens or qualifies a hypothesis, and is shown apart from what was observed directly.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Question, [string]$Key, [System.Collections.IDictionary]$Values)
    $current = @()
    if ($Question.Contains('supportItems')) { $current = @($Question['supportItems']) }
    $Question['supportItems'] = @($current + @(, [ordered]@{ key = $Key; values = $Values }))
}

function Get-FmpCatalogFamilyStats {
    param([object]$D, [string]$Family)
    $count = 0; $queried = 0; $maxDays = 0; $truncated = $false; $last = $null
    $days = @{}
    $failed = New-Object System.Collections.Generic.List[string]
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($e in @(Get-FmpValue $D 'events.catalog.entries')) {
        if ($null -eq $e -or [string](Get-FmpValue $e 'family') -ne $Family) { continue }
        $st = [string](Get-FmpValue $e 'status')
        if ($st -in @('ok', 'empty')) { $queried++ }
        elseif ($st -in @('access_denied', 'unsupported', 'error')) { $failed.Add($st) }
        if ((Get-FmpValue $e 'truncated') -eq $true) { $truncated = $true }
        $n = ConvertTo-FmpNullableInt (Get-FmpValue $e 'count')
        if ($null -eq $n -or $n -lt 1) { continue }
        $count += $n
        $items.Add(([string](Get-FmpValue $e 'provider')) + ' ' + (Get-FmpValue $e 'eventId') + ' (' + $n + 'x)')
        $dd = ConvertTo-FmpNullableInt (Get-FmpValue $e 'distinctDays')
        if ($null -ne $dd -and $dd -gt $maxDays) { $maxDays = $dd }
        foreach ($o in @(Get-FmpValue $e 'occurrences')) {
            $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
            if ($null -eq $at) { continue }
            $utc = $at.ToUniversalTime()
            $days[$utc.ToString('yyyy-MM-dd')] = $true
            if ($null -eq $last -or $utc -gt $last) { $last = $utc }
        }
    }
    return @{ count = $count; days = [Math]::Max($days.Count, $maxDays); last = $last; queried = $queried; failed = $failed.ToArray(); truncated = $truncated; items = ($items.ToArray() -join ', ') }
}

function Get-FmpCatalogOccurrences {
    param([object]$D, [string[]]$Keys)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-FmpValue $D 'events.catalog.entries')) {
        if ($null -eq $e -or [string](Get-FmpValue $e 'key') -cnotin $Keys) { continue }
        foreach ($o in @(Get-FmpValue $e 'occurrences')) {
            $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
            if ($null -ne $at) { $out.Add($at.ToUniversalTime()) }
        }
    }
    return $out.ToArray()
}

function Get-FmpCatalogPairs {
    # Versioned pairs from rules.json. A pair is temporal proximity between two recorded events, never a proven cause.
    param([object]$D, [object]$Config)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($rule in @(Get-FmpValue $Config 'diagnosis.correlation.pairs')) {
        if ($null -eq $rule) { continue }
        $win = ConvertTo-FmpNullableDouble (Get-FmpValue $rule 'windowSec')
        if ($null -eq $win -or $win -le 0) { continue }
        $directed = (Get-FmpValue $rule 'directed') -eq $true
        $aTimes = @(Get-FmpCatalogOccurrences $D @(Get-FmpValue $rule 'a'))
        $bTimes = @(Get-FmpCatalogOccurrences $D @(Get-FmpValue $rule 'b'))
        $matched = 0; $closest = $null; $lastAt = $null
        foreach ($ta in $aTimes) {
            $best = $null
            foreach ($tb in $bTimes) {
                $dt = ($tb - $ta).TotalSeconds
                if ($directed -and $dt -lt 0) { continue }
                if ([Math]::Abs($dt) -le $win -and ($null -eq $best -or [Math]::Abs($dt) -lt [Math]::Abs($best))) { $best = $dt }
            }
            if ($null -eq $best) { continue }
            $matched++
            if ($null -eq $closest -or [Math]::Abs($best) -lt [Math]::Abs($closest)) { $closest = $best }
            if ($null -eq $lastAt -or $ta -gt $lastAt) { $lastAt = $ta }
        }
        if ($matched -gt 0) {
            $out.Add([ordered]@{ id = [string](Get-FmpValue $rule 'id'); count = $matched; closestSec = [Math]::Round([Math]::Abs($closest), 0); windowSec = $win
                lastAt = $lastAt.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) })
        }
    }
    return $out.ToArray()
}

function Get-FmpDiagProcessCommitQuestion {
    param([object]$D, [object]$Config, [string]$MemoryAnswer)
    $state = [string](Get-FmpValue $D 'observation.processes.state')
    $alts = @('diag.alt.commit_reserved', 'diag.alt.short_window_leak')
    $lims = @('diag.lim.commit_not_leak', 'diag.lim.window_only')
    if ($state -ne 'pass') {
        if ($state -notin @('access_denied', 'unsupported', 'error')) { $state = 'unknown' }
        return New-FmpDiagQuestion -Id 'process_commit' -Area 'memory' -Answer $state -Confidence 'low' -Source 'observation.processes' -Window 'none' -Values ([ordered]@{})
    }
    $rows = @(Get-FmpValue $D 'observation.processes.topCommit' | Where-Object { $null -ne (Get-FmpDiagNumber $_ 'commitPrivateMB') })
    if ($rows.Count -eq 0) {
        return New-FmpDiagQuestion -Id 'process_commit' -Area 'memory' -Answer 'unknown' -Confidence 'low' -Source 'observation.processes' -Window 'observation' -Values ([ordered]@{}) -Limitations @('diag.lim.commit_unavailable')
    }
    $high = Get-FmpDiagThreshold $Config 'procCommitHighMB' 4096
    $hiddenRatio = Get-FmpDiagThreshold $Config 'procCommitHiddenWsRatio' 0.35
    $top = $rows[0]
    # The process to name: the largest one whose memory is mostly NOT resident, if any crosses the limit; else the largest.
    foreach ($r in $rows) {
        $c = Get-FmpDiagNumber $r 'commitPrivateMB'
        $w = Get-FmpDiagNumber $r 'workingSetMB'
        if ($c -ge $high -and $null -ne $w -and ($w / $c) -le $hiddenRatio) { $top = $r; break }
    }
    $commit = Get-FmpDiagNumber $top 'commitPrivateMB'
    $ws = Get-FmpDiagNumber $top 'workingSetMB'
    $hidden = ($commit -ge $high -and $null -ne $ws -and ($ws / $commit) -le $hiddenRatio)
    $answer = 'no'
    if ($commit -ge $high) {
        $answer = 'partial'
        if ($MemoryAnswer -in @('yes', 'partial')) { $answer = 'yes' }
    }
    $growth = Get-FmpDiagNumber $top 'commitGrowthMB'
    $vals = [ordered]@{
        name = [string](Get-FmpValue $top 'name'); pid = (Get-FmpValue $top 'pid'); commitMB = $commit; workingSetMB = $ws; hidden = $hidden
        growthMB = $growth; window = (Get-FmpValue $D 'observation.actualSec'); highMB = $high
        processes = (@($rows | Select-Object -First 3 | ForEach-Object { ([string](Get-FmpValue $_ 'name')) + ' (' + (Get-FmpValue $_ 'commitPrivateMB') + ' MB)' }) -join ', ')
    }
    if ($hidden) { $lims = @('diag.lim.commit_low_resident') + $lims }
    return New-FmpDiagQuestion -Id 'process_commit' -Area 'memory' -Answer $answer -Confidence 'medium' -Source 'observation.processes' -Window 'observation' -Values $vals -Limitations $lims -Alternatives $alts
}

function Get-FmpDiagProcessIoQuestion {
    # Co-occurrence only: process counters include network and device I/O, so they cannot attribute disk load by themselves.
    param([object]$D, [object]$Config, [string]$BusyAnswer, [string]$SlowAnswer)
    $state = [string](Get-FmpValue $D 'observation.processes.state')
    if ($state -ne 'pass') {
        if ($state -notin @('access_denied', 'unsupported', 'error')) { $state = 'unknown' }
        return New-FmpDiagQuestion -Id 'process_io' -Area 'storage' -Answer $state -Confidence 'low' -Source 'observation.processes' -Window 'none' -Values ([ordered]@{})
    }
    $rows = @(Get-FmpValue $D 'observation.processes.topIo' | Where-Object { $null -ne (Get-FmpDiagNumber $_ 'readBytesPerSec') })
    $lims = @('diag.lim.io_not_only_disk', 'diag.lim.window_only')
    if ($rows.Count -eq 0) {
        return New-FmpDiagQuestion -Id 'process_io' -Area 'storage' -Answer 'unknown' -Confidence 'low' -Source 'observation.processes' -Window 'observation' -Values ([ordered]@{}) -Limitations $lims
    }
    $notableMB = Get-FmpDiagThreshold $Config 'procIoNotableMBps' 5
    $top = $rows[0]
    $mbps = [Math]::Round(((Get-FmpDiagNumber $top 'readBytesPerSec') + (Get-FmpDiagNumber $top 'writeBytesPerSec')) / 1MB, 1)
    $text = @($rows | Select-Object -First 3 | ForEach-Object {
        ([string](Get-FmpValue $_ 'name')) + ' (' + [Math]::Round((Get-FmpDiagNumber $_ 'readBytesPerSec') / 1MB, 1) + '/' + [Math]::Round((Get-FmpDiagNumber $_ 'writeBytesPerSec') / 1MB, 1) + ' MB/s, ' + (Get-FmpValue $_ 'ioSharePct') + '%)'
    }) -join ', '
    $vals = [ordered]@{ name = [string](Get-FmpValue $top 'name'); mbPerSec = $mbps; sharePct = (Get-FmpDiagNumber $top 'ioSharePct'); processes = $text; window = (Get-FmpValue $D 'observation.actualSec') }
    $answer = 'no'
    if ($BusyAnswer -notin @('yes', 'partial', 'no') -and $SlowAnswer -notin @('yes', 'partial', 'no')) { $answer = 'unknown' }
    elseif ($mbps -ge $notableMB -and ($BusyAnswer -eq 'yes' -or $SlowAnswer -eq 'yes')) { $answer = 'yes' }
    elseif ($mbps -ge $notableMB -and ($BusyAnswer -eq 'partial' -or $SlowAnswer -eq 'partial')) { $answer = 'partial' }
    return New-FmpDiagQuestion -Id 'process_io' -Area 'storage' -Answer $answer -Confidence 'medium' -Source 'observation.processes' -Window 'observation' -Values $vals -Limitations $lims -Alternatives @('diag.alt.legit_io', 'diag.alt.io_network_cache')
}

function Get-FmpDiagCatalogQuestion {
    # History from the closed catalog. Recurrence on separate days is what separates "yes" from an isolated record.
    param([object]$D, [object]$Config, [string]$Id, [string]$Area, [string]$Family, [object[]]$Pairs, [string[]]$PairIds, [string[]]$Limits, [string[]]$Alts)
    $st = Get-FmpCatalogFamilyStats $D $Family
    $coversWindow = (Get-FmpValue $D 'events.catalog.retention.coversWindow') -eq $true
    $recurring = Get-FmpDiagThreshold $Config 'eventRecurringDays' 2
    $win = Get-FmpValue $D 'events.catalog.windowDays'
    $lims = @('diag.lim.history_not_current') + @($Limits)
    if (-not $coversWindow) { $lims += 'diag.lim.retention_short' }
    if ($st.truncated) { $lims += 'diag.lim.catalog_truncated' }
    $paired = @($Pairs | Where-Object { $null -ne $_ -and [string]$_['id'] -in @($PairIds) })
    $pairedCount = 0
    foreach ($p in $paired) { $pairedCount += [int]$p['count'] }
    $vals = [ordered]@{ count = $st.count; days = $st.days; windowDays = $win; last = (Format-FmpDiagUtc $st.last); items = $st.items; paired = $pairedCount }
    if ($st.count -gt 0) {
        $answer = 'partial'
        if ($st.days -ge $recurring -or $pairedCount -gt 0) { $answer = 'yes' }
        $conf = 'medium'
        if ($st.truncated -or -not $coversWindow) { $conf = 'low' }
        return New-FmpDiagQuestion -Id $Id -Area $Area -Answer $answer -Confidence $conf -Source 'events.catalog' -Window 'history' -Values $vals -Limitations $lims -Alternatives $Alts
    }
    if ($st.queried -eq 0) {
        $a = 'unknown'
        if (@($st.failed).Count -gt 0) { $a = [string]@($st.failed)[0] }
        return New-FmpDiagQuestion -Id $Id -Area $Area -Answer $a -Confidence 'low' -Source 'events.catalog' -Window 'none' -Values ([ordered]@{})
    }
    # "No" needs the whole window to have been readable; otherwise absence proves nothing.
    if (@($st.failed).Count -gt 0 -or -not $coversWindow -or $st.truncated) {
        return New-FmpDiagQuestion -Id $Id -Area $Area -Answer 'unknown' -Confidence 'low' -Source 'events.catalog' -Window 'history' -Values $vals -Limitations $lims
    }
    return New-FmpDiagQuestion -Id $Id -Area $Area -Answer 'no' -Confidence 'medium' -Source 'events.catalog' -Window 'history' -Values $vals -Limitations @('diag.lim.history_not_current')
}

function Get-FmpDiagTimelineRows {
    # Faults and clock changes always; routine start/stop records only when they fall inside the incident window.
    param([object]$D, [object]$Window = $null)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-FmpValue $D 'events.catalog.entries')) {
        if ($null -eq $e) { continue }
        $family = [string](Get-FmpValue $e 'family')
        $meaning = [string](Get-FmpValue $e 'meaning')
        $isFault = $family -in @('graphics', 'storage', 'network') -or $meaning -in @('unexpected_restart', 'unexpected_shutdown')
        foreach ($o in @(Get-FmpValue $e 'occurrences')) {
            $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
            if ($null -eq $at) { continue }
            $utc = $at.ToUniversalTime()
            $delta = $null; $near = $false
            if ($null -ne $Window) {
                $delta = [Math]::Round(($utc - $Window.centerUtc).TotalSeconds, 0)
                $near = ($utc -ge $Window.startUtc -and $utc -le $Window.endUtc)
            }
            if (-not $isFault -and -not $near -and $family -ne 'clock') { continue }
            $rows.Add([ordered]@{
                at = $utc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                provider = [string](Get-FmpValue $e 'provider'); eventId = (Get-FmpValue $e 'eventId'); family = $family; meaning = $meaning
                level = (Get-FmpValue $o 'level'); isFault = $isFault; deltaSec = $delta; near = $near
                deltaText = $(if ($null -ne $delta) { Format-FmpDeltaText ([double]$delta) } else { '' })
            })
        }
    }
    if ($null -ne $Window) { return @($rows.ToArray() | Sort-Object -Property @{ Expression = { [Math]::Abs($_['deltaSec']) } }, @{ Expression = { $_['at'] } }) }
    return @($rows.ToArray() | Sort-Object -Property { $_['at'] } -Descending)
}

function Get-FmpDiagIncident {
    # Places the reported time against the catalog and states whether the clock and the log retention allow a comparison.
    param([object]$D)
    $inc = Get-FmpValue $D 'run.incident'
    $kind = [string](Get-FmpValue $inc 'kind')
    if ($kind -notin @('at', 'during_run')) { return $null }
    $runStart = Get-FmpParsedDate (Get-FmpValue $D 'run.startedAt')
    $runEnd = Get-FmpParsedDate (Get-FmpValue $D 'run.finishedAt')
    if ($null -eq $runEnd) { return $null }
    $runEnd = $runEnd.ToUniversalTime()
    if ($kind -eq 'at') {
        $center = Get-FmpParsedDate (Get-FmpValue $inc 'atUtc')
        if ($null -eq $center) { return $null }
        $center = $center.ToUniversalTime()
        $tolMin = [double](Get-FmpValue $inc 'effectiveToleranceMinutes' -Default 30)
        $window = @{ centerUtc = $center; startUtc = $center.AddDays(-$tolMin / 1440); endUtc = $center.AddDays($tolMin / 1440) }
    }
    else {
        if ($null -eq $runStart) { return $null }
        $center = $runStart.ToUniversalTime()
        $tolMin = 0
        $window = @{ centerUtc = $center; startUtc = $center; endUtc = $runEnd }
    }
    $reliability = 'ok'
    $hasCatalog = $null -ne (Get-FmpValue $D 'events.catalog')
    $rows = @()
    if (-not $hasCatalog) { $reliability = 'no_catalog' }
    else {
        $rows = @(Get-FmpDiagTimelineRows $D $window)
        $maxFuture = $runEnd.AddDays(5 / 1440)
        $future = @($rows | Where-Object { (Get-FmpParsedDate $_['at']).ToUniversalTime() -gt $maxFuture }).Count
        $step = $false
        foreach ($e in @(Get-FmpValue $D 'events.catalog.entries')) {
            if ($null -eq $e -or [string](Get-FmpValue $e 'family') -ne 'clock') { continue }
            foreach ($o in @(Get-FmpValue $e 'occurrences')) {
                $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
                $size = ConvertTo-FmpNullableDouble (Get-FmpValue $o 'stepSec')
                if ($null -eq $at -or $null -eq $size) { continue }
                # A step can have moved a record across the window by up to its own size.
                $utc = $at.ToUniversalTime()
                if ($utc -ge $window.startUtc.AddDays(-$size / 86400) -and $utc -le $window.endUtc.AddDays($size / 86400)) { $step = $true }
            }
        }
        $oldest = Get-FmpParsedDate (Get-FmpValue $D 'events.catalog.retention.oldestAt')
        if ($window.startUtc -gt $maxFuture) { $reliability = 'after_run' }
        elseif ($future -gt 0) { $reliability = 'clock_future' }
        elseif ($step) { $reliability = 'clock_step' }
        elseif ($null -eq $oldest) { $reliability = 'retention_unknown' }
        elseif ($oldest.ToUniversalTime() -gt $window.endUtc) { $reliability = 'before_retention' }
        elseif ($oldest.ToUniversalTime() -gt $window.startUtc) { $reliability = 'partial_retention' }
    }
    $nearRows = @($rows | Where-Object { $_['near'] })
    $faults = @($nearRows | Where-Object { $_['isFault'] })
    $families = @($faults | ForEach-Object { [string]$_['family'] } | Sort-Object -Unique)
    $closest = ''
    $pick = @($faults) + @($nearRows)
    if ($pick.Count -gt 0) { $closest = [string]$pick[0]['provider'] + ' ' + $pick[0]['eventId'] + ' (' + (Format-FmpDeltaText ([double]$pick[0]['deltaSec'])) + ')' }
    return [ordered]@{
        kind = $kind; atUtc = $center.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        toleranceMinutes = (Get-FmpValue $inc 'toleranceMinutes'); effectiveToleranceMinutes = $tolMin
        windowStart = $window.startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        windowEnd = $window.endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        offsetKnown = (Get-FmpValue $inc 'offsetKnown'); ambiguousLocal = (Get-FmpValue $inc 'ambiguousLocal')
        reliability = $reliability; nearCount = $nearRows.Count; nearFaults = $faults.Count; families = $families; closest = $closest
    }
}

function Get-FmpDiagIncidentQuestion {
    param([System.Collections.IDictionary]$Incident)
    $rel = [string]$Incident['reliability']
    $when = (Format-FmpDiagUtc $Incident['atUtc']) + ' (' + [char]0x00B1 + $Incident['effectiveToleranceMinutes'] + ' min)'
    if ($Incident['kind'] -eq 'during_run') { $when = (Format-FmpDiagUtc $Incident['windowStart']) + ' - ' + (Format-FmpDiagUtc $Incident['windowEnd']) }
    $vals = [ordered]@{
        when = $when; near = [string]$Incident['nearCount']; faults = [string]$Incident['nearFaults']
        families = (@($Incident['families']) -join ', '); closest = $Incident['closest']
    }
    $lims = @('diag.lim.incident_proximity')
    if ($rel -ne 'ok') { $lims = @('diag.lim.incident_' + $rel) + $lims }
    if ($Incident['ambiguousLocal'] -eq $true) { $lims += 'diag.lim.incident_ambiguous' }
    if ($rel -in @('no_catalog', 'after_run', 'clock_future', 'clock_step', 'before_retention', 'retention_unknown')) {
        return New-FmpDiagQuestion -Id 'incident_correlation' -Area 'incident' -Answer 'unknown' -Confidence 'low' -Source 'events.catalog' -Window 'none' -Values $vals -Limitations $lims
    }
    $conf = 'medium'
    if ($rel -ne 'ok') { $conf = 'low' }
    $answer = 'no'
    if ([int]$Incident['nearFaults'] -gt 0) { $answer = 'yes' }
    elseif ([int]$Incident['nearCount'] -gt 0) { $answer = 'partial' }
    elseif ($rel -ne 'ok') { $answer = 'unknown' }
    return New-FmpDiagQuestion -Id 'incident_correlation' -Area 'incident' -Answer $answer -Confidence $conf -Source 'events.catalog' -Window 'history' -Values $vals -Limitations $lims -Alternatives @('diag.alt.coincidence')
}

# ---------------------------------------------------------------
# Driver
# ---------------------------------------------------------------
function Get-FmpDiagnosis {
    param(
        [Parameter(Mandatory)][object]$Diagnostic,
        [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][object]$RuleConfig,
        [string]$Symptom = 'general',
        [string]$DuringProblem = 'unknown'
    )
    if ($Symptom -cnotin $script:FmpSymptoms) { $Symptom = 'general' }
    if ($DuringProblem -cnotin @('yes', 'no', 'unknown')) { $DuringProblem = 'unknown' }
    $mode = [string](Get-FmpValue $Diagnostic 'run.mode')

    $qs = New-Object System.Collections.Generic.List[object]
    # A reported incident comes first: ties in the key findings keep question order.
    $incident = Get-FmpDiagIncident $Diagnostic
    if ($null -ne $incident) { $qs.Add((Get-FmpDiagIncidentQuestion $incident)) }
    $qs.Add((Get-FmpDiagCpuQuestion $Diagnostic $RuleConfig))
    $memoryQ = Get-FmpDiagMemoryQuestion $Diagnostic $RuleConfig
    $qs.Add($memoryQ)
    $storageQs = @(Get-FmpDiagStorageQuestions $Diagnostic $RuleConfig)
    foreach ($q in $storageQs) { $qs.Add($q) }
    foreach ($q in @(Get-FmpDiagStorageHistoryQuestions $Diagnostic $Analysis $RuleConfig)) { $qs.Add($q) }
    $qs.Add((Get-FmpDiagBootQuestion $Diagnostic $RuleConfig))
    $qs.Add((Get-FmpDiagCrashQuestion $Diagnostic $RuleConfig))
    if ($null -ne (Get-FmpValue $Diagnostic 'observation.processes.appGroupBasis')) {
        $commitQ = Get-FmpDiagProcessCommitQuestion $Diagnostic $RuleConfig ([string]$memoryQ['answer'])
        $qs.Add($commitQ)
        $ioQ = Get-FmpDiagProcessIoQuestion $Diagnostic $RuleConfig ([string]$storageQs[0]['answer']) ([string]$storageQs[1]['answer'])
        $qs.Add($ioQ)
        if ($commitQ['answer'] -in @('yes', 'partial') -and $memoryQ['answer'] -in @('yes', 'partial')) { Add-FmpDiagSupport -Question $memoryQ -Key 'diag.sup.top_commit' -Values $commitQ['values'] }
        if ($ioQ['answer'] -in @('yes', 'partial')) {
            foreach ($sq in $storageQs) { if ($sq['answer'] -in @('yes', 'partial')) { Add-FmpDiagSupport -Question $sq -Key 'diag.sup.top_io' -Values $ioQ['values'] } }
        }
    }
    $hasCatalog = $null -ne (Get-FmpValue $Diagnostic 'events.catalog')
    $pairs = @()
    if ($hasCatalog) {
        $pairs = @(Get-FmpCatalogPairs $Diagnostic $RuleConfig)
        $gpuQ = Get-FmpDiagCatalogQuestion -D $Diagnostic -Config $RuleConfig -Id 'graphics_events' -Area 'graphics' -Family 'graphics' -Pairs $pairs -PairIds @('graphics_timeout') -Limits @('diag.lim.graphics_not_hardware') -Alts @('diag.alt.driver', 'diag.alt.graphics_app')
        $diskQ = Get-FmpDiagCatalogQuestion -D $Diagnostic -Config $RuleConfig -Id 'storage_signals' -Area 'storage_history' -Family 'storage' -Pairs $pairs -PairIds @('storage_reset_retry') -Limits @('diag.lim.storage_signal_not_failure') -Alts @('diag.alt.cable_or_removable', 'diag.alt.storage_driver')
        $netQ = Get-FmpDiagCatalogQuestion -D $Diagnostic -Config $RuleConfig -Id 'network_ports' -Area 'network' -Family 'network' -Pairs $pairs -PairIds @() -Limits @('diag.lim.ports_history_only') -Alts @('diag.alt.port_heavy_app')
        $qs.Add($gpuQ); $qs.Add($diskQ); $qs.Add($netQ)
        if ($diskQ['answer'] -in @('yes', 'partial')) {
            foreach ($sq in $storageQs) { if ($sq['answer'] -in @('yes', 'partial')) { Add-FmpDiagSupport -Question $sq -Key 'diag.sup.storage_events' -Values $diskQ['values'] } }
        }
    }
    $hasInvestigations = $null -ne (Get-FmpValue $Diagnostic 'investigations')
    $storageMap = @()
    if ($hasInvestigations) {
        $storageMap = @(Get-FmpDiskEventMap $Diagnostic)
        foreach ($q in @(Get-FmpDiagInvestigationQuestions $Diagnostic $RuleConfig $storageMap)) { $qs.Add($q) }
        Add-FmpDiagInvestigationSupport -Questions $qs.ToArray() -D $Diagnostic -Map $storageMap
    }
    foreach ($q in $qs) { Set-FmpDiagRelevance -Question $q -Relevance (Get-FmpDiagRelevance $RuleConfig $Symptom ([string]$q['area'])) }
    # A common window supports a hypothesis only when page reads were actually elevated.
    $pagingHigh = Get-FmpDiagThreshold $RuleConfig 'pagesInputHighPerSec' 100
    $memQ = @($qs | Where-Object { $_.id -eq 'memory_pressure' -and $_.answer -eq 'yes' -and $_.window -eq 'observation' -and $_.values.pagesAvg -ge $pagingHigh })
    foreach ($q in $qs) {
        if ($memQ.Count -gt 0 -and $q.id -in @('storage_busy', 'storage_slow') -and $q.answer -in @('yes', 'partial')) { Add-FmpDiagAlternative -Question $q -Key 'diag.alt.paging_io' }
    }

    # ---- Key findings: proven storage failures first (never hidden), then relevant yes/partial answers ----
    $relRank = @{ high = 3; medium = 2; low = 1 }
    $ansRank = @{ yes = 2; partial = 1 }
    $candidates = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-FmpValue $Analysis 'findings')) {
        if ((Get-FmpValue $f 'riskGate') -ceq 'critical' -or ((Get-FmpValue $f 'id') -ceq 'storage.disk_space_critical')) {
            $candidates.Add([ordered]@{ kind = 'rule'; id = [string](Get-FmpValue $f 'id'); answer = 'yes'; relevance = 'high'; confidence = [string](Get-FmpValue $f 'confidence'); sort = 100 })
        }
    }
    foreach ($q in $qs) {
        if (-not $ansRank.ContainsKey([string]$q.answer)) { continue }
        # Low-relevance partial signals stay in the details: they are not what the person asked about.
        if ($q.relevance -eq 'low' -and $q.answer -eq 'partial') { continue }
        if ($q.id -eq 'storage_health' -and @($candidates | Where-Object { $_.kind -eq 'rule' }).Count -gt 0) { continue }
        # Detail of another finding: the mapped disk qualifies storage signals, and the timeout question replaces the raw count.
        if ($q.id -eq 'storage_device') { continue }
        if ($q.id -eq 'graphics_events' -and @($qs | Where-Object { $_.id -eq 'graphics_timeout' -and $_.answer -in @('yes', 'partial') }).Count -gt 0) { continue }
        $candidates.Add([ordered]@{ kind = 'question'; id = [string]$q.id; answer = [string]$q.answer; relevance = [string]$q.relevance; confidence = [string]$q.confidence
            sort = (10 * $relRank[[string]$q.relevance] + $ansRank[[string]$q.answer]); order = $candidates.Count })
    }
    # Ties keep the fixed question order (cpu, memory, storage, history...), so the ranking is deterministic.
    $key = @($candidates.ToArray() | Sort-Object -Property @{ Expression = { $_.sort }; Descending = $true }, @{ Expression = { $_['order'] }; Descending = $false } | Select-Object -First 3)

    # ---- Coverage of the questions that matter for this symptom ----
    $relevant = @($qs | Where-Object { $_.relevance -eq 'high' })
    $answered = @($relevant | Where-Object { $_.answer -in @('yes', 'no', 'partial') }).Count
    $coverage = $null
    if ($relevant.Count -gt 0) { $coverage = [Math]::Round(100 * $answered / $relevant.Count, 0) }

    $conclusion = 'none'
    if (@($key | Where-Object { $_.answer -eq 'yes' -and $_.relevance -eq 'high' }).Count -gt 0) { $conclusion = 'found' }
    elseif ($key.Count -gt 0) { $conclusion = 'weak' }
    elseif ($null -eq $coverage -or $coverage -lt 50) { $conclusion = 'insufficient' }

    # ---- Next steps (informative, safe, verifiable; never a repair) ----
    $next = New-Object System.Collections.Generic.List[string]
    if ($key.Count -gt 0) { $next.Add('diag.next.see_findings') }
    $obsAvailable = ($null -ne (Get-FmpValue $Diagnostic 'observation'))
    if ($Symptom -eq 'slow' -and $DuringProblem -ne 'yes' -and $conclusion -ne 'found') { $next.Add('diag.next.reproduce') }
    if ($mode -eq 'simple' -and $Symptom -ne 'general') { $next.Add('diag.next.full_audit') }
    if ($mode -eq 'simple' -and $Symptom -eq 'general' -and -not $obsAvailable) { $next.Add('diag.next.full_for_symptom') }
    foreach ($q in $qs) {
        if ($q.id -eq 'boot_history' -and $q.answer -eq 'access_denied' -and $q.relevance -eq 'high') { $next.Add('diag.next.boot_admin') }
        if ($q.id -eq 'crash_history' -and $q.answer -in @('yes', 'partial') -and $q.relevance -ne 'low') { $next.Add('diag.next.reliability_monitor') }
        if ($q.id -in @('storage_errors', 'storage_health') -and $q.answer -eq 'yes') { if (-not $next.Contains('diag.next.backup')) { $next.Add('diag.next.backup') } }
        if ($q.id -eq 'storage_health' -and $q.answer -in @('unknown', 'partial_unknown') -and $q.relevance -eq 'high') { $next.Add('diag.next.smart_vendor') }
    }
    if ($conclusion -in @('none', 'insufficient')) { $next.Add('diag.next.note_when') }

    $notVerified = New-Object System.Collections.Generic.List[object]
    foreach ($q in $qs) {
        if ($q.answer -in @('unknown', 'not_collected', 'access_denied', 'unsupported', 'error', 'partial_unknown')) {
            $notVerified.Add([ordered]@{ id = $q.id; state = $q.answer; relevance = $q.relevance })
        }
    }

    $hypotheses = @()
    if ($hasInvestigations) {
        $hypotheses = @(Get-FmpHypotheses -Questions $qs.ToArray() -Config $RuleConfig -Investigations (Get-FmpValue $Diagnostic 'investigations'))
        $canDeepen = [string](Get-FmpValue $Diagnostic 'investigations.depth') -ceq 'standard'
        if ($canDeepen -and @($hypotheses | Where-Object { $_['state'] -in @('inconclusive', 'untested') }).Count -gt 0 -and $conclusion -ne 'found') { $next.Add('diag.next.depth_deep') }
    }

    $result = [ordered]@{
        version       = $script:FmpDiagnosisVersion
        symptom       = $Symptom
        mode          = $mode
        duringProblem = $DuringProblem
        observation   = [ordered]@{
            available   = $obsAvailable
            windowSec   = (Get-FmpValue $Diagnostic 'observation.actualSec')
            requestedSec = (Get-FmpValue $Diagnostic 'observation.requestedSec')
            intervalSec = (Get-FmpValue $Diagnostic 'observation.intervalSec')
            startedAt   = (Get-FmpValue $Diagnostic 'observation.startedAt')
            finishedAt  = (Get-FmpValue $Diagnostic 'observation.finishedAt')
            truncated   = (Get-FmpValue $Diagnostic 'observation.truncated')
        }
        conclusion    = $conclusion
        coveragePct   = $coverage
        questions     = $qs.ToArray()
        keyFindings   = $key
        nextSteps     = $next.ToArray()
        notVerified   = $notVerified.ToArray()
    }
    if ($null -ne $incident) { $result['incident'] = $incident }
    if ($hasCatalog) {
        $win = $null
        if ($null -ne $incident) {
            $win = @{ centerUtc = (Get-FmpParsedDate $incident['atUtc']).ToUniversalTime(); startUtc = (Get-FmpParsedDate $incident['windowStart']).ToUniversalTime(); endUtc = (Get-FmpParsedDate $incident['windowEnd']).ToUniversalTime() }
        }
        $maxRows = [int](Get-FmpValue $RuleConfig 'diagnosis.correlation.maxTimelineRows' -Default 60)
        $result['timeline'] = @(Get-FmpDiagTimelineRows $Diagnostic $win | Select-Object -First $maxRows)
        $result['correlations'] = $pairs
    }
    if ($hasInvestigations) {
        $result['hypotheses'] = $hypotheses
        $result['storageMap'] = $storageMap
    }
    return $result
}

# ---------------------------------------------------------------
# Localized text (filled once, in the run language, so the HTML, the
# console summary and an agent reading the JSON say the same thing)
# ---------------------------------------------------------------
function Format-FmpNamedTemplate {
    param([string]$Template, [object]$Values, [string]$Language)
    $out = $Template
    foreach ($e in (Get-FmpEntries $Values)) {
        $v = $e.Value
        $txt = ''
        if ($null -eq $v) { $txt = '-' }
        elseif ($v -is [double] -or $v -is [int] -or $v -is [long] -or $v -is [decimal]) { $txt = Format-FmpNumber -Value $v -Decimals 1 -Language $Language }
        else { $txt = [string]$v }
        $out = $out.Replace('{' + $e.Key + '}', $txt)
    }
    return $out
}

function Get-FmpDiagText {
    param([object[]]$Locales, [string]$Key, [object]$Values = $null, [string]$Language = 'en')
    $t = [string](Get-FmpLocaleString -Locales $Locales -Key $Key)
    if ($null -ne $Values) { $t = Format-FmpNamedTemplate -Template $t -Values $Values -Language $Language }
    return $t
}

function Add-FmpDiagQuestionText {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Question, [object[]]$Locales, [string]$Language)
    $ans = [string]$Question['answer']
    if ($null -ne $Question['values'] -and $Question['values'].Contains('trendKey')) {
        $Question['values']['trend'] = Get-FmpDiagText $Locales ('diag.trend.' + $Question['values']['trendKey']) $null $Language
    }
    if ($ans -in @('access_denied', 'unsupported', 'error', 'not_collected', 'unknown', 'partial_unknown')) {
        $line = Get-FmpDiagText $Locales ('diag.q.' + $Question['id'] + '.label') $null $Language
        $Question['text'] = $line + ': ' + (Get-FmpDiagText $Locales ('diag.state.' + $ans) $null $Language)
    }
    else { $Question['text'] = Get-FmpDiagText $Locales ('diag.q.' + $Question['id'] + '.' + $ans) $Question['values'] $Language }
    $Question['limitations'] = @(@($Question['limitationKeys']) | ForEach-Object { Get-FmpDiagText $Locales $_ $null $Language })
    $Question['alternatives'] = @(@($Question['alternativeKeys']) | ForEach-Object { Get-FmpDiagText $Locales $_ $null $Language })
    if ($Question.Contains('supportItems')) {
        $Question['supporting'] = @(@($Question['supportItems']) | ForEach-Object { Get-FmpDiagText $Locales $_['key'] $_['values'] $Language })
        $null = $Question.Remove('supportItems')
    }
}

function Add-FmpDiagFindingText {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Finding, [object]$Question, [object[]]$Locales, [string]$Language)
    $id = [string]$Finding['id']
    if ($Finding['kind'] -eq 'rule') {
        $Finding['title'] = Get-FmpDiagText $Locales ('rules.' + $id + '.title') $null $Language
        $Finding['observed'] = Get-FmpDiagText $Locales ('rules.' + $id + '.title') $null $Language
        $Finding['why'] = Get-FmpDiagText $Locales 'diag.rule.why' $null $Language
        $Finding['whatToDo'] = Get-FmpDiagText $Locales ('rules.' + $id + '.humanCheck') $null $Language
        $Finding['source'] = 'analysis.findings'
        $Finding['window'] = 'snapshot'
        return
    }
    $vals = Get-FmpValue $Question 'values'
    $Finding['title'] = Get-FmpDiagText $Locales ('diag.q.' + $id + '.title') $null $Language
    $Finding['observed'] = Get-FmpValue $Question 'text'
    $Finding['why'] = Get-FmpDiagText $Locales ('diag.f.' + $id + '.why') $vals $Language
    $Finding['whatToDo'] = Get-FmpDiagText $Locales ('diag.f.' + $id + '.action') $vals $Language
    $Finding['hypothesis'] = Get-FmpDiagText $Locales ('diag.f.' + $id + '.hypothesis') $vals $Language
    $Finding['supporting'] = @(Get-FmpValue $Question 'supporting' | Where-Object { $null -ne $_ })
    $Finding['source'] = Get-FmpValue $Question 'source'
    $Finding['window'] = Get-FmpValue $Question 'window'
    $Finding['limitations'] = @(Get-FmpValue $Question 'limitations')
    $Finding['alternatives'] = @(Get-FmpValue $Question 'alternatives')
}

function Add-FmpHypothesisText {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Hypothesis, [object[]]$Locales, [string]$Language)
    $Hypothesis['title'] = Get-FmpDiagText $Locales ('diag.h.' + $Hypothesis['id']) $null $Language
    $Hypothesis['stateText'] = Get-FmpDiagText $Locales ('diag.hstate.' + $Hypothesis['state']) $null $Language
}

function Add-FmpDiagnosisText {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Diagnosis, [Parameter(Mandatory)][object[]]$Locales, [string]$Language = 'en')
    $byId = @{}
    foreach ($q in @($Diagnosis['questions'])) {
        Add-FmpDiagQuestionText -Question $q -Locales $Locales -Language $Language
        $byId[[string]$q['id']] = $q
    }
    if ($Diagnosis.Contains('hypotheses')) {
        foreach ($h in @($Diagnosis['hypotheses'])) { if ($null -ne $h) { Add-FmpHypothesisText -Hypothesis $h -Locales $Locales -Language $Language } }
    }
    foreach ($k in @($Diagnosis['keyFindings'])) {
        Add-FmpDiagFindingText -Finding $k -Question $byId[[string]$k['id']] -Locales $Locales -Language $Language
    }
    $Diagnosis['conclusionText'] = Get-FmpDiagText $Locales ('diag.conclusion.' + $Diagnosis['conclusion']) $null $Language
    $Diagnosis['symptomText'] = Get-FmpDiagText $Locales ('diag.symptom.' + $Diagnosis['symptom']) $null $Language
    $Diagnosis['nextStepsText'] = @(@($Diagnosis['nextSteps']) | ForEach-Object { Get-FmpDiagText $Locales $_ $null $Language })
}
