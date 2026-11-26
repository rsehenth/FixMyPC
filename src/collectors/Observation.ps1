# =====================================================================
# FIX MY PC - Observation.ps1 (collector, Full audit only)
# Observes CPU, memory, storage and processes over a bounded window
# (default 60 s for "slow", 5 s interval, hard caps below). Uses the RAW
# CIM perf classes and computes rates from deltas, so it is locale
# independent (Get-Counter paths are localized) and does not depend on
# the formatted-data cooker returning 0 on its first read.
# Nothing is written, benchmarked or stressed: each tick is a handful of
# read-only CIM enumerations. A failed family is recorded with its state
# (access_denied / unsupported / error) and never turned into "healthy".
# The math helpers at the top are pure functions (tested with fixtures).
# =====================================================================

function Get-FmpRawUInt64 {
    param([object]$Sample, [string]$Name)
    $value = [string](Get-FmpValue $Sample $Name)
    if ($value -notmatch '\A[0-9]{1,20}\z') { return $null }
    $n = [decimal]$value
    if ($n -le 18446744073709551615d) { return [uint64]$n }
}

function Get-FmpRawDelta {
    # Delta of one raw counter between two snapshots; $null on missing values or counter reset.
    param([object]$Prev, [object]$Curr, [string]$Name)
    $a = Get-FmpRawUInt64 $Prev $Name
    $b = Get-FmpRawUInt64 $Curr $Name
    if ($null -eq $a -or $null -eq $b -or $b -lt $a) { return $null }
    return [double]([decimal]$b - [decimal]$a)
}

function Get-FmpCpuPctFromRaw {
    # Processor(_Total) PercentProcessorTime is an inverse 100ns timer (it counts idle time).
    param([object]$Prev, [object]$Curr)
    $dIdle = Get-FmpRawDelta $Prev $Curr 'PercentProcessorTime'
    $dT = Get-FmpRawDelta $Prev $Curr 'Timestamp_Sys100NS'
    if ($null -eq $dIdle -or $null -eq $dT -or $dT -le 0 -or $dIdle -gt $dT) { return $null }
    $pct = 100 * (1 - ($dIdle / $dT))
    return [Math]::Round($pct, 1)
}

function Get-FmpPerfSeconds {
    # Elapsed seconds between two raw snapshots using the perf timestamp and its frequency.
    param([object]$Prev, [object]$Curr)
    $dT = Get-FmpRawDelta $Prev $Curr 'Timestamp_PerfTime'
    $f = Get-FmpRawUInt64 $Curr 'Frequency_PerfTime'
    if ($null -eq $dT -or $null -eq $f -or $f -eq 0 -or $dT -le 0 -or $f -ne (Get-FmpRawUInt64 $Prev 'Frequency_PerfTime')) { return $null }
    return $dT / $f
}

function Get-FmpMemoryIntervalFromRaw {
    param([object]$Prev, [object]$Curr)
    $avail = ConvertTo-FmpNullableDouble (Get-FmpValue $Curr 'AvailableBytes')
    $committed = ConvertTo-FmpNullableDouble (Get-FmpValue $Curr 'CommittedBytes')
    $limit = ConvertTo-FmpNullableDouble (Get-FmpValue $Curr 'CommitLimit')
    $commitPct = $null
    if ($null -ne $committed -and $committed -ge 0 -and $null -ne $limit -and $limit -gt 0) { $commitPct = [Math]::Round(100 * $committed / $limit, 1) }
    $pagesIn = $null
    $sec = Get-FmpPerfSeconds $Prev $Curr
    $dPages = Get-FmpRawDelta $Prev $Curr 'PagesInputPersec'
    if ($null -ne $sec -and $null -ne $dPages) { $pagesIn = [Math]::Round($dPages / $sec, 1) }
    $availMB = $null
    if ($null -ne $avail -and $avail -ge 0) { $availMB = [Math]::Round($avail / 1MB, 0) }
    return [ordered]@{ availableMB = $availMB; commitPct = $commitPct; pagesInputPerSec = $pagesIn }
}

function Get-FmpDiskIntervalFromRaw {
    # PhysicalDisk raw math: average timers ((dN / F) / dBase), bulk counts (dN / seconds),
    # and the 100ns queue-length counter (dN / dSys100NS).
    param([object]$Prev, [object]$Curr)
    $f = ConvertTo-FmpNullableDouble (Get-FmpValue $Curr 'Frequency_PerfTime')
    $sec = Get-FmpPerfSeconds $Prev $Curr
    $out = [ordered]@{ readLatencyMs = $null; writeLatencyMs = $null; readsPerSec = $null; writesPerSec = $null
        avgQueue = $null; currentQueue = $null; readBytesPerSec = $null; writeBytesPerSec = $null }
    $dReadBase = Get-FmpRawDelta $Prev $Curr 'AvgDisksecPerRead_Base'
    $dReadTime = Get-FmpRawDelta $Prev $Curr 'AvgDisksecPerRead'
    if ($null -ne $sec -and $null -ne $dReadBase -and $dReadBase -gt 0 -and $null -ne $dReadTime) {
        $out['readLatencyMs'] = [Math]::Round(1000 * ($dReadTime / $f) / $dReadBase, 2)
    }
    $dWriteBase = Get-FmpRawDelta $Prev $Curr 'AvgDisksecPerWrite_Base'
    $dWriteTime = Get-FmpRawDelta $Prev $Curr 'AvgDisksecPerWrite'
    if ($null -ne $sec -and $null -ne $dWriteBase -and $dWriteBase -gt 0 -and $null -ne $dWriteTime) {
        $out['writeLatencyMs'] = [Math]::Round(1000 * ($dWriteTime / $f) / $dWriteBase, 2)
    }
    if ($null -ne $sec) {
        if ($null -ne $dReadBase) { $out['readsPerSec'] = [Math]::Round($dReadBase / $sec, 1) }
        if ($null -ne $dWriteBase) { $out['writesPerSec'] = [Math]::Round($dWriteBase / $sec, 1) }
        $dRb = Get-FmpRawDelta $Prev $Curr 'DiskReadBytesPersec'
        $dWb = Get-FmpRawDelta $Prev $Curr 'DiskWriteBytesPersec'
        if ($null -ne $dRb) { $out['readBytesPerSec'] = [Math]::Round($dRb / $sec, 0) }
        if ($null -ne $dWb) { $out['writeBytesPerSec'] = [Math]::Round($dWb / $sec, 0) }
    }
    $dQ = Get-FmpRawDelta $Prev $Curr 'AvgDiskQueueLength'
    $dSys = Get-FmpRawDelta $Prev $Curr 'Timestamp_Sys100NS'
    if ($null -ne $dQ -and $null -ne $dSys -and $dSys -gt 0) { $out['avgQueue'] = [Math]::Round($dQ / $dSys, 2) }
    $cq = ConvertTo-FmpNullableDouble (Get-FmpValue $Curr 'CurrentDiskQueueLength')
    if ($null -ne $cq -and $cq -ge 0) { $out['currentQueue'] = $cq }
    return $out
}

function Get-FmpSeriesStats {
    # Summary of one numeric series: average, extremes, nearest-rank p90, share and longest run at/above High.
    param([object[]]$Values, [double]$High = 1e308)
    $nums = New-Object System.Collections.Generic.List[object]
    $sum = [double]0
    $highCount = 0
    $run = 0
    $longest = 0
    foreach ($v in $Values) {
        $n = ConvertTo-FmpNullableDouble $v
        if ($null -eq $n) { $run = 0; continue }
        $nums.Add($n)
        $sum += $n
        if ($n -ge $High) { $highCount++; $run++; if ($run -gt $longest) { $longest = $run } } else { $run = 0 }
    }
    if ($nums.Count -eq 0) { return [ordered]@{ count = 0; avg = $null; min = $null; max = $null; p90 = $null; highShare = $null; longestHighRun = 0 } }
    $sorted = @($nums.ToArray() | Sort-Object)
    $p90 = $sorted[$sorted.Count - [int][Math]::Floor($sorted.Count / 10) - 1]
    return [ordered]@{
        count          = $nums.Count
        avg            = [Math]::Round($sum / $nums.Count, 2)
        min            = $sorted[0]
        max            = $sorted[$sorted.Count - 1]
        p90            = $p90
        highShare      = [Math]::Round($highCount / $nums.Count, 2)
        longestHighRun = $longest
    }
}

function Get-FmpProcessGroupName {
    # Perf instance names carry a volatile "#n" suffix. The result is an executable-level name, not proof of one application.
    param([string]$Name)
    return ($Name -replace '#\d+$', '')
}

function Get-FmpProcessIoInterval {
    # Deltas of the cumulative per-process I/O counters over the real time between two samples.
    # A missing, reset or decreasing counter yields $null for that metric, never 0.
    param([object]$Prev, [object]$Curr)
    $sec = Get-FmpPerfSeconds $Prev $Curr
    $out = [ordered]@{ seconds = $sec; readBytes = $null; writeBytes = $null; readOps = $null; writeOps = $null }
    if ($null -eq $sec -or $sec -le 0) { $out['seconds'] = $null; return $out }
    $out['readBytes'] = Get-FmpRawDelta $Prev $Curr 'IOReadBytesPersec'
    $out['writeBytes'] = Get-FmpRawDelta $Prev $Curr 'IOWriteBytesPersec'
    $out['readOps'] = Get-FmpRawDelta $Prev $Curr 'IOReadOperationsPersec'
    $out['writeOps'] = Get-FmpRawDelta $Prev $Curr 'IOWriteOperationsPersec'
    return $out
}

function Get-FmpProcessStartUtc {
    # PERF_ELAPSED_TIME raw value is the start stamp in Timestamp_Object units; the age avoids assuming that clock's epoch.
    param([object]$Sample, [datetime]$SampleUtc)
    $start = Get-FmpRawUInt64 $Sample 'ElapsedTime'
    $stamp = Get-FmpRawUInt64 $Sample 'Timestamp_Object'
    $freq = Get-FmpRawUInt64 $Sample 'Frequency_Object'
    if ($null -eq $start -or $null -eq $stamp -or $null -eq $freq -or $freq -eq 0 -or $stamp -lt $start) { return $null }
    $ageSec = ([double]([decimal]$stamp - [decimal]$start)) / [double]$freq
    return $SampleUtc.AddDays(-$ageSec / 86400).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Add-FmpProcessGroupTick {
    # One snapshot per call. Values are summed across the instances alive in THIS snapshot, so a group's maximum is a
    # real simultaneous total and never a sum of per-process maxima taken at different moments.
    param([hashtable]$Groups, [object[]]$Instances, [int]$MaxGroups = 200)
    $tick = @{}
    foreach ($inst in $Instances) {
        $g = [string]$inst['group']
        if (-not $tick.ContainsKey($g)) { $tick[$g] = @{ n = 0; commit = [double]0; hasCommit = $false; missingCommit = $false; ws = [double]0; hasWs = $false; cores = [double]0; hasCores = $false; read = [double]0; write = [double]0; hasIo = $false } }
        $t = $tick[$g]
        $t.n++
        if ($null -ne $inst['commit']) { $t.commit += [double]$inst['commit']; $t.hasCommit = $true } else { $t.missingCommit = $true }
        if ($null -ne $inst['ws']) { $t.ws += [double]$inst['ws']; $t.hasWs = $true }
        if ($null -ne $inst['cores']) { $t.cores += [double]$inst['cores']; $t.hasCores = $true }
        if ($null -ne $inst['readBps']) { $t.read += [double]$inst['readBps']; $t.hasIo = $true }
        if ($null -ne $inst['writeBps']) { $t.write += [double]$inst['writeBps']; $t.hasIo = $true }
    }
    foreach ($g in @($tick.Keys)) {
        if (-not $Groups.ContainsKey($g)) {
            if ($Groups.Count -ge $MaxGroups) { continue }
            $Groups[$g] = @{ name = $g; maxInstances = 0; memTicks = 0; commitSum = [double]0; commitMax = $null; commitIncomplete = $false
                wsTicks = 0; wsSum = [double]0; wsMax = $null; cpuTicks = 0; coresSum = [double]0; coresMax = $null; ioTicks = 0; readSum = [double]0; writeSum = [double]0 }
        }
        $r = $Groups[$g]; $t = $tick[$g]
        if ($t.n -gt $r.maxInstances) { $r.maxInstances = $t.n }
        if ($t.missingCommit) { $r.commitIncomplete = $true }
        if ($t.hasCommit) { $r.memTicks++; $r.commitSum += $t.commit; if ($null -eq $r.commitMax -or $t.commit -gt $r.commitMax) { $r.commitMax = $t.commit } }
        if ($t.hasWs) { $r.wsTicks++; $r.wsSum += $t.ws; if ($null -eq $r.wsMax -or $t.ws -gt $r.wsMax) { $r.wsMax = $t.ws } }
        if ($t.hasCores) { $r.cpuTicks++; $r.coresSum += $t.cores; if ($null -eq $r.coresMax -or $t.cores -gt $r.coresMax) { $r.coresMax = $t.cores } }
        if ($t.hasIo) { $r.ioTicks++; $r.readSum += $t.read; $r.writeSum += $t.write }
    }
}

function Get-FmpProcessGroupSummary {
    # Per-group averages and simultaneous peaks. basis says what the grouping really is: the same executable name.
    param([hashtable]$Groups, [int]$Top = 10)
    $rows = New-Object System.Collections.Generic.List[object]
    $ioTotal = [double]0
    foreach ($r in $Groups.Values) { if ($r.ioTicks -gt 0) { $ioTotal += ($r.readSum + $r.writeSum) / $r.ioTicks } }
    foreach ($r in $Groups.Values) {
        $commitAvg = $null; $commitMax = $null; $wsAvg = $null; $wsMax = $null; $coresAvg = $null; $coresMax = $null; $readBps = $null; $writeBps = $null; $share = $null
        if ($r.memTicks -gt 0) { $commitAvg = [Math]::Round($r.commitSum / $r.memTicks / 1MB, 1); $commitMax = [Math]::Round($r.commitMax / 1MB, 1) }
        if ($r.wsTicks -gt 0) { $wsAvg = [Math]::Round($r.wsSum / $r.wsTicks / 1MB, 1); $wsMax = [Math]::Round($r.wsMax / 1MB, 1) }
        if ($r.cpuTicks -gt 0) { $coresAvg = [Math]::Round($r.coresSum / $r.cpuTicks, 2); $coresMax = [Math]::Round($r.coresMax, 2) }
        if ($r.ioTicks -gt 0) {
            $readBps = [Math]::Round($r.readSum / $r.ioTicks, 0); $writeBps = [Math]::Round($r.writeSum / $r.ioTicks, 0)
            if ($ioTotal -gt 0) { $share = [Math]::Round(100 * ($readBps + $writeBps) / $ioTotal, 1) }
        }
        $rows.Add([ordered]@{
            name = $r.name; basis = 'executable_name'; instancesMax = $r.maxInstances
            commitAvgMB = $commitAvg; commitPeakMB = $commitMax; commitIncomplete = $r.commitIncomplete
            workingSetAvgMB = $wsAvg; workingSetPeakMB = $wsMax; avgCores = $coresAvg; peakCores = $coresMax
            readBytesPerSec = $readBps; writeBytesPerSec = $writeBps; ioSharePct = $share
        })
    }
    return @($rows.ToArray() | Sort-Object -Property @{ Expression = { if ($null -ne $_['commitPeakMB']) { $_['commitPeakMB'] } else { -1 } }; Descending = $true }, @{ Expression = { $_['name'] }; Descending = $false } | Select-Object -First $Top)
}

function Get-FmpObservationData {
    param(
        [int]$DurationSec = 60, [int]$IntervalSec = 5, [int]$MaxSamples = 61, [int]$TopProcesses = 8,
        [int]$MaxProcesses = 1000, [int]$MaxDisks = 8, [double]$CpuHighPct = 85, [double]$ProcActiveCores = 0.5,
        [string[]]$Families = @('cpu', 'memory', 'disk', 'processes')
    )

    return Invoke-FmpCollector -Name 'observation' -Body {
        param([System.Collections.IDictionary]$ctx)
        # Hard bounds, whatever the caller passes.
        if ($IntervalSec -lt 1) { $IntervalSec = 1 }
        if ($IntervalSec -gt 30) { $IntervalSec = 30 }
        if ($DurationSec -lt $IntervalSec) { $DurationSec = $IntervalSec }
        if ($DurationSec -gt 300) { $DurationSec = 300 }
        if ($MaxSamples -lt 2) { $MaxSamples = 2 }
        if ($MaxSamples -gt 61) { $MaxSamples = 61 }
        $ticks = [int][Math]::Floor($DurationSec / $IntervalSec)
        if ($ticks -gt ($MaxSamples - 1)) { $ticks = $MaxSamples - 1 }
        # Budget: the window plus room for slow providers; past it the loop stops and the result is partial.
        $budgetMs = ($DurationSec + 45) * 1000

        $ctx.data['requestedSec'] = $DurationSec
        $ctx.data['intervalSec'] = $IntervalSec
        $ctx.data['startedAt'] = Get-FmpTimestamp

        $logical = $null
        $totalBytes = $null
        try {
            $lpSum = 0
            foreach ($pc in @(Get-CimInstance -ClassName Win32_Processor -Property NumberOfLogicalProcessors -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
                $lp = ConvertTo-FmpNullableInt (Get-FmpValue $pc 'NumberOfLogicalProcessors')
                if ($null -ne $lp -and $lp -gt 0) { $lpSum += $lp }
            }
            if ($lpSum -gt 0) { $logical = $lpSum }
        }
        catch { }
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
            $kb = ConvertTo-FmpNullableDouble (Get-FmpValue $os 'TotalVisibleMemorySize')
            if ($null -ne $kb -and $kb -gt 0) { $totalBytes = $kb * 1KB }
        }
        catch { }
        $ctx.data['logicalProcessors'] = $logical

        $state = [ordered]@{ cpu = 'pass'; memory = 'pass'; disk = 'pass'; processes = 'pass' }
        foreach ($family in @('cpu', 'memory', 'disk', 'processes')) { if ($family -notin $Families) { $state[$family] = 'not_collected' } }
        $cpuSeries = New-Object System.Collections.Generic.List[object]
        $memSeries = New-Object System.Collections.Generic.List[object]
        $diskSeries = [ordered]@{}
        $procs = @{}
        $appGroups = @{}
        $lastProcTick = -1
        $queryMs = New-Object System.Collections.Generic.List[object]
        $prevCpu = $null; $prevMem = $null; $prevDisks = @{}
        $intervals = 0
        $truncated = $false
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        for ($i = 0; $i -le $ticks; $i++) {
            if ($sw.ElapsedMilliseconds -gt $budgetMs) { $truncated = $true; break }
            $q = [System.Diagnostics.Stopwatch]::StartNew()

            if ($state.cpu -eq 'pass') {
                try {
                    $c = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -Property PercentProcessorTime, Timestamp_Sys100NS -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
                    if ($i -gt 0) { $cpuSeries.Add((Get-FmpCpuPctFromRaw $prevCpu $c)) }
                    $prevCpu = $c
                }
                catch {
                    $state['cpu'] = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    Add-FmpCollectorError -Ctx $ctx -Where 'observation.cpu' -Message $_.Exception.Message
                }
            }
            if ($state.memory -eq 'pass') {
                try {
                    $m = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory -Property AvailableBytes, CommittedBytes, CommitLimit, PagesInputPersec, Timestamp_PerfTime, Frequency_PerfTime -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
                    if ($null -ne $prevMem) { $memSeries.Add((Get-FmpMemoryIntervalFromRaw $prevMem $m)) }
                    $prevMem = $m
                }
                catch {
                    $state['memory'] = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    Add-FmpCollectorError -Ctx $ctx -Where 'observation.memory' -Message $_.Exception.Message
                }
            }
            if ($state.disk -eq 'pass') {
                try {
                    $currDisks = @{}
                    foreach ($dk in @(Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -Property Name, AvgDisksecPerRead, AvgDisksecPerRead_Base, AvgDisksecPerWrite, AvgDisksecPerWrite_Base, AvgDiskQueueLength, CurrentDiskQueueLength, DiskReadBytesPersec, DiskWriteBytesPersec, Timestamp_PerfTime, Frequency_PerfTime, Timestamp_Sys100NS -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
                        $dn = Get-FmpCleanString (Get-FmpValue $dk 'Name')
                        if ($null -eq $dn -or $dn -eq '_Total') { continue }
                        if ($currDisks.Count -ge $MaxDisks) { break }
                        $currDisks[$dn] = $dk
                        if ($prevDisks.ContainsKey($dn)) {
                            if (-not $diskSeries.Contains($dn)) { $diskSeries[$dn] = New-Object System.Collections.Generic.List[object] }
                            $diskSeries[$dn].Add((Get-FmpDiskIntervalFromRaw $prevDisks[$dn] $dk))
                        }
                    }
                    $prevDisks = $currDisks
                }
                catch {
                    $state['disk'] = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    Add-FmpCollectorError -Ctx $ctx -Where 'observation.disk' -Message $_.Exception.Message
                }
            }
            if ($state.processes -eq 'pass') {
                try {
                    $rows = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -Property Name, IDProcess, ElapsedTime, PercentProcessorTime, WorkingSet, WorkingSetPrivate, PrivateBytes, IOReadBytesPersec, IOWriteBytesPersec, IOReadOperationsPersec, IOWriteOperationsPersec, Timestamp_Sys100NS, Timestamp_PerfTime, Frequency_PerfTime, Timestamp_Object, Frequency_Object -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
                    $tickUtc = [DateTime]::UtcNow
                    $tickInstances = New-Object System.Collections.Generic.List[object]
                    foreach ($p in $rows) {
                        $pn = Get-FmpCleanString (Get-FmpValue $p 'Name')
                        if ($null -eq $pn -or $pn -in @('_Total', 'Idle')) { continue }
                        $pid0 = Get-FmpRawUInt64 $p 'IDProcess'
                        # Raw PERF_ELAPSED_TIME is the start timestamp, independent of the instance name suffix.
                        $start = Get-FmpRawUInt64 $p 'ElapsedTime'
                        if ($null -eq $pid0 -or $pid0 -eq 0 -or $null -eq $start -or $start -eq 0) { continue }
                        $key = ([string]$pid0) + ':' + $start
                        $ws = Get-FmpRawUInt64 $p 'WorkingSetPrivate'
                        $wsTotal = Get-FmpRawUInt64 $p 'WorkingSet'
                        # A protected process can report 0 here: that is "not readable", not "no committed memory".
                        $commit = Get-FmpRawUInt64 $p 'PrivateBytes'
                        if ($commit -eq 0) { $commit = $null }
                        $inst = @{ group = (Get-FmpProcessGroupName $pn); commit = $commit; ws = $wsTotal; cores = $null; readBps = $null; writeBps = $null }
                        if (-not $procs.ContainsKey($key)) {
                            if ($procs.Count -ge $MaxProcesses) { continue }
                            $procs[$key] = [ordered]@{ name = $pn; pid = $pid0; startedAt = (Get-FmpProcessStartUtc $p $tickUtc); lastSample = $p; lastTick = $i; cpuTicks = [double]0; elapsedTicks = [double]0
                                firstWs = $ws; lastWs = $ws; lastWsTotal = $wsTotal; firstCommit = $commit; lastCommit = $commit; firstCommitTick = $i; lastCommitTick = $i; maxCores = [double]0; activeIntervals = 0; intervals = 0
                                ioSeconds = [double]0; ioIntervals = 0; ioInvalid = 0; readBytes = [double]0; writeBytes = [double]0; readOps = [double]0; writeOps = [double]0 }
                            $tickInstances.Add($inst)
                            continue
                        }
                        $rec = $procs[$key]
                        if ($rec.lastTick -eq ($i - 1)) {
                            $cpuTicks = Get-FmpRawDelta $rec.lastSample $p 'PercentProcessorTime'
                            $elapsed = Get-FmpRawDelta $rec.lastSample $p 'Timestamp_Sys100NS'
                            if ($null -ne $cpuTicks -and $elapsed -gt 0) {
                                $cores = $cpuTicks / $elapsed
                                $inst['cores'] = $cores
                                $procs[$key]['cpuTicks'] += $cpuTicks
                                $procs[$key]['elapsedTicks'] += $elapsed
                                $procs[$key]['intervals']++
                                if ($cores -ge $ProcActiveCores) { $procs[$key]['activeIntervals']++ }
                                if ($cores -gt $rec.maxCores) { $procs[$key]['maxCores'] = $cores }
                            }
                            $io = Get-FmpProcessIoInterval $rec.lastSample $p
                            # All four counters must be valid in the interval, so totals and rates cover the same time.
                            if ($null -ne $io.seconds -and $null -ne $io.readBytes -and $null -ne $io.writeBytes -and $null -ne $io.readOps -and $null -ne $io.writeOps) {
                                $procs[$key]['ioSeconds'] += $io.seconds
                                $procs[$key]['ioIntervals']++
                                $procs[$key]['readBytes'] += $io.readBytes
                                $procs[$key]['writeBytes'] += $io.writeBytes
                                $procs[$key]['readOps'] += $io.readOps
                                $procs[$key]['writeOps'] += $io.writeOps
                                $inst['readBps'] = $io.readBytes / $io.seconds
                                $inst['writeBps'] = $io.writeBytes / $io.seconds
                            }
                            else { $procs[$key]['ioInvalid']++ }
                        }
                        $procs[$key]['lastSample'] = $p
                        $procs[$key]['lastTick'] = $i
                        $procs[$key]['lastWs'] = $ws
                        $procs[$key]['lastWsTotal'] = $wsTotal
                        if ($null -ne $commit) {
                            if ($null -eq $rec.firstCommit) { $procs[$key]['firstCommit'] = $commit; $procs[$key]['firstCommitTick'] = $i }
                            $procs[$key]['lastCommit'] = $commit
                            $procs[$key]['lastCommitTick'] = $i
                        }
                        $tickInstances.Add($inst)
                    }
                    Add-FmpProcessGroupTick -Groups $appGroups -Instances $tickInstances.ToArray()
                    $lastProcTick = $i
                }
                catch {
                    $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    $state['processes'] = $st
                    Add-FmpCollectorError -Ctx $ctx -Where 'observation.processes' -Message $_.Exception.Message
                }
            }
            $q.Stop()
            $queryMs.Add($q.ElapsedMilliseconds)
            if ($i -gt 0) { $intervals++ }
            if ($i -lt $ticks) { Start-Sleep -Seconds $IntervalSec }
        }
        $sw.Stop()

        $ctx.data['finishedAt'] = Get-FmpTimestamp
        $ctx.data['actualSec'] = [Math]::Round($sw.ElapsedMilliseconds / 1000.0, 1)
        $ctx.data['intervals'] = $intervals
        $ctx.data['truncated'] = $truncated
        $qStats = Get-FmpSeriesStats -Values $queryMs.ToArray()
        $ctx.data['cost'] = [ordered]@{ queryMsAvg = $qStats.avg; queryMsMax = $qStats.max; snapshots = $queryMs.Count }
        if ($truncated) {
            Add-FmpLimitation -Ctx $ctx -Key 'observation_truncated' -DetailText 'The observation hit its time budget and stopped early; results cover a shorter window.'
        }

        # ---- CPU ----
        $cpuStats = Get-FmpSeriesStats -Values $cpuSeries.ToArray() -High $CpuHighPct
        if ($state.cpu -eq 'pass' -and $cpuStats.count -lt 2) { $state['cpu'] = 'unknown' }
        $ctx.data['cpu'] = [ordered]@{ state = $state.cpu; highPct = $CpuHighPct; stats = $cpuStats; series = $cpuSeries.ToArray() }
        Add-FmpSubCheck -Ctx $ctx -Id 'observation.cpu' -State $state.cpu

        # ---- Memory ----
        $memRows = $memSeries.ToArray()
        $available = Get-FmpSeriesStats -Values @($memRows | ForEach-Object { $_['availableMB'] })
        if ($state.memory -eq 'pass' -and $available.count -lt 2) { $state['memory'] = 'unknown' }
        $ctx.data['memory'] = [ordered]@{
            state            = $state.memory
            totalBytes       = $totalBytes
            availableMB      = $available
            commitPct        = Get-FmpSeriesStats -Values @($memRows | ForEach-Object { $_['commitPct'] })
            pagesInputPerSec = Get-FmpSeriesStats -Values @($memRows | ForEach-Object { $_['pagesInputPerSec'] })
            series           = $memRows
        }
        Add-FmpSubCheck -Ctx $ctx -Id 'observation.memory' -State $state.memory

        # ---- Storage ----
        $diskItems = New-Object System.Collections.Generic.List[object]
        foreach ($dn in @($diskSeries.Keys)) {
            $rowsD = $diskSeries[$dn].ToArray()
            $active = @($rowsD | Where-Object { $null -ne $_['readLatencyMs'] -or $null -ne $_['writeLatencyMs'] }).Count
            $diskItems.Add([ordered]@{
                name             = $dn
                intervals        = $rowsD.Count
                activeIntervals  = $active
                readLatencyMs    = Get-FmpSeriesStats -Values @($rowsD | ForEach-Object { $_['readLatencyMs'] })
                writeLatencyMs   = Get-FmpSeriesStats -Values @($rowsD | ForEach-Object { $_['writeLatencyMs'] })
                avgQueue         = Get-FmpSeriesStats -Values @($rowsD | ForEach-Object { $_['avgQueue'] })
                readBytesPerSec  = Get-FmpSeriesStats -Values @($rowsD | ForEach-Object { $_['readBytesPerSec'] })
                writeBytesPerSec = Get-FmpSeriesStats -Values @($rowsD | ForEach-Object { $_['writeBytesPerSec'] })
            })
        }
        if ($state.disk -eq 'pass' -and @($diskItems.ToArray() | Where-Object {
            $_['activeIntervals'] -gt 0 -or $_['avgQueue']['count'] -gt 0 -or $_['readBytesPerSec']['count'] -gt 0 -or $_['writeBytesPerSec']['count'] -gt 0
        }).Count -eq 0) { $state['disk'] = 'unknown' }
        $ctx.data['disks'] = [ordered]@{ state = $state.disk; items = $diskItems.ToArray() }
        Add-FmpSubCheck -Ctx $ctx -Id 'observation.disk' -State $state.disk

        # ---- Processes (names only: no command lines, no paths) ----
        $procRows = New-Object System.Collections.Generic.List[object]
        # Share of the I/O seen across tracked processes in the window (a relative figure, not a share of disk activity).
        $ioTotalRate = [double]0
        foreach ($rec in $procs.Values) { if ($rec.ioSeconds -gt 0) { $ioTotalRate += ($rec.readBytes + $rec.writeBytes) / $rec.ioSeconds } }
        foreach ($rec in $procs.Values) {
            $avgCores = $null
            if ($rec.elapsedTicks -gt 0) { $avgCores = $rec.cpuTicks / $rec.elapsedTicks }
            $pctMachine = $null
            if ($null -ne $avgCores -and $null -ne $logical -and $logical -gt 0) { $pctMachine = [Math]::Round(100 * $avgCores / $logical, 1) }
            $growth = $null
            if ($null -ne $rec.firstWs -and $null -ne $rec.lastWs) { $growth = [Math]::Round(([double]$rec.lastWs - [double]$rec.firstWs) / 1MB, 1) }
            $privMB = $null
            if ($null -ne $rec.lastWs) { $privMB = [Math]::Round($rec.lastWs / 1MB, 1) }
            $activeShare = $null
            if ($rec.intervals -gt 0) { $activeShare = [Math]::Round($rec.activeIntervals / $rec.intervals, 2) }
            $cores = $null
            if ($null -ne $avgCores) { $cores = [Math]::Round($avgCores, 2) }
            $wsTotalMB = $null
            if ($null -ne $rec.lastWsTotal) { $wsTotalMB = [Math]::Round($rec.lastWsTotal / 1MB, 1) }
            $commitMB = $null
            if ($null -ne $rec.lastCommit) { $commitMB = [Math]::Round($rec.lastCommit / 1MB, 1) }
            # Growth needs two distinct readings; one reading says nothing about a trend.
            $commitGrowth = $null
            if ($null -ne $rec.firstCommit -and $rec.lastCommitTick -gt $rec.firstCommitTick) { $commitGrowth = [Math]::Round(([double]$rec.lastCommit - [double]$rec.firstCommit) / 1MB, 1) }
            $readBps = $null; $writeBps = $null; $readOps = $null; $writeOps = $null; $ioShare = $null
            if ($rec.ioSeconds -gt 0) {
                $readBps = [Math]::Round($rec.readBytes / $rec.ioSeconds, 0)
                $writeBps = [Math]::Round($rec.writeBytes / $rec.ioSeconds, 0)
                $readOps = [Math]::Round($rec.readOps / $rec.ioSeconds, 1)
                $writeOps = [Math]::Round($rec.writeOps / $rec.ioSeconds, 1)
                if ($ioTotalRate -gt 0) { $ioShare = [Math]::Round(100 * (($rec.readBytes + $rec.writeBytes) / $rec.ioSeconds) / $ioTotalRate, 1) }
            }
            $procRows.Add([ordered]@{
                name = $rec.name; pid = $rec.pid; startedAt = $rec.startedAt; exited = ($rec.lastTick -lt $lastProcTick)
                avgCores = $cores; avgPctOfMachine = $pctMachine; maxCores = [Math]::Round($rec.maxCores, 2)
                activeShare = $activeShare; intervals = $rec.intervals
                # Legacy pair: privateMB is the private WORKING SET (resident), kept unchanged for 2.0 readers.
                privateMB = $privMB; privateGrowth = $growth
                workingSetMB = $wsTotalMB; workingSetPrivateMB = $privMB; commitPrivateMB = $commitMB; commitGrowthMB = $commitGrowth
                readBytesPerSec = $readBps; writeBytesPerSec = $writeBps; readOpsPerSec = $readOps; writeOpsPerSec = $writeOps
                ioSharePct = $ioShare; ioIntervals = $rec.ioIntervals; ioInvalidIntervals = $rec.ioInvalid
            })
        }
        $topCpu = @($procRows.ToArray() | Where-Object { $null -ne $_['avgCores'] } | Sort-Object -Property { $_['avgCores'] } -Descending | Select-Object -First $TopProcesses)
        $topMem = @($procRows.ToArray() | Where-Object { $null -ne $_['privateMB'] } | Sort-Object -Property { $_['privateMB'] } -Descending | Select-Object -First $TopProcesses)
        $topCommit = @($procRows.ToArray() | Where-Object { $null -ne $_['commitPrivateMB'] } | Sort-Object -Property { $_['commitPrivateMB'] } -Descending | Select-Object -First $TopProcesses)
        $topIo = @($procRows.ToArray() | Where-Object { $null -ne $_['readBytesPerSec'] -and ($_['readBytesPerSec'] + $_['writeBytesPerSec']) -gt 0 } | Sort-Object -Property { $_['readBytesPerSec'] + $_['writeBytesPerSec'] } -Descending | Select-Object -First $TopProcesses)
        if ($state.processes -eq 'pass' -and $procRows.Count -eq 0) { $state['processes'] = 'unknown' }
        $ctx.data['processes'] = [ordered]@{
            state = $state.processes; tracked = $procRows.Count; capped = ($procs.Count -ge $MaxProcesses)
            topCpu = $topCpu; topMemory = $topMem; topCommit = $topCommit; topIo = $topIo
            exitedDuringWindow = @($procRows.ToArray() | Where-Object { $_['exited'] }).Count
            ioInvalidIntervals = [int](@($procRows.ToArray() | ForEach-Object { $_['ioInvalidIntervals'] } | Measure-Object -Sum).Sum)
            appGroups = @(Get-FmpProcessGroupSummary -Groups $appGroups)
            appGroupBasis = 'executable_name'
        }
        Add-FmpSubCheck -Ctx $ctx -Id 'observation.processes' -State $state.processes
        if ($state.processes -eq 'pass') {
            Add-FmpLimitation -Ctx $ctx -Key 'process_io_scope' -DetailText 'Per-process I/O counters include file, network and device I/O, so they are not physical disk activity.'
            Add-FmpLimitation -Ctx $ctx -Key 'process_group_basis' -DetailText 'Process groups use the executable name; the same name does not prove the same application.'
        }
        Add-FmpLimitation -Ctx $ctx -Key 'observation_window' -DetailText ('Observation covers ~' + $ctx.data['actualSec'] + ' s; intermittent problems outside it are not captured.') -Values @($ctx.data['actualSec'])

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'observation.cpu' -Summary ('Raw CIM perf classes, ' + $queryMs.Count + ' snapshots, ' + $IntervalSec + 's interval')
    }
}
