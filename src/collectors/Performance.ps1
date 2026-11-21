# =====================================================================
# FIX MY PC - Performance.ps1 (collector)
# Short, finite, passive sampling. CPU is sampled 3 times over ~4 s via
# locale-independent CIM perf counters (Get-Counter is locale-sensitive).
# Process CPU uses the formatted PerfProc counter (per-core scale), NOT
# accumulated process CPU time. A point-in-time reading is never treated
# as a chronic condition by the rules engine.
# =====================================================================

function Get-FmpPerformanceData {
    param([int]$CpuSamples = 3, [int]$SampleIntervalSec = 2, [int]$TopProcesses = 15)

    return Invoke-FmpCollector -Name 'performance' -Body {
        param([System.Collections.IDictionary]$ctx)

        if ($CpuSamples -lt 1) { $CpuSamples = 1 }
        if ($SampleIntervalSec -lt 0) { $SampleIntervalSec = 0 }
        if ($TopProcesses -lt 1) { $TopProcesses = 1 }

        $ctx.data['memory'] = $null
        $ctx.data['cpu'] = $null
        $ctx.data['topProcessesByMemory'] = @()
        $ctx.data['topProcessesByCpu'] = @()
        $ctx.data['pagefile'] = $null

        # ---- Memory snapshot (CIM perf memory class is locale-independent) ----
        try {
            $mem = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
            $os = $null
            try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1 } catch { }
            $totalBytes = $null
            $freeBytes = $null
            $totalKB = ConvertTo-FmpNullableDouble (Get-FmpValue $os 'TotalVisibleMemorySize')
            $freeKB = ConvertTo-FmpNullableDouble (Get-FmpValue $os 'FreePhysicalMemory')
            if ($null -ne $totalKB -and $totalKB -gt 0) { $totalBytes = $totalKB * 1KB }
            if ($null -ne $freeKB -and $freeKB -ge 0 -and ($null -eq $totalKB -or $freeKB -le $totalKB)) { $freeBytes = $freeKB * 1KB }
            $commitPct = ConvertTo-FmpNullableDouble (Get-FmpValue $mem 'PercentCommittedBytesInUse')
            if ($null -ne $commitPct -and ($commitPct -lt 0 -or $commitPct -gt 100)) { $commitPct = $null }
            $committed = ConvertTo-FmpNullableDouble (Get-FmpValue $mem 'CommittedBytes')
            $commitLimit = ConvertTo-FmpNullableDouble (Get-FmpValue $mem 'CommitLimit')
            $availMB = ConvertTo-FmpNullableDouble (Get-FmpValue $mem 'AvailableMBytes')
            $ctx.data['memory'] = [ordered]@{
                totalBytes       = $totalBytes
                freeBytes        = $freeBytes
                availablePct     = $(if ($null -ne $totalBytes -and $totalBytes -gt 0 -and $null -ne $freeBytes) { [Math]::Round(($freeBytes / $totalBytes) * 100, 1) } else { $null })
                committedBytes   = $committed
                commitLimitBytes = $commitLimit
                commitPct        = $commitPct
                availableMB      = $availMB
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.memory' -State $(if ($null -ne $commitPct) { 'pass' } else { 'unknown' })
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.memory' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'performance.memory' -Message $_.Exception.Message
        }

        # ---- Logical processors (for context on per-core CPU scale) ----
        $logicalProcessors = $null
        try {
            $procsCim = @(Get-CimInstance -ClassName Win32_Processor -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $lpSum = 0
            $hasLp = $false
            foreach ($pc in $procsCim) {
                $lp = ConvertTo-FmpNullableInt (Get-FmpValue $pc 'NumberOfLogicalProcessors')
                if ($null -ne $lp -and $lp -gt 0) { $lpSum += $lp; $hasLp = $true }
            }
            if ($hasLp) { $logicalProcessors = $lpSum }
        }
        catch { }

        # ---- CPU samples ----
        $samples = New-Object System.Collections.Generic.List[object]
        $okSamples = 0
        $cpuErrState = 'error'
        for ($i = 0; $i -lt $CpuSamples; $i++) {
            try {
                $c = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 15 -ErrorAction Stop |
                    Select-Object -First 1
                $pct = ConvertTo-FmpNullableDouble (Get-FmpValue $c 'PercentProcessorTime')
                if ($null -eq $pct -or $pct -lt 0 -or $pct -gt 100) { throw 'CPU counter unavailable or out of range.' }
                $okSamples++
                $samples.Add([ordered]@{ at = Get-FmpTimestamp; percent = [Math]::Round($pct, 1) })
            }
            catch {
                $cpuErrState = Resolve-FmpCollectorErrorState -ErrorRecord $_
                Add-FmpCollectorError -Ctx $ctx -Where 'performance.cpu' -Message $_.Exception.Message
                break
            }
            if ($i -lt ($CpuSamples - 1) -and $SampleIntervalSec -gt 0) { Start-Sleep -Seconds $SampleIntervalSec }
        }
        $avg = $null; $max = $null; $min = $null
        if ($okSamples -gt 0) {
            $vals = @($samples | ForEach-Object { $_.percent })
            $avg = [Math]::Round((($vals | Measure-Object -Average).Average), 1)
            $max = [Math]::Round(($vals | Measure-Object -Maximum).Maximum, 1)
            $min = [Math]::Round(($vals | Measure-Object -Minimum).Minimum, 1)
        }
        $ctx.data['cpu'] = [ordered]@{
            sampleCount       = $okSamples
            requestedSamples  = $CpuSamples
            intervalSec       = $SampleIntervalSec
            logicalProcessors = $logicalProcessors
            avgPercent        = $avg
            maxPercent        = $max
            minPercent        = $min
            samples           = $samples.ToArray()
        }
        Add-FmpLimitation -Ctx $ctx -Key 'cpu_short_window' -DetailText ('Sampling covers only ~' + ($CpuSamples * $SampleIntervalSec) + ' seconds; it cannot establish chronic behavior.') -Values @($CpuSamples * $SampleIntervalSec)
        if ($okSamples -eq $CpuSamples) { Add-FmpSubCheck -Ctx $ctx -Id 'performance.cpu' -State 'pass' }
        else { Add-FmpSubCheck -Ctx $ctx -Id 'performance.cpu' -State $cpuErrState }

        # ---- Top processes by RAM (instant) ----
        $topMem = New-Object System.Collections.Generic.List[object]
        try {
            $procs = @(Get-Process -ErrorAction Stop | Where-Object { $null -ne $_ })
            $memRows = New-Object System.Collections.Generic.List[object]
            foreach ($p in $procs) {
                try {
                    $ws = ConvertTo-FmpNullableDouble (Get-FmpValue $p 'WorkingSet64')
                    if ($null -eq $ws -or $ws -lt 0) { continue }
                    $memRows.Add([ordered]@{
                        name         = Get-FmpCleanString (Get-FmpValue $p 'ProcessName')
                        id           = ConvertTo-FmpNullableInt (Get-FmpValue $p 'Id')
                        workingSet   = $ws
                        workingSetMB = [Math]::Round($ws / 1MB, 1)
                    })
                }
                catch { continue }
            }
            foreach ($row in ($memRows | Sort-Object -Property { $_['workingSet'] } -Descending | Select-Object -First $TopProcesses)) {
                $topMem.Add([ordered]@{
                    name         = $row.name
                    id           = $row.id
                    workingSetMB = $row.workingSetMB
                })
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.topMemory' -State 'pass' -Detail @{ count = $topMem.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.topMemory' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'performance.topMemory' -Message $_.Exception.Message
        }
        $ctx.data['topProcessesByMemory'] = $topMem.ToArray()

        # ---- Most active processes during sampling (formatted counter, per-core scale) ----
        $topCpu = New-Object System.Collections.Generic.List[object]
        try {
            $pp = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $cpuRows = New-Object System.Collections.Generic.List[object]
            foreach ($p in $pp) {
                $pName = Get-FmpCleanString (Get-FmpValue $p 'Name')
                if ($null -eq $pName -or $pName -eq '_Total' -or $pName -eq 'Idle') { continue }
                $pPct = ConvertTo-FmpNullableDouble (Get-FmpValue $p 'PercentProcessorTime')
                if ($null -eq $pPct -or $pPct -lt 0) { continue }
                $norm = $null
                if ($null -ne $logicalProcessors -and $logicalProcessors -gt 0) {
                    $norm = [Math]::Round([Math]::Min(100, ($pPct / $logicalProcessors)), 1)
                }
                $cpuRows.Add([ordered]@{
                    name                 = $pName
                    idProcess            = ConvertTo-FmpNullableInt (Get-FmpValue $p 'IDProcess')
                    percentProcessorTime = [Math]::Round($pPct, 1)
                    normalizedPercent    = $norm
                })
            }
            foreach ($row in ($cpuRows | Sort-Object -Property { $_['percentProcessorTime'] } -Descending | Select-Object -First 10)) {
                $topCpu.Add($row)
            }
            Add-FmpLimitation -Ctx $ctx -Key 'proc_cpu_instant' -DetailText 'PercentProcessorTime is a per-core scaled instantaneous value and may exceed 100.'
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.topCpu' -State 'pass' -Detail @{ count = $topCpu.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            if ($st -eq 'error') { $st = 'unknown' }
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.topCpu' -State $st -Detail @{ reason = $_.Exception.Message }
        }
        $ctx.data['topProcessesByCpu'] = $topCpu.ToArray()

        # ---- Pagefile ----
        try {
            $pfs = @(Get-CimInstance -ClassName Win32_PageFileUsage -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            if ($pfs.Count -gt 0) {
                $allocSum = [double]0; $currSum = [double]0; $peakSum = [double]0
                $hasAlloc = $false; $hasCurr = $false; $hasPeak = $false
                foreach ($pfItem in $pfs) {
                    $a = ConvertTo-FmpNullableDouble (Get-FmpValue $pfItem 'AllocatedBaseSize')
                    $u = ConvertTo-FmpNullableDouble (Get-FmpValue $pfItem 'CurrentUsage')
                    $k = ConvertTo-FmpNullableDouble (Get-FmpValue $pfItem 'PeakUsage')
                    if ($null -ne $a -and $a -ge 0) { $allocSum += $a; $hasAlloc = $true }
                    if ($null -ne $u -and $u -ge 0) { $currSum += $u; $hasCurr = $true }
                    if ($null -ne $k -and $k -ge 0) { $peakSum += $k; $hasPeak = $true }
                }
                $pfName = Get-FmpCleanString (Get-FmpValue $pfs[0] 'Name')
                if ($pfs.Count -gt 1 -and $null -ne $pfName) { $pfName = $pfName + ' (+' + ($pfs.Count - 1) + ')' }
                $ctx.data['pagefile'] = [ordered]@{
                    name           = $pfName
                    allocatedMB    = $(if ($hasAlloc) { $allocSum } else { $null })
                    currentUsageMB = $(if ($hasCurr) { $currSum } else { $null })
                    peakUsageMB    = $(if ($hasPeak) { $peakSum } else { $null })
                }
                Add-FmpSubCheck -Ctx $ctx -Id 'performance.pagefile' -State $(if ($hasAlloc) { 'pass' } else { 'unknown' })
            }
            else {
                $ctx.data['pagefile'] = $null
                Add-FmpSubCheck -Ctx $ctx -Id 'performance.pagefile' -State 'unknown' -Detail @{ reason = 'no pagefile configured' }
            }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            if ($st -eq 'error') { $st = 'unknown' }
            Add-FmpSubCheck -Ctx $ctx -Id 'performance.pagefile' -State $st
        }

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'performance.cpu' -Summary ('CIM perf counters, ' + $okSamples + ' samples, ' + $SampleIntervalSec + 's interval') -Data $null
    }
}
