# =====================================================================
# FIX MY PC - Investigations.ps1 (collector, Full audit only)
# Closed catalog of complementary read-only investigations. Which ones
# run is decided by Select-FmpInvestigations (Correlation.ps1) from the
# triage; dispatch is a switch over fixed ids. Nothing here repairs,
# elevates, reaches the network or runs anything the AI suggests.
# Never kept: addresses, ports of connections, command lines, paths,
# WER buckets, modules, attached files or event messages.
# =====================================================================

function ConvertFrom-FmpWerEventXml {
    # Pure. WER 1001 may carry named or unnamed <Data>; unnamed values are read by template position only after a shape check.
    param([string]$Xml)
    $out = @{ ok = $false; kind = 'other'; code = $null; reportId = $null }
    if ([string]::IsNullOrEmpty($Xml)) { return $out }
    $named = ConvertFrom-FmpEventXmlData -Xml $Xml -MaxFields 40
    $eventName = $null; $p1 = $null; $report = $null
    if ($named.Contains('EventName')) {
        $eventName = Get-FmpCleanString $named['EventName']
        $p1 = Get-FmpCleanString $named['P1']
        $report = Get-FmpCleanString $named['ReportId']
    }
    else {
        $vals = New-Object System.Collections.Generic.List[string]
        $rest = $Xml
        while ($vals.Count -lt 30 -and $rest -match '<Data(?:\s[^>]*?)?(?:/>|>([^<]*)</Data>)([\s\S]*)$') {
            $vals.Add([string]$Matches[1])
            $rest = [string]$Matches[2]
        }
        # Template: 2 EventName, 5 P1, 19 ReportId. Another layout is reported as unidentified, never guessed.
        if ($vals.Count -lt 21 -or $vals[19] -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { return $out }
        $eventName = Get-FmpCleanString $vals[2]
        $p1 = Get-FmpCleanString $vals[5]
        $report = Get-FmpCleanString $vals[19]
    }
    if ($null -eq $eventName) { return $out }
    $out['ok'] = $true
    if ($eventName -cmatch '^(APPCRASH|BEX|BEX64|MoAppCrash)$') { $out['kind'] = 'app_crash' }
    elseif ($eventName -cmatch '^(AppHang|MoAppHang)') { $out['kind'] = 'app_hang' }
    elseif ($eventName -ceq 'LiveKernelEvent') { $out['kind'] = 'live_kernel' }
    elseif ($eventName -ceq 'BlueScreen') { $out['kind'] = 'blue_screen' }
    # Only kernel codes are kept: P1 of an application report is the program name. WER may mask values as aaaa...
    if ($out['kind'] -in @('live_kernel', 'blue_screen') -and $null -ne $p1 -and $p1 -match '^(0x)?[0-9a-fA-F]{1,8}$' -and $p1 -notmatch '^a+$') {
        $out['code'] = (($p1 -replace '^0x', '') -replace '^0+', '')
    }
    if ($null -ne $report -and $report -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -and $report -notmatch '^[0-]+$') { $out['reportId'] = $report }
    return $out
}

function Get-FmpWerSummary {
    # Pure. One failure = one ReportId. Later records of the same id are re-sends, not new failures. When the read was
    # truncated an older record may exist, so a report first seen recently is "indeterminate" instead of "new".
    param([object[]]$Records = @(), [object]$NowUtc, [double]$RecentHours = 48, [bool]$Truncated = $false, [int]$MaxItems = 40)
    $recentCut = (Get-FmpParsedDate $NowUtc).ToUniversalTime().AddDays(-$RecentHours / 24)
    $byRef = @{}
    $total = 0; $unidentified = 0
    foreach ($r in $Records) {
        $at = Get-FmpParsedDate $r['at']
        if ($null -eq $at) { continue }
        $utc = $at.ToUniversalTime()
        $total++
        $ref = [string]$r['ref']
        if ($ref -eq '') { $unidentified++; continue }
        if (-not $byRef.ContainsKey($ref)) { $byRef[$ref] = @{ ref = $ref; kind = [string]$r['kind']; code = $r['code']; records = 0; first = $utc; last = $utc } }
        $byRef[$ref]['records']++
        if ($utc -lt $byRef[$ref]['first']) { $byRef[$ref]['first'] = $utc }
        if ($utc -gt $byRef[$ref]['last']) { $byRef[$ref]['last'] = $utc }
    }
    $items = New-Object System.Collections.Generic.List[object]
    $byKind = [ordered]@{}
    $newRecent = 0; $resendRecent = 0; $indeterminate = 0; $resendRecords = 0
    foreach ($g in $byRef.Values) {
        $class = 'old'
        if ($g['last'] -ge $recentCut) {
            if ($g['first'] -lt $recentCut) { $class = 'resend'; $resendRecent++ }
            elseif ($Truncated) { $class = 'indeterminate'; $indeterminate++ }
            else { $class = 'new'; $newRecent++ }
        }
        $resendRecords += ($g['records'] - 1)
        $k = [string]$g['kind']
        if (-not $byKind.Contains($k)) { $byKind[$k] = [ordered]@{ reports = 0; records = 0; newRecent = 0 } }
        $byKind[$k]['reports']++
        $byKind[$k]['records'] += $g['records']
        if ($class -eq 'new') { $byKind[$k]['newRecent']++ }
        $items.Add([ordered]@{
            ref = $g['ref']; kind = $k; code = $g['code']; records = $g['records']; classification = $class
            firstSeen = $g['first'].ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            lastSeen = $g['last'].ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        })
    }
    # Kernel reports first: they are the ones correlated with graphics events, and the list is capped.
    $sorted = @($items.ToArray() | Sort-Object -Property @{ Expression = { if ($_['kind'] -in @('live_kernel', 'blue_screen')) { 0 } else { 1 } } }, @{ Expression = { $_['lastSeen'] }; Descending = $true }, @{ Expression = { $_['ref'] } })
    return [ordered]@{
        records = $total; reports = $byRef.Count; unidentified = $unidentified; resendRecords = $resendRecords
        newRecent = $newRecent; resendRecent = $resendRecent; indeterminateRecent = $indeterminate
        recentHours = $RecentHours; readTruncated = $Truncated; byKind = $byKind
        reportsList = @($sorted | Select-Object -First $MaxItems)
    }
}

function Get-FmpWerEvents {
    param([datetime]$Since, [object]$NowUtc, [int]$MaxEvents = 500, [long]$BudgetMs = 10000)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; summary = $null }
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $Since } -MaxEvents $MaxEvents -ErrorAction Stop | Where-Object { $null -ne $_ })
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $rec['summary'] = Get-FmpWerSummary -Records @() -NowUtc $NowUtc; return $rec }
        if ($_.FullyQualifiedErrorId -like 'NoMatchingProvidersFound*') { $rec['state'] = 'unsupported'; return $rec }
        $rec['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_
        return $rec
    }
    $cut = ($events.Count -ge $MaxEvents)
    $parsed = New-Object System.Collections.Generic.List[object]
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($e in $events) {
        if ($sw.ElapsedMilliseconds -gt $BudgetMs) { $cut = $true; break }
        $w = ConvertFrom-FmpWerEventXml ([string]$e.ToXml())
        $ref = ''
        if ($null -ne $w['reportId']) { $ref = Get-FmpShortRef $w['reportId'] }
        $parsed.Add(@{ at = (Get-FmpValue $e 'TimeCreated'); kind = [string]$w['kind']; code = $w['code']; ref = $ref })
    }
    $rec['truncated'] = $cut
    $rec['summary'] = Get-FmpWerSummary -Records $parsed.ToArray() -NowUtc $NowUtc -Truncated $cut
    if ($parsed.Count -gt 0) { $rec['state'] = 'ok' }
    return $rec
}

function Get-FmpGpuVendorEvents {
    # Warnings and errors of the graphics driver providers. A provider this PC does not have is recorded, not an error.
    # AMD and Intel provider names come from public references and still need validation on real hardware.
    param([datetime]$Since, [int]$MaxPerProvider = 100)
    $rows = New-Object System.Collections.Generic.List[object]
    $failed = New-Object System.Collections.Generic.List[string]
    $absent = 0; $checked = 0
    foreach ($prov in @('nvlddmkm', 'amdkmdag', 'amdkmdap', 'atikmdag', 'igfx', 'igfxn')) {
        $checked++
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $prov; Level = @(1, 2, 3); StartTime = $Since } -MaxEvents $MaxPerProvider -ErrorAction Stop | Where-Object { $null -ne $_ })
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingProvidersFound*') { $absent++; continue }
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $failed.Add((Resolve-FmpCollectorErrorState -ErrorRecord $_)); continue }
        }
        $vendor = 'nvidia'
        if ($prov -like 'igfx*') { $vendor = 'intel' } elseif ($prov -ne 'nvlddmkm') { $vendor = 'amd' }
        $ids = @{}
        $times = New-Object System.Collections.Generic.List[string]
        foreach ($e in $events) {
            $id = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Id')
            if ($null -ne $id) { if (-not $ids.ContainsKey($id)) { $ids[$id] = 0 }; $ids[$id]++ }
            $at = Get-FmpParsedDate (Get-FmpValue $e 'TimeCreated')
            if ($null -ne $at -and $times.Count -lt 30) { $times.Add($at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)) }
        }
        $idRows = @($ids.Keys | Sort-Object | Select-Object -First 8 | ForEach-Object { [ordered]@{ eventId = [int]$_; count = $ids[$_] } })
        $rows.Add([ordered]@{ provider = $prov; vendor = $vendor; count = $events.Count; truncated = ($events.Count -ge $MaxPerProvider); ids = $idRows; times = $times.ToArray() })
    }
    $state = 'empty'
    if (@($rows.ToArray() | Where-Object { $_['count'] -gt 0 }).Count -gt 0) { $state = 'ok' }
    elseif ($failed.Count -gt 0 -and ($failed.Count + $absent) -eq $checked) { $state = $failed[0] }
    return [ordered]@{ state = $state; truncated = (@($rows.ToArray() | Where-Object { $_['truncated'] }).Count -gt 0); absentProviders = $absent; providers = $rows.ToArray() }
}

function Get-FmpTcpStateName {
    # MSFT_NetTCPConnection.State. A value outside this list is counted as "other".
    param([object]$Code)
    switch ([string]$Code) {
        '1' { return 'closed' } '2' { return 'listen' } '3' { return 'syn_sent' } '4' { return 'syn_received' }
        '5' { return 'established' } '6' { return 'fin_wait1' } '7' { return 'fin_wait2' } '8' { return 'close_wait' }
        '9' { return 'closing' } '10' { return 'last_ack' } '11' { return 'time_wait' } '12' { return 'delete_tcb' }
        '100' { return 'bound' }
    }
    return 'other'
}

function Get-FmpPortTrend {
    # Pure. A few readings seconds apart can suggest a direction; they cannot predict exhaustion.
    param([double[]]$Totals, [double]$RangeSize, [double]$HighPct = 80, [double]$ElevatedPct = 50, [double]$RisingMinPct = 1)
    $out = [ordered]@{ usagePct = $null; growthPctOfRange = $null; trend = 'unknown'; risk = 'unknown' }
    if ($Totals.Count -lt 2 -or $RangeSize -le 0) { return $out }
    $last = $Totals[$Totals.Count - 1]
    $delta = $last - $Totals[0]
    $usage = [Math]::Round(100 * $last / $RangeSize, 1)
    $growth = [Math]::Round(100 * $delta / $RangeSize, 2)
    $up = $true; $down = $true
    for ($i = 1; $i -lt $Totals.Count; $i++) {
        if ($Totals[$i] -lt $Totals[$i - 1]) { $up = $false }
        if ($Totals[$i] -gt $Totals[$i - 1]) { $down = $false }
    }
    $trend = 'stable'
    if ($up -and $growth -ge $RisingMinPct) { $trend = 'rising' } elseif ($down -and $growth -le (-$RisingMinPct)) { $trend = 'falling' }
    $risk = 'normal'
    if ($usage -ge $HighPct) { $risk = 'high' } elseif ($usage -ge $ElevatedPct -or ($trend -eq 'rising' -and $usage -ge ($ElevatedPct / 2))) { $risk = 'elevated' }
    $out['usagePct'] = $usage; $out['growthPctOfRange'] = $growth; $out['trend'] = $trend; $out['risk'] = $risk
    return $out
}

function Get-FmpNetPortData {
    # Counts only: state and owning process. Addresses and ports are never requested (the scanner enforces the property list).
    param([int]$Samples = 3, [int]$IntervalSec = 5, [int]$TopOwners = 5, [double]$HighPct = 80, [double]$ElevatedPct = 50)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; rangeStart = $null; rangeSize = $null; rangeVaries = $false; udpRangeSize = $null
        samples = @(); byState = [ordered]@{}; udpEndpoints = $null; topOwners = @(); usagePct = $null; growthPctOfRange = $null; trend = 'unknown'; risk = 'unknown' }
    try {
        $sizes = New-Object System.Collections.Generic.List[object]
        foreach ($s in @(Get-CimInstance -Namespace 'root\StandardCimv2' -ClassName MSFT_NetTCPSetting -Property SettingName, DynamicPortRangeStartPort, DynamicPortRangeNumberOfPorts -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
            $n = ConvertTo-FmpNullableInt (Get-FmpValue $s 'DynamicPortRangeNumberOfPorts')
            $st = ConvertTo-FmpNullableInt (Get-FmpValue $s 'DynamicPortRangeStartPort')
            if ($null -ne $n -and $n -gt 0) { $sizes.Add(@{ n = $n; start = $st }) }
        }
        if ($sizes.Count -gt 0) {
            # Profiles can differ and the profile of each connection is not read, so the smallest range is the safe reference.
            $small = @($sizes.ToArray() | Sort-Object -Property { $_['n'] })[0]
            $rec['rangeSize'] = $small['n']; $rec['rangeStart'] = $small['start']
            $rec['rangeVaries'] = (@($sizes.ToArray() | ForEach-Object { $_['n'] } | Sort-Object -Unique).Count -gt 1)
        }
        foreach ($u in @(Get-CimInstance -Namespace 'root\StandardCimv2' -ClassName MSFT_NetUDPSetting -Property DynamicPortRangeStartPort, DynamicPortRangeNumberOfPorts -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First 1)) {
            $rec['udpRangeSize'] = ConvertTo-FmpNullableInt (Get-FmpValue $u 'DynamicPortRangeNumberOfPorts')
        }
        $sampleRows = New-Object System.Collections.Generic.List[object]
        $totals = New-Object System.Collections.Generic.List[object]
        $lastByPid = @{}
        $lastStates = [ordered]@{}
        for ($i = 0; $i -lt $Samples; $i++) {
            $byPid = @{}
            $states = [ordered]@{}
            $inUse = 0; $all = 0
            foreach ($c in @(Get-CimInstance -Namespace 'root\StandardCimv2' -ClassName MSFT_NetTCPConnection -Property State, OwningProcess -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
                $all++
                $name = Get-FmpTcpStateName (Get-FmpValue $c 'State')
                if (-not $states.Contains($name)) { $states[$name] = 0 }
                $states[$name]++
                # A listening or merely bound socket does not consume one ephemeral port per connection.
                if ($name -in @('listen', 'bound')) { continue }
                $inUse++
                $owner = ConvertTo-FmpNullableInt (Get-FmpValue $c 'OwningProcess')
                if ($null -ne $owner) { if (-not $byPid.ContainsKey($owner)) { $byPid[$owner] = 0 }; $byPid[$owner]++ }
            }
            $sampleRows.Add([ordered]@{ total = $all; inUse = $inUse; timeWait = $(if ($states.Contains('time_wait')) { $states['time_wait'] } else { 0 }) })
            $totals.Add([double]$inUse)
            $lastByPid = $byPid
            $lastStates = $states
            if ($i -lt ($Samples - 1)) { Start-Sleep -Seconds $IntervalSec }
        }
        $rec['samples'] = $sampleRows.ToArray()
        $rec['byState'] = $lastStates
        $rec['udpEndpoints'] = @(Get-CimInstance -Namespace 'root\StandardCimv2' -ClassName MSFT_NetUDPEndpoint -Property OwningProcess -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ }).Count
        $names = @{}
        try { foreach ($p in @(Get-Process -ErrorAction Stop | Where-Object { $null -ne $_ })) { $names[[int](Get-FmpValue $p 'Id')] = Get-FmpCleanString (Get-FmpValue $p 'ProcessName') } }
        catch { $names = @{} }
        $owners = New-Object System.Collections.Generic.List[object]
        foreach ($ownerPid in @($lastByPid.Keys)) { $owners.Add([ordered]@{ pid = [int]$ownerPid; name = $names[[int]$ownerPid]; connections = $lastByPid[$ownerPid] }) }
        $rec['topOwners'] = @($owners.ToArray() | Sort-Object -Property @{ Expression = { $_['connections'] }; Descending = $true }, @{ Expression = { $_['pid'] } } | Select-Object -First $TopOwners)
        if ($null -ne $rec['rangeSize']) {
            $t = Get-FmpPortTrend -Totals ([double[]]$totals.ToArray()) -RangeSize ([double]$rec['rangeSize']) -HighPct $HighPct -ElevatedPct $ElevatedPct
            $rec['usagePct'] = $t['usagePct']; $rec['growthPctOfRange'] = $t['growthPctOfRange']; $rec['trend'] = $t['trend']; $rec['risk'] = $t['risk']
        }
        $rec['state'] = 'ok'
    }
    catch { $rec['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
    return $rec
}

function Get-FmpServiceHostData {
    # Service names of the svchost PIDs among the top consumers. Load inside a shared host cannot be split per service.
    param([object[]]$Hosts = @(), [int]$MaxServices = 12)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; hosts = @() }
    try {
        $byPid = @{}
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter "State='Running'" -Property Name, ProcessId, State -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
            $svcPid = ConvertTo-FmpNullableInt (Get-FmpValue $s 'ProcessId')
            $svcName = Get-FmpCleanString (Get-FmpValue $s 'Name')
            if ($null -eq $svcPid -or $svcPid -le 0 -or $null -eq $svcName) { continue }
            if (-not $byPid.ContainsKey($svcPid)) { $byPid[$svcPid] = New-Object System.Collections.Generic.List[string] }
            $byPid[$svcPid].Add($svcName)
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($h in $Hosts) {
            $hostPid = ConvertTo-FmpNullableInt $h['pid']
            if ($null -eq $hostPid) { continue }
            $names = @()
            if ($byPid.ContainsKey($hostPid)) { $names = [string[]]@($byPid[$hostPid].ToArray() | Sort-Object) }
            $rows.Add([ordered]@{ pid = $hostPid; serviceCount = $names.Count; shared = ($names.Count -gt 1); services = @($names | Select-Object -First $MaxServices); metric = $h['metric'] })
        }
        $rec['hosts'] = $rows.ToArray()
        if ($rows.Count -gt 0) { $rec['state'] = 'ok' }
    }
    catch { $rec['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
    return $rec
}

function ConvertFrom-FmpGpuEngineName {
    # Pure. pid_<n>_luid_<a>_<b>_phys_<p>_eng_<e>_engtype_<type>. The LUID identifies this session's adapter and stays in memory.
    param([string]$Name)
    if ($Name -notmatch '^pid_(\d+)_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.*)$') { return $null }
    # Read the groups first: the next -match replaces $Matches.
    $out = @{ pid = [int]$Matches[1]; adapter = ([string]$Matches[2] + '|' + $Matches[3]); engine = [int]$Matches[4]; type = [string]$Matches[5] }
    if ($out['type'] -notmatch '^[A-Za-z0-9_ ]{1,40}$') { $out['type'] = 'other' }
    return $out
}

function Get-FmpGpuIntervalUsage {
    # Pure. UtilizationPercentage is a PERF_100NSEC_TIMER: busy time delta over Timestamp_Sys100NS delta.
    param([hashtable]$Prev, [object[]]$Curr)
    $engines = @{}
    $procs = @{}
    foreach ($row in $Curr) {
        $n = [string](Get-FmpValue $row 'Name')
        if (-not $Prev.ContainsKey($n)) { continue }
        $info = ConvertFrom-FmpGpuEngineName $n
        if ($null -eq $info) { continue }
        $busy = Get-FmpRawDelta $Prev[$n] $row 'UtilizationPercentage'
        $time = Get-FmpRawDelta $Prev[$n] $row 'Timestamp_Sys100NS'
        if ($null -eq $busy -or $null -eq $time -or $time -le 0) { continue }
        $pct = 100 * $busy / $time
        $key = [string]$info['adapter'] + '|' + $info['engine'] + '|' + $info['type']
        if (-not $engines.ContainsKey($key)) { $engines[$key] = [double]0 }
        $engines[$key] += $pct
        $perProc = ([string]$info['pid'] + '|' + $key)
        if (-not $procs.ContainsKey($perProc)) { $procs[$perProc] = [double]0 }
        $procs[$perProc] += $pct
    }
    return @{ engines = $engines; procs = $procs }
}

function Get-FmpGpuUseData {
    # Engine load and adapter memory in use. Temperature, power and clocks have no vendor-neutral read-only source here.
    param([int]$Samples = 3, [int]$IntervalSec = 2, [int]$MaxInstances = 4000, [int]$TopProcesses = 5)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; adapters = @(); topProcesses = @(); intervals = 0 }
    try {
        $prev = @{}
        $typeStats = @{}
        $procSum = @{}
        $intervals = 0
        for ($i = 0; $i -lt $Samples; $i++) {
            $rows = @(Get-CimInstance -ClassName Win32_PerfRawData_GPUPerformanceCounters_GPUEngine -Property Name, UtilizationPercentage, Timestamp_Sys100NS -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First $MaxInstances)
            if ($rows.Count -ge $MaxInstances) { $rec['truncated'] = $true }
            if ($i -gt 0) {
                $u = Get-FmpGpuIntervalUsage -Prev $prev -Curr $rows
                $intervals++
                $perType = @{}
                foreach ($k in @($u['engines'].Keys)) {
                    $parts = ([string]$k).Split('|')
                    $tk = $parts[0] + '|' + $parts[1] + '|' + $parts[3]
                    $v = [Math]::Min(100, [double]$u['engines'][$k])
                    if (-not $perType.ContainsKey($tk) -or $v -gt $perType[$tk]) { $perType[$tk] = $v }
                }
                foreach ($tk in @($perType.Keys)) {
                    if (-not $typeStats.ContainsKey($tk)) { $typeStats[$tk] = @{ sum = [double]0; max = [double]0; n = 0 } }
                    $typeStats[$tk]['sum'] += $perType[$tk]
                    $typeStats[$tk]['n']++
                    if ($perType[$tk] -gt $typeStats[$tk]['max']) { $typeStats[$tk]['max'] = $perType[$tk] }
                }
                $procMax = @{}
                foreach ($k in @($u['procs'].Keys)) {
                    $pidText = ([string]$k).Split('|')[0]
                    if (-not $procMax.ContainsKey($pidText) -or $u['procs'][$k] -gt $procMax[$pidText]) { $procMax[$pidText] = [double]$u['procs'][$k] }
                }
                foreach ($pidText in @($procMax.Keys)) {
                    if (-not $procSum.ContainsKey($pidText)) { $procSum[$pidText] = [double]0 }
                    $procSum[$pidText] += $procMax[$pidText]
                }
            }
            $prev = @{}
            foreach ($r in $rows) { $prev[[string](Get-FmpValue $r 'Name')] = $r }
            if ($i -lt ($Samples - 1)) { Start-Sleep -Seconds $IntervalSec }
        }
        $rec['intervals'] = $intervals
        $memory = @{}
        foreach ($m in @(Get-CimInstance -ClassName Win32_PerfRawData_GPUPerformanceCounters_GPUAdapterMemory -Property Name, DedicatedUsage, SharedUsage -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })) {
            $mn = [string](Get-FmpValue $m 'Name')
            if ($mn -notmatch '^luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_(\d+)') { continue }
            $memory[[string]$Matches[1] + '|' + $Matches[2]] = @{ dedicated = (ConvertTo-FmpNullableDouble (Get-FmpValue $m 'DedicatedUsage')); shared = (ConvertTo-FmpNullableDouble (Get-FmpValue $m 'SharedUsage')) }
        }
        $keys = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($memory.Keys)) { if (-not $keys.Contains([string]$k)) { $keys.Add([string]$k) } }
        foreach ($k in @($typeStats.Keys)) {
            $parts = ([string]$k).Split('|')
            $ak = $parts[0] + '|' + $parts[1]
            if (-not $keys.Contains($ak)) { $keys.Add($ak) }
        }
        $adapters = New-Object System.Collections.Generic.List[object]
        $ordinal = 0
        foreach ($ak in @($keys.ToArray() | Sort-Object)) {
            $engRows = New-Object System.Collections.Generic.List[object]
            foreach ($k in @($typeStats.Keys)) {
                $parts = ([string]$k).Split('|')
                if (($parts[0] + '|' + $parts[1]) -cne $ak) { continue }
                $engRows.Add([ordered]@{ type = $parts[2]; avgPct = [Math]::Round($typeStats[$k]['sum'] / $typeStats[$k]['n'], 1); maxPct = [Math]::Round($typeStats[$k]['max'], 1) })
            }
            $dedicated = $null; $shared = $null
            if ($memory.ContainsKey($ak)) {
                if ($null -ne $memory[$ak]['dedicated']) { $dedicated = [Math]::Round($memory[$ak]['dedicated'] / 1MB, 0) }
                if ($null -ne $memory[$ak]['shared']) { $shared = [Math]::Round($memory[$ak]['shared'] / 1MB, 0) }
            }
            $adapters.Add([ordered]@{ adapter = $ordinal; dedicatedUsedMB = $dedicated; sharedUsedMB = $shared; engines = @($engRows.ToArray() | Sort-Object -Property @{ Expression = { $_['maxPct'] }; Descending = $true }, @{ Expression = { $_['type'] } }) })
            $ordinal++
        }
        $rec['adapters'] = $adapters.ToArray()
        if ($intervals -gt 0 -and $procSum.Count -gt 0) {
            $names = @{}
            try { foreach ($p in @(Get-Process -ErrorAction Stop | Where-Object { $null -ne $_ })) { $names[[string](Get-FmpValue $p 'Id')] = Get-FmpCleanString (Get-FmpValue $p 'ProcessName') } }
            catch { $names = @{} }
            $top = New-Object System.Collections.Generic.List[object]
            foreach ($pidText in @($procSum.Keys)) { $top.Add([ordered]@{ pid = [int]$pidText; name = $names[$pidText]; avgPct = [Math]::Round($procSum[$pidText] / $intervals, 1) }) }
            $rec['topProcesses'] = @($top.ToArray() | Where-Object { $_['avgPct'] -gt 0 } | Sort-Object -Property @{ Expression = { $_['avgPct'] }; Descending = $true }, @{ Expression = { $_['pid'] } } | Select-Object -First $TopProcesses)
        }
        if ($adapters.Count -gt 0) { $rec['state'] = 'ok' }
    }
    catch { $rec['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
    return $rec
}

function Get-FmpConfirmVerdict {
    # Pure. Second short window for a peak seen in triage: did it hold, come back, or not repeat?
    param([object]$Count, [object]$Avg, [object]$Max, [object]$HighShare, [double]$High, [double]$SustainedShare = 0.5)
    $n = ConvertTo-FmpNullableDouble $Count
    if ($null -eq $n -or $n -lt 2) { return 'unknown' }
    $a = ConvertTo-FmpNullableDouble $Avg
    $m = ConvertTo-FmpNullableDouble $Max
    $s = ConvertTo-FmpNullableDouble $HighShare
    if (($null -ne $a -and $a -ge $High) -or ($null -ne $s -and $s -ge $SustainedShare)) { return 'sustained' }
    if ($null -ne $m -and $m -ge $High) { return 'recurring' }
    if ($null -eq $m) { return 'unknown' }
    return 'isolated'
}

function Get-FmpConfirmPeakData {
    param([string[]]$Families, [object]$Config)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; windowSec = 30; families = [ordered]@{} }
    $cpuHigh = [double](Get-FmpValue $Config 'diagnosis.thresholds.cpuHighPct' -Default 85)
    $share = [double](Get-FmpValue $Config 'diagnosis.thresholds.cpuSustainedShare' -Default 0.5)
    $pagesHigh = [double](Get-FmpValue $Config 'diagnosis.thresholds.pagesInputHighPerSec' -Default 100)
    $latHigh = [double](Get-FmpValue $Config 'diagnosis.thresholds.diskLatencyHighMs' -Default 50)
    $m = Get-FmpObservationData -DurationSec 30 -IntervalSec 2 -MaxSamples 16 -CpuHighPct $cpuHigh -Families $Families
    $data = Get-FmpValue $m 'data'
    $rec['truncated'] = ((Get-FmpValue $data 'truncated') -eq $true)
    if ('cpu' -in $Families) {
        $c = Get-FmpValue $data 'cpu.stats'
        $rec['families']['cpu'] = Get-FmpConfirmVerdict (Get-FmpValue $c 'count') (Get-FmpValue $c 'avg') (Get-FmpValue $c 'max') (Get-FmpValue $c 'highShare') $cpuHigh $share
    }
    if ('memory' -in $Families) {
        $series = @(Get-FmpValue $data 'memory.series' | Where-Object { $null -ne $_ } | ForEach-Object { $_['pagesInputPerSec'] })
        $p = Get-FmpSeriesStats -Values $series -High $pagesHigh
        $rec['families']['memory'] = Get-FmpConfirmVerdict $p['count'] $p['avg'] $p['max'] $p['highShare'] $pagesHigh $share
    }
    if ('disk' -in $Families) {
        $best = 'unknown'
        $rank = @{ unknown = 0; isolated = 1; recurring = 2; sustained = 3 }
        foreach ($d in @(Get-FmpValue $data 'disks.items' | Where-Object { $null -ne $_ })) {
            foreach ($metric in @('readLatencyMs', 'writeLatencyMs')) {
                $st = Get-FmpValue $d $metric
                $v = Get-FmpConfirmVerdict (Get-FmpValue $st 'count') (Get-FmpValue $st 'avg') (Get-FmpValue $st 'max') $null $latHigh $share
                if ($rank[$v] -gt $rank[$best]) { $best = $v }
            }
        }
        $rec['families']['disk'] = $best
    }
    if (@($rec['families'].Values | Where-Object { $_ -ne 'unknown' }).Count -gt 0) { $rec['state'] = 'ok' }
    return $rec
}

function Get-FmpStorageReliabilityData {
    # Usually needs administrator rights. Denied access is reported and never elevated. The counters carry no dates.
    param([int]$MaxDisks = 8)
    $rec = [ordered]@{ state = 'empty'; truncated = $false; disks = @() }
    try {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($pd in @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First $MaxDisks)) {
            $r = @(Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First 1)
            if ($r.Count -eq 0) { continue }
            $rows.Add([ordered]@{
                diskNumber = ConvertTo-FmpNullableInt (Get-FmpValue $pd 'DeviceId')
                temperatureC = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'Temperature')
                temperatureMaxC = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'TemperatureMax')
                readErrorsTotal = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'ReadErrorsTotal')
                writeErrorsTotal = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'WriteErrorsTotal')
                readLatencyMaxMs = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'ReadLatencyMax')
                writeLatencyMaxMs = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'WriteLatencyMax')
                wearPct = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'Wear')
                powerOnHours = ConvertTo-FmpNullableDouble (Get-FmpValue $r[0] 'PowerOnHours')
            })
        }
        $rec['disks'] = $rows.ToArray()
        if ($rows.Count -gt 0) { $rec['state'] = 'ok' }
    }
    catch { $rec['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
    return $rec
}

function Invoke-FmpInvestigation {
    # Fixed dispatch: an id outside this switch cannot run anything.
    param([string]$Id, [object]$Diagnostic, [object]$Config, [string]$Depth, [object]$Facts, [long]$BudgetMs)
    $days = 30
    if ($Depth -ceq 'deep') { $days = 60 }
    $since = (Get-Date).AddDays(-$days)
    switch -Exact ($Id) {
        'gpu_events' { return Get-FmpGpuVendorEvents -Since $since }
        'wer_events' {
            $max = 500
            if ($Depth -ceq 'deep') { $max = 1500 }
            return Get-FmpWerEvents -Since $since -NowUtc ([DateTime]::UtcNow) -MaxEvents $max -BudgetMs $BudgetMs
        }
        'net_ports' { return Get-FmpNetPortData -HighPct ([double](Get-FmpValue $Config 'diagnosis.thresholds.portUsageHighPct' -Default 80)) -ElevatedPct ([double](Get-FmpValue $Config 'diagnosis.thresholds.portUsageElevatedPct' -Default 50)) }
        'service_hosts' { return Get-FmpServiceHostData -Hosts @(Get-FmpSvchostTargets $Diagnostic) }
        'gpu_use' { return Get-FmpGpuUseData }
        'storage_reliability' { return Get-FmpStorageReliabilityData }
        'confirm_peak' { return Get-FmpConfirmPeakData -Families @(Get-FmpPeakFamilies $Facts) -Config $Config }
    }
    return [ordered]@{ state = 'unsupported'; truncated = $false }
}

function Invoke-FmpInvestigationPlan {
    # Two levels at most. Stops on: no trigger, category not approved, budget, source failure (never retried) or run limit.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Diagnostic, [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][object]$RuleConfig, [string]$Symptom = 'general', [string]$DuringProblem = 'unknown', [string]$Depth = 'standard'
    )
    if ($Depth -cnotin @('standard', 'deep')) { $Depth = 'standard' }
    $hardMs = [long](Get-FmpValue $RuleConfig 'diagnosis.budgets.hardMs' -Default 180000)
    $budgetMs = [long](Get-FmpValue $RuleConfig ('diagnosis.budgets.' + $Depth + 'Ms') -Default 45000)
    if ($budgetMs -gt $hardMs) { $budgetMs = $hardMs }
    $maxRuns = [int](Get-FmpValue $RuleConfig 'diagnosis.budgets.maxInvestigations' -Default 10)
    $maxLevel = [int](Get-FmpValue $RuleConfig 'diagnosis.budgets.maxLevel' -Default 2)
    if ($maxLevel -gt 2) { $maxLevel = 2 }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $results = [ordered]@{}
    $runs = New-Object System.Collections.Generic.List[object]
    $done = New-Object System.Collections.Generic.List[string]
    $executed = 0
    $exceeded = $false
    $doc = [ordered]@{ version = '1'; depth = $Depth; categories = @(Get-FmpDepthCategories $RuleConfig $Depth); budgetMs = $budgetMs; elapsedMs = 0; budgetExceeded = $false; runs = @(); results = $results }
    $Diagnostic['investigations'] = $doc
    for ($level = 1; $level -le $maxLevel; $level++) {
        $dx = Get-FmpDiagnosis -Diagnostic $Diagnostic -Analysis $Analysis -RuleConfig $RuleConfig -Symptom $Symptom -DuringProblem $DuringProblem
        $facts = Get-FmpTriggerFacts -Diagnostic $Diagnostic -Diagnosis $dx -Symptom $Symptom
        foreach ($spec in @(Select-FmpInvestigations -Config $RuleConfig -Facts $facts -Depth $Depth -Level $level -Done $done.ToArray())) {
            $id = [string]$spec['id']
            $done.Add($id)
            $run = [ordered]@{ id = $id; level = $level; category = $spec['category']; hypotheses = $spec['hypotheses']; state = [string]$spec['decision']; elapsedMs = 0; truncated = $false }
            if ($spec['decision'] -eq 'run') {
                if ($executed -ge $maxRuns) { $run['state'] = 'limit' }
                elseif (($sw.ElapsedMilliseconds + [long]$spec['budgetMs']) -gt $budgetMs) { $run['state'] = 'budget'; $exceeded = $true }
                else {
                    $executed++
                    $itemSw = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        $out = Invoke-FmpInvestigation -Id $id -Diagnostic $Diagnostic -Config $RuleConfig -Depth $Depth -Facts $facts -BudgetMs ([long]$spec['budgetMs'])
                        $results[$id] = $out
                        $run['state'] = [string](Get-FmpValue $out 'state')
                        $run['truncated'] = ((Get-FmpValue $out 'truncated') -eq $true)
                    }
                    # The error text can hold local details, so only its classified state is kept.
                    catch { $run['state'] = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
                    $itemSw.Stop()
                    $run['elapsedMs'] = $itemSw.ElapsedMilliseconds
                }
            }
            $runs.Add($run)
        }
    }
    $sw.Stop()
    $doc['runs'] = $runs.ToArray()
    $doc['elapsedMs'] = $sw.ElapsedMilliseconds
    $doc['budgetExceeded'] = $exceeded
    return $doc
}
