# =====================================================================
# FIX MY PC - Correlation.ps1
# Pure functions over collected data: which investigations a triage
# triggers, how WER, GPU, network and disk evidence answers the fixed
# questions, and the state of each hypothesis in the closed catalog.
# The same input always gives the same output. Nothing here reads the
# system, and no function states a cause: proximity stays proximity.
# =====================================================================

function Get-FmpDepthCategories {
    param([object]$Config, [string]$Depth)
    return @(Get-FmpValue $Config ('diagnosis.depths.' + $Depth + '.categories') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
}

function Get-FmpSvchostTargets {
    # svchost instances among the top consumers, with the resource that put them there.
    param([object]$D)
    $seen = [ordered]@{}
    foreach ($pair in @(@('topCpu', 'cpu'), @('topCommit', 'commit'), @('topIo', 'io'))) {
        foreach ($p in @(Get-FmpValue $D ('observation.processes.' + $pair[0]))) {
            if ($null -eq $p) { continue }
            if (([string](Get-FmpValue $p 'name') -replace '#\d+$', '') -ine 'svchost') { continue }
            $n = ConvertTo-FmpNullableInt (Get-FmpValue $p 'pid')
            if ($null -eq $n) { continue }
            $k = [string]$n
            if (-not $seen.Contains($k)) { $seen[$k] = @{ pid = $n; metric = $pair[1] } }
            elseif (([string]$seen[$k]['metric']).Split(',') -notcontains $pair[1]) { $seen[$k]['metric'] = [string]$seen[$k]['metric'] + ',' + $pair[1] }
        }
    }
    return @($seen.Values)
}

function Get-FmpPeakFamilies {
    # Families whose triage answer was only a partial signal, at most two, in a fixed order.
    param([object]$Facts)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@('cpu_load', 'cpu'), @('memory_pressure', 'memory'), @('storage_slow', 'disk'))) {
        if ($out.Count -lt 2 -and [string]$Facts['answers'][$pair[0]] -eq 'partial') { $out.Add($pair[1]) }
    }
    return $out.ToArray()
}

function Get-FmpTriggerFacts {
    param([object]$Diagnostic, [object]$Diagnosis, [string]$Symptom)
    $answers = @{}
    foreach ($q in @(Get-FmpValue $Diagnosis 'questions')) {
        if ($null -ne $q) { $answers[[string](Get-FmpValue $q 'id')] = [string](Get-FmpValue $q 'answer') }
    }
    $families = @{}
    foreach ($e in @(Get-FmpValue $Diagnostic 'events.catalog.entries')) {
        if ($null -eq $e) { continue }
        $f = [string](Get-FmpValue $e 'family')
        $n = ConvertTo-FmpNullableInt (Get-FmpValue $e 'count')
        if ($null -eq $n) { $n = 0 }
        if (-not $families.ContainsKey($f)) { $families[$f] = 0 }
        $families[$f] += $n
    }
    $top = @{}
    foreach ($list in @('topCpu', 'topCommit', 'topIo')) {
        foreach ($p in @(Get-FmpValue $Diagnostic ('observation.processes.' + $list))) {
            if ($null -ne $p) { $top[([string](Get-FmpValue $p 'name') -replace '#\d+$', '')] = $true }
        }
    }
    return @{ symptom = $Symptom; answers = $answers; families = $families; topNames = $top }
}

function Test-FmpInvestigationTrigger {
    # Closed vocabulary: and, or, symptom, question + answers, eventFamily, topProcess. No expressions, at most two nested levels.
    param([object]$Trigger, [hashtable]$Facts, [int]$Nesting = 0)
    if ($null -eq $Trigger -or $Nesting -gt 2) { return $false }
    $all = @(Get-FmpValue $Trigger 'and' | Where-Object { $null -ne $_ })
    if ($all.Count -gt 0) {
        foreach ($t in $all) { if (-not (Test-FmpInvestigationTrigger $t $Facts ($Nesting + 1))) { return $false } }
        return $true
    }
    $any = @(Get-FmpValue $Trigger 'or' | Where-Object { $null -ne $_ })
    if ($any.Count -gt 0) {
        foreach ($t in $any) { if (Test-FmpInvestigationTrigger $t $Facts ($Nesting + 1)) { return $true } }
        return $false
    }
    $symptoms = @(Get-FmpValue $Trigger 'symptom' | Where-Object { $null -ne $_ })
    if ($symptoms.Count -gt 0) { return ([string]$Facts['symptom'] -cin $symptoms) }
    $question = Get-FmpValue $Trigger 'question'
    if ($null -ne $question) { return ([string]$Facts['answers'][[string]$question] -cin @(Get-FmpValue $Trigger 'answers')) }
    $family = Get-FmpValue $Trigger 'eventFamily'
    if ($null -ne $family) { return ([int]$Facts['families'][[string]$family] -gt 0) }
    $process = Get-FmpValue $Trigger 'topProcess'
    if ($null -ne $process) { return $Facts['topNames'].ContainsKey([string]$process) }
    return $false
}

function Select-FmpInvestigations {
    # Deterministic: catalog order, one decision per id. An id that already had its decision is never chosen again.
    param([object]$Config, [hashtable]$Facts, [string]$Depth, [int]$Level, [string[]]$Done = @())
    $allowed = @(Get-FmpDepthCategories $Config $Depth)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($inv in @(Get-FmpValue $Config 'diagnosis.investigations')) {
        if ($null -eq $inv) { continue }
        $id = [string](Get-FmpValue $inv 'id')
        if ([int](Get-FmpValue $inv 'level') -ne $Level -or $id -cin $Done) { continue }
        $category = [string](Get-FmpValue $inv 'category')
        $decision = 'run'
        if ($category -cnotin $allowed) { $decision = 'not_authorized' }
        elseif (-not (Test-FmpInvestigationTrigger (Get-FmpValue $inv 'trigger') $Facts)) { $decision = 'not_triggered' }
        $out.Add([ordered]@{ id = $id; level = $Level; category = $category; hypotheses = @(Get-FmpValue $inv 'hypotheses' | ForEach-Object { [string]$_ }); budgetMs = [long](Get-FmpValue $inv 'budgetMs' -Default 5000); decision = $decision })
    }
    return $out.ToArray()
}

function Get-FmpDiskEventMap {
    # \Device\HarddiskN against today's disks. A number is only stable within one boot, so older events are flagged.
    param([object]$D)
    $known = @{}
    foreach ($k in @(Get-FmpValue $D 'system.disks')) {
        if ($null -eq $k) { continue }
        $n = ConvertTo-FmpNullableInt (Get-FmpValue $k 'diskNumber')
        if ($null -ne $n) { $known[$n] = $k }
    }
    $boot = Get-FmpParsedDate (Get-FmpValue $D 'system.os.lastBootAt')
    $byNumber = @{}
    foreach ($e in @(Get-FmpValue $D 'events.catalog.entries')) {
        if ($null -eq $e -or [string](Get-FmpValue $e 'provider') -cne 'disk') { continue }
        foreach ($o in @(Get-FmpValue $e 'occurrences')) {
            if ($null -eq $o) { continue }
            $n = ConvertTo-FmpNullableInt (Get-FmpValue $o 'diskNumber')
            $at = Get-FmpParsedDate (Get-FmpValue $o 'at')
            if ($null -eq $n -or $null -eq $at) { continue }
            $utc = $at.ToUniversalTime()
            if (-not $byNumber.ContainsKey($n)) { $byNumber[$n] = @{ events = 0; sinceBoot = 0; last = $utc } }
            $byNumber[$n]['events']++
            if ($null -ne $boot -and $utc -ge $boot.ToUniversalTime()) { $byNumber[$n]['sinceBoot']++ }
            if ($utc -gt $byNumber[$n]['last']) { $byNumber[$n]['last'] = $utc }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($byNumber.Keys | Sort-Object)) {
        $present = $known.ContainsKey($n)
        $mapping = 'device_absent'
        if ($present) { $mapping = 'earlier_boot'; if ($byNumber[$n]['sinceBoot'] -gt 0) { $mapping = 'current_boot' } }
        $iface = $null; $size = $null
        if ($present) {
            $iface = Get-FmpValue $known[$n] 'interfaceType'
            $bytes = ConvertTo-FmpNullableDouble (Get-FmpValue $known[$n] 'sizeBytes')
            if ($null -ne $bytes) { $size = [Math]::Round($bytes / 1GB, 0) }
        }
        $rows.Add([ordered]@{ diskNumber = [int]$n; present = $present; mapping = $mapping; interfaceType = $iface; sizeGB = $size
            events = $byNumber[$n]['events']; eventsSinceBoot = $byNumber[$n]['sinceBoot']
            lastSeen = $byNumber[$n]['last'].ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) })
    }
    return $rows.ToArray()
}

function Get-FmpDiagGraphicsTimeoutQuestion {
    # Driver record near a kernel video timeout report. The WER time is when the report was written: an upper bound.
    param([object]$D, [object]$Config)
    $wer = Get-FmpValue $D 'investigations.results.wer_events'
    $gpu = Get-FmpValue $D 'investigations.results.gpu_events'
    if ($null -eq $wer -and $null -eq $gpu) { return $null }
    $driver = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-FmpCatalogOccurrences $D @('nvlddmkm|153', 'Display|4101'))) { if ($null -ne $t) { $driver.Add($t) } }
    $vendors = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(Get-FmpValue $gpu 'providers')) {
        if ($null -eq $p -or [int](Get-FmpValue $p 'count' -Default 0) -lt 1) { continue }
        $v = [string](Get-FmpValue $p 'vendor')
        if (-not $vendors.Contains($v)) { $vendors.Add($v) }
        if ([string](Get-FmpValue $p 'provider') -ceq 'nvlddmkm') { continue }
        foreach ($s in @(Get-FmpValue $p 'times')) { $at = Get-FmpParsedDate $s; if ($null -ne $at) { $driver.Add($at.ToUniversalTime()) } }
    }
    $timeoutCodes = @(Get-FmpValue $Config 'diagnosis.codes.liveKernelTimeouts' | ForEach-Object { [string]$_ })
    $win = ConvertTo-FmpNullableDouble (Get-FmpValue $Config 'diagnosis.correlation.graphicsLiveKernelSec')
    if ($null -eq $win) { $win = 120 }
    $kernel = 0; $paired = 0; $closest = $null
    $days = @{}
    $codes = @{}
    foreach ($r in @(Get-FmpValue $wer 'summary.reportsList')) {
        if ($null -eq $r -or [string](Get-FmpValue $r 'kind') -cne 'live_kernel') { continue }
        $code = [string](Get-FmpValue $r 'code')
        if ($code -cnotin $timeoutCodes) { continue }
        $at = Get-FmpParsedDate (Get-FmpValue $r 'firstSeen')
        if ($null -eq $at) { continue }
        $utc = $at.ToUniversalTime()
        $kernel++
        $days[$utc.ToString('yyyy-MM-dd')] = $true
        $codes[$code] = $true
        $best = $null
        foreach ($t in $driver) { $dt = [Math]::Abs(($utc - $t).TotalSeconds); if ($null -eq $best -or $dt -lt $best) { $best = $dt } }
        if ($null -ne $best -and $best -le $win) {
            $paired++
            if ($null -eq $closest -or $best -lt $closest) { $closest = $best }
        }
    }
    $codeText = @($codes.Keys | Sort-Object | ForEach-Object { [string]$_ + ' (' + (Get-FmpValue $Config ('diagnosis.codes.liveKernel.' + $_)) + ')' }) -join ', '
    $vals = [ordered]@{ driverEvents = [string]$driver.Count; liveKernel = [string]$kernel; paired = [string]$paired; days = [string]$days.Count
        closestSec = $(if ($null -ne $closest) { [string][Math]::Round($closest, 0) } else { '-' }); codes = $codeText; vendors = ($vendors.ToArray() -join ', '); windowSec = [string]$win }
    $lims = @('diag.lim.graphics_not_hardware', 'diag.lim.wer_time_upper')
    $alts = @('diag.alt.driver', 'diag.alt.graphics_app')
    $werState = [string](Get-FmpValue $wer 'state')
    $werOk = $werState -in @('ok', 'empty')
    if (-not $werOk) {
        if ($driver.Count -gt 0) { return New-FmpDiagQuestion -Id 'graphics_timeout' -Area 'graphics' -Answer 'partial' -Confidence 'low' -Source 'investigations.gpu_events' -Window 'history' -Values $vals -Limitations (@('diag.lim.wer_unavailable') + $lims) -Alternatives $alts }
        $a = 'unknown'
        if ($werState -in @('access_denied', 'unsupported', 'error')) { $a = $werState }
        return New-FmpDiagQuestion -Id 'graphics_timeout' -Area 'graphics' -Answer $a -Confidence 'low' -Source 'investigations.wer_events' -Window 'none' -Values ([ordered]@{})
    }
    $answer = 'no'
    if ($paired -gt 0 -or $days.Count -ge 2) { $answer = 'yes' }
    elseif ($kernel -gt 0 -or $driver.Count -gt 0) { $answer = 'partial' }
    $conf = 'medium'
    if ((Get-FmpValue $wer 'truncated') -eq $true) { $conf = 'low'; $lims = @('diag.lim.wer_truncated') + $lims }
    return New-FmpDiagQuestion -Id 'graphics_timeout' -Area 'graphics' -Answer $answer -Confidence $conf -Source 'investigations.wer_events' -Window 'history' -Values $vals -Limitations $lims -Alternatives $alts
}

function Get-FmpDiagWerQuestion {
    param([object]$D)
    $wer = Get-FmpValue $D 'investigations.results.wer_events'
    if ($null -eq $wer) { return $null }
    $state = [string](Get-FmpValue $wer 'state')
    if ($state -notin @('ok', 'empty')) {
        if ($state -notin @('access_denied', 'unsupported', 'error')) { $state = 'unknown' }
        return New-FmpDiagQuestion -Id 'wer_failures' -Area 'stability' -Answer $state -Confidence 'low' -Source 'investigations.wer_events' -Window 'none' -Values ([ordered]@{})
    }
    $s = Get-FmpValue $wer 'summary'
    $reports = [int](Get-FmpValue $s 'reports' -Default 0)
    $newRecent = [int](Get-FmpValue $s 'newRecent' -Default 0)
    $vals = [ordered]@{
        reports = [string]$reports; records = [string](Get-FmpValue $s 'records' -Default 0); resends = [string](Get-FmpValue $s 'resendRecords' -Default 0)
        newRecent = [string]$newRecent; resendRecent = [string](Get-FmpValue $s 'resendRecent' -Default 0); indeterminate = [string](Get-FmpValue $s 'indeterminateRecent' -Default 0)
        recentHours = [string](Get-FmpValue $s 'recentHours' -Default 48)
        appCrash = [string](Get-FmpValue $s 'byKind.app_crash.reports' -Default 0); appHang = [string](Get-FmpValue $s 'byKind.app_hang.reports' -Default 0)
        liveKernel = [string](Get-FmpValue $s 'byKind.live_kernel.reports' -Default 0); blueScreen = [string](Get-FmpValue $s 'byKind.blue_screen.reports' -Default 0)
    }
    $lims = @('diag.lim.wer_time_upper', 'diag.lim.history_not_current')
    $conf = 'medium'
    if ((Get-FmpValue $wer 'truncated') -eq $true) { $conf = 'low'; $lims = @('diag.lim.wer_truncated') + $lims }
    if ([int](Get-FmpValue $s 'unidentified' -Default 0) -gt 0) { $lims += 'diag.lim.wer_unidentified' }
    $answer = 'no'
    if ($newRecent -gt 0) { $answer = 'yes' } elseif ($reports -gt 0) { $answer = 'partial' }
    elseif ((Get-FmpValue $wer 'truncated') -eq $true) { $answer = 'unknown' }
    return New-FmpDiagQuestion -Id 'wer_failures' -Area 'stability' -Answer $answer -Confidence $conf -Source 'investigations.wer_events' -Window 'history' -Values $vals -Limitations $lims
}

function Get-FmpDiagPortsCurrentQuestion {
    param([object]$D)
    $net = Get-FmpValue $D 'investigations.results.net_ports'
    if ($null -eq $net) { return $null }
    $state = [string](Get-FmpValue $net 'state')
    if ($state -ne 'ok' -or $null -eq (Get-FmpValue $net 'usagePct')) {
        if ($state -notin @('access_denied', 'unsupported', 'error')) { $state = 'unknown' }
        return New-FmpDiagQuestion -Id 'ports_current' -Area 'network' -Answer $state -Confidence 'low' -Source 'investigations.net_ports' -Window 'none' -Values ([ordered]@{}) -Limitations @('diag.lim.ports_owner_history')
    }
    $samples = @(Get-FmpValue $net 'samples' | Where-Object { $null -ne $_ })
    $inUse = $null
    if ($samples.Count -gt 0) { $inUse = Get-FmpValue $samples[$samples.Count - 1] 'inUse' }
    $owners =@(Get-FmpValue $net 'topOwners' | Where-Object { $null -ne $_ } | Select-Object -First 3 | ForEach-Object {
        $ownerName = [string](Get-FmpValue $_ 'name')
        if ($ownerName -eq '') { $ownerName = 'PID ' + (Get-FmpValue $_ 'pid') }
        $ownerName + ' (' + (Get-FmpValue $_ 'connections') + ')'
    }) -join ', '
    $trend = [string](Get-FmpValue $net 'trend')
    $vals = [ordered]@{ usagePct = (Get-FmpValue $net 'usagePct'); inUse = [string]$inUse; rangeSize = [string](Get-FmpValue $net 'rangeSize'); trendKey = $trend; trend = $trend; owners = $owners }
    $risk = [string](Get-FmpValue $net 'risk')
    $answer = 'no'
    if ($risk -eq 'high') { $answer = 'yes' } elseif ($risk -eq 'elevated') { $answer = 'partial' }
    $lims = @('diag.lim.ports_approximate', 'diag.lim.ports_owner_history', 'diag.lim.window_only')
    if ((Get-FmpValue $net 'rangeVaries') -eq $true) { $lims += 'diag.lim.ports_range_varies' }
    return New-FmpDiagQuestion -Id 'ports_current' -Area 'network' -Answer $answer -Confidence 'medium' -Source 'investigations.net_ports' -Window 'snapshot' -Values $vals -Limitations $lims -Alternatives @('diag.alt.port_heavy_app')
}

function Get-FmpDiagStorageDeviceQuestion {
    param([object]$D, [object[]]$Map = @())
    if ($Map.Count -eq 0) { return $null }
    $current = @($Map | Where-Object { $_['mapping'] -eq 'current_boot' })
    $text = @($Map | Select-Object -First 4 | ForEach-Object { '#' + $_['diskNumber'] + ' (' + $_['events'] + 'x)' }) -join ', '
    $vals = [ordered]@{ disks = $text; currentBoot = [string]$current.Count; absent = [string]@($Map | Where-Object { $_['mapping'] -eq 'device_absent' }).Count; earlier = [string]@($Map | Where-Object { $_['mapping'] -eq 'earlier_boot' }).Count }
    $answer = 'partial'
    if ($current.Count -gt 0) { $answer = 'yes' }
    return New-FmpDiagQuestion -Id 'storage_device' -Area 'storage_history' -Answer $answer -Confidence 'medium' -Source 'events.catalog+system.disks' -Window 'history' -Values $vals -Limitations @('diag.lim.disk_number_boot', 'diag.lim.storage_signal_not_failure')
}

function Get-FmpDiagInvestigationQuestions {
    param([object]$D, [object]$Config, [object[]]$Map = @())
    foreach ($q in @((Get-FmpDiagGraphicsTimeoutQuestion $D $Config), (Get-FmpDiagWerQuestion $D), (Get-FmpDiagPortsCurrentQuestion $D), (Get-FmpDiagStorageDeviceQuestion $D $Map))) {
        if ($null -ne $q) { Write-Output $q }
    }
}

function Add-FmpDiagInvestigationSupport {
    # Complementary evidence goes to questions that already found something, and never changes their answer.
    param([object[]]$Questions, [object]$D, [object[]]$Map = @())
    $byId = @{}
    foreach ($q in $Questions) { $byId[[string]$q['id']] = $q }
    $hosts =@(Get-FmpValue $D 'investigations.results.service_hosts.hosts' | Where-Object { $null -ne $_ })
    if ($hosts.Count -gt 0) {
        $text = @($hosts | Select-Object -First 3 | ForEach-Object { 'PID ' + (Get-FmpValue $_ 'pid') + ': ' + (@(Get-FmpValue $_ 'services' | Select-Object -First 5) -join ', ') }) -join '; '
        foreach ($id in @('cpu_load', 'process_commit', 'process_io')) {
            if ($byId.ContainsKey($id) -and [string]$byId[$id]['answer'] -in @('yes', 'partial')) { Add-FmpDiagSupport -Question $byId[$id] -Key 'diag.sup.service_hosts' -Values ([ordered]@{ hosts = $text }) }
        }
    }
    $adapters = @(Get-FmpValue $D 'investigations.results.gpu_use.adapters' | Where-Object { $null -ne $_ })
    if ($adapters.Count -gt 0) {
        $text = @($adapters | Select-Object -First 2 | ForEach-Object {
            $eng = @(Get-FmpValue $_ 'engines' | Where-Object { $null -ne $_ } | Select-Object -First 1)
            $part = 'GPU ' + (Get-FmpValue $_ 'adapter')
            if ($eng.Count -gt 0) { $part += ': ' + (Get-FmpValue $eng[0] 'type') + ' ' + (Get-FmpValue $eng[0] 'avgPct') + '%' }
            if ($null -ne (Get-FmpValue $_ 'dedicatedUsedMB')) { $part += ', VRAM ' + (Get-FmpValue $_ 'dedicatedUsedMB') + ' MB' }
            $part
        }) -join '; '
        foreach ($id in @('graphics_timeout', 'graphics_events')) {
            if ($byId.ContainsKey($id) -and [string]$byId[$id]['answer'] -in @('yes', 'partial')) { Add-FmpDiagSupport -Question $byId[$id] -Key 'diag.sup.gpu_use' -Values ([ordered]@{ gpu = $text }) }
        }
    }
    if ($byId.ContainsKey('storage_signals') -and [string]$byId['storage_signals']['answer'] -in @('yes', 'partial')) {
        if ($Map.Count -gt 0) {
            $text = @($Map | Select-Object -First 4 | ForEach-Object { '#' + $_['diskNumber'] + ' (' + $_['events'] + 'x)' }) -join ', '
            Add-FmpDiagSupport -Question $byId['storage_signals'] -Key 'diag.sup.storage_device' -Values ([ordered]@{ disks = $text })
        }
        $rel = @(Get-FmpValue $D 'investigations.results.storage_reliability.disks' | Where-Object { $null -ne $_ })
        if ($rel.Count -gt 0) {
            $text = @($rel | Select-Object -First 4 | ForEach-Object { '#' + (Get-FmpValue $_ 'diskNumber') + ': ' + (Get-FmpValue $_ 'readErrorsTotal') + '/' + (Get-FmpValue $_ 'writeErrorsTotal') }) -join ', '
            Add-FmpDiagSupport -Question $byId['storage_signals'] -Key 'diag.sup.storage_reliability' -Values ([ordered]@{ disks = $text })
        }
    }
    $confirm = Get-FmpValue $D 'investigations.results.confirm_peak.families'
    foreach ($pair in @(@('cpu', 'cpu_load'), @('memory', 'memory_pressure'), @('disk', 'storage_slow'))) {
        $verdict = [string](Get-FmpValue $confirm $pair[0])
        if ($verdict -in @('sustained', 'recurring', 'isolated') -and $byId.ContainsKey($pair[1])) { Add-FmpDiagSupport -Question $byId[$pair[1]] -Key ('diag.sup.confirm_' + $verdict) -Values ([ordered]@{}) }
    }
}

function Get-FmpSignalResult {
    # yes | partial | no | unknown | absent (the question was not asked in this audit), plus its confidence.
    param([object]$Signal, [hashtable]$ById, [object]$Confirm)
    $confirmFamily = Get-FmpValue $Signal 'confirm'
    if ($null -ne $confirmFamily) {
        $v = [string](Get-FmpValue $Confirm ([string]$confirmFamily))
        switch ($v) {
            'sustained' { return @{ result = 'yes'; confidence = 'medium'; id = 'confirm_peak' } }
            'recurring' { return @{ result = 'partial'; confidence = 'medium'; id = 'confirm_peak' } }
            'isolated' { return @{ result = 'no'; confidence = 'medium'; id = 'confirm_peak' } }
        }
        return @{ result = 'absent'; confidence = 'low'; id = 'confirm_peak' }
    }
    $id = [string](Get-FmpValue $Signal 'question')
    if (-not $ById.ContainsKey($id)) { return @{ result = 'absent'; confidence = 'low'; id = $id } }
    $q = $ById[$id]
    $answer = [string]$q['answer']
    $conf = [string]$q['confidence']
    $above = Get-FmpValue $Signal 'valueAbove'
    if ($null -ne $above -and $answer -in @('yes', 'partial', 'no')) {
        $value = ConvertTo-FmpNullableDouble (Get-FmpValue $q ('values.' + [string](Get-FmpValue $above 'key')))
        if ($null -eq $value) { return @{ result = 'unknown'; confidence = 'low'; id = $id } }
        if ($value -gt [double](Get-FmpValue $above 'min' -Default 0)) { return @{ result = 'yes'; confidence = $conf; id = $id } }
        return @{ result = 'no'; confidence = $conf; id = $id }
    }
    if ($answer -in @('yes', 'partial', 'no')) { return @{ result = $answer; confidence = $conf; id = $id } }
    return @{ result = 'unknown'; confidence = 'low'; id = $id }
}

function Get-FmpHypotheses {
    # supported: direct evidence. not_supported: the sources answered against it. inconclusive: data that does not
    # discriminate. untested: nothing could be checked. "Not supported" is never reported as "ruled out".
    param([object[]]$Questions, [object]$Config, [object]$Investigations)
    $byId = @{}
    foreach ($q in $Questions) { $byId[[string]$q['id']] = $q }
    $confirm = Get-FmpValue $Investigations 'results.confirm_peak.families'
    $rank = @{ low = 1; medium = 2; high = 3 }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($h in @(Get-FmpValue $Config 'diagnosis.hypotheses')) {
        if ($null -eq $h) { continue }
        $evidence = New-Object System.Collections.Generic.List[string]
        $missing = New-Object System.Collections.Generic.List[string]
        $yes = 0; $partial = 0; $no = 0; $unknown = 0
        $bestYes = 'low'; $worstNo = 'high'
        foreach ($sig in @(Get-FmpValue $h 'signals')) {
            if ($null -eq $sig) { continue }
            $r = Get-FmpSignalResult $sig $byId $confirm
            switch ([string]$r['result']) {
                'yes' { $yes++; if ($rank[[string]$r['confidence']] -gt $rank[$bestYes]) { $bestYes = [string]$r['confidence'] } }
                'partial' { $partial++ }
                'no' { $no++; if ($rank[[string]$r['confidence']] -lt $rank[$worstNo]) { $worstNo = [string]$r['confidence'] } }
                'unknown' { $unknown++ }
            }
            if ($r['result'] -in @('yes', 'partial', 'no')) { if (-not $evidence.Contains([string]$r['id'])) { $evidence.Add([string]$r['id']) } }
            elseif (-not $missing.Contains([string]$r['id'])) { $missing.Add([string]$r['id']) }
        }
        $state = 'untested'; $conf = 'low'
        if ($yes -gt 0) { $state = 'supported'; $conf = $bestYes }
        elseif ($partial -gt 0) { $state = 'inconclusive' }
        elseif ($no -gt 0 -and $unknown -eq 0) { $state = 'not_supported'; $conf = $worstNo }
        elseif ($no -gt 0) { $state = 'inconclusive' }
        $out.Add([ordered]@{ id = [string](Get-FmpValue $h 'id'); state = $state; confidence = $conf; evidence = $evidence.ToArray(); missing = $missing.ToArray() })
    }
    return $out.ToArray()
}
