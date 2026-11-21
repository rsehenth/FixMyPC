# =====================================================================
# FIX MY PC - Rules.ps1
#
# Deterministic, conservative rule evaluation over the diagnostic JSON.
# Each rule maps to a named evaluator invoked through an explicit switch
# (no dynamic dispatch - keeps the read-only scan meaningful).
#
# Evaluators return:
#   State      pass | finding | unknown | unsupported | access_denied |
#              not_collected | error
#   Measured   the values that were compared against the threshold
#   Values     values interpolated into the localized finding text
#   Limitations why a conclusion may be weak (never silently dropped)
#   SeverityOverride / PenaltyOverride  only when the evidence supports
#              a different tier than the default (documented per rule)
# Unknown/absent data NEVER produces a finding or a penalty.
# =====================================================================

# Stable localization keys for the canonical (English) limitation texts.
# The JSON keeps the canonical text unchanged; limitationKeys is added in
# parallel so the report can render it in the user's language.
$script:FmpRuleLimitationKeys = @{
    'CPU sampling not collected' = 'lim.cpu_not_collected'
    'Defender status unavailable (product may be absent or replaced)' = 'lim.defender_unavailable'
    'OS edition unavailable' = 'lim.os_edition_unavailable'
    'SMART data not collected' = 'lim.smart_not_collected'
    'SMART unavailable: health cannot be confirmed nor denied from this data' = 'lim.smart_unavailable'
    'Windows display version (e.g. 22H2) unavailable; support state cannot be determined locally' = 'lim.display_version_unavailable'
    'a long list is not a fault by itself; review only if boot time matters to you' = 'lim.startup_long_list'
    'a missing signature is common in legitimate tools; it is NOT evidence of malware' = 'lim.unsigned_not_malware'
    'build not present in the built-in lifecycle snapshot; no conclusion drawn' = 'lim.build_not_in_snapshot'
    'built-in lifecycle table missing' = 'lim.lifecycle_table_missing'
    'commit data not collected' = 'lim.commit_not_collected'
    'date from the built-in lifecycle snapshot (rules.json); it may be outdated - confirm with Microsoft lifecycle pages' = 'lim.lifecycle_snapshot_date'
    'edition outside the built-in Home/Pro lifecycle snapshot' = 'lim.edition_outside_snapshot'
    'evaluator returned nothing' = 'lim.evaluator_empty'
    'free space percentage unavailable for the system volume' = 'lim.free_pct_unavailable'
    'health status missing or inconclusive for one or more disks or volumes' = 'lim.health_inconclusive'
    'historical crash; current fault not established' = 'lim.historical_crash'
    'historical event; current hardware fault not established' = 'lim.historical_hw_event'
    'memory data not collected' = 'lim.memory_not_collected'
    'no SMART predictors exposed' = 'lim.smart_no_predictors'
    'no evaluator registered for this rule' = 'lim.no_evaluator'
    'no hotfix with a date was found' = 'lim.no_dated_hotfix'
    'no offline signature result available' = 'lim.no_offline_signature'
    'no volume data collected' = 'lim.no_volume_data'
    'runs only in full mode' = 'lim.full_mode_only'
    'short sampling window; verify during normal use' = 'lim.short_sampling_window'
    'single point-in-time reading' = 'lim.point_in_time'
    'single point-in-time reading; it cannot establish chronic pressure' = 'lim.point_in_time_not_chronic'
    'startup inventory empty or not collected' = 'lim.startup_inventory_empty'
    'startup inventory incomplete' = 'lim.startup_inventory_incomplete'
    'system volume not identified' = 'lim.system_volume_unknown'
    'third-party registration does not confirm active protection' = 'lim.third_party_not_active'
    'too few valid CPU samples' = 'lim.too_few_cpu_samples'
    'uptime unavailable' = 'lim.uptime_unavailable'
}

function Get-FmpRuleLimitationKeys {
    # Parallel key list; an unregistered text maps to '' (renderer falls back to the text).
    param([object[]]$Limitations)
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($t in $Limitations) {
        $k = ''
        if ($null -ne $t -and $script:FmpRuleLimitationKeys.ContainsKey([string]$t)) { $k = $script:FmpRuleLimitationKeys[[string]$t] }
        $keys.Add($k)
    }
    return ,$keys.ToArray()
}

function Get-FmpRuleConfig {
    param([Parameter(Mandatory)][string]$Root)
    $res = Read-FmpJsonFile -Path (Join-Path (Join-Path $Root 'rules') 'rules.json')
    if (-not $res.Ok) { throw "rules.json could not be loaded: $($res.Error)" }
    return $res.Data
}

function Get-FmpHoursBetween {
    param([object]$FromIso, [object]$ToIso)
    $a = Get-FmpParsedDate -Value $FromIso
    $b = Get-FmpParsedDate -Value $ToIso
    if ($null -eq $a -or $null -eq $b) { return $null }
    return ($b.ToUniversalTime() - $a.ToUniversalTime()).TotalHours
}

function Get-FmpRuleNumber {
    param([object]$Value, [double]$Min = 0, [double]$Max = 1.7976931348623157E+308)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string]) { return }
    $number = [double]0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Any,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number) -and
        $number -ge $Min -and $number -le $Max) { return $number }
}

function Get-FmpEvidenceState {
    param([string]$Status)
    if ($Status -in @('error', 'access_denied', 'unsupported', 'not_collected')) { return $Status }
    return 'unknown'
}

function Get-FmpBaseEventGroups {
    param([object]$D)
    foreach ($log in @('System', 'Application')) {
        if ((Get-FmpValue $D ('events.logs.' + $log + '.status')) -ne 'ok') { continue }
        foreach ($g in @(Get-FmpValue $D ('events.logs.' + $log + '.groups'))) {
            Write-Output ([ordered]@{ log = $log; group = $g })
        }
    }
}

function Get-FmpEventAbsenceState {
    param([object]$D, [switch]$SystemOnly)
    $logs = @('System', 'Application')
    if ($SystemOnly) { $logs = @('System') }
    $state = 'pass'
    foreach ($log in $logs) {
        $path = 'events.logs.' + $log
        $status = Get-FmpValue $D ($path + '.status')
        if ((Get-FmpValue $D ($path + '.truncated')) -eq $true) { $state = 'unknown' }
        if ($status -in @('access_denied', 'error')) { return $status }
        if ($status -notin @('ok', 'empty')) { $state = Get-FmpEvidenceState $status }
    }
    return $state
}

function Get-FmpRecentEventCount {
    param([object]$Group, [object]$Now, [double]$Hours, [switch]$Critical)
    $occurrences = @(Get-FmpValue $Group 'occurrences')
    if ($occurrences.Count -gt 0) {
        $count = 0
        foreach ($event in $occurrences) {
            if ($Critical -and (Get-FmpValue $event 'level') -ne 1) { continue }
            $age = Get-FmpHoursBetween (Get-FmpValue $event 'at') $Now
            if ($null -ne $age -and $age -ge 0 -and $age -le $Hours) { $count++ }
        }
        return $count
    }
    # Legacy groups can prove the full count only when the entire range is in-window.
    if ($Critical -and (Get-FmpValue $Group 'maxLevel') -ne 1) { return 0 }
    $last = Get-FmpHoursBetween (Get-FmpValue $Group 'lastSeen') $Now
    if ($null -eq $last -or $last -lt 0 -or $last -gt $Hours) { return 0 }
    $first = Get-FmpHoursBetween (Get-FmpValue $Group 'firstSeen') $Now
    $total = Get-FmpRuleNumber (Get-FmpValue $Group 'count') -Max 2000
    if ($null -eq $total -or $total -lt 1) { return 0 }
    if ($null -ne $first -and $first -ge $last -and $first -le $Hours) { return $total }
    return 1
}

# ---------------------------------------------------------------
# STORAGE
# ---------------------------------------------------------------
function Test-FmpRule_storage_low_free_space {
    param([object]$D, [object]$Rule, [object]$Config)
    $vols = Get-FmpValue -Data $D -Path 'storage.volumes'
    if ($null -eq $vols) { $vols = Get-FmpValue -Data $D -Path 'system.volumes' }
    if ($null -eq $vols -or @($vols).Count -eq 0) {
        return @{ State = 'unknown'; Limitations = @('no volume data collected') }
    }
    $sys = $null
    foreach ($v in @($vols)) { if (Get-FmpValue -Data $v -Path 'isSystem') { $sys = $v; break } }
    if ($null -eq $sys) { return @{ State = 'unknown'; Limitations = @('system volume not identified') } }
    $freePct = Get-FmpRuleNumber (Get-FmpValue $sys 'freePct') -Max 100
    if ($null -eq $freePct) {
        return @{ State = 'unknown'; Limitations = @('free space percentage unavailable for the system volume') }
    }
    $lowPct = [double](Get-FmpValue -Data $Rule -Path 'threshold.lowPct' -Default 10)
    $measured = [ordered]@{ drive = (Get-FmpValue -Data $sys -Path 'driveLetter'); freePct = $freePct }
    if ($freePct -lt $lowPct) {
        $measured['freeBytes'] = Get-FmpValue -Data $sys -Path 'freeBytes'
        $measured['sizeBytes'] = Get-FmpValue -Data $sys -Path 'sizeBytes'
        return @{ State = 'finding'; Measured = $measured; Values = @{ drive = $measured.drive; freePct = $freePct; lowPct = $lowPct } }
    }
    return @{ State = 'pass'; Measured = $measured }
}

function Test-FmpRule_storage_disk_space_critical {
    param([object]$D, [object]$Rule, [object]$Config)
    $vols = Get-FmpValue -Data $D -Path 'storage.volumes'
    if ($null -eq $vols) { $vols = Get-FmpValue -Data $D -Path 'system.volumes' }
    if ($null -eq $vols -or @($vols).Count -eq 0) {
        return @{ State = 'unknown'; Limitations = @('no volume data collected') }
    }
    $sys = $null
    foreach ($v in @($vols)) { if (Get-FmpValue -Data $v -Path 'isSystem') { $sys = $v; break } }
    if ($null -eq $sys) { return @{ State = 'unknown'; Limitations = @('system volume not identified') } }
    $freePct = Get-FmpRuleNumber (Get-FmpValue $sys 'freePct') -Max 100
    if ($null -eq $freePct) { return @{ State = 'unknown' } }
    $crit = [double](Get-FmpValue -Data $Rule -Path 'threshold.criticalPct' -Default 5)
    if ($freePct -lt $crit) {
        return @{ State = 'finding'; Values = @{ drive = (Get-FmpValue -Data $sys -Path 'driveLetter'); freePct = $freePct; criticalPct = $crit } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_storage_disk_health_unhealthy {
    param([object]$D, [object]$Rule, [object]$Config)
    $disks = @(Get-FmpValue $D 'storage.physicalDisks')
    $vols = @(Get-FmpValue $D 'storage.volumes')
    $inconclusive = $disks.Count -eq 0
    $unhealthy = $false
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($entry in @($disks) + @($vols)) {
        $health = Get-FmpValue $entry 'healthStatus'
        if ($health -eq 'Healthy') { continue }
        if ($health -in @('Warning', 'Unhealthy')) {
            if ($health -eq 'Unhealthy') { $unhealthy = $true }
            $name = Get-FmpValue $entry 'friendlyName' -Default (Get-FmpValue $entry 'driveLetter' -Default (Get-FmpValue $entry 'label' -Default 'volume'))
            $bad.Add(([string]$name + ' [' + $health + ']'))
        }
        else { $inconclusive = $true }
    }
    if ($bad.Count -gt 0) {
        # Only Windows' own 'Unhealthy' verdict is a proven critical failure; 'Warning' stays elevated.
        $res = @{ State = 'finding'; Values = @{ items = ($bad -join '; '); count = $bad.Count } }
        if ($unhealthy) { $res['Gate'] = 'critical' }
        return $res
    }
    if ($inconclusive) { return @{ State = 'unknown'; Limitations = @('health status missing or inconclusive for one or more disks or volumes') } }
    return @{ State = 'pass' }
}

function Test-FmpRule_storage_smart_predict_failure {
    param([object]$D, [object]$Rule, [object]$Config)
    $smart = Get-FmpValue -Data $D -Path 'storage.smart'
    if ($null -eq $smart) { return @{ State = 'unknown'; Limitations = @('SMART data not collected') } }
    $status = Get-FmpValue -Data $smart -Path 'status'
    if ($status -ne 'ok') {
        return @{ State = (Get-FmpEvidenceState $status); Limitations = @('SMART unavailable: health cannot be confirmed nor denied from this data') }
    }
    $items = Get-FmpValue -Data $smart -Path 'items'
    if ($null -eq $items -or @($items).Count -eq 0) {
        return @{ State = 'unknown'; Limitations = @('no SMART predictors exposed') }
    }
    $failed = New-Object System.Collections.Generic.List[string]
    $inconclusive = $false
    foreach ($i in @($items)) {
        $prediction = Get-FmpValue $i 'predictFailure'
        if ($prediction -isnot [bool] -or (Get-FmpValue $i 'active') -eq $false) { $inconclusive = $true; continue }
        if ($prediction) { $failed.Add([string](Get-FmpValue $i 'reason')) }
    }
    if ($failed.Count -gt 0) {
        # The drive's own firmware predicts failure: proven critical condition.
        return @{ State = 'finding'; Values = @{ count = $failed.Count }; Gate = 'critical' }
    }
    if ($inconclusive) { return @{ State = 'unknown' } }
    return @{ State = 'pass' }
}

function Test-FmpRule_storage_disk_event_errors {
    param([object]$D, [object]$Rule, [object]$Config)
    $recentHours = [double](Get-FmpValue $Rule 'threshold.recentHours' -Default 48)
    $now = Get-FmpValue $D 'run.finishedAt'
    if ($null -eq (Get-FmpParsedDate $now) -and (Get-FmpEventAbsenceState $D -SystemOnly) -eq 'pass') { return @{ State = 'unknown' } }
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        $g = $entry.group
        $provider = [string](Get-FmpValue $g 'provider')
        if ($entry.log -ne 'System' -or $provider -notmatch '^(?:Microsoft-Windows-)?(?:disk|ntfs|volmgr|storahci|stornvme|nvme|iastor[a-z]*|partmgr|volsnap|vhdmp|fsrec)$') { continue }
        $count = Get-FmpRecentEventCount $g $now $recentHours
        if ($count -gt 0) { $hits.Add(($provider + ' #' + (Get-FmpValue $g 'eventId') + ' x' + $count)) }
    }
    if ($hits.Count -gt 0) { return @{ State = 'finding'; Values = @{ items = ($hits -join '; '); recentHours = $recentHours } } }
    return @{ State = (Get-FmpEventAbsenceState $D -SystemOnly) }
}

function Test-FmpRule_events_critical_recurring {
    param([object]$D, [object]$Rule, [object]$Config)
    $minCount = [int](Get-FmpValue $Rule 'threshold.minCount' -Default 5)
    $recentHours = [double](Get-FmpValue $Rule 'threshold.recentHours' -Default 48)
    $now = Get-FmpValue $D 'run.finishedAt'
    $recent = $null
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        $g = $entry.group
        $count = Get-FmpRecentEventCount $g $now $recentHours -Critical
        if ($count -lt $minCount -or ($null -ne $recent -and $count -le $recent.count)) { continue }
        $recent = [ordered]@{ provider = (Get-FmpValue $g 'provider'); eventId = (Get-FmpValue $g 'eventId'); count = $count; log = $entry.log }
    }
    if ($null -ne $recent) { return @{ State = 'finding'; Values = $recent; Measured = $recent } }
    $state = Get-FmpEventAbsenceState $D
    if ($state -eq 'pass' -and $null -eq (Get-FmpParsedDate $now)) { $state = 'unknown' }
    return @{ State = $state }
}

function Test-FmpRule_events_error_concentration {
    param([object]$D, [object]$Rule, [object]$Config)
    $minCount = [int](Get-FmpValue $Rule 'threshold.minCount' -Default 30)
    $recentHours = [double](Get-FmpValue $Rule 'threshold.recentHours' -Default 48)
    $now = Get-FmpValue $D 'run.finishedAt'
    $best = $null
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        $g = $entry.group
        $count = Get-FmpRecentEventCount $g $now $recentHours
        if ($count -lt $minCount -or ($null -ne $best -and $count -le $best.count)) { continue }
        $best = [ordered]@{ provider = (Get-FmpValue $g 'provider'); eventId = (Get-FmpValue $g 'eventId'); count = $count }
    }
    if ($null -ne $best) { return @{ State = 'finding'; Values = $best } }
    $state = Get-FmpEventAbsenceState $D
    if ($state -eq 'pass' -and $null -eq (Get-FmpParsedDate $now)) { $state = 'unknown' }
    return @{ State = $state }
}

function Test-FmpRule_events_whea_hardware {
    param([object]$D, [object]$Rule, [object]$Config)
    $total = 0
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        if ($entry.log -eq 'System' -and (Get-FmpValue $entry.group 'provider') -match '^(Microsoft-Windows-)?WHEA-Logger$') {
            $total += Get-FmpRecentEventCount $entry.group (Get-FmpValue $D 'run.finishedAt') 168
        }
    }
    if ($total -gt 0) { return @{ State = 'finding'; Values = @{ count = $total }; Limitations = @('historical event; current hardware fault not established') } }
    return @{ State = (Get-FmpEventAbsenceState $D -SystemOnly) }
}

function Test-FmpRule_events_unexpected_shutdown {
    param([object]$D, [object]$Rule, [object]$Config)
    $power = 0
    $log = 0
    $now = Get-FmpValue $D 'run.finishedAt'
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        if ($entry.log -ne 'System') { continue }
        $provider = Get-FmpValue $entry.group 'provider'
        $eventId = Get-FmpValue $entry.group 'eventId'
        if ($provider -match '^(Microsoft-Windows-)?Kernel-Power$' -and $eventId -eq 41) {
            $power += Get-FmpRecentEventCount $entry.group $now 168
        }
        elseif ($provider -eq 'EventLog' -and $eventId -eq 6008) {
            $log += Get-FmpRecentEventCount $entry.group $now 168
        }
    }
    # Both providers can describe the same restart.
    $total = [Math]::Max($power, $log)
    $minCount = [int](Get-FmpValue $Rule 'threshold.minCount' -Default 2)
    if ($total -ge $minCount) { return @{ State = 'finding'; Values = @{ count = $total } } }
    if ($total -eq 1) { return @{ State = 'finding'; SeverityOverride = 'info'; PenaltyOverride = 0; Values = @{ count = $total } } }
    return @{ State = (Get-FmpEventAbsenceState $D -SystemOnly) }
}

function Test-FmpRule_events_bsod {
    param([object]$D, [object]$Rule, [object]$Config)
    $total = 0
    foreach ($entry in (Get-FmpBaseEventGroups $D)) {
        if ($entry.log -ne 'System' -or (Get-FmpValue $entry.group 'eventId') -ne 1001) { continue }
        if ((Get-FmpValue $entry.group 'provider') -match '^(BugCheck|Microsoft-Windows-WER-SystemErrorReporting)$') {
            $total = [Math]::Max($total, (Get-FmpRecentEventCount $entry.group (Get-FmpValue $D 'run.finishedAt') 168))
        }
    }
    if ($total -gt 0) { return @{ State = 'finding'; Values = @{ count = $total }; Limitations = @('historical crash; current fault not established') } }
    return @{ State = (Get-FmpEventAbsenceState $D -SystemOnly) }
}

# ---------------------------------------------------------------
# PERFORMANCE
# ---------------------------------------------------------------
function Test-FmpRule_perf_cpu_sustained_high {
    param([object]$D, [object]$Rule, [object]$Config)
    $cpu = Get-FmpValue -Data $D -Path 'performance.cpu'
    if ($null -eq $cpu) { return @{ State = 'unknown'; Limitations = @('CPU sampling not collected') } }
    $count = Get-FmpRuleNumber (Get-FmpValue $cpu 'sampleCount')
    $avg = Get-FmpRuleNumber (Get-FmpValue $cpu 'avgPercent') -Max 100
    $minSamples = [int](Get-FmpValue -Data $Rule -Path 'threshold.minSamples' -Default 3)
    $pct = [double](Get-FmpValue -Data $Rule -Path 'threshold.pctThreshold' -Default 90)
    if ($null -eq $avg -or $null -eq $count -or $count -lt $minSamples) { return @{ State = 'unknown'; Limitations = @('too few valid CPU samples') } }
    # FMP-07: the window is only a few seconds long, so a high average is an observation, never "sustained" load.
    $interval = Get-FmpRuleNumber (Get-FmpValue $cpu 'intervalSec')
    $windowSec = $null
    if ($null -ne $interval) { $windowSec = [double]($count - 1) * [double]$interval }
    if ($avg -ge $pct) {
        return @{
            State = 'finding'
            Values = @{ avg = $avg; max = (Get-FmpValue -Data $cpu -Path 'maxPercent'); samples = $count; windowSec = $windowSec }
            Limitations = @('short sampling window; verify during normal use')
        }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_perf_ram_pressure {
    param([object]$D, [object]$Rule, [object]$Config)
    $mem = Get-FmpValue -Data $D -Path 'performance.memory'
    if ($null -eq $mem) { $mem = Get-FmpValue -Data $D -Path 'system.memory' }
    if ($null -eq $mem) { return @{ State = 'unknown'; Limitations = @('memory data not collected') } }
    $pct = Get-FmpRuleNumber (Get-FmpValue $mem 'availablePct') -Max 100
    $total = Get-FmpRuleNumber (Get-FmpValue $mem 'totalBytes') -Min 1
    $free = Get-FmpRuleNumber (Get-FmpValue $mem 'freeBytes')
    if ($null -eq $pct -or $null -eq $total -or $null -eq $free -or $free -gt $total) { return @{ State = 'unknown' } }
    $minPct = [double](Get-FmpValue -Data $Rule -Path 'threshold.minAvailablePct' -Default 10)
    $minGB = [double](Get-FmpValue -Data $Rule -Path 'threshold.minAvailableGB' -Default 2)
    $freeGB = [Math]::Round(([double]$free) / 1GB, 2)
    if ($pct -lt $minPct -and $freeGB -lt $minGB) {
        return @{
            State = 'finding'
            Values = @{ availablePct = $pct; availableGB = $freeGB }
            Limitations = @('single point-in-time reading; it cannot establish chronic pressure')
        }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_perf_commit_pressure {
    param([object]$D, [object]$Rule, [object]$Config)
    $mem = Get-FmpValue -Data $D -Path 'performance.memory'
    if ($null -eq $mem) { return @{ State = 'unknown'; Limitations = @('commit data not collected') } }
    $pct = Get-FmpRuleNumber (Get-FmpValue $mem 'commitPct') -Max 100
    if ($null -eq $pct) { return @{ State = 'unknown' } }
    $thr = [double](Get-FmpValue -Data $Rule -Path 'threshold.pctThreshold' -Default 90)
    if ($pct -gt $thr) {
        return @{
            State = 'finding'
            Values = @{ commitPct = $pct; thresholdPct = $thr }
            Limitations = @('single point-in-time reading')
        }
    }
    return @{ State = 'pass' }
}

# ---------------------------------------------------------------
# SYSTEM / OS
# ---------------------------------------------------------------
function Test-FmpRule_os_w10_eol {
    param([object]$D, [object]$Rule, [object]$Config)
    $caption = Get-FmpCleanString (Get-FmpValue -Data $D -Path 'system.os.caption')
    $displayVersion = Get-FmpCleanString (Get-FmpValue -Data $D -Path 'system.os.displayVersion')
    if ([string]::IsNullOrWhiteSpace([string]$caption)) {
        return @{ State = 'unknown'; Limitations = @('OS edition unavailable') }
    }
    if ([string]::IsNullOrWhiteSpace([string]$displayVersion)) {
        return @{ State = 'unknown'; Limitations = @('Windows display version (e.g. 22H2) unavailable; support state cannot be determined locally') }
    }
    $entries = Get-FmpValue -Data $Config -Path 'windowsLifecycle.entries'
    if ($null -eq $entries) {
        return @{ State = 'unsupported'; Limitations = @('built-in lifecycle table missing') }
    }
    $now = Get-FmpParsedDate -Value (Get-FmpValue -Data $D -Path 'run.finishedAt')
    if ($null -eq $now) { return @{ State = 'unknown' } }
    if ($caption -notmatch '^Microsoft Windows (10|11) (Home|Pro)(?: N)?$|^Windows (10|11) (Home|Pro)(?: N)?$') {
        return @{ State = 'unknown'; Limitations = @('edition outside the built-in Home/Pro lifecycle snapshot') }
    }
    foreach ($e in @($entries)) {
        $eosName = [string](Get-FmpValue -Data $e -Path 'os')
        $eosVer = [string](Get-FmpValue -Data $e -Path 'displayVersion')
        if (($caption -replace '^Microsoft ', '') -like ($eosName + ' *') -and $displayVersion -eq $eosVer) {
            $eol = Get-FmpParsedDate -Value (Get-FmpValue -Data $e -Path 'endOfSupport')
            if ($null -eq $eol) { return @{ State = 'unknown' } }
            $values = @{ os = $eosName; displayVersion = $eosVer; endOfSupport = $eol.ToString('yyyy-MM-dd') }
            if ($now -gt $eol) {
                return @{
                    State = 'finding'
                    Values = $values
                    Limitations = @('date from the built-in lifecycle snapshot (rules.json); it may be outdated - confirm with Microsoft lifecycle pages')
                }
            }
            return @{ State = 'pass'; Measured = $values }
        }
    }
    return @{ State = 'unknown'; Limitations = @('build not present in the built-in lifecycle snapshot; no conclusion drawn') }
}

function Test-FmpRule_os_long_uptime {
    param([object]$D, [object]$Rule, [object]$Config)
    $hours = Get-FmpRuleNumber (Get-FmpValue $D 'system.os.uptimeHours')
    if ($null -eq $hours) { return @{ State = 'unknown'; Limitations = @('uptime unavailable') } }
    $days = [int](Get-FmpValue -Data $Rule -Path 'threshold.daysThreshold' -Default 60)
    if ([double]$hours -ge ($days * 24)) {
        return @{ State = 'finding'; Values = @{ days = [Math]::Round(([double]$hours) / 24, 1); thresholdDays = $days } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_startup_unsigned_autostart {
    param([object]$D, [object]$Rule, [object]$Config)
    $sig = Get-FmpValue -Data $D -Path 'advanced.signatures'
    if ($null -eq $sig) { return @{ State = 'not_collected'; Limitations = @('no offline signature result available') } }
    $status = Get-FmpValue $sig 'status'
    if ($status -ne 'ok') { return @{ State = (Get-FmpEvidenceState $status) } }
    $unsigned = New-Object System.Collections.Generic.List[string]
    $solid = 0
    foreach ($i in @(Get-FmpValue -Data $sig -Path 'items')) {
        if ((Get-FmpValue $i 'status') -in @('Valid', 'NotSigned')) { $solid++ }
        if (([string](Get-FmpValue -Data $i -Path 'status')) -eq 'NotSigned') {
            $unsigned.Add([string](Get-FmpValue -Data $i -Path 'file'))
        }
    }
    if ($unsigned.Count -gt 0) {
        return @{
            State = 'finding'
            Values = @{ count = $unsigned.Count; names = (($unsigned | Select-Object -First 5) -join '; ') }
            Limitations = @('a missing signature is common in legitimate tools; it is NOT evidence of malware')
        }
    }
    if ($solid -eq 0) { return @{ State = 'unknown' } }
    return @{ State = 'pass' }
}

function Test-FmpRule_startup_high_count {
    param([object]$D, [object]$Rule, [object]$Config)
    $items = @(Get-FmpValue -Data $D -Path 'startup.items')
    $tasks = @(Get-FmpValue -Data $D -Path 'startup.logonTasks')
    $svcs = @(Get-FmpValue -Data $D -Path 'startup.autoServices')
    $countedSubChecks = @('startup.registry', 'startup.folders', 'startup.logonTasks')
    $subChecks = @(Get-FmpValue $D 'subChecks')
    $passedCounted = 0
    foreach ($check in $subChecks) {
        if ((Get-FmpValue $check 'id') -in $countedSubChecks -and (Get-FmpValue $check 'state') -eq 'pass') {
            $passedCounted++
        }
    }
    if ($items.Count -eq 0 -and $tasks.Count -eq 0 -and $svcs.Count -eq 0 -and $passedCounted -lt $countedSubChecks.Count) {
        return @{ State = 'unknown'; Limitations = @('startup inventory empty or not collected') }
    }
    # FMP-06: only entries a user can act on count (Run keys, Startup folders, logon tasks). Automatic services
    # are Windows plumbing (a stock install has 80-120), so they are reported separately and never counted.
    $total = $items.Count + $tasks.Count
    $thr = [int](Get-FmpValue -Data $Rule -Path 'threshold.threshold' -Default 30)
    $inventory = @{ items = $items.Count; tasks = $tasks.Count; services = $svcs.Count }
    if ($total -gt $thr) {
        return @{
            State = 'finding'
            Values = @{ total = $total; threshold = $thr; services = $svcs.Count }
            Measured = $inventory
            Limitations = @('a long list is not a fault by itself; review only if boot time matters to you')
        }
    }
    foreach ($check in $subChecks) {
        if ((Get-FmpValue $check 'id') -in @('startup.registry', 'startup.folders', 'startup.logonTasks', 'startup.module') -and
            (Get-FmpValue $check 'state') -ne 'pass') {
            $st = Get-FmpEvidenceState (Get-FmpValue $check 'state')
            if ($st -eq 'unsupported') { $st = 'unknown' }
            return @{ State = $st; Limitations = @('startup inventory incomplete') }
        }
    }
    return @{ State = 'pass'; Measured = $inventory }
}

function Test-FmpRule_os_pending_reboot {
    param([object]$D, [object]$Rule, [object]$Config)
    $pr = Get-FmpValue -Data $D -Path 'advanced.pendingReboot'
    if ($null -eq $pr) { return @{ State = 'not_collected'; Limitations = @('runs only in full mode') } }
    $status = Get-FmpValue $pr 'status'
    if ($status -ne 'ok') { return @{ State = (Get-FmpEvidenceState $status) } }
    $pending = Get-FmpValue $pr 'any'
    if ($pending -isnot [bool]) { return @{ State = 'unknown' } }
    if ($pending) {
        return @{ State = 'finding'; Values = @{
            wu = (Get-FmpValue -Data $pr -Path 'pendingWuReboot'); cbs = (Get-FmpValue -Data $pr -Path 'pendingCbs'); fileRename = (Get-FmpValue -Data $pr -Path 'pendingFileRename')
        } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_os_outdated_patch {
    param([object]$D, [object]$Rule, [object]$Config)
    $hf = Get-FmpValue -Data $D -Path 'advanced.hotfixes'
    if ($null -eq $hf) { return @{ State = 'not_collected'; Limitations = @('runs only in full mode') } }
    $status = Get-FmpValue $hf 'status'
    if ($status -ne 'ok') { return @{ State = (Get-FmpEvidenceState $status) } }
    $latest = Get-FmpValue -Data $hf -Path 'latest'
    if ($null -eq $latest) { return @{ State = 'unknown'; Limitations = @('no hotfix with a date was found') } }
    $days = Get-FmpHoursBetween -FromIso $latest -ToIso (Get-FmpValue -Data $D -Path 'run.finishedAt')
    if ($null -eq $days -or $days -lt 0) { return @{ State = 'unknown' } }
    $days = [Math]::Round($days / 24, 0)
    $thr = [int](Get-FmpValue -Data $Rule -Path 'threshold.daysThreshold' -Default 365)
    if ($days -gt $thr) {
        return @{ State = 'finding'; Values = @{ days = $days; thresholdDays = $thr } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_security_defender_disabled {
    param([object]$D, [object]$Rule, [object]$Config)
    $def = Get-FmpValue -Data $D -Path 'advanced.defender'
    if ($null -eq $def) { return @{ State = 'not_collected'; Limitations = @('runs only in full mode') } }
    $st = Get-FmpValue -Data $def -Path 'status'
    if ($st -ne 'ok') { return @{ State = (Get-FmpEvidenceState $st); Limitations = @('Defender status unavailable (product may be absent or replaced)') } }
    $rt = Get-FmpValue -Data $def -Path 'data.realTimeProtection'
    if ($rt -isnot [bool]) { return @{ State = 'unknown' } }
    $third = Get-FmpRuleNumber (Get-FmpValue $D 'advanced.thirdPartyAv.count')
    if (-not $rt) {
        if ((Get-FmpValue $D 'advanced.thirdPartyAv.status') -ne 'ok' -or $null -eq $third) { return @{ State = 'unknown' } }
        if ($third -gt 0) {
            return @{ State = 'unknown'; Limitations = @('third-party registration does not confirm active protection') }
        }
        return @{ State = 'finding'; Values = @{ component = 'real-time protection' } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_security_third_party_av {
    param([object]$D, [object]$Rule, [object]$Config)
    $av = Get-FmpValue -Data $D -Path 'advanced.thirdPartyAv'
    if ($null -eq $av) { return @{ State = 'not_collected'; Limitations = @('runs only in full mode') } }
    $status = Get-FmpValue $av 'status'
    if ($status -ne 'ok') { return @{ State = (Get-FmpEvidenceState $status) } }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($i in @(Get-FmpValue -Data $av -Path 'items')) {
        $n = [string](Get-FmpValue -Data $i -Path 'displayName')
        if ($n) { $names.Add($n) }
    }
    if ($names.Count -gt 0) {
        return @{ State = 'finding'; Values = @{ names = (($names | Select-Object -First 3) -join '; ') } }
    }
    return @{ State = 'pass' }
}

function Test-FmpRule_devices_problem_codes {
    param([object]$D, [object]$Rule, [object]$Config)
    $pd = Get-FmpValue -Data $D -Path 'advanced.problemDevices'
    if ($null -eq $pd) { return @{ State = 'not_collected'; Limitations = @('runs only in full mode') } }
    if ((Get-FmpValue -Data $pd -Path 'status') -ne 'ok') { return @{ State = (Get-FmpEvidenceState (Get-FmpValue $pd 'status')) } }
    $count = Get-FmpRuleNumber (Get-FmpValue $pd 'count')
    if ($null -eq $count) { return @{ State = 'unknown' } }
    if ($count -gt 0) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($i in @(Get-FmpValue -Data $pd -Path 'items')) {
            $items.Add(([string](Get-FmpValue -Data $i -Path 'name')) + ' (code ' + (Get-FmpValue -Data $i -Path 'code') + ')')
        }
        return @{ State = 'finding'; Values = @{ count = $count; names = (($items | Select-Object -First 5) -join '; ') } }
    }
    return @{ State = 'pass' }
}

# ---------------------------------------------------------------
# Evaluation driver
# ---------------------------------------------------------------
function Invoke-FmpRules {
    param(
        [Parameter(Mandatory)][object]$Diagnostic,
        [Parameter(Mandatory)][object]$RuleConfig,
        [Parameter(Mandatory)][ValidateSet('simple', 'full')][string]$Mode
    )
    $checks = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($rule in $RuleConfig.rules) {
        $modes = @(Get-FmpValue -Data $rule -Path 'modes')
        if ($modes -notcontains $Mode) { continue }
        $id = [string](Get-FmpValue -Data $rule -Path 'id')

        $res = $null
        switch ($id) {
            'storage.low_free_space'         { $res = Test-FmpRule_storage_low_free_space $Diagnostic $rule $RuleConfig }
            'storage.disk_space_critical'    { $res = Test-FmpRule_storage_disk_space_critical $Diagnostic $rule $RuleConfig }
            'storage.disk_health_unhealthy'  { $res = Test-FmpRule_storage_disk_health_unhealthy $Diagnostic $rule $RuleConfig }
            'storage.smart_predict_failure'  { $res = Test-FmpRule_storage_smart_predict_failure $Diagnostic $rule $RuleConfig }
            'storage.disk_event_errors'      { $res = Test-FmpRule_storage_disk_event_errors $Diagnostic $rule $RuleConfig }
            'events.critical_recurring'      { $res = Test-FmpRule_events_critical_recurring $Diagnostic $rule $RuleConfig }
            'events.error_concentration'     { $res = Test-FmpRule_events_error_concentration $Diagnostic $rule $RuleConfig }
            'events.whea_hardware'           { $res = Test-FmpRule_events_whea_hardware $Diagnostic $rule $RuleConfig }
            'events.unexpected_shutdown'     { $res = Test-FmpRule_events_unexpected_shutdown $Diagnostic $rule $RuleConfig }
            'events.bsod'                    { $res = Test-FmpRule_events_bsod $Diagnostic $rule $RuleConfig }
            'perf.cpu_sustained_high'        { $res = Test-FmpRule_perf_cpu_sustained_high $Diagnostic $rule $RuleConfig }
            'perf.ram_pressure'              { $res = Test-FmpRule_perf_ram_pressure $Diagnostic $rule $RuleConfig }
            'perf.commit_pressure'           { $res = Test-FmpRule_perf_commit_pressure $Diagnostic $rule $RuleConfig }
            'os.w10_eol'                     { $res = Test-FmpRule_os_w10_eol $Diagnostic $rule $RuleConfig }
            'os.long_uptime'                 { $res = Test-FmpRule_os_long_uptime $Diagnostic $rule $RuleConfig }
            'startup.unsigned_autostart'     { $res = Test-FmpRule_startup_unsigned_autostart $Diagnostic $rule $RuleConfig }
            'startup.high_count'             { $res = Test-FmpRule_startup_high_count $Diagnostic $rule $RuleConfig }
            'os.pending_reboot'              { $res = Test-FmpRule_os_pending_reboot $Diagnostic $rule $RuleConfig }
            'os.outdated_patch'              { $res = Test-FmpRule_os_outdated_patch $Diagnostic $rule $RuleConfig }
            'security.defender_disabled'     { $res = Test-FmpRule_security_defender_disabled $Diagnostic $rule $RuleConfig }
            'security.third_party_av'        { $res = Test-FmpRule_security_third_party_av $Diagnostic $rule $RuleConfig }
            'devices.problem_codes'          { $res = Test-FmpRule_devices_problem_codes $Diagnostic $rule $RuleConfig }
            default { $res = @{ State = 'error'; Limitations = @('no evaluator registered for this rule') } }
        }
        if ($null -eq $res) { $res = @{ State = 'error'; Limitations = @('evaluator returned nothing') } }

        $state = [string]$res.State
        $severity = [string](Get-FmpValue -Data $rule -Path 'severity')
        $penalty = [double](Get-FmpValue -Data $rule -Path 'penalty' -Default 0)
        $confidence = [string](Get-FmpValue -Data $rule -Path 'confidence')
        if ($res.ContainsKey('SeverityOverride') -and $null -ne $res.SeverityOverride) { $severity = [string]$res.SeverityOverride }
        if ($res.ContainsKey('PenaltyOverride') -and $null -ne $res.PenaltyOverride) { $penalty = [double]$res.PenaltyOverride }
        $isAnalysisOnly = ($modes.Count -eq 1 -and $modes[0] -eq 'full')
        if ($state -notin @('pass', 'finding', 'unknown', 'unsupported', 'access_denied', 'not_collected', 'error')) { $state = 'error' }
        if ($state -ne 'finding' -or $severity -eq 'info' -or $isAnalysisOnly) { $penalty = 0 }

        $check = [ordered]@{
            id          = $id
            category    = [string](Get-FmpValue -Data $rule -Path 'category')
            state       = $state
            severity    = $severity
            penalty     = $penalty
            confidence  = $confidence
            dedupeGroup = (Get-FmpValue -Data $rule -Path 'dedupeGroup')
            analysisOnly = $isAnalysisOnly
        }
        if ($res.ContainsKey('Measured') -and $null -ne $res.Measured) { $check['measured'] = $res.Measured }
        if ($res.ContainsKey('Limitations') -and $null -ne $res.Limitations -and @($res.Limitations).Count -gt 0) {
            $check['limitations'] = @($res.Limitations)
            $check['limitationKeys'] = Get-FmpRuleLimitationKeys -Limitations @($res.Limitations)
        }
        $checks.Add($check)

        if ($state -eq 'finding') {
            $f = [ordered]@{
                id          = $id
                category    = $check.category
                severity    = $severity
                penalty     = $penalty
                confidence  = $confidence
                dedupeGroup = $check.dedupeGroup
                analysisOnly = $isAnalysisOnly
            }
            if ($res.ContainsKey('Values') -and $null -ne $res.Values) { $f['values'] = $res.Values }
            if ($res.ContainsKey('Measured') -and $null -ne $res.Measured) { $f['measured'] = $res.Measured }
            if ($res.ContainsKey('Limitations') -and $null -ne $res.Limitations) {
                $f['limitations'] = @($res.Limitations)
                $f['limitationKeys'] = Get-FmpRuleLimitationKeys -Limitations @($res.Limitations)
            }
            if ($res.ContainsKey('Gate') -and $res.Gate -ceq 'critical' -and -not $isAnalysisOnly) { $f['riskGate'] = 'critical' }
            $findings.Add($f)
        }
    }

    return @{ checks = $checks.ToArray(); findings = $findings.ToArray(); mode = $Mode }
}
