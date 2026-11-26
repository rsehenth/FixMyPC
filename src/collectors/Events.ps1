# =====================================================================
# FIX MY PC - Events.ps1 (collector)
# Read-only event log queries. System + Application logs, Error/Critical
# level, last 7 days (configurable), filtered AT THE SOURCE so full logs
# are never loaded. Full mode adds Security (if accessible) and the
# Reliability Monitor data when the RAC provider is available.
# Historical events are recorded but never treated as current faults.
# =====================================================================

function ConvertFrom-FmpEventXmlData {
    # Pure parser: <Data Name='X'>value</Data> pairs from an event's XML, by name (field order differs across builds).
    param([string]$Xml, [int]$MaxFields = 80)
    $out = [ordered]@{}
    if ([string]::IsNullOrEmpty($Xml)) { return $out }
    $rest = $Xml
    $n = 0
    while ($n -lt $MaxFields -and $rest -match '<Data Name=[''"]([A-Za-z0-9_]{1,64})[''"]\s*>([^<]{0,400})</Data>([\s\S]*)$') {
        $out[$Matches[1]] = $Matches[2]
        $rest = $Matches[3]
        $n++
    }
    return $out
}

function Get-FmpLeafName {
    # File name only: paths never leave the collector.
    param([object]$Value)
    $s = Get-FmpCleanString $Value
    if ($null -eq $s) { return $null }
    if ($s -match '([^\\/]+)$') { return $Matches[1] }
    return $s
}

function Get-FmpBootHistory {
    # Microsoft-Windows-Diagnostics-Performance/Operational: 100 = boot timing, 101-109 = components Windows flagged
    # as slowing a boot. The channel is usually readable only by administrators; that is reported, never elevated.
    param([System.Collections.IDictionary]$Ctx, [int]$Days = 60, [int]$MaxEvents = 200)
    $rec = [ordered]@{ status = 'empty'; windowDays = $Days; boots = @(); contributors = @(); truncated = $false }
    $events = @()
    try {
        $bootCutoff = (Get-Date).AddDays(-$Days)
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = @(100, 101, 102, 103, 106, 109); StartTime = $bootCutoff } -MaxEvents $MaxEvents -ErrorAction Stop | Where-Object { $null -ne $_ })
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $rec.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $Ctx -Id 'events.bootPerformance' -State $rec.status
            if ($rec.status -eq 'access_denied') {
                Add-FmpLimitation -Ctx $Ctx -Key 'boot_log_needs_admin' -DetailText 'The Windows boot performance log is restricted to administrators; boot history was not verified.'
            }
            return $rec
        }
    }
    $boots = New-Object System.Collections.Generic.List[object]
    $contrib = @{}
    $kinds = @{ 101 = 'app'; 102 = 'driver'; 103 = 'service'; 106 = 'background'; 109 = 'device' }
    foreach ($e in $events) {
        $id = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Id')
        $at = Get-FmpParsedDate -Value (Get-FmpValue $e 'TimeCreated')
        $fields = ConvertFrom-FmpEventXmlData -Xml ([string]$e.ToXml())
        if ($id -eq 100) {
            $boots.Add([ordered]@{
                at            = $at
                level         = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Level')
                bootMs        = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'BootTime')
                mainPathMs    = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'MainPathBootTime')
                postBootMs    = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'BootPostBootTime')
                userProfileMs = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'BootUserProfileProcessingTime')
                explorerMs    = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'BootExplorerInitTime')
                startupApps   = ConvertTo-FmpNullableInt (Get-FmpValue $fields 'BootNumStartupApps')
                degraded      = ((Get-FmpValue $fields 'BootIsDegradation') -in @('true', '1'))
                afterUpdate   = ((Get-FmpValue $fields 'BootIsRebootAfterInstall') -in @('true', '1'))
            })
            continue
        }
        if (-not $kinds.ContainsKey($id)) { continue }
        $name = Get-FmpCleanString (Get-FmpValue $fields 'FriendlyName')
        if ($null -eq $name) { $name = Get-FmpLeafName (Get-FmpValue $fields 'Name') }
        if ($null -eq $name) { $name = '(unknown)' }
        $key = $kinds[$id] + '|' + $name
        $total = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'TotalTime')
        $degr = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'DegradationTime')
        if (-not $contrib.ContainsKey($key)) {
            if ($contrib.Count -ge 40) { continue }
            $contrib[$key] = [ordered]@{ kind = $kinds[$id]; name = $name; count = 0; maxTotalMs = $null; maxDegradationMs = $null; lastSeen = $null }
        }
        $contrib[$key]['count']++
        if ($null -ne $total -and ($null -eq $contrib[$key].maxTotalMs -or $total -gt $contrib[$key].maxTotalMs)) { $contrib[$key]['maxTotalMs'] = $total }
        if ($null -ne $degr -and ($null -eq $contrib[$key].maxDegradationMs -or $degr -gt $contrib[$key].maxDegradationMs)) { $contrib[$key]['maxDegradationMs'] = $degr }
        if ($null -ne $at -and ($null -eq $contrib[$key].lastSeen -or $at -gt $contrib[$key].lastSeen)) { $contrib[$key]['lastSeen'] = $at }
    }
    $rec.boots = @($boots.ToArray() | Sort-Object -Property { $_['at'] } -Descending | Select-Object -First 30)
    $rec.contributors = @($contrib.Values | Sort-Object -Property { $_['count'] } -Descending | Select-Object -First 15)
    $rec.truncated = ($events.Count -ge $MaxEvents)
    if ($events.Count -gt 0) { $rec.status = 'ok' }
    Add-FmpSubCheck -Ctx $Ctx -Id 'events.bootPerformance' -State 'pass' -Detail @{ boots = $boots.Count }
    return $rec
}

function Get-FmpUnexpectedRestartContext {
    # Kernel-Power 41 says the previous session ended without a clean shutdown. Its fields separate a preceding
    # bugcheck (BugcheckCode) and a held power button (PowerButtonTimestamp); neither identifies a failed part.
    param([System.Collections.IDictionary]$Ctx, [datetime]$Cutoff, [int]$MaxEvents = 50)
    $rec = [ordered]@{ status = 'empty'; items = @() }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; StartTime = $Cutoff } -MaxEvents $MaxEvents -ErrorAction Stop | Where-Object { $null -ne $_ })
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($e in $events) {
            $fields = ConvertFrom-FmpEventXmlData -Xml ([string]$e.ToXml())
            $bug = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'BugcheckCode')
            $btn = ConvertTo-FmpNullableDouble (Get-FmpValue $fields 'PowerButtonTimestamp')
            $items.Add([ordered]@{
                at              = Get-FmpParsedDate -Value (Get-FmpValue $e 'TimeCreated')
                bugcheck        = ($null -ne $bug -and $bug -ne 0)
                powerButton     = ($null -ne $btn -and $btn -ne 0)
                sleepInProgress = ((Get-FmpValue $fields 'SleepInProgress') -notin @($null, '0', 'false'))
            })
        }
        $rec.items = $items.ToArray()
        if ($items.Count -gt 0) { $rec.status = 'ok' }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $rec.status = Resolve-FmpCollectorErrorState -ErrorRecord $_ }
    }
    return $rec
}

function Get-FmpEventCatalog {
    # Closed diagnostic catalog, System channel. An entry is always provider + ID: 153 from nvlddmkm and 153 from disk
    # are unrelated events. Levels are the ones accepted for that pair; anything else from the provider is ignored.
    return @(
        @{ provider = 'nvlddmkm'; id = 153; family = 'graphics'; meaning = 'gpu_driver_error'; levels = @(1, 2, 3) }
        @{ provider = 'Display'; id = 4101; family = 'graphics'; meaning = 'display_driver_recovered'; levels = @(1, 2, 3) }
        @{ provider = 'disk'; id = 7; family = 'storage'; meaning = 'disk_bad_block'; levels = @(1, 2, 3) }
        @{ provider = 'disk'; id = 51; family = 'storage'; meaning = 'disk_paging_error'; levels = @(1, 2, 3) }
        @{ provider = 'disk'; id = 153; family = 'storage'; meaning = 'disk_io_retried'; levels = @(1, 2, 3) }
        @{ provider = 'stornvme'; id = 129; family = 'storage'; meaning = 'storage_controller_reset'; levels = @(1, 2, 3) }
        @{ provider = 'storahci'; id = 129; family = 'storage'; meaning = 'storage_controller_reset'; levels = @(1, 2, 3) }
        @{ provider = 'Ntfs'; id = 55; family = 'storage'; meaning = 'ntfs_corruption'; levels = @(1, 2, 3) }
        @{ provider = 'Microsoft-Windows-Ntfs'; id = 140; family = 'storage'; meaning = 'ntfs_flush_failed'; levels = @(1, 2, 3) }
        @{ provider = 'Tcpip'; id = 4231; family = 'network'; meaning = 'tcp_ports_exhausted'; levels = @(1, 2, 3) }
        @{ provider = 'Tcpip'; id = 4266; family = 'network'; meaning = 'udp_ports_exhausted'; levels = @(1, 2, 3) }
        @{ provider = 'Microsoft-Windows-Kernel-Power'; id = 41; family = 'lifecycle'; meaning = 'unexpected_restart'; levels = @(1, 2) }
        @{ provider = 'Microsoft-Windows-Kernel-Power'; id = 109; family = 'lifecycle'; meaning = 'kernel_shutdown_started'; levels = @(4) }
        @{ provider = 'EventLog'; id = 6008; family = 'lifecycle'; meaning = 'unexpected_shutdown'; levels = @(2) }
        @{ provider = 'EventLog'; id = 6005; family = 'lifecycle'; meaning = 'eventlog_started'; levels = @(4) }
        @{ provider = 'EventLog'; id = 6006; family = 'lifecycle'; meaning = 'eventlog_stopped'; levels = @(4) }
        @{ provider = 'User32'; id = 1074; family = 'lifecycle'; meaning = 'planned_shutdown'; levels = @(4) }
        @{ provider = 'Microsoft-Windows-Kernel-General'; id = 12; family = 'lifecycle'; meaning = 'os_started'; levels = @(4) }
        @{ provider = 'Microsoft-Windows-Kernel-General'; id = 13; family = 'lifecycle'; meaning = 'os_stopped'; levels = @(4) }
        @{ provider = 'Microsoft-Windows-Kernel-General'; id = 1; family = 'clock'; meaning = 'clock_step'; levels = @(4) }
    )
}

function Get-FmpHarddiskNumber {
    # Pure: only the N of \Device\HarddiskN from a disk event's XML; the rest of the event data is not kept.
    param([string]$Xml)
    if ($Xml -match '\\Device\\Harddisk(\d{1,3})\\') { return [int]$Matches[1] }
    return $null
}

function Get-FmpClockStepSeconds {
    # Pure: size of a system time change from Kernel-General 1 fields; $null when the fields do not say.
    param([object]$Fields)
    $delta = ConvertTo-FmpNullableDouble (Get-FmpValue $Fields 'TimeDeltaInMs')
    if ($null -ne $delta) { return [Math]::Abs($delta) / 1000 }
    $new = Get-FmpParsedDate (Get-FmpValue $Fields 'NewTime')
    $old = Get-FmpParsedDate (Get-FmpValue $Fields 'OldTime')
    if ($null -eq $new -or $null -eq $old) { return $null }
    return [Math]::Abs(($new.ToUniversalTime() - $old.ToUniversalTime()).TotalSeconds)
}

function ConvertTo-FmpCatalogEntries {
    # Pure: one entry per catalog provider + ID, whatever happened to its query. No message text is kept.
    # Clock changes count only from MinClockStepSec: routine time sync adjustments are not evidence of a bad clock.
    param([object[]]$Catalog, [hashtable]$ProviderState, [object[]]$Records = @(), [int]$MaxOccurrences = 60, [double]$MinClockStepSec = 120)
    $byKey = @{}
    foreach ($r in $Records) {
        $k = [string]$r['provider'] + '|' + $r['id']
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[object] }
        $byKey[$k].Add($r)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($spec in $Catalog) {
        $k = [string]$spec.provider + '|' + $spec.id
        $st = $ProviderState[[string]$spec.provider]
        $status = 'error'
        $truncated = $false
        if ($null -ne $st) { $status = [string]$st['status']; $truncated = [bool]$st['truncated'] }
        $kept = New-Object System.Collections.Generic.List[object]
        $levelCounts = [ordered]@{ critical = 0; error = 0; warning = 0; information = 0 }
        $days = @{}
        $first = $null; $last = $null
        if ($byKey.ContainsKey($k)) {
            foreach ($r in $byKey[$k]) {
                if ([int]$r['level'] -notin @($spec.levels)) { continue }
                $at = Get-FmpParsedDate $r['at']
                if ($null -eq $at) { continue }
                if ($spec.family -eq 'clock' -and ($null -eq $r['stepSec'] -or [double]$r['stepSec'] -lt $MinClockStepSec)) { continue }
                $utc = $at.ToUniversalTime()
                $occ = [ordered]@{ at = $utc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture); level = [int]$r['level'] }
                if ($spec.family -eq 'clock') { $occ['stepSec'] = [Math]::Round([double]$r['stepSec'], 0) }
                if ($null -ne $r['diskNumber']) { $occ['diskNumber'] = [int]$r['diskNumber'] }
                $kept.Add($occ)
                $days[$utc.ToString('yyyy-MM-dd')] = $true
                if ($null -eq $first -or $utc -lt $first) { $first = $utc }
                if ($null -eq $last -or $utc -gt $last) { $last = $utc }
                switch ([int]$r['level']) { 1 { $levelCounts['critical']++ } 2 { $levelCounts['error']++ } 3 { $levelCounts['warning']++ } 4 { $levelCounts['information']++ } }
            }
        }
        if ($status -eq 'ok' -and $kept.Count -eq 0) { $status = 'empty' }
        $sorted = @($kept.ToArray() | Sort-Object -Property { $_['at'] } -Descending)
        $out.Add([ordered]@{
            key = ([string]$spec.provider + '|' + $spec.id); provider = [string]$spec.provider; eventId = [int]$spec.id
            channel = 'System'; family = [string]$spec.family; meaning = [string]$spec.meaning; status = $status
            count = $kept.Count; truncated = $truncated; distinctDays = $days.Count; levels = $levelCounts
            firstSeen = $(if ($null -ne $first) { $first.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null })
            lastSeen = $(if ($null -ne $last) { $last.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null })
            occurrences = @($sorted | Select-Object -First $MaxOccurrences)
        })
    }
    return $out.ToArray()
}

function Get-FmpEventRetention {
    # Reads only the time of the single oldest System record, to say what the log could still contain.
    param([System.Collections.IDictionary]$Ctx, [datetime]$Since)
    $rec = [ordered]@{ status = 'empty'; oldestAt = $null; coversWindow = $null }
    try {
        $oldest = @(Get-WinEvent -FilterHashtable @{ LogName = 'System' } -Oldest -MaxEvents 1 -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First 1)
        if ($oldest.Count -gt 0) {
            $at = Get-FmpParsedDate (Get-FmpValue $oldest[0] 'TimeCreated')
            if ($null -ne $at) {
                $rec.status = 'ok'
                $rec.oldestAt = $at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                $rec.coversWindow = ($at.ToUniversalTime() -le $Since.ToUniversalTime())
            }
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $rec.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpCollectorError -Ctx $Ctx -Where 'events.catalog.retention' -Message $_.Exception.Message
        }
    }
    return $rec
}

function Get-FmpEventCatalogData {
    # One bounded query per provider: filtering on a provider Windows does not know raises an error for the whole query.
    param([System.Collections.IDictionary]$Ctx, [int]$Days = 30, [int]$MaxPerProvider = 300)
    if ($Days -lt 1) { $Days = 1 }
    if ($Days -gt 60) { $Days = 60 }
    if ($MaxPerProvider -lt 1) { $MaxPerProvider = 1 }
    if ($MaxPerProvider -gt 500) { $MaxPerProvider = 500 }
    $since = (Get-Date).AddDays(-$Days)
    $catalog = @(Get-FmpEventCatalog)
    $state = @{}
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($prov in @('nvlddmkm', 'Display', 'disk', 'stornvme', 'storahci', 'Ntfs', 'Microsoft-Windows-Ntfs', 'Tcpip', 'Microsoft-Windows-Kernel-Power', 'EventLog', 'User32', 'Microsoft-Windows-Kernel-General')) {
        $spec = @($catalog | Where-Object { $_.provider -ceq $prov })
        $ids = @($spec | ForEach-Object { $_.id })
        $levels = @($spec | ForEach-Object { $_.levels } | Sort-Object -Unique)
        $st = 'empty'
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $prov; Id = $ids; Level = $levels; StartTime = $since } -MaxEvents $MaxPerProvider -ErrorAction Stop | Where-Object { $null -ne $_ })
            if ($events.Count -gt 0) { $st = 'ok' }
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $st = 'empty' }
            elseif ($_.FullyQualifiedErrorId -like 'NoMatchingProvidersFound*') { $st = 'provider_absent' }
            else {
                $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
                Add-FmpCollectorError -Ctx $Ctx -Where ('events.catalog.' + $prov) -Message $_.Exception.Message
            }
        }
        $state[$prov] = @{ status = $st; truncated = ($events.Count -ge $MaxPerProvider) }
        foreach ($e in $events) {
            $id = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Id')
            $lvl = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Level')
            if ($null -eq $id -or $null -eq $lvl) { continue }
            $step = $null
            if ($prov -ceq 'Microsoft-Windows-Kernel-General' -and $id -eq 1) { $step = Get-FmpClockStepSeconds (ConvertFrom-FmpEventXmlData -Xml ([string]$e.ToXml())) }
            $diskNo = $null
            if ($prov -ceq 'disk') { $diskNo = Get-FmpHarddiskNumber ([string]$e.ToXml()) }
            $records.Add(@{ provider = $prov; id = $id; level = $lvl; at = (Get-FmpValue $e 'TimeCreated'); stepSec = $step; diskNumber = $diskNo })
        }
    }
    $entries = @(ConvertTo-FmpCatalogEntries -Catalog $catalog -ProviderState $state -Records $records.ToArray())
    $retention = Get-FmpEventRetention -Ctx $Ctx -Since $since
    $failed = @($state.Values | Where-Object { $_['status'] -notin @('ok', 'empty', 'provider_absent') }).Count
    $overall = 'pass'
    if ($failed -eq $state.Count) { $overall = 'error' } elseif ($failed -gt 0) { $overall = 'unknown' }
    $anyTruncated = @($entries | Where-Object { $_['truncated'] }).Count -gt 0
    Add-FmpSubCheck -Ctx $Ctx -Id 'events.catalog' -State $overall -Detail @{ providers = $state.Count; failed = $failed }
    if ($retention.coversWindow -eq $false) {
        Add-FmpLimitation -Ctx $Ctx -Key 'events_retention' -DetailText 'The System log does not reach the start of the requested window; older events cannot be confirmed or ruled out.'
    }
    if ($anyTruncated) {
        Add-FmpLimitation -Ctx $Ctx -Key 'events_catalog_truncated' -DetailText 'A diagnostic event source reached its record limit; the oldest occurrences in the window were not read.'
    }
    return [ordered]@{
        version = '1'; state = $overall; channel = 'System'; windowDays = $Days
        since = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        maxPerProvider = $MaxPerProvider; anyTruncated = $anyTruncated; retention = $retention; entries = $entries
    }
}

function Get-FmpEventData {
    param([int]$WindowDays = 7, [bool]$Full = $false, [int]$MaxPerLog = 2000, [int]$MaxGroups = 40, [bool]$BootHistory = $false, [int]$BootDays = 60, [int]$CatalogDays = 0, [int]$CatalogMaxPerProvider = 300)

    return Invoke-FmpCollector -Name 'events' -Body {
        param([System.Collections.IDictionary]$ctx)
        if ($WindowDays -lt 1) { $WindowDays = 1 }
        if ($MaxPerLog -lt 1) { $MaxPerLog = 1 }
        if ($MaxGroups -lt 1) { $MaxGroups = 1 }

        $cutoff = (Get-Date).AddDays(-$WindowDays)
        $ctx.data['windowDays'] = $WindowDays
        $logs = [ordered]@{}

        foreach ($logName in @('System', 'Application')) {
            $logRec = [ordered]@{ status = 'empty'; totalEvents = $null; groups = @(); truncated = $false }
            $events = $null
            try {
                $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(1, 2); StartTime = $cutoff } `
                    -MaxEvents $MaxPerLog -ErrorAction Stop
            }
            catch {
                $msg = $_.Exception.Message
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                    $logRec.status = 'empty'
                }
                else {
                    $logRec.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    Add-FmpCollectorError -Ctx $ctx -Where ('events.' + $logName) -Message $msg
                }
                $events = @()
            }

            if ($null -eq $events) { $events = @() }
            if ($events -isnot [System.Collections.IEnumerable]) { $events = @($events) }

            # Keep timestamps and levels for recurrence without rendering event messages.
            $map = @{}
            $seenRecordIds = @{}
            $uniqueCount = 0
            $rawCount = 0
            foreach ($e in $events) {
                if ($null -eq $e) { continue }
                $rawCount++
                $recId = Get-FmpValue $e 'RecordId'
                if ($null -ne $recId) {
                    $recKey = [string]$recId
                    if ($seenRecordIds.ContainsKey($recKey)) { continue }
                    $seenRecordIds[$recKey] = $true
                }
                $uniqueCount++
                $prov = Get-FmpCleanString (Get-FmpValue $e 'ProviderName')
                if ($null -eq $prov) { $prov = '(unknown)' }
                $id = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Id')
                if ($null -eq $id) { $id = 0 }
                $key = $prov + '|' + $id
                if (-not $map.ContainsKey($key)) {
                    $map[$key] = [ordered]@{
                        provider    = $prov
                        eventId     = $id
                        count       = 0
                        firstSeen   = $null
                        lastSeen    = $null
                        maxLevel    = 0
                        sample      = $null
                        msgMissing  = $false
                        occurrences = New-Object System.Collections.Generic.List[object]
                    }
                }
                $g = $map[$key]
                $map[$key]['count']++
                $lvl = ConvertTo-FmpNullableInt (Get-FmpValue $e 'Level')
                $t = Get-FmpParsedDate -Value (Get-FmpValue $e 'TimeCreated')
                if ($null -ne $t) {
                    $map[$key]['occurrences'].Add([ordered]@{ at = $t; level = $lvl })
                    if ($null -eq $g.firstSeen -or $t -lt $g.firstSeen) { $map[$key]['firstSeen'] = $t }
                    if ($null -eq $g.lastSeen -or $t -gt $g.lastSeen) { $map[$key]['lastSeen'] = $t }
                }
                if ($null -ne $lvl -and $lvl -gt 0 -and ($g.maxLevel -eq 0 -or $lvl -lt $g.maxLevel)) { $map[$key]['maxLevel'] = $lvl }
            }

            if ($logRec.status -eq 'empty') {
                $logRec.totalEvents = $uniqueCount
                if ($uniqueCount -gt 0) { $logRec.status = 'ok' }
            }

            foreach ($mapKey in @($map.Keys)) { $map[$mapKey]['occurrences'] = $map[$mapKey]['occurrences'].ToArray() }
            $groupList = @($map.Values | Sort-Object -Property { $_['count'] } -Descending | Select-Object -First $MaxGroups)
            $logRec.truncated = ($rawCount -ge $MaxPerLog -or $map.Count -gt $MaxGroups)
            $logRec.groups = $groupList
            $logs[$logName] = $logRec
            if ($logRec.truncated) {
                Add-FmpLimitation -Ctx $ctx -Key ('events_truncated_' + $logName) -DetailText ('Event log ' + $logName + ' reached collection limit; total count is a lower bound.') -LocaleKey 'events_truncated' -Values @($logName)
            }
            if ($logRec.status -in @('ok', 'empty')) {
                Add-FmpSubCheck -Ctx $ctx -Id ('events.log.' + $logName) -State $(if ($logRec.truncated) { 'unknown' } else { 'pass' }) -Detail @{ total = $logRec.totalEvents; truncated = $logRec.truncated }
            }
            else {
                Add-FmpSubCheck -Ctx $ctx -Id ('events.log.' + $logName) -State $logRec.status
            }
        }
        $ctx.data['logs'] = $logs

        # ---- Full mode: Reliability Monitor (passive; RAC may be disabled) ----
        if ($Full) {
            $rel = [ordered]@{ status = 'ok'; records = @(); metrics = @() }
            try {
                $recs = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First 100)
                $rl = New-Object System.Collections.Generic.List[object]
                foreach ($r in $recs) {
                    $rl.Add([ordered]@{
                        source  = Get-FmpCleanString (Get-FmpValue $r 'SourceName')
                        eventId = ConvertTo-FmpNullableInt (Get-FmpValue $r 'EventIdentifier')
                        product = Get-FmpCleanString (Get-FmpValue $r 'ProductName')
                        at      = Get-FmpParsedDate -Value (Get-FmpValue $r 'TimeGenerated')
                    })
                }
                $rel.records = $rl.ToArray()
                if ($rl.Count -eq 0) { $rel.status = 'empty' }
                Add-FmpSubCheck -Ctx $ctx -Id 'events.reliability' -State 'pass'
            }
            catch {
                $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
                $rel.status = $st
                Add-FmpSubCheck -Ctx $ctx -Id 'events.reliability' -State $st -Detail @{ reason = 'Reliability Analysis Component (RAC) unavailable or disabled' }
            }
            try {
                $cut30 = (Get-Date).AddDays(-30)
                $mets = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object {
                    if ($null -eq $_) { return $false }
                    $tg = Get-FmpParsedDate -Value (Get-FmpValue $_ 'TimeGenerated')
                    return ($null -ne $tg -and $tg -ge $cut30)
                } | Select-Object -First 60)
                $ml = New-Object System.Collections.Generic.List[object]
                foreach ($mm in $mets) {
                    $stab = ConvertTo-FmpNullableDouble (Get-FmpValue $mm 'SystemStabilityIndex')
                    if ($null -eq $stab) { continue }
                    $ml.Add([ordered]@{
                        at        = Get-FmpParsedDate -Value (Get-FmpValue $mm 'TimeGenerated')
                        stability = [Math]::Round($stab, 2)
                    })
                }
                $rel.metrics = $ml.ToArray()
            }
            catch {
                # Metrics unavailable: keep records result as-is.
            }
            $ctx.data['reliability'] = $rel

            # ---- Full mode: Security log logon failures (usually needs admin) ----
            $sec = [ordered]@{ status = 'ok'; logonFailures = $null; truncated = $false; firstSeen = $null; lastSeen = $null }
            try {
                $secEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $cutoff } `
                    -MaxEvents 500 -ErrorAction Stop
                $secList = @($secEvents | Where-Object { $null -ne $_ })
                $sec.logonFailures = $secList.Count
                $sec.truncated = ($secList.Count -ge 500)
                $minSec = $null
                $maxSec = $null
                foreach ($se in $secList) {
                    $stAt = Get-FmpParsedDate -Value (Get-FmpValue $se 'TimeCreated')
                    if ($null -eq $stAt) { continue }
                    if ($null -eq $minSec -or $stAt -lt $minSec) { $minSec = $stAt }
                    if ($null -eq $maxSec -or $stAt -gt $maxSec) { $maxSec = $stAt }
                }
                $sec.firstSeen = $minSec
                $sec.lastSeen = $maxSec
                if ($secList.Count -eq 0) { $sec.status = 'empty' }
                Add-FmpSubCheck -Ctx $ctx -Id 'events.security' -State 'pass'
            }
            catch {
                $msg = $_.Exception.Message
                if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                    $sec.status = 'empty'
                    $sec.logonFailures = 0
                    Add-FmpSubCheck -Ctx $ctx -Id 'events.security' -State 'pass'
                }
                else {
                    $sec.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
                    Add-FmpSubCheck -Ctx $ctx -Id 'events.security' -State $sec.status -Detail @{ reason = $msg }
                    if ($sec.status -eq 'access_denied') {
                        Add-FmpLimitation -Ctx $ctx -Key 'security_log_needs_admin' -DetailText 'Security log requires elevated privileges.'
                    }
                }
            }
            $ctx.data['security'] = $sec
            $ctx.data['restartContext'] = Get-FmpUnexpectedRestartContext -Ctx $ctx -Cutoff $cutoff
        }
        if ($BootHistory) { $ctx.data['bootPerformance'] = Get-FmpBootHistory -Ctx $ctx -Days $BootDays }
        if ($CatalogDays -gt 0) { $ctx.data['catalog'] = Get-FmpEventCatalogData -Ctx $ctx -Days $CatalogDays -MaxPerProvider $CatalogMaxPerProvider }

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'events.log.System' -Summary 'Get-WinEvent FilterHashtable (Level 1,2; StartTime -7d; MaxEvents cap)' -Data $null
    }
}
