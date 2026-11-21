# =====================================================================
# FIX MY PC - Events.ps1 (collector)
# Read-only event log queries. System + Application logs, Error/Critical
# level, last 7 days (configurable), filtered AT THE SOURCE so full logs
# are never loaded. Full mode adds Security (if accessible) and the
# Reliability Monitor data when the RAC provider is available.
# Historical events are recorded but never treated as current faults.
# =====================================================================

function Get-FmpEventData {
    param([int]$WindowDays = 7, [bool]$Full = $false, [int]$MaxPerLog = 2000, [int]$MaxGroups = 40)

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
        }

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'events.log.System' -Summary 'Get-WinEvent FilterHashtable (Level 1,2; StartTime -7d; MaxEvents cap)' -Data $null
    }
}
