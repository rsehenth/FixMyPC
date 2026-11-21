# =====================================================================
# FIX MY PC - Storage.ps1 (collector)
# Read-only: volume space and health, physical disk health, SMART
# failure prediction (when WMI exposes it), and passive volume-to-disk
# correspondence. Absence of SMART data is recorded as
# unknown/access_denied/unsupported - NEVER as "disk is healthy".
# Storage event errors are cross-referenced by the rules engine from
# the events module (no duplicate collection).
# =====================================================================

function Get-FmpStorageData {
    return Invoke-FmpCollector -Name 'storage' -Body {
        param([System.Collections.IDictionary]$ctx)

        $ctx.data['volumes'] = @()
        $ctx.data['physicalDisks'] = @()
        $ctx.data['smart'] = [ordered]@{ status = 'unknown'; checked = 0; items = @() }

        # ---- Volumes: space + health when Get-Volume is available ----
        $healthByLetter = @{}
        $unletteredFixed = New-Object System.Collections.Generic.List[object]
        try {
            $vols = @(Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_ })
            foreach ($v in $vols) {
                $rawLetter = Get-FmpValue $v 'DriveLetter'
                $letterChar = ''
                if ($null -ne $rawLetter) { $letterChar = ([string]$rawLetter).Replace([string][char]0, '').Trim() }
                $hStatus = Get-FmpCleanString (Get-FmpValue $v 'HealthStatus')
                $opRaw = @(@(Get-FmpValue $v 'OperationalStatus') | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
                $opStatus = if ($opRaw.Count -gt 0) { ($opRaw -join ',') } else { $null }
                if ($letterChar -match '^[A-Za-z]$') {
                    $healthByLetter[$letterChar + ':'] = [ordered]@{
                        healthStatus      = $hStatus
                        operationalStatus = $opStatus
                    }
                }
                else {
                    $dType = Get-FmpCleanString (Get-FmpValue $v 'DriveType')
                    if ($dType -eq 'Fixed') {
                        $vSize = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'Size')
                        $vFree = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'SizeRemaining')
                        if ($null -ne $vSize -and $vSize -lt 0) { $vSize = $null }
                        if ($null -ne $vFree -and $vFree -lt 0) { $vFree = $null }
                        $vPct = $null
                        if ($null -ne $vSize -and $vSize -gt 0 -and $null -ne $vFree -and $vFree -le $vSize) {
                            $vPct = [Math]::Round(($vFree / $vSize) * 100, 1)
                        }
                        $unletteredFixed.Add([ordered]@{
                            driveLetter         = $null
                            label               = Get-FmpCleanString (Get-FmpValue $v 'FileSystemLabel')
                            sizeBytes           = $vSize
                            freeBytes           = $vFree
                            freePct             = $vPct
                            isSystem            = $false
                            healthStatus        = $hStatus
                            operationalStatus   = $opStatus
                            physicalDiskIndices = @()
                        })
                    }
                }
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.volumeHealth' -State 'pass'
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.volumeHealth' -State $st -Detail @{ reason = $_.Exception.Message }
            if ($st -ne 'unsupported') { Add-FmpCollectorError -Ctx $ctx -Where 'storage.volumeHealth' -Message $_.Exception.Message }
        }

        # ---- Volume to physical disk correspondence (passive CIM associations) ----
        $diskIndicesByLetter = @{}
        try {
            $partToDisk = @{}
            $d2p = @(Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            foreach ($link in $d2p) {
                $ant = Get-FmpValue $link 'Antecedent'
                $dep = Get-FmpValue $link 'Dependent'
                $antId = if ($ant -is [string]) { $ant } else { [string](Get-FmpValue $ant 'DeviceID') }
                $depId = if ($dep -is [string]) { $dep } else { [string](Get-FmpValue $dep 'DeviceID') }
                if ($antId -match 'PHYSICALDRIVE(\d+)') {
                    $diskIdx = [int]$Matches[1]
                    if ($depId -match '(Disk #\d+,\s*Partition #\d+)') {
                        $partKey = $Matches[1]
                        if (-not $partToDisk.ContainsKey($partKey)) {
                            $partToDisk[$partKey] = New-Object System.Collections.Generic.List[object]
                        }
                        if (-not $partToDisk[$partKey].Contains($diskIdx)) { $partToDisk[$partKey].Add($diskIdx) }
                    }
                }
            }
            if ($partToDisk.Count -gt 0) {
                $l2p = @(Get-CimInstance -ClassName Win32_LogicalDiskToPartition -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
                foreach ($link in $l2p) {
                    $ant = Get-FmpValue $link 'Antecedent'
                    $dep = Get-FmpValue $link 'Dependent'
                    $antId = if ($ant -is [string]) { $ant } else { [string](Get-FmpValue $ant 'DeviceID') }
                    $depId = if ($dep -is [string]) { $dep } else { [string](Get-FmpValue $dep 'DeviceID') }
                    if ($antId -match '(Disk #\d+,\s*Partition #\d+)') {
                        $partKey = $Matches[1]
                        if ($depId -match '([A-Za-z]:)') {
                            $dl = $Matches[1]
                            if ($partToDisk.ContainsKey($partKey)) {
                                if (-not $diskIndicesByLetter.ContainsKey($dl)) {
                                    $diskIndicesByLetter[$dl] = New-Object System.Collections.Generic.List[object]
                                }
                                foreach ($idx in $partToDisk[$partKey]) {
                                    if (-not $diskIndicesByLetter[$dl].Contains($idx)) { $diskIndicesByLetter[$dl].Add($idx) }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Correspondence unavailable; degrade gracefully without failing volumes.
        }

        $vList = New-Object System.Collections.Generic.List[object]
        try {
            $ld = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $sysDrive = Get-FmpSystemDrive
            foreach ($v in $ld) {
                $size = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'Size')
                $free = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'FreeSpace')
                if ($null -ne $size -and $size -lt 0) { $size = $null }
                if ($null -ne $free -and $free -lt 0) { $free = $null }
                $pct = $null
                if ($null -ne $size -and $size -gt 0 -and $null -ne $free -and $free -le $size) {
                    $pct = [Math]::Round(($free / $size) * 100, 1)
                }
                $letter = Get-FmpCleanString (Get-FmpValue $v 'DeviceID')
                $health = $null
                $opStatus = $null
                if (-not [string]::IsNullOrEmpty($letter) -and $healthByLetter.ContainsKey($letter)) {
                    $health = $healthByLetter[$letter].healthStatus
                    $opStatus = $healthByLetter[$letter].operationalStatus
                }
                $mappedDisks = @()
                if (-not [string]::IsNullOrEmpty($letter) -and $diskIndicesByLetter.ContainsKey($letter)) {
                    $mappedDisks = $diskIndicesByLetter[$letter].ToArray()
                }
                $isSys = (-not [string]::IsNullOrEmpty($letter) -and -not [string]::IsNullOrEmpty($sysDrive) -and $letter -eq $sysDrive)
                $vList.Add([ordered]@{
                    driveLetter         = $letter
                    label               = Get-FmpCleanString (Get-FmpValue $v 'VolumeName')
                    sizeBytes           = $size
                    freeBytes           = $free
                    freePct             = $pct
                    isSystem            = $isSys
                    healthStatus        = $health
                    operationalStatus   = $opStatus
                    physicalDiskIndices = $mappedDisks
                })
            }
            foreach ($uv in $unletteredFixed) { $vList.Add($uv) }
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.volumes' -State $(if ($vList.Count -gt 0) { 'pass' } else { 'unknown' }) -Detail @{ count = $vList.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.volumes' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'storage.volumes' -Message $_.Exception.Message
        }
        $ctx.data['volumes'] = $vList.ToArray()

        # ---- Physical disks health ----
        try {
            $pds = @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { $null -ne $_ })
            $pdList = New-Object System.Collections.Generic.List[object]
            $i = 0
            foreach ($d in $pds) {
                $i++
                $sizeBytes = ConvertTo-FmpNullableDouble (Get-FmpValue $d 'Size')
                if ($null -ne $sizeBytes -and $sizeBytes -lt 0) { $sizeBytes = $null }
                $devNum = ConvertTo-FmpNullableInt (Get-FmpValue $d 'DeviceId')
                $opRaw = @(@(Get-FmpValue $d 'OperationalStatus') | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
                $pdList.Add([ordered]@{
                    index             = $i
                    deviceId          = $devNum
                    friendlyName      = Get-FmpCleanString (Get-FmpValue $d 'FriendlyName')
                    mediaType         = Get-FmpCleanString (Get-FmpValue $d 'MediaType')
                    busType           = Get-FmpCleanString (Get-FmpValue $d 'BusType')
                    healthStatus      = Get-FmpCleanString (Get-FmpValue $d 'HealthStatus')
                    operationalStatus = if ($opRaw.Count -gt 0) { ($opRaw -join ',') } else { $null }
                    sizeBytes         = $sizeBytes
                })
            }
            $ctx.data['physicalDisks'] = $pdList.ToArray()
            $pdState = if ($pdList.Count -gt 0) { 'pass' } else { 'unknown' }
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.physicalDisks' -State $pdState -Detail @{ count = $pdList.Count }
        }
        catch {
            $ctx.data['physicalDisks'] = @()
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.physicalDisks' -State $st -Detail @{ reason = $_.Exception.Message }
            if ($st -ne 'unsupported') { Add-FmpCollectorError -Ctx $ctx -Where 'storage.physicalDisks' -Message $_.Exception.Message }
        }

        # ---- SMART failure prediction (often needs admin; absence != healthy) ----
        $smart = [ordered]@{ status = 'ok'; checked = 0; items = @() }
        try {
            $sp = @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSStorageDriver_FailurePredictStatus' -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $sList = New-Object System.Collections.Generic.List[object]
            $i = 0
            foreach ($s in $sp) {
                $i++
                $pred = Get-FmpValue $s 'PredictFailure'
                if ($pred -isnot [bool]) { $pred = $null }
                $act = Get-FmpValue $s 'Active'
                if ($act -isnot [bool]) { $act = $null }
                $sList.Add([ordered]@{
                    index          = $i
                    predictFailure = $pred
                    reason         = ConvertTo-FmpNullableInt (Get-FmpValue $s 'Reason')
                    active         = $act
                })
            }
            $smart.items = $sList.ToArray()
            $smart.checked = $sList.Count
            if ($sList.Count -eq 0) { $smart.status = 'empty' }
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.smart' -State $(if ($smart.checked -gt 0) { 'pass' } else { 'unknown' }) -Detail @{ checked = $smart.checked }
        }
        catch {
            $msg = $_.Exception.Message
            $smart.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
            $smart.note = 'SMART status unavailable; disk health cannot be confirmed from this data.'
            Add-FmpSubCheck -Ctx $ctx -Id 'storage.smart' -State $smart.status
            Add-FmpLimitation -Ctx $ctx -Key 'smart_unavailable' -DetailText $msg
            if ($smart.status -ne 'unsupported') { Add-FmpCollectorError -Ctx $ctx -Where 'storage.smart' -Message $msg }
        }
        $ctx.data['smart'] = $smart

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'storage.volumes' -Summary 'Win32_LogicalDisk + Get-Volume health + Get-PhysicalDisk + SMART predict status' -Data $null
    }
}
