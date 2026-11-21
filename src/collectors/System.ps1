# =====================================================================
# FIX MY PC - System.ps1 (collector)
# Read-only: OS, build, CPU, memory, GPU, disks, volumes, uptime.
# Never collected: serial numbers, product keys, machine GUIDs.
# Every sub-check is isolated; failures degrade to per-check states.
# =====================================================================

function Get-FmpSystemData {
    return Invoke-FmpCollector -Name 'system' -Body {
        param([System.Collections.IDictionary]$ctx)

        $ctx.data['os'] = $null
        $ctx.data['cpu'] = $null
        $ctx.data['memory'] = $null
        $ctx.data['gpu'] = @()
        $ctx.data['disks'] = @()
        $ctx.data['volumes'] = @()

        # ---- OS core ----
        $os = $null
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
            Add-FmpSubCheck -Ctx $ctx -Id 'system.os' -State $(if ($null -ne $os) { 'pass' } else { 'unknown' })
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'system.os' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'system.os' -Message $_.Exception.Message
        }

        if ($null -ne $os) {
            $lastBoot = Get-FmpParsedDate -Value (Get-FmpValue $os 'LastBootUpTime')
            $installDate = Get-FmpParsedDate -Value (Get-FmpValue $os 'InstallDate')
            $uptimeHours = $null
            try {
                if ($null -ne $lastBoot) {
                    $hours = ((Get-Date) - $lastBoot).TotalHours
                    if ($hours -ge 0) {
                        $uptimeHours = [Math]::Round($hours, 1)
                        Add-FmpSubCheck -Ctx $ctx -Id 'system.uptime' -State 'pass'
                    }
                    else {
                        Add-FmpLimitation -Ctx $ctx -Key 'uptime_clock_skew' -DetailText 'LastBootUpTime is in the future relative to current clock; uptime omitted.'
                        Add-FmpSubCheck -Ctx $ctx -Id 'system.uptime' -State 'unknown'
                    }
                }
                else {
                    Add-FmpSubCheck -Ctx $ctx -Id 'system.uptime' -State 'unknown'
                }
            }
            catch {
                Add-FmpSubCheck -Ctx $ctx -Id 'system.uptime' -State 'unknown'
            }

            $ctx.data['os'] = [ordered]@{
                caption       = Get-FmpCleanString (Get-FmpValue $os 'Caption')
                version       = Get-FmpCleanString (Get-FmpValue $os 'Version')
                buildNumber   = Get-FmpCleanString (Get-FmpValue $os 'BuildNumber')
                architecture  = Get-FmpCleanString (Get-FmpValue $os 'OSArchitecture')
                installDate   = $installDate
                lastBootAt    = $lastBoot
                uptimeHours   = $uptimeHours
                localeId      = $null
            }

            # Memory totals live here too (KB units from WMI).
            $totalKB = ConvertTo-FmpNullableDouble (Get-FmpValue $os 'TotalVisibleMemorySize')
            $freeKB = ConvertTo-FmpNullableDouble (Get-FmpValue $os 'FreePhysicalMemory')
            if ($null -ne $totalKB -and $totalKB -gt 0 -and $null -ne $freeKB -and $freeKB -ge 0 -and $freeKB -le $totalKB) {
                $ctx.data['memory'] = [ordered]@{
                    totalBytes   = $totalKB * 1KB
                    freeBytes    = $freeKB * 1KB
                    availablePct = [Math]::Round(($freeKB / $totalKB) * 100, 1)
                }
                Add-FmpSubCheck -Ctx $ctx -Id 'system.memory' -State 'pass'
            }
            else {
                Add-FmpSubCheck -Ctx $ctx -Id 'system.memory' -State 'unknown'
            }
        }

        # ---- Build details (registry, read-only) ----
        try {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $osd = $ctx.data['os']
            if ($null -ne $osd -and $null -ne $cv) {
                $ctx.data['os']['displayVersion'] = Get-FmpCleanString (Get-FmpValue $cv 'DisplayVersion')
                $ctx.data['os']['releaseId']      = Get-FmpCleanString (Get-FmpValue $cv 'ReleaseId')
                $ctx.data['os']['currentBuild']   = Get-FmpCleanString (Get-FmpValue $cv 'CurrentBuildNumber')
                $ctx.data['os']['ubr']            = ConvertTo-FmpNullableInt (Get-FmpValue $cv 'UBR')
                $ctx.data['os']['editionId']      = Get-FmpCleanString (Get-FmpValue $cv 'EditionID')
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'system.build' -State $(if ($null -ne $cv) { 'pass' } else { 'unknown' })
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            if ($st -eq 'error') { $st = 'unknown' }
            Add-FmpSubCheck -Ctx $ctx -Id 'system.build' -State $st -Detail @{ reason = $_.Exception.Message }
        }

        # ---- CPU ----
        try {
            $cpus = @(Get-CimInstance -ClassName Win32_Processor -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            if ($cpus.Count -gt 0) {
                $first = $cpus[0]
                $coresSum = $null
                $logicalSum = $null
                $hasCores = $false
                $hasLogical = $false
                foreach ($c in $cpus) {
                    $nc = ConvertTo-FmpNullableInt (Get-FmpValue $c 'NumberOfCores')
                    if ($null -ne $nc -and $nc -ge 0) {
                        if (-not $hasCores) { $coresSum = 0; $hasCores = $true }
                        $coresSum += $nc
                    }
                    $nl = ConvertTo-FmpNullableInt (Get-FmpValue $c 'NumberOfLogicalProcessors')
                    if ($null -ne $nl -and $nl -ge 0) {
                        if (-not $hasLogical) { $logicalSum = 0; $hasLogical = $true }
                        $logicalSum += $nl
                    }
                }
                $cpuName = Get-FmpCleanString (Get-FmpValue $first 'Name')
                $clock = ConvertTo-FmpNullableInt (Get-FmpValue $first 'MaxClockSpeed')
                $ctx.data['cpu'] = [ordered]@{
                    name              = $cpuName
                    cores             = $coresSum
                    logicalProcessors = $logicalSum
                    maxClockMhz       = $clock
                }
                $cpuState = if ($null -ne $cpuName -and ($null -ne $coresSum -or $null -ne $logicalSum)) { 'pass' } else { 'unknown' }
                Add-FmpSubCheck -Ctx $ctx -Id 'system.cpu' -State $cpuState
            }
            else { Add-FmpSubCheck -Ctx $ctx -Id 'system.cpu' -State 'unknown' }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'system.cpu' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'system.cpu' -Message $_.Exception.Message
        }

        # ---- GPU (AdapterRAM is uint32 and saturates above 4 GB; documented) ----
        try {
            $gpus = @(Get-CimInstance -ClassName Win32_VideoController -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($g in $gpus) {
                $gName = Get-FmpCleanString (Get-FmpValue $g 'Name')
                if ($null -eq $gName) { continue }
                $list.Add([ordered]@{
                    name          = $gName
                    driverVersion = Get-FmpCleanString (Get-FmpValue $g 'DriverVersion')
                    status        = Get-FmpCleanString (Get-FmpValue $g 'Status')
                })
            }
            $ctx.data['gpu'] = $list.ToArray()
            if ($list.Count -gt 0) {
                Add-FmpLimitation -Ctx $ctx -Key 'gpu_ram_uint32' -DetailText 'VRAM above 4 GB is not reported precisely by Win32_VideoController.'
                Add-FmpSubCheck -Ctx $ctx -Id 'system.gpu' -State 'pass'
            }
            else {
                Add-FmpSubCheck -Ctx $ctx -Id 'system.gpu' -State 'unknown'
            }
        }
        catch {
            $ctx.data['gpu'] = @()
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            if ($st -eq 'error') { $st = 'unknown' }
            Add-FmpSubCheck -Ctx $ctx -Id 'system.gpu' -State $st
        }

        # ---- Physical disks (no serial numbers) ----
        try {
            $disks = @(Get-CimInstance -ClassName Win32_DiskDrive -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $list = New-Object System.Collections.Generic.List[object]
            $i = 0
            foreach ($d in $disks) {
                $i++
                $sizeBytes = ConvertTo-FmpNullableDouble (Get-FmpValue $d 'Size')
                if ($null -ne $sizeBytes -and $sizeBytes -lt 0) { $sizeBytes = $null }
                $list.Add([ordered]@{
                    index         = $i
                    model         = Get-FmpCleanString (Get-FmpValue $d 'Model')
                    sizeBytes     = $sizeBytes
                    status        = Get-FmpCleanString (Get-FmpValue $d 'Status')
                    interfaceType = Get-FmpCleanString (Get-FmpValue $d 'InterfaceType')
                })
            }
            $ctx.data['disks'] = $list.ToArray()
            Add-FmpSubCheck -Ctx $ctx -Id 'system.disks' -State $(if ($list.Count -gt 0) { 'pass' } else { 'unknown' })
        }
        catch {
            $ctx.data['disks'] = @()
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'system.disks' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'system.disks' -Message $_.Exception.Message
        }

        # ---- Logical volumes ----
        try {
            $vols = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $list = New-Object System.Collections.Generic.List[object]
            $sysDrive = Get-FmpSystemDrive
            foreach ($v in $vols) {
                $size = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'Size')
                $free = ConvertTo-FmpNullableDouble (Get-FmpValue $v 'FreeSpace')
                if ($null -ne $size -and $size -lt 0) { $size = $null }
                if ($null -ne $free -and $free -lt 0) { $free = $null }
                $pct = $null
                if ($null -ne $size -and $size -gt 0 -and $null -ne $free -and $free -le $size) {
                    $pct = [Math]::Round(($free / $size) * 100, 1)
                }
                $letter = Get-FmpCleanString (Get-FmpValue $v 'DeviceID')
                $isSys = (-not [string]::IsNullOrEmpty($letter) -and -not [string]::IsNullOrEmpty($sysDrive) -and $letter -eq $sysDrive)
                $list.Add([ordered]@{
                    driveLetter = $letter
                    label       = Get-FmpCleanString (Get-FmpValue $v 'VolumeName')
                    sizeBytes   = $size
                    freeBytes   = $free
                    freePct     = $pct
                    isSystem    = $isSys
                })
            }
            $ctx.data['volumes'] = $list.ToArray()
            Add-FmpSubCheck -Ctx $ctx -Id 'system.volumes' -State $(if ($list.Count -gt 0) { 'pass' } else { 'unknown' })
        }
        catch {
            $ctx.data['volumes'] = @()
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'system.volumes' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'system.volumes' -Message $_.Exception.Message
        }

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'system.os' -Summary 'WMI Win32_OperatingSystem + registry CurrentVersion + Win32_Processor/VideoController/DiskDrive/LogicalDisk' -Data $null
    }
}
