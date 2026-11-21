# =====================================================================
# FIX MY PC - Advanced.ps1 (collector, FULL mode only)
# Read-only extra checks: problem devices, driver versions for problem
# devices, Defender status, third-party AV registration, pending-reboot
# indicators, hotfix recency, installed apps from registry (never
# Win32_Product). Anything not passively viable stays not_collected.
# =====================================================================

function ConvertTo-FmpHotfixDate {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $iso = Get-FmpParsedDate -Value $Value
    if ($null -ne $iso) { return $iso }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    foreach ($fmt in @('M/d/yyyy', 'MM/dd/yyyy', 'yyyy-MM-dd', 'yyyyMMdd')) {
        try {
            return [DateTime]::ParseExact($s, $fmt, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind)
        }
        catch { }
    }
    return $null
}

function Get-FmpAdvancedData {
    param([int]$MaxApps = 300)

    return Invoke-FmpCollector -Name 'advanced' -Body {
        param([System.Collections.IDictionary]$ctx)

        if ($MaxApps -lt 1) { $MaxApps = 1 }

        # ---- Problem devices ----
        $problem = New-Object System.Collections.Generic.List[object]
        $problemStatus = 'ok'
        try {
            $devs = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            foreach ($d in $devs) {
                if ($problem.Count -ge 50) {
                    Add-FmpLimitation -Ctx $ctx -Key 'problem_devices_truncated' -DetailText 'Problem devices list capped at 50 entries.'
                    break
                }
                $code = ConvertTo-FmpNullableInt (Get-FmpValue $d 'ConfigManagerErrorCode')
                $problem.Add([ordered]@{
                    name     = Get-FmpCleanString (Get-FmpValue $d 'Name')
                    deviceId = Get-FmpCleanString (Get-FmpValue $d 'DeviceID')
                    code     = $code
                })
            }
            $ctx.data['problemDevices'] = [ordered]@{ status = 'ok'; count = $problem.Count; items = $problem.ToArray() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.problemDevices' -State 'pass' -Detail @{ count = $problem.Count }
        }
        catch {
            $problemStatus = Resolve-FmpCollectorErrorState -ErrorRecord $_
            $ctx.data['problemDevices'] = [ordered]@{ status = $problemStatus; count = 0; items = @() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.problemDevices' -State $problemStatus -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'advanced.problemDevices' -Message $_.Exception.Message
        }

        # ---- Driver versions for problem devices only (full enumeration is slow) ----
        $drv = [ordered]@{ status = 'ok'; items = @() }
        if ($problemStatus -eq 'ok' -and $problem.Count -gt 0 -and $problem.Count -le 10) {
            try {
                $allDrv = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
                $driverByDev = @{}
                foreach ($d in $allDrv) {
                    $did = Get-FmpCleanString (Get-FmpValue $d 'DeviceID')
                    if ($null -ne $did -and -not $driverByDev.ContainsKey($did)) {
                        $driverByDev[$did] = $d
                    }
                }
                $dList = New-Object System.Collections.Generic.List[object]
                foreach ($p in $problem) {
                    if ($null -eq $p.deviceId -or -not $driverByDev.ContainsKey($p.deviceId)) { continue }
                    $d = $driverByDev[$p.deviceId]
                    $rawSigned = Get-FmpValue $d 'IsSigned'
                    $signed = if ($rawSigned -is [bool]) { $rawSigned } else { $null }
                    $dList.Add([ordered]@{
                        deviceName = $p.name
                        version    = Get-FmpCleanString (Get-FmpValue $d 'DriverVersion')
                        provider   = Get-FmpCleanString (Get-FmpValue $d 'DriverProviderName')
                        signed     = $signed
                        driverDate = Get-FmpParsedDate -Value (Get-FmpValue $d 'DriverDate')
                    })
                }
                $drv.items = $dList.ToArray()
                Add-FmpSubCheck -Ctx $ctx -Id 'advanced.driverInfo' -State 'pass'
            }
            catch {
                $drv.status = Resolve-FmpCollectorErrorState -ErrorRecord $_
                Add-FmpSubCheck -Ctx $ctx -Id 'advanced.driverInfo' -State $drv.status -Detail @{ reason = $_.Exception.Message }
            }
        }
        else {
            $drv.status = 'not_collected'
            if ($problem.Count -gt 10) { Add-FmpLimitation -Ctx $ctx -Key 'too_many_problem_devices' -DetailText 'Driver details capped to runs with at most 10 problem devices.' }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.driverInfo' -State 'not_collected'
        }
        $ctx.data['driverInfo'] = $drv

        # ---- Defender status ----
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($null -eq $mp) {
                $ctx.data['defender'] = [ordered]@{ status = 'unknown'; data = $null }
                Add-FmpSubCheck -Ctx $ctx -Id 'advanced.defender' -State 'unknown'
            }
            else {
                $am = Get-FmpValue $mp 'AMServiceEnabled'
                $av = Get-FmpValue $mp 'AntivirusEnabled'
                $rt = Get-FmpValue $mp 'RealTimeProtectionEnabled'
                $bm = Get-FmpValue $mp 'BehaviorMonitorEnabled'
                $ctx.data['defender'] = [ordered]@{
                    status = 'ok'
                    data   = [ordered]@{
                        amServiceEnabled     = $(if ($am -is [bool]) { $am } else { $null })
                        antivirusEnabled     = $(if ($av -is [bool]) { $av } else { $null })
                        realTimeProtection   = $(if ($rt -is [bool]) { $rt } else { $null })
                        behaviorMonitor      = $(if ($bm -is [bool]) { $bm } else { $null })
                        signatureLastUpdated = Get-FmpParsedDate -Value (Get-FmpValue $mp 'AntivirusSignatureLastUpdated')
                        signatureAgeDays     = ConvertTo-FmpNullableInt (Get-FmpValue $mp 'AntivirusSignatureAge')
                        quickScanEnd         = Get-FmpParsedDate -Value (Get-FmpValue $mp 'QuickScanEndTime')
                        fullScanEnd          = Get-FmpParsedDate -Value (Get-FmpValue $mp 'FullScanEndTime')
                    }
                }
                Add-FmpSubCheck -Ctx $ctx -Id 'advanced.defender' -State 'pass'
            }
        }
        catch {
            $state = Resolve-FmpCollectorErrorState -ErrorRecord $_
            $ctx.data['defender'] = [ordered]@{ status = $state; data = $null }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.defender' -State $state -Detail @{ reason = $_.Exception.Message }
        }

        # ---- Third-party AV registered with Security Center ----
        try {
            $avs = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            $aList = New-Object System.Collections.Generic.List[object]
            $seenAv = @{}
            foreach ($a in $avs) {
                $dName = Get-FmpCleanString (Get-FmpValue $a 'displayName')
                if ($null -eq $dName) { continue }
                if ($dName -in @('Windows Defender', 'Microsoft Defender', 'Microsoft Defender Antivirus', 'Windows Defender Antivirus')) { continue }
                $pState = ConvertTo-FmpNullableInt (Get-FmpValue $a 'productState')
                $avKey = $dName + '|' + [string]$pState
                if ($seenAv.ContainsKey($avKey)) { continue }
                $seenAv[$avKey] = $true
                $aList.Add([ordered]@{
                    displayName  = $dName
                    productState = $pState
                })
            }
            $ctx.data['thirdPartyAv'] = [ordered]@{ status = 'ok'; count = $aList.Count; items = $aList.ToArray() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.thirdPartyAv' -State 'pass' -Detail @{ count = $aList.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            $ctx.data['thirdPartyAv'] = [ordered]@{ status = $st; count = 0; items = @() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.thirdPartyAv' -State $st -Detail @{ reason = $_.Exception.Message }
        }

        # ---- Pending reboot indicators (registry existence checks) ----
        $pr = [ordered]@{ status = 'ok'; pendingWuReboot = $false; pendingCbs = $false; pendingFileRename = $false }
        try {
            $pr.pendingWuReboot = [bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop)
            $pr.pendingCbs = [bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop)
            $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
            $renames = @(Get-FmpValue $sm 'PendingFileRenameOperations' | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $pr.pendingFileRename = ($renames.Count -gt 0)
            $pr['any'] = ($pr.pendingWuReboot -or $pr.pendingCbs -or $pr.pendingFileRename)
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.pendingReboot' -State 'pass'
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            $pr.status = $st
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.pendingReboot' -State $st -Detail @{ reason = $_.Exception.Message }
        }
        $ctx.data['pendingReboot'] = $pr

        # ---- Windows Update pending scan: intentionally NOT performed ----
        # A COM UpdateSession search activates the Windows Update Agent and
        # network traffic - outside the passive-only policy. Pending-reboot
        # registry indicators above cover the actionable part passively.
        $ctx.data['updates'] = [ordered]@{
            status = 'not_collected'
            justification = 'Querying Windows Update via COM starts update-agent activity and network access; not passive. Use Settings > Windows Update to verify.'
        }
        Add-FmpSubCheck -Ctx $ctx -Id 'advanced.updates' -State 'not_collected'

        # ---- Hotfix recency ----
        try {
            $hfRaw = @(Get-HotFix -ErrorAction Stop | Where-Object { $null -ne $_ })
            $dated = New-Object System.Collections.Generic.List[object]
            foreach ($h in $hfRaw) {
                $dt = ConvertTo-FmpHotfixDate -Value (Get-FmpValue $h 'InstalledOn')
                if ($null -eq $dt) { continue }
                $dated.Add([ordered]@{
                    hotFixId    = Get-FmpCleanString (Get-FmpValue $h 'HotFixID')
                    description = Get-FmpCleanString (Get-FmpValue $h 'Description')
                    installedOn = $dt
                })
            }
            $sorted = @($dated | Sort-Object -Property { $_['installedOn'] } -Descending | Select-Object -First 5)
            $latest = $null
            if ($sorted.Count -gt 0) { $latest = $sorted[0].installedOn }
            $ctx.data['hotfixes'] = [ordered]@{ status = 'ok'; latest = $latest; items = $sorted }
            Add-FmpLimitation -Ctx $ctx -Key 'hotfixes_cbs_only' -DetailText 'Get-HotFix reflects CBS quick-fix engineering records only; absence does not prove missing updates.'
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.hotfixes' -State 'pass'
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            if ($st -eq 'error') { $st = 'unknown' }
            $ctx.data['hotfixes'] = [ordered]@{ status = $st; latest = $null; items = @() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.hotfixes' -State $st
        }

        # ---- Installed apps from registry uninstall keys (never Win32_Product) ----
        $wow64 = Test-FmpIsWow64Process
        if ($wow64) {
            Add-FmpLimitation -Ctx $ctx -Key 'wow64_32bit_process' -DetailText 'Running in 32-bit PowerShell on 64-bit Windows: HKLM 64-bit uninstall view is redirected to 32-bit view.'
        }
        $appPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $apps = New-Object System.Collections.Generic.List[object]
        $total = 0
        $pathFailures = 0
        $lastAppErr = 'error'
        $seenApps = @{}
        foreach ($ap in $appPaths) {
            if ($wow64 -and $ap -like '*WOW6432Node*') { continue }
            $loc = if ($ap -like '*WOW6432Node*') { 'hklm32' } elseif ($ap -like '*HKCU*') { 'hkcu' } elseif ($wow64) { 'hklm32' } else { 'hklm64' }
            try {
                # FMP-03: only allowlisted Uninstall keys are read; anything else throws before any query.
                $parentKey = Get-FmpSafeRegistryPath ($ap.Substring(0, $ap.Length - 2))
                $uninstallKey = Get-FmpSafeRegistryPath $ap
                if (-not (Test-Path -LiteralPath $parentKey -ErrorAction Stop)) { continue }
                foreach ($k in @(Get-ItemProperty -Path $uninstallKey -ErrorAction Stop | Where-Object { $null -ne $_ })) {
                    $dName = Get-FmpCleanString (Get-FmpValue $k 'DisplayName')
                    if ($null -eq $dName) { continue }
                    $dVer = Get-FmpCleanString (Get-FmpValue $k 'DisplayVersion')
                    $appKey = $loc + '|' + $dName + '|' + [string]$dVer
                    if ($seenApps.ContainsKey($appKey)) { continue }
                    $seenApps[$appKey] = $true
                    $total++
                    if ($apps.Count -ge $MaxApps) { continue }
                    $estSize = ConvertTo-FmpNullableInt (Get-FmpValue $k 'EstimatedSize')
                    if ($null -ne $estSize -and $estSize -lt 0) { $estSize = $null }
                    $apps.Add([ordered]@{
                        displayName     = $dName
                        displayVersion  = $dVer
                        publisher       = Get-FmpCleanString (Get-FmpValue $k 'Publisher')
                        installDate     = Get-FmpCleanString (Get-FmpValue $k 'InstallDate')
                        estimatedSizeKB = $estSize
                        source          = $loc
                    })
                }
            }
            catch {
                $pathFailures++
                $lastAppErr = Resolve-FmpCollectorErrorState -ErrorRecord $_
                Add-FmpCollectorError -Ctx $ctx -Where ('advanced.installedApps.' + $loc) -Message $_.Exception.Message
            }
        }
        if ($total -eq 0 -and $pathFailures -gt 0) {
            $ctx.data['installedApps'] = [ordered]@{ status = $lastAppErr; totalCount = 0; truncated = $false; items = @() }
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.installedApps' -State $lastAppErr
        }
        else {
            $ctx.data['installedApps'] = [ordered]@{
                status     = 'ok'
                totalCount = $total
                truncated  = ($total -gt $apps.Count)
                items      = $apps.ToArray()
            }
            Add-FmpLimitation -Ctx $ctx -Key 'apps_registry_only' -DetailText 'Store apps and apps without an uninstall entry are not listed.'
            Add-FmpSubCheck -Ctx $ctx -Id 'advanced.installedApps' -State $(if ($pathFailures -gt 0) { 'unknown' } else { 'pass' }) -Detail @{ count = $total }
        }

        # ---- Authenticode is unavailable under the offline policy ----
        $ctx.data['signatures'] = [ordered]@{
            status = 'not_collected'; checked = 0; truncated = $false; items = @()
        }
        Add-FmpSubCheck -Ctx $ctx -Id 'advanced.signatures' -State 'not_collected'
        Add-FmpLimitation -Ctx $ctx -Key 'signature_offline_unverified' -DetailText 'Authenticode verification may retrieve certificate trust data. Offline verification is not implemented.'

        $null = New-FmpEvidence -Ctx $ctx -CheckId 'advanced.problemDevices' -Summary 'Win32_PnPEntity problems, Defender status, SecurityCenter2, pending reboot, uninstall keys' -Data $null
    }
}
