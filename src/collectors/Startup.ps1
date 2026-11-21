# =====================================================================
# FIX MY PC - Startup.ps1 (collector)
# Read-only inventory of auto-start locations: registry Run/RunOnce
# (HKCU, HKLM 64-bit view, WOW6432Node 32-bit view when present), user
# and common Startup folders, logon-trigger scheduled tasks, automatic
# services. Only metadata is collected; nothing is executed or opened.
# =====================================================================

function Get-FmpStartupFolderPath {
    param([Parameter(Mandatory)][ValidateSet('user', 'common')][string]$Scope)
    $folder = if ($Scope -eq 'user') { [Environment+SpecialFolder]::Startup } else { [Environment+SpecialFolder]::CommonStartup }
    return [Environment]::GetFolderPath($folder, [Environment+SpecialFolderOption]::DoNotVerify)
}

function Get-FmpCommandPathState {
    param([object]$RawCommand)
    if ($null -eq $RawCommand -or $RawCommand -isnot [string]) { return 'empty' }
    $s = $RawCommand.Trim()
    if ($s -eq '') { return 'empty' }
    if ($s -match '^"?\\\\') { return 'unc' }
    if ($s -match '[:*?"<>|]' -and $s -notmatch '^"?[A-Za-z]:[\\/]') { return 'invalid' }
    if ($s -match '^"?[A-Za-z]:[\\/][^"*?<>|\r\n]+') { return 'valid_syntax' }
    return 'unidentifiable'
}

function Get-FmpStartupData {
    param([int]$MaxItems = 300)

    return Invoke-FmpCollector -Name 'startup' -Body {
        param([System.Collections.IDictionary]$ctx)
        if ($MaxItems -lt 1) { $MaxItems = 1 }
        $items = New-Object System.Collections.Generic.List[object]
        $ctx.data['items'] = @()
        $ctx.data['logonTasks'] = @()
        $ctx.data['autoServices'] = @()

        $wow64 = Test-FmpIsWow64Process
        if ($wow64) {
            Add-FmpLimitation -Ctx $ctx -Key 'wow64_32bit_process' -DetailText 'Running in 32-bit PowerShell on 64-bit Windows: HKLM 64-bit view is redirected to 32-bit view.'
        }

        # ---- Registry Run / RunOnce ----
        $runPaths = @(
            @{ source = 'HKCU'; view = '64'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';       kind = 'run' },
            @{ source = 'HKCU'; view = '64'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce';  kind = 'runOnce' },
            @{ source = 'HKLM'; view = '64'; path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';       kind = 'run' },
            @{ source = 'HKLM'; view = '64'; path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce';  kind = 'runOnce' },
            @{ source = 'HKLM'; view = '32'; path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';      kind = 'run' },
            @{ source = 'HKLM'; view = '32'; path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; kind = 'runOnce' }
        )
        $no32BitLimitationAdded = $false
        $regFailureState = $null
        $regTruncated = $false
        $seenReg = @{}
        foreach ($rp in $runPaths) {
            if ($wow64 -and $rp.view -eq '32') { continue }
            $effectiveView = if ($wow64 -and $rp.source -eq 'HKLM') { '32' } else { $rp.view }
            try {
                # FMP-03: only allowlisted Run/RunOnce keys are read; anything else throws before any query.
                $runKey = Get-FmpSafeRegistryPath $rp.path
                if (-not (Test-Path -LiteralPath $runKey -ErrorAction Stop)) {
                    if ($rp.view -eq '32' -and -not $no32BitLimitationAdded) {
                        Add-FmpLimitation -Ctx $ctx -Key 'no_32bit_view' -DetailText 'WOW6432Node not present (32-bit OS?).'
                        $no32BitLimitationAdded = $true
                    }
                    continue
                }
                $props = Get-ItemProperty -Path $runKey -ErrorAction Stop
                if ($null -eq $props) { continue }
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    if ($null -eq $p.Value -or $p.Value -isnot [string]) { continue }
                    $dedupeKey = $rp.source + '|' + $effectiveView + '|' + $rp.kind + '|' + $p.Name
                    if ($seenReg.ContainsKey($dedupeKey)) { continue }
                    $seenReg[$dedupeKey] = $true
                    $items.Add([ordered]@{
                        kind      = $rp.kind
                        name      = $p.Name
                        command   = $null
                        pathState = Get-FmpCommandPathState -RawCommand $p.Value
                        source    = $rp.source
                        view      = $effectiveView
                        origin    = 'registry'
                    })
                    if ($items.Count -ge $MaxItems) { $regTruncated = $true; break }
                }
            }
            catch {
                $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
                if ($null -eq $regFailureState -or $st -eq 'error') { $regFailureState = $st }
                Add-FmpCollectorError -Ctx $ctx -Where ('startup.' + $rp.source + $effectiveView) -Message $_.Exception.Message
            }
            if ($items.Count -ge $MaxItems) { break }
        }
        if ($regTruncated) {
            Add-FmpLimitation -Ctx $ctx -Key 'startup_items_truncated' -DetailText ('Startup items reached cap of ' + $MaxItems + '.') -Values @($MaxItems)
        }
        $regSubState = if ($null -ne $regFailureState) { $regFailureState } else { 'pass' }
        Add-FmpSubCheck -Ctx $ctx -Id 'startup.registry' -State $regSubState -Detail @{ count = $items.Count }

        # ---- Startup folders (shortcut targets are not parsed - passive limit) ----
        $foldersBefore = $items.Count
        $folderSubState = 'pass'
        $scannedFolderPaths = New-Object System.Collections.Generic.List[string]
        foreach ($f in @(@{ kind = 'folder'; label = 'user' }, @{ kind = 'folder'; label = 'common' })) {
            try {
                if ($items.Count -ge $MaxItems) { break }
                $dir = Get-FmpStartupFolderPath -Scope $f.label
                if ([string]::IsNullOrWhiteSpace($dir)) { continue }
                if ($dir -like '\\*') {
                    Add-FmpLimitation -Ctx $ctx -Key ('startup_folder_network_' + $f.label) -DetailText 'Redirected network/UNC Startup folder skipped under passive offline policy.' -LocaleKey 'startup_folder_network'
                    if ($folderSubState -eq 'pass') { $folderSubState = 'unknown' }
                    continue
                }
                $checkedDir = $null
                try {
                    $checkedDir = Get-FmpCheckedPath $dir
                }
                catch {
                    Add-FmpLimitation -Ctx $ctx -Key ('startup_folder_skipped_' + $f.label) -DetailText ('Startup folder could not be inspected passively: ' + $_.Exception.Message) -LocaleKey 'startup_folder_skipped'
                    if ($folderSubState -eq 'pass') { $folderSubState = 'unknown' }
                    continue
                }
                if ([string]::IsNullOrEmpty($checkedDir) -or -not (Test-Path -LiteralPath $checkedDir -ErrorAction Stop)) { continue }
                if ($scannedFolderPaths.Contains($checkedDir)) { continue }
                $scannedFolderPaths.Add($checkedDir)
                foreach ($file in @(Get-ChildItem -LiteralPath $checkedDir -File -ErrorAction Stop | Where-Object { $null -ne $_ })) {
                    $isReparse = $false
                    $attrs = Get-FmpValue $file 'Attributes'
                    if ($null -ne $attrs -and ($attrs -band [System.IO.FileAttributes]::ReparsePoint)) { $isReparse = $true }
                    $items.Add([ordered]@{
                        kind         = $f.kind
                        name         = Get-FmpCleanString (Get-FmpValue $file 'Name')
                        command      = $null
                        reparsePoint = $isReparse
                        source       = $f.label
                        view         = $null
                        origin       = 'startupFolder'
                    })
                    if ($items.Count -ge $MaxItems) { break }
                }
            }
            catch {
                $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
                $folderSubState = $st
                Add-FmpCollectorError -Ctx $ctx -Where ('startup.folder.' + $f.label) -Message $_.Exception.Message
            }
            if ($items.Count -ge $MaxItems) { break }
        }
        $ctx.data['items'] = $items.ToArray()
        Add-FmpLimitation -Ctx $ctx -Key 'startup_lnk_not_parsed' -DetailText 'Shortcut (.lnk) targets and publishers are not resolved: passive-only policy avoids COM shell automation and file inspection.'
        Add-FmpSubCheck -Ctx $ctx -Id 'startup.folders' -State $folderSubState -Detail @{ count = ($items.Count - $foldersBefore) }

        # ---- Scheduled tasks with logon triggers ----
        $tasks = New-Object System.Collections.Generic.List[object]
        $seenTasks = @{}
        try {
            $allTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $null -ne $_ })
            foreach ($t in $allTasks) {
                $isLogon = $false
                try {
                    $trgs = @(Get-FmpValue $t 'Triggers')
                    foreach ($trg in $trgs) {
                        if ($null -eq $trg) { continue }
                        $cname = Get-FmpValue $trg 'CimClass.CimClassName'
                        if ($cname -eq 'MSFT_TaskLogonTrigger') { $isLogon = $true; break }
                    }
                }
                catch { continue }
                if (-not $isLogon) { continue }
                if ($tasks.Count -ge 100) {
                    Add-FmpLimitation -Ctx $ctx -Key 'startup_logon_tasks_truncated' -DetailText 'Logon scheduled tasks capped at 100 entries.'
                    break
                }
                $tName = Get-FmpCleanString (Get-FmpValue $t 'TaskName')
                $tPath = Get-FmpCleanString (Get-FmpValue $t 'TaskPath')
                $tKey = [string]$tPath + '|' + [string]$tName
                if ($seenTasks.ContainsKey($tKey)) { continue }
                $seenTasks[$tKey] = $true
                $exec = $null
                try {
                    $a = @(Get-FmpValue $t 'Actions') | Select-Object -First 1
                    if ($null -ne $a) { $exec = Get-FmpCleanString (Get-FmpValue $a 'Execute') }
                }
                catch { }
                $tasks.Add([ordered]@{
                    name   = $tName
                    path   = $tPath
                    state  = Get-FmpCleanString (Get-FmpValue $t 'State')
                    action = $exec
                })
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'startup.logonTasks' -State 'pass' -Detail @{ count = $tasks.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'startup.logonTasks' -State $st -Detail @{ reason = $_.Exception.Message }
            if ($st -ne 'unsupported') { Add-FmpCollectorError -Ctx $ctx -Where 'startup.logonTasks' -Message $_.Exception.Message }
        }
        $ctx.data['logonTasks'] = $tasks.ToArray()

        # ---- Automatic services ----
        $svcs = New-Object System.Collections.Generic.List[object]
        $seenSvcs = @{}
        try {
            $auto = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" -OperationTimeoutSec 15 -ErrorAction Stop | Where-Object { $null -ne $_ })
            foreach ($s in $auto) {
                if ($svcs.Count -ge $MaxItems) {
                    Add-FmpLimitation -Ctx $ctx -Key 'startup_services_truncated' -DetailText ('Automatic services reached cap of ' + $MaxItems + '.') -Values @($MaxItems)
                    break
                }
                $sName = Get-FmpCleanString (Get-FmpValue $s 'Name')
                if ($null -ne $sName -and $seenSvcs.ContainsKey($sName)) { continue }
                if ($null -ne $sName) { $seenSvcs[$sName] = $true }
                $rawDelayed = Get-FmpValue $s 'DelayedAutoStart'
                $delayed = $null
                if ($rawDelayed -is [bool]) { $delayed = $rawDelayed }
                elseif ($null -ne $rawDelayed) {
                    try { $delayed = [bool]$rawDelayed } catch { $delayed = $null }
                }
                $svcs.Add([ordered]@{
                    name        = $sName
                    displayName = Get-FmpCleanString (Get-FmpValue $s 'DisplayName')
                    state       = Get-FmpCleanString (Get-FmpValue $s 'State')
                    startMode   = Get-FmpCleanString (Get-FmpValue $s 'StartMode')
                    delayed     = $delayed
                    account     = Get-FmpCleanString (Get-FmpValue $s 'StartName')
                })
            }
            Add-FmpSubCheck -Ctx $ctx -Id 'startup.autoServices' -State 'pass' -Detail @{ count = $svcs.Count }
        }
        catch {
            $st = Resolve-FmpCollectorErrorState -ErrorRecord $_
            Add-FmpSubCheck -Ctx $ctx -Id 'startup.autoServices' -State $st -Detail @{ reason = $_.Exception.Message }
            Add-FmpCollectorError -Ctx $ctx -Where 'startup.autoServices' -Message $_.Exception.Message
        }
        $ctx.data['autoServices'] = $svcs.ToArray()

        Add-FmpLimitation -Ctx $ctx -Key 'startup_metadata_only' -DetailText 'Entries are listed, never executed or validated.'
        $null = New-FmpEvidence -Ctx $ctx -CheckId 'startup.registry' -Summary 'Run/RunOnce keys, Startup folders, logon tasks, auto services (metadata only)' -Data $null
    }
}
