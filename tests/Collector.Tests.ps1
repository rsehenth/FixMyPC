# =====================================================================
# FIX MY PC - Collector.Tests.ps1
# Offline fail-closed integration test harness for all 6 collectors.
# Never queries the real Windows host: every collector executes inside a
# locked-down PowerShell Runspace with Registry provider removed,
# PSModuleAutoLoadingPreference='None', real query cmdlets removed, and
# Applications/Scripts cleared.
# =====================================================================
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src\common\Common.ps1')
. (Join-Path $root 'src\security\ReadOnlyPolicy.ps1')
. (Join-Path $root 'src\security\Privacy.ps1')
. (Join-Path $root 'src\analysis\Evidence.ps1')
. (Join-Path $root 'src\analysis\Rules.ps1')
. (Join-Path $root 'src\analysis\HealthScore.ps1')
. (Join-Path $root 'src\reports\HtmlRenderer.ps1')

$script:PassCount = 0
$script:FailCount = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:CurrentSuite = ''

function Assert-FmpTrue {
    param([Parameter(Mandatory)][string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        $script:PassCount++
        Write-Host ('  [PASS] ' + $Name)
    }
    else {
        $script:FailCount++
        $msg = $Name
        if ($Detail -ne '') { $msg = $msg + ' :: ' + $Detail }
        $script:Failures.Add('[' + $script:CurrentSuite + '] ' + $msg)
        Write-Host ('  [FAIL] ' + $msg) -ForegroundColor Red
    }
}

function Assert-FmpEqual {
    param([Parameter(Mandatory)][string]$Name, $Expected, $Actual)
    $ok = ($Expected -eq $Actual)
    if ($Expected -is [double] -and $Actual -is [double]) { $ok = ([Math]::Abs($Expected - $Actual) -lt 0.01) }
    Assert-FmpTrue -Name $Name -Condition $ok -Detail ('expected=' + $Expected + ' actual=' + $Actual)
}

function Start-FmpSuite {
    param([Parameter(Mandatory)][string]$Name)
    $script:CurrentSuite = $Name
    Write-Host ('== ' + $Name + ' ==')
}

$script:BlockedCmdlets = @(
    'Get-CimInstance', 'Get-WinEvent', 'Get-Process', 'Get-Volume',
    'Get-PhysicalDisk', 'Get-ScheduledTask', 'Get-MpComputerStatus',
    'Get-HotFix', 'Get-ItemProperty', 'Get-ItemPropertyValue',
    'Get-Item', 'Get-ChildItem', 'Test-Path', 'Resolve-Path',
    'Start-Sleep', 'Get-Date', 'Get-Service', 'Get-WmiObject',
    'Get-Counter', 'Get-AuthenticodeSignature', 'Get-CimAssociatedInstance',
    'Get-Disk', 'Get-Partition', 'Import-Module', 'Get-Module'
)

$script:SourceCache = @{
    Common   = [System.IO.File]::ReadAllText((Join-Path $root 'src\common\Common.ps1'))
    Policy   = [System.IO.File]::ReadAllText((Join-Path $root 'src\security\ReadOnlyPolicy.ps1'))
    Evidence = [System.IO.File]::ReadAllText((Join-Path $root 'src\analysis\Evidence.ps1'))
}

function Invoke-FmpIsolatedCollector {
    param(
        [AllowEmptyString()][string]$CollectorFile = '',
        [Parameter(Mandatory)][string]$InvocationScript,
        [AllowEmptyString()][string]$MockScript = '',
        [string[]]$MissingCmdlets = @(),
        [switch]$NoSentinels
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('PSModuleAutoLoadingPreference', 'None', ''))
    for ($i = $iss.Providers.Count - 1; $i -ge 0; $i--) {
        if ($iss.Providers[$i].Name -in @('Registry', 'Certificate', 'WSMan')) {
            $iss.Providers.RemoveItem($i)
        }
    }
    for ($i = $iss.Commands.Count - 1; $i -ge 0; $i--) {
        if ($iss.Commands[$i].Name -in $script:BlockedCmdlets) {
            $iss.Commands.RemoveItem($i)
        }
    }

    $sentinelSb = New-Object System.Text.StringBuilder
    if (-not $NoSentinels) {
        foreach ($cmd in $script:BlockedCmdlets) {
            if ($MissingCmdlets -contains $cmd) { continue }
            [void]$sentinelSb.Append("function $cmd { `$script:FmpMockEscape = 'UNMOCKED_COMMAND: $cmd'; throw `$script:FmpMockEscape }`n")
        }
    }

    $collectorCode = ''
    if ($CollectorFile -ne '') {
        $collectorCode = [System.IO.File]::ReadAllText((Join-Path $root ('src\collectors\' + $CollectorFile)))
    }

    $fullScript = @"
`$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
`$ExecutionContext.SessionState.Applications.Clear()
`$ExecutionContext.SessionState.Scripts.Clear()
`$script:FmpMockEscape = `$null
`$script:FmpRoot = '$($root.Replace("'", "''"))'
$($sentinelSb.ToString())
$($script:SourceCache.Common)
$($script:SourceCache.Policy)
$($script:SourceCache.Evidence)
function Get-FmpRoot { return `$script:FmpRoot }
$collectorCode
$MockScript
`$__res = & {
    $InvocationScript
}
[ordered]@{
    Result = `$__res
    Escape = `$script:FmpMockEscape
}
"@

    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    try {
        $null = $ps.AddScript($fullScript)
        $output = $ps.Invoke()
        if ($ps.HadErrors) {
            $errMsgs = @($ps.Streams.Error | ForEach-Object { $_.Exception.Message }) -join ' | '
            return [ordered]@{ Threw = $true; Error = $errMsgs; Output = $null; Escape = $null }
        }
        $last = $output | Select-Object -Last 1
        return [ordered]@{ Threw = $false; Error = $null; Output = $last.Result; Escape = $last.Escape }
    }
    catch {
        return [ordered]@{ Threw = $true; Error = $_.Exception.Message; Output = $null; Escape = $null }
    }
    finally {
        $ps.Dispose()
        $rs.Dispose()
    }
}

function New-FmpErrorRecord {
    param([string]$Message, [string]$Category = 'NotSpecified', [string]$FullyQualifiedId = 'MockError', [string]$ExceptionType = 'Exception')
    $ex = switch ($ExceptionType) {
        'UnauthorizedAccessException' { New-Object System.UnauthorizedAccessException($Message) }
        'CommandNotFoundException'    { New-Object System.Management.Automation.CommandNotFoundException($Message) }
        default                       { New-Object System.Exception($Message) }
    }
    $cat = [System.Management.Automation.ErrorCategory]$Category
    return (New-Object System.Management.Automation.ErrorRecord($ex, $FullyQualifiedId, $cat, $null))
}

function Get-FmpSubCheckState {
    param([object]$Module, [string]$Id)
    foreach ($sc in @($Module.subChecks)) {
        if ($sc.id -eq $Id) { return $sc.state }
    }
    return $null
}

# =====================================================================
Start-FmpSuite '0. Fail-closed sandbox isolation proof'
# =====================================================================

$probeCmd = Invoke-FmpIsolatedCollector -CollectorFile '' -NoSentinels -MockScript '' -InvocationScript 'Get-CimInstance -ClassName Win32_OperatingSystem'
Assert-FmpTrue -Name 'unmocked Get-CimInstance fails closed (CommandNotFound)' -Condition ($probeCmd.Threw) -Detail ([string]$probeCmd.Error)

$probeReg = Invoke-FmpIsolatedCollector -CollectorFile '' -NoSentinels -MockScript '' -InvocationScript 'Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Assert-FmpTrue -Name 'unmocked Get-ItemProperty fails closed' -Condition ($probeReg.Threw) -Detail ([string]$probeReg.Error)

$probeProv = Invoke-FmpIsolatedCollector -CollectorFile '' -NoSentinels -MockScript '' -InvocationScript 'Get-PSDrive -PSProvider Registry -ErrorAction Stop'
Assert-FmpTrue -Name 'Registry PSProvider is absent in sandbox' -Condition ($probeProv.Threw) -Detail ([string]$probeProv.Error)

$probeSentinel = Invoke-FmpIsolatedCollector -CollectorFile '' -MockScript '' -InvocationScript 'Get-Process'
Assert-FmpTrue -Name 'unmocked cmdlet triggers fail-closed escape sentinel' -Condition ($probeSentinel.Threw -and $probeSentinel.Error -match 'UNMOCKED_COMMAND: Get-Process') -Detail ([string]$probeSentinel.Error)

# =====================================================================
Start-FmpSuite '1. System collector (Win10/Win11, malformed, invalid numbers)'
# =====================================================================

$sysWin11Mock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-FmpSystemDrive { return 'C:' }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            return [pscustomobject]@{
                Caption = 'Microsoft Windows 11 Pro '
                Version = '10.0.26100'
                BuildNumber = '26100'
                OSArchitecture = '64-bit'
                InstallDate = [DateTime]::new(2025, 1, 10, 9, 0, 0, [DateTimeKind]::Utc)
                LastBootUpTime = [DateTime]::new(2026, 11, 18, 12, 0, 0, [DateTimeKind]::Utc)
                TotalVisibleMemorySize = [uint64]33554432
                FreePhysicalMemory = [uint64]16777216
            }
        }
        'Win32_Processor' {
            return [pscustomobject]@{ Name = 'Mock Ryzen 7'; NumberOfCores = 8; NumberOfLogicalProcessors = 16; MaxClockSpeed = 4500 }
        }
        'Win32_VideoController' {
            return @(
                [pscustomobject]@{ Name = 'Integrated GPU'; DriverVersion = '31.0.1'; Status = 'OK' },
                [pscustomobject]@{ Name = 'Discrete GPU'; DriverVersion = '32.0.2'; Status = 'OK' }
            )
        }
        'Win32_DiskDrive' {
            return @(
                [pscustomobject]@{ Model = 'NVMe 1TB'; Size = [uint64]1000204886016; Status = 'OK'; InterfaceType = 'SCSI' },
                [pscustomobject]@{ Model = 'SATA SSD'; Size = [uint64]500107862016; Status = 'OK'; InterfaceType = 'IDE' }
            )
        }
        'Win32_LogicalDisk' {
            return @(
                [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'Windows'; Size = [uint64]500000000000; FreeSpace = [uint64]250000000000 },
                [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Data'; Size = [uint64]500000000000; FreeSpace = [uint64]400000000000 }
            )
        }
    }
}
function Get-ItemProperty {
    param([string]$Path, $ErrorAction)
    return [pscustomobject]@{ DisplayVersion = '24H2'; ReleaseId = '2009'; CurrentBuildNumber = '26100'; UBR = 2161; EditionID = 'Professional' }
}
'@
$sys11 = Invoke-FmpIsolatedCollector -CollectorFile 'System.ps1' -MockScript $sysWin11Mock -InvocationScript 'Get-FmpSystemData'
Assert-FmpTrue -Name 'System Win11 executed without escape' -Condition (-not $sys11.Threw -and $null -eq $sys11.Escape) -Detail ([string]$sys11.Error)
if ($null -eq $sys11.Output) { throw ('System Win11 failed early: ' + $sys11.Error) }
Assert-FmpEqual -Name 'System Win11 status ok' -Expected 'ok' -Actual $sys11.Output.status
Assert-FmpEqual -Name 'System Win11 caption trimmed' -Expected 'Microsoft Windows 11 Pro' -Actual $sys11.Output.data.os.caption
Assert-FmpEqual -Name 'System Win11 uptimeHours 48' -Expected 48.0 -Actual $sys11.Output.data.os.uptimeHours
Assert-FmpEqual -Name 'System Win11 2 GPUs' -Expected 2 -Actual $sys11.Output.data.gpu.Count
Assert-FmpTrue -Name 'System Win11 limitation recorded as object (not OrderedDictionary string)' -Condition ($sys11.Output.limits.Count -gt 0 -and $sys11.Output.limits[0] -is [System.Collections.IDictionary] -and $sys11.Output.limits[0].key -eq 'gpu_ram_uint32')

# Malformed CIM objects & invalid numeric strings under StrictMode
$sysMalformedMock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-FmpSystemDrive { return 'C:' }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            # Missing OSArchitecture, InstallDate, LastBootUpTime; invalid numeric memory strings
            return [pscustomobject]@{
                Caption = 'Microsoft Windows 10 Home'
                Version = '10.0.19045'
                BuildNumber = '19045'
                TotalVisibleMemorySize = 'invalid_num'
                FreePhysicalMemory = -100
            }
        }
        'Win32_Processor' {
            # Missing NumberOfCores, MaxClockSpeed = $null
            return [pscustomobject]@{ Name = 'Partial CPU'; NumberOfLogicalProcessors = 'bad'; MaxClockSpeed = $null }
        }
        'Win32_VideoController' { return @() }
        'Win32_DiskDrive' { return @([pscustomobject]@{ Model = 'DiskNoSize'; Status = 'OK' }) }
        'Win32_LogicalDisk' { return @([pscustomobject]@{ DeviceID = 'C:'; Size = 'notanumber'; FreeSpace = 100 }) }
    }
}
function Get-ItemProperty {
    param([string]$Path, $ErrorAction)
    # Missing UBR, missing DisplayVersion (older Win10 style with ReleaseId)
    return [pscustomobject]@{ ReleaseId = '1909'; CurrentBuildNumber = '18363'; EditionID = 'Core' }
}
'@
$sysMal = Invoke-FmpIsolatedCollector -CollectorFile 'System.ps1' -MockScript $sysMalformedMock -InvocationScript 'Get-FmpSystemData'
Assert-FmpTrue -Name 'System malformed CIM objects do not crash collector' -Condition (-not $sysMal.Threw -and $null -eq $sysMal.Escape -and $null -ne $sysMal.Output)
Assert-FmpTrue -Name 'System malformed OS data still populated' -Condition ($null -ne (Get-FmpValue $sysMal.Output 'data.os') -and (Get-FmpValue $sysMal.Output 'data.os.caption') -eq 'Microsoft Windows 10 Home')
Assert-FmpTrue -Name 'System invalid memory string does not crash -> unknown' -Condition ((Get-FmpSubCheckState $sysMal.Output 'system.memory') -eq 'unknown')
Assert-FmpTrue -Name 'System missing UBR stays null (not fabricated 0)' -Condition ($null -eq (Get-FmpValue $sysMal.Output 'data.os.ubr'))
Assert-FmpTrue -Name 'System missing CPU cores stays null (not fabricated 0)' -Condition ($null -eq (Get-FmpValue $sysMal.Output 'data.cpu') -or $null -eq (Get-FmpValue $sysMal.Output 'data.cpu.cores'))
Assert-FmpTrue -Name 'System missing disk size stays null (not fabricated 0)' -Condition (@(Get-FmpValue $sysMal.Output 'data.disks').Count -eq 1 -and $null -eq (Get-FmpValue $sysMal.Output 'data.disks[0].sizeBytes'))
Assert-FmpTrue -Name 'System invalid volume size -> freePct null' -Condition (@(Get-FmpValue $sysMal.Output 'data.volumes').Count -eq 1 -and $null -eq (Get-FmpValue $sysMal.Output 'data.volumes[0].freePct'))

# Multi-CPU, future clock skew, timeout & empty arrays
$sysSkewTimeoutMock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-FmpSystemDrive { return 'C:' }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_OperatingSystem' {
            return [pscustomobject]@{
                Caption = 'Microsoft Windows 10 Home '
                Version = '10.0.19045'
                BuildNumber = '19045'
                LastBootUpTime = [DateTime]::new(2026, 11, 21, 12, 0, 0, [DateTimeKind]::Utc)
                TotalVisibleMemorySize = [uint64]8388608
                FreePhysicalMemory = [uint64]4194304
            }
        }
        'Win32_Processor' {
            return @(
                [pscustomobject]@{ Name = 'Dual Xeon'; NumberOfCores = 4; NumberOfLogicalProcessors = 8; MaxClockSpeed = 3000 },
                [pscustomobject]@{ Name = 'Dual Xeon'; NumberOfCores = 4; NumberOfLogicalProcessors = 8; MaxClockSpeed = 3000 }
            )
        }
        'Win32_VideoController' { return @() }
        'Win32_DiskDrive' { throw (New-Object System.TimeoutException('CIM OperationTimeout')) }
        'Win32_LogicalDisk' { return @() }
    }
}
function Get-ItemProperty { param([string]$Path, $ErrorAction) throw (New-Object System.UnauthorizedAccessException('Denied')) }
'@
$sysSkew = Invoke-FmpIsolatedCollector -CollectorFile 'System.ps1' -MockScript $sysSkewTimeoutMock -InvocationScript 'Get-FmpSystemData'
Assert-FmpTrue -Name 'System future LastBootUpTime -> null uptimeHours + unknown' -Condition ($null -eq (Get-FmpValue $sysSkew.Output 'data.os.uptimeHours') -and (Get-FmpSubCheckState $sysSkew.Output 'system.uptime') -eq 'unknown')
Assert-FmpEqual -Name 'System multi-socket CPU sums cores (8)' -Expected 8 -Actual (Get-FmpValue $sysSkew.Output 'data.cpu.cores')
Assert-FmpEqual -Name 'System multi-socket CPU sums logicalProcessors (16)' -Expected 16 -Actual (Get-FmpValue $sysSkew.Output 'data.cpu.logicalProcessors')
Assert-FmpEqual -Name 'System disk CIM timeout -> error subcheck' -Expected 'error' -Actual (Get-FmpSubCheckState $sysSkew.Output 'system.disks')
Assert-FmpEqual -Name 'System registry denied -> access_denied subcheck' -Expected 'access_denied' -Actual (Get-FmpSubCheckState $sysSkew.Output 'system.build')
Assert-FmpEqual -Name 'System partial failure yields module partial' -Expected 'partial' -Actual $sysSkew.Output.status

# =====================================================================
Start-FmpSuite '2. Storage collector (SMART, unlettered volumes, disk map, errors)'
# =====================================================================

$storageEdgeMock = @'
function Get-FmpSystemDrive { return 'C:' }
function Get-Volume {
    param($ErrorAction)
    return @(
        [pscustomobject]@{ DriveLetter = 'C'; FileSystemLabel = 'OS'; DriveType = 'Fixed'; HealthStatus = 'Healthy'; OperationalStatus = 'OK'; Size = 250GB; SizeRemaining = 100GB },
        # Unlettered volume with [char]0 (real Windows behavior for EFI/Recovery!) and Warning health!
        [pscustomobject]@{ DriveLetter = [char]0; FileSystemLabel = 'Recovery'; DriveType = 'Fixed'; HealthStatus = 'Warning'; OperationalStatus = 'Degraded'; Size = 1GB; SizeRemaining = 200MB }
    )
}
function Get-PhysicalDisk {
    param($ErrorAction)
    return @(
        [pscustomobject]@{ DeviceId = '0'; FriendlyName = 'NVMe Drive'; MediaType = 'SSD'; BusType = 'NVMe'; HealthStatus = 'Healthy'; OperationalStatus = 'OK'; Size = 256GB },
        [pscustomobject]@{ DeviceId = '1'; FriendlyName = 'Virtual VHD'; MediaType = 'Unspecified'; BusType = 'File Backed Virtual'; HealthStatus = 'Healthy'; OperationalStatus = 'OK'; Size = 50GB }
    )
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_LogicalDisk' {
            return @(
                [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; Size = 250GB; FreeSpace = 100GB },
                [pscustomobject]@{ DeviceID = 'Z:'; VolumeName = 'ZeroVol'; Size = 0; FreeSpace = 0 }
            )
        }
        'Win32_LogicalDiskToPartition' {
            return @([pscustomobject]@{
                Antecedent = [pscustomobject]@{ DeviceID = 'Disk #0, Partition #1' }
                Dependent  = [pscustomobject]@{ DeviceID = 'C:' }
            })
        }
        'Win32_DiskDriveToDiskPartition' {
            return @([pscustomobject]@{
                Antecedent = [pscustomobject]@{ DeviceID = '\\.\PHYSICALDRIVE0' }
                Dependent  = [pscustomobject]@{ DeviceID = 'Disk #0, Partition #1' }
            })
        }
        'MSStorageDriver_FailurePredictStatus' {
            # Missing Reason property on SMART object!
            return @([pscustomobject]@{ PredictFailure = $false; Active = $true })
        }
    }
}
'@
$stEdge = Invoke-FmpIsolatedCollector -CollectorFile 'Storage.ps1' -MockScript $storageEdgeMock -InvocationScript 'Get-FmpStorageData'
Assert-FmpTrue -Name 'Storage edge executed without escape' -Condition (-not $stEdge.Threw -and $null -eq $stEdge.Escape)
Assert-FmpTrue -Name 'Storage zero-size volume has null freePct' -Condition ($stEdge.Output.data.volumes[1].freePct -eq $null)
Assert-FmpEqual -Name 'Storage SMART missing Reason does not fail SMART subcheck' -Expected 'pass' -Actual (Get-FmpSubCheckState $stEdge.Output 'storage.smart')
Assert-FmpTrue -Name 'Storage unlettered Warning volume is captured (not dropped or NUL-char keyed)' -Condition (@(Get-FmpValue $stEdge.Output 'data.volumes' | Where-Object { $_.healthStatus -eq 'Warning' }).Count -eq 1) -Detail (ConvertTo-FmpJsonText @{ vols = $stEdge.Output.data.volumes; errs = $stEdge.Output.errors })
Assert-FmpTrue -Name 'Storage maps volume C: to physical disk index 0' -Condition (@(Get-FmpValue $stEdge.Output 'data.volumes[0].physicalDiskIndices') -contains 0)

# Storage access_denied vs missing cmdlets
$storageDeniedMock = @'
function Get-FmpSystemDrive { return 'C:' }
function Get-Volume { param($ErrorAction) throw (New-Object System.UnauthorizedAccessException('Access denied to Get-Volume')) }
function Get-PhysicalDisk { param($ErrorAction) throw (New-Object System.UnauthorizedAccessException('Access denied to Get-PhysicalDisk')) }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_LogicalDisk') { return @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; Size = 100GB; FreeSpace = 50GB }) }
    if ($ClassName -eq 'MSStorageDriver_FailurePredictStatus') { throw (New-Object System.UnauthorizedAccessException('Access denied')) }
    return @()
}
'@
$stDen = Invoke-FmpIsolatedCollector -CollectorFile 'Storage.ps1' -MockScript $storageDeniedMock -InvocationScript 'Get-FmpStorageData'
Assert-FmpEqual -Name 'Storage Get-Volume UnauthorizedAccess -> access_denied (not unsupported)' -Expected 'access_denied' -Actual (Get-FmpSubCheckState $stDen.Output 'storage.volumeHealth')
Assert-FmpEqual -Name 'Storage Get-PhysicalDisk UnauthorizedAccess -> access_denied' -Expected 'access_denied' -Actual (Get-FmpSubCheckState $stDen.Output 'storage.physicalDisks')
Assert-FmpEqual -Name 'Storage SMART UnauthorizedAccess -> access_denied' -Expected 'access_denied' -Actual (Get-FmpSubCheckState $stDen.Output 'storage.smart')

# Missing Storage cmdlets (CommandNotFoundException)
$storageMissingMock = @'
function Get-FmpSystemDrive { return 'C:' }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_LogicalDisk') { return @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; Size = 100GB; FreeSpace = 50GB }) }
    if ($ClassName -eq 'MSStorageDriver_FailurePredictStatus') { return @() }
    throw (New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception('Invalid class')), 'InvalidClass', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null))
}
'@
$stMiss = Invoke-FmpIsolatedCollector -CollectorFile 'Storage.ps1' -MockScript $storageMissingMock -MissingCmdlets @('Get-Volume', 'Get-PhysicalDisk') -InvocationScript 'Get-FmpStorageData'
Assert-FmpTrue -Name 'Storage missing cmdlets executed without escape' -Condition (-not $stMiss.Threw -and $null -eq $stMiss.Escape)
Assert-FmpEqual -Name 'Storage missing Get-Volume -> unsupported' -Expected 'unsupported' -Actual (Get-FmpSubCheckState $stMiss.Output 'storage.volumeHealth')
Assert-FmpEqual -Name 'Storage missing Get-PhysicalDisk -> unsupported' -Expected 'unsupported' -Actual (Get-FmpSubCheckState $stMiss.Output 'storage.physicalDisks')
Assert-FmpEqual -Name 'Storage empty SMART -> unknown subcheck' -Expected 'unknown' -Actual (Get-FmpSubCheckState $stMiss.Output 'storage.smart')

# =====================================================================
Start-FmpSuite '3. Startup collector (UNC/reparse, COM tasks, WOW64, nulls)'
# =====================================================================

$startupEdgeMock = @'
function Get-FmpStartupFolderPath {
    param([string]$Scope)
    if ($Scope -eq 'user') { return '\\fileserver\redirected\Startup' }
    return 'C:\Synthetic\ProgramData\Startup'
}
function Test-FmpIsWow64Process { return $true }
function Test-Path {
    param([string]$LiteralPath, $ErrorAction)
    if ($LiteralPath -like 'HK*') { return $true }
    if ($LiteralPath -eq 'C:\Synthetic\ProgramData\Startup') { return $true }
    return $false
}
function Get-Item {
    param([string]$LiteralPath, [switch]$Force, $ErrorAction)
    if ($LiteralPath -eq 'C:\') { return [pscustomobject]@{ Attributes = [System.IO.FileAttributes]::Directory } }
    if ($LiteralPath -eq 'C:\Synthetic') { return [pscustomobject]@{ Attributes = [System.IO.FileAttributes]::Directory } }
    if ($LiteralPath -eq 'C:\Synthetic\ProgramData') { return [pscustomobject]@{ Attributes = [System.IO.FileAttributes]::Directory } }
    if ($LiteralPath -eq 'C:\Synthetic\ProgramData\Startup') {
        # ReparsePoint (junction)!
        return [pscustomobject]@{ Attributes = ([System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint) }
    }
    throw (New-Object System.Management.Automation.ItemNotFoundException('Not found'))
}
function Get-ItemProperty {
    param([string]$Path, $ErrorAction)
    if ($Path -like 'HKCU:\*\Run') {
        return [pscustomobject]@{
            PSPath = $Path
            ValidTool = '"C:\Program Files\Tool\tool.exe" --bg'
            UncApp = '\\server\share\app.exe'
            NoPath = 'justname'
        }
    }
    return [pscustomobject]@{ PSPath = $Path }
}
function Get-ScheduledTask {
    param($ErrorAction)
    return @(
        # COM Handler task (no Execute property on Actions[0], and one trigger has null CimClass!)
        [pscustomobject]@{
            TaskName = 'ComLogonTask'
            TaskPath = '\Custom\'
            State = 'Ready'
            Triggers = @(
                [pscustomobject]@{ CimClass = $null },
                [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' } }
            )
            Actions = @([pscustomobject]@{ ClassId = '{12345678-1234-1234-1234-1234567890AB}' })
        }
    )
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_Service') {
        return @([pscustomobject]@{ Name = 'Svc1'; DisplayName = 'Service 1'; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $null; StartName = 'LocalSystem' })
    }
    return @()
}
'@
$suEdge = Invoke-FmpIsolatedCollector -CollectorFile 'Startup.ps1' -MockScript $startupEdgeMock -InvocationScript 'Get-FmpStartupData'
Assert-FmpTrue -Name 'Startup edge executed without escape' -Condition (-not $suEdge.Threw -and $null -eq $suEdge.Escape)
Assert-FmpEqual -Name 'Startup UNC/reparse Startup folders do not crash as error -> unknown/pass with limitation' -Expected 'unknown' -Actual (Get-FmpSubCheckState $suEdge.Output 'startup.folders')
Assert-FmpTrue -Name 'Startup UNC/reparse folder limitation recorded' -Condition (@($suEdge.Output.limits | Where-Object { $_.key -match 'startup_folder' }).Count -ge 1)
Assert-FmpTrue -Name 'Startup COM logon task without Execute still collected safely' -Condition ($suEdge.Output.data.logonTasks.Count -eq 1 -and $suEdge.Output.data.logonTasks[0].name -eq 'ComLogonTask' -and $null -eq $suEdge.Output.data.logonTasks[0].action)
Assert-FmpTrue -Name 'Startup DelayedAutoStart null stays null (not false)' -Condition ($suEdge.Output.data.autoServices.Count -eq 1 -and $null -eq $suEdge.Output.data.autoServices[0].delayed)
Assert-FmpTrue -Name 'Startup WOW64 32-bit process skips duplicate HKLM32 view and records limitation' -Condition ($suEdge.Output.data.items.Count -eq 3 -and @($suEdge.Output.limits | Where-Object { $_.key -eq 'wow64_32bit_process' }).Count -eq 1)
Assert-FmpTrue -Name 'Startup pathState classifies UNC and unidentifiable strings passively' -Condition ($suEdge.Output.data.items[1].pathState -eq 'unc' -and $suEdge.Output.data.items[2].pathState -eq 'unidentifiable')

# Valid Startup folders (with duplicate user/common resolution + reparse file) and missing Get-ScheduledTask
$startupDupFolderMock = @'
function Get-FmpStartupFolderPath { param([string]$Scope) return 'C:\Synthetic\Shared\Startup' }
function Test-FmpIsWow64Process { return $false }
function Test-Path { param([string]$LiteralPath, $ErrorAction) return ($LiteralPath -eq 'C:\Synthetic\Shared\Startup') }
function Get-Item {
    param([string]$LiteralPath, [switch]$Force, $ErrorAction)
    return [pscustomobject]@{ Attributes = [System.IO.FileAttributes]::Directory }
}
function Get-ChildItem {
    param([string]$LiteralPath, [switch]$File, $ErrorAction)
    return @(
        [pscustomobject]@{ Name = 'Normal.lnk'; Attributes = [System.IO.FileAttributes]::Archive },
        [pscustomobject]@{ Name = 'Link.lnk'; Attributes = [System.IO.FileAttributes]::ReparsePoint }
    )
}
function Get-CimInstance { param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction) return @() }
'@
$suDup = Invoke-FmpIsolatedCollector -CollectorFile 'Startup.ps1' -MockScript $startupDupFolderMock -MissingCmdlets @('Get-ScheduledTask') -InvocationScript 'Get-FmpStartupData'
Assert-FmpTrue -Name 'Startup missing Get-ScheduledTask executed without escape' -Condition (-not $suDup.Threw -and $null -eq $suDup.Escape)
Assert-FmpEqual -Name 'Startup duplicate user/common Startup path scanned once (2 items)' -Expected 2 -Actual $suDup.Output.data.items.Count
Assert-FmpEqual -Name 'Startup reparse file flagged passively' -Expected $true -Actual $suDup.Output.data.items[1].reparsePoint
Assert-FmpEqual -Name 'Startup missing Get-ScheduledTask -> unsupported' -Expected 'unsupported' -Actual (Get-FmpSubCheckState $suDup.Output 'startup.logonTasks')

# =====================================================================
Start-FmpSuite '4. Performance collector (PIDs, invalid CPU %, terminated procs)'
# =====================================================================

$perfMock = @'
function Start-Sleep { param([int]$Seconds) }
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_PerfFormattedData_PerfOS_Memory' {
            return [pscustomobject]@{ PercentCommittedBytesInUse = 42; CommittedBytes = 4GB; CommitLimit = 10GB; AvailableMBytes = 8192 }
        }
        'Win32_OperatingSystem' {
            return [pscustomobject]@{ TotalVisibleMemorySize = [uint64]16777216; FreePhysicalMemory = [uint64]8388608 }
        }
        'Win32_Processor' {
            return @([pscustomobject]@{ NumberOfLogicalProcessors = 8 })
        }
        'Win32_PerfFormattedData_PerfOS_Processor' {
            return [pscustomobject]@{ PercentProcessorTime = 25 }
        }
        'Win32_PerfFormattedData_PerfProc_Process' {
            return @(
                [pscustomobject]@{ Name = '_Total'; IDProcess = 0; PercentProcessorTime = 100 },
                [pscustomobject]@{ Name = 'Idle'; IDProcess = 0; PercentProcessorTime = 75 },
                [pscustomobject]@{ Name = 'worker'; IDProcess = 4321; PercentProcessorTime = 120 }
            )
        }
        'Win32_PageFileUsage' {
            return @([pscustomobject]@{ Name = 'C:\pagefile.sys'; AllocatedBaseSize = 2048; CurrentUsage = 256; PeakUsage = 512 })
        }
    }
}
function Get-Process {
    param($ErrorAction)
    return @(
        [pscustomobject]@{ ProcessName = 'worker'; Id = 4321; WorkingSet64 = 512MB },
        [pscustomobject]@{ ProcessName = 'exited_proc'; Id = 9999 }
    )
}
'@
$pfRes = Invoke-FmpIsolatedCollector -CollectorFile 'Performance.ps1' -MockScript $perfMock -InvocationScript 'Get-FmpPerformanceData'
Assert-FmpTrue -Name 'Performance executed without escape' -Condition (-not $pfRes.Threw -and $null -eq $pfRes.Escape)
Assert-FmpEqual -Name 'Performance status ok' -Expected 'ok' -Actual $pfRes.Output.status
Assert-FmpTrue -Name 'Performance topProcessesByMemory includes id (PID)' -Condition (@(Get-FmpValue $pfRes.Output 'data.topProcessesByMemory').Count -ge 1 -and (Get-FmpValue $pfRes.Output 'data.topProcessesByMemory[0].id') -eq 4321)
Assert-FmpTrue -Name 'Performance topProcessesByCpu includes idProcess (PID)' -Condition (@(Get-FmpValue $pfRes.Output 'data.topProcessesByCpu').Count -eq 1 -and (Get-FmpValue $pfRes.Output 'data.topProcessesByCpu[0].idProcess') -eq 4321)
Assert-FmpEqual -Name 'Performance logicalProcessors recorded' -Expected 8 -Actual (Get-FmpValue $pfRes.Output 'data.cpu.logicalProcessors')

# Out-of-range CPU counter (>100%)
$perfBadCpuMock = @'
function Start-Sleep { param([int]$Seconds) }
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_PerfFormattedData_PerfOS_Memory' { return [pscustomobject]@{ PercentCommittedBytesInUse = 50; CommittedBytes = 4GB; CommitLimit = 8GB; AvailableMBytes = 4096 } }
        'Win32_OperatingSystem' { return [pscustomobject]@{ TotalVisibleMemorySize = [uint64]8388608; FreePhysicalMemory = [uint64]4194304 } }
        'Win32_PerfFormattedData_PerfOS_Processor' { return [pscustomobject]@{ PercentProcessorTime = 250 } }
        'Win32_PerfFormattedData_PerfProc_Process' { return @() }
        'Win32_PageFileUsage' { return $null }
    }
}
function Get-Process { param($ErrorAction) return @() }
'@
$pfBad = Invoke-FmpIsolatedCollector -CollectorFile 'Performance.ps1' -MockScript $perfBadCpuMock -InvocationScript 'Get-FmpPerformanceData'
Assert-FmpEqual -Name 'Performance invalid CPU >100% rejected -> subcheck error' -Expected 'error' -Actual (Get-FmpSubCheckState $pfBad.Output 'performance.cpu')
Assert-FmpEqual -Name 'Performance invalid CPU -> sampleCount 0' -Expected 0 -Actual $pfBad.Output.data.cpu.sampleCount

# Incomplete CPU sampling (1 of 3 samples succeeds) + multiple pagefiles
$perfPartialMock = @'
$script:cpuCalls = 0
function Start-Sleep { param([int]$Seconds) }
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_PerfFormattedData_PerfOS_Memory' { return [pscustomobject]@{ PercentCommittedBytesInUse = 50; CommittedBytes = 4GB; CommitLimit = 8GB; AvailableMBytes = 4096 } }
        'Win32_OperatingSystem' { return [pscustomobject]@{ TotalVisibleMemorySize = [uint64]8388608; FreePhysicalMemory = [uint64]4194304 } }
        'Win32_PerfFormattedData_PerfOS_Processor' {
            $script:cpuCalls++
            if ($script:cpuCalls -eq 1) { return [pscustomobject]@{ PercentProcessorTime = 15 } }
            throw (New-Object System.TimeoutException('CPU sample timeout'))
        }
        'Win32_PerfFormattedData_PerfProc_Process' { return @() }
        'Win32_PageFileUsage' {
            return @(
                [pscustomobject]@{ Name = 'C:\pagefile.sys'; AllocatedBaseSize = 2048; CurrentUsage = 100; PeakUsage = 300 },
                [pscustomobject]@{ Name = 'D:\pagefile.sys'; AllocatedBaseSize = 4096; CurrentUsage = 200; PeakUsage = 400 }
            )
        }
    }
}
function Get-Process { param($ErrorAction) return @() }
'@
$pfPart = Invoke-FmpIsolatedCollector -CollectorFile 'Performance.ps1' -MockScript $perfPartialMock -InvocationScript 'Get-FmpPerformanceData'
Assert-FmpEqual -Name 'Performance partial CPU sampleCount 1' -Expected 1 -Actual $pfPart.Output.data.cpu.sampleCount
Assert-FmpEqual -Name 'Performance partial CPU -> error subcheck' -Expected 'error' -Actual (Get-FmpSubCheckState $pfPart.Output 'performance.cpu')
Assert-FmpEqual -Name 'Performance multiple pagefiles summed (6144 MB)' -Expected 6144.0 -Actual $pfPart.Output.data.pagefile.allocatedMB

# =====================================================================
Start-FmpSuite '5. Events collector (scalar, duplicates, RAC, Security order, privacy)'
# =====================================================================

$eventsMock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-WinEvent {
    param([hashtable]$FilterHashtable, [int]$MaxEvents, $ErrorAction)
    if ($FilterHashtable.LogName -eq 'System') {
        # Include duplicate RecordId=101 and a scalar/single-like set + Message (must NOT be collected!)
        return @(
            [pscustomobject]@{ RecordId = 101; ProviderName = 'Disk'; Id = 7; Level = 2; TimeCreated = [DateTime]::new(2026, 11, 19, 10, 0, 0, [DateTimeKind]::Utc); Message = 'SECRET_EVENT_MESSAGE_1' },
            [pscustomobject]@{ RecordId = 101; ProviderName = 'Disk'; Id = 7; Level = 2; TimeCreated = [DateTime]::new(2026, 11, 19, 10, 0, 0, [DateTimeKind]::Utc); Message = 'SECRET_EVENT_MESSAGE_1' }
        )
    }
    if ($FilterHashtable.LogName -eq 'Application') {
        # Single scalar object return!
        return [pscustomobject]@{ RecordId = 201; ProviderName = 'AppErr'; Id = 1000; Level = 2; TimeCreated = [DateTime]::new(2026, 11, 19, 11, 0, 0, [DateTimeKind]::Utc); Message = 'SECRET_APP_MSG' }
    }
    if ($FilterHashtable.LogName -eq 'Security') {
        # Deliberately NOT sorted descending by TimeCreated!
        return @(
            [pscustomobject]@{ RecordId = 301; Id = 4625; TimeCreated = [DateTime]::new(2026, 11, 18, 8, 0, 0, [DateTimeKind]::Utc) },
            [pscustomobject]@{ RecordId = 302; Id = 4625; TimeCreated = [DateTime]::new(2026, 11, 15, 6, 0, 0, [DateTimeKind]::Utc) },
            [pscustomobject]@{ RecordId = 303; Id = 4625; TimeCreated = [DateTime]::new(2026, 11, 19, 22, 0, 0, [DateTimeKind]::Utc) }
        )
    }
}
function Get-CimInstance {
    param([string]$ClassName, [int]$OperationTimeoutSec, $ErrorAction)
    if ($ClassName -eq 'Win32_ReliabilityRecords') {
        return @([pscustomobject]@{ SourceName = 'AppErr'; EventIdentifier = 1000; ProductName = 'Example'; TimeGenerated = [DateTime]::new(2026, 11, 19, 11, 0, 0, [DateTimeKind]::Utc) })
    }
    if ($ClassName -eq 'Win32_ReliabilityStabilityMetrics') {
        return @([pscustomobject]@{ TimeGenerated = [DateTime]::new(2026, 11, 19, 0, 0, 0, [DateTimeKind]::Utc); SystemStabilityIndex = 8.5 })
    }
}
'@
$evRes = Invoke-FmpIsolatedCollector -CollectorFile 'Events.ps1' -MockScript $eventsMock -InvocationScript 'Get-FmpEventData -WindowDays 7 -Full:$true'
Assert-FmpTrue -Name 'Events executed without escape' -Condition (-not $evRes.Threw -and $null -eq $evRes.Escape)
Assert-FmpEqual -Name 'Events System deduplicates duplicate RecordId' -Expected 1 -Actual $evRes.Output.data.logs.System.totalEvents
Assert-FmpEqual -Name 'Events Application single scalar handled' -Expected 1 -Actual $evRes.Output.data.logs.Application.totalEvents
Assert-FmpEqual -Name 'Events Security firstSeen is min timestamp' -Expected ([DateTime]::new(2026, 11, 15, 6, 0, 0, [DateTimeKind]::Utc)) -Actual $evRes.Output.data.security.firstSeen
Assert-FmpEqual -Name 'Events Security lastSeen is max timestamp' -Expected ([DateTime]::new(2026, 11, 19, 22, 0, 0, [DateTimeKind]::Utc)) -Actual $evRes.Output.data.security.lastSeen
$evJson = ConvertTo-FmpJsonText -Data $evRes.Output
Assert-FmpTrue -Name 'Events never stores raw event Message' -Condition ($evJson -notmatch 'SECRET_EVENT_MESSAGE|SECRET_APP_MSG')

# Truncation, empty channel, timezone offset, and disabled RAC
$eventsTruncMock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-WinEvent {
    param([hashtable]$FilterHashtable, [int]$MaxEvents, $ErrorAction)
    if ($FilterHashtable.LogName -eq 'System') {
        $list = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le 5; $i++) {
            $list.Add([pscustomobject]@{ RecordId = $i; ProviderName = ('Prov' + $i); Id = $i; Level = 2; TimeCreated = '2026-11-20T10:00:00-03:00' })
        }
        return $list.ToArray()
    }
    if ($FilterHashtable.LogName -eq 'Application') {
        throw (New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception('No events')), 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null))
    }
    throw (New-Object System.UnauthorizedAccessException('Security denied'))
}
function Get-CimInstance {
    param([string]$ClassName, [int]$OperationTimeoutSec, $ErrorAction)
    throw (New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception('Invalid class')), 'InvalidClass', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null))
}
'@
$evTr = Invoke-FmpIsolatedCollector -CollectorFile 'Events.ps1' -MockScript $eventsTruncMock -InvocationScript 'Get-FmpEventData -WindowDays 7 -Full:$true -MaxPerLog 5 -MaxGroups 2'
Assert-FmpEqual -Name 'Events System truncated=true at MaxPerLog' -Expected $true -Actual $evTr.Output.data.logs.System.truncated
Assert-FmpEqual -Name 'Events System truncated -> subcheck unknown' -Expected 'unknown' -Actual (Get-FmpSubCheckState $evTr.Output 'events.log.System')
Assert-FmpEqual -Name 'Events Application empty -> status empty' -Expected 'empty' -Actual $evTr.Output.data.logs.Application.status
Assert-FmpEqual -Name 'Events Application empty -> subcheck pass' -Expected 'pass' -Actual (Get-FmpSubCheckState $evTr.Output 'events.log.Application')
Assert-FmpEqual -Name 'Events disabled RAC -> unsupported' -Expected 'unsupported' -Actual $evTr.Output.data.reliability.status
Assert-FmpEqual -Name 'Events denied Security -> access_denied' -Expected 'access_denied' -Actual $evTr.Output.data.security.status

# =====================================================================
Start-FmpSuite '6. Advanced collector (null IsSigned, empty rename, hotfix dates, partial apps)'
# =====================================================================

$advMock = @'
function Test-FmpIsWow64Process { return $false }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Filter, [int]$OperationTimeoutSec, $ErrorAction)
    switch ($ClassName) {
        'Win32_PnPEntity' {
            return @([pscustomobject]@{ Name = 'USB Device'; DeviceID = 'USB\VID_0001'; ConfigManagerErrorCode = 43 })
        }
        'Win32_PnPSignedDriver' {
            # IsSigned is $null (unknown) and DriverProviderName missing!
            return @([pscustomobject]@{ DeviceID = 'USB\VID_0001'; DriverVersion = '1.0.0.0'; IsSigned = $null; DriverDate = $null })
        }
        'AntiVirusProduct' {
            throw (New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception('Invalid namespace')), 'InvalidNamespace', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null))
        }
    }
}
function Get-MpComputerStatus {
    param($ErrorAction)
    throw (New-Object System.Management.Automation.CommandNotFoundException('Get-MpComputerStatus not found'))
}
function Test-Path {
    param([string]$LiteralPath, $ErrorAction)
    if ($LiteralPath -like '*RebootRequired*' -or $LiteralPath -like '*RebootPending*') { return $false }
    if ($LiteralPath -like '*Uninstall*') { return $true }
    return $false
}
function Get-ItemProperty {
    param([string]$Path, $ErrorAction)
    if ($Path -like '*Session Manager*') {
        # Empty string in PendingFileRenameOperations must NOT trigger false positive pending reboot!
        return [pscustomobject]@{ PendingFileRenameOperations = @('') }
    }
    if ($Path -like 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        return @([pscustomobject]@{ DisplayName = 'App64'; DisplayVersion = '1.0'; Publisher = 'Pub'; EstimatedSize = 1024 })
    }
    if ($Path -like 'HKCU:\*') {
        throw (New-Object System.UnauthorizedAccessException('HKCU uninstall denied'))
    }
    return @()
}
function Get-HotFix {
    param($ErrorAction)
    return @(
        # String dates where lexicographical sort ('12/01/2025' > '01/15/2026') would pick the WRONG latest date!
        [pscustomobject]@{ HotFixID = 'KB5000001'; Description = 'Update'; InstalledOn = '12/01/2025' },
        [pscustomobject]@{ HotFixID = 'KB5000002'; Description = 'Update'; InstalledOn = '01/15/2026' }
    )
}
'@
$advRes = Invoke-FmpIsolatedCollector -CollectorFile 'Advanced.ps1' -MockScript $advMock -InvocationScript 'Get-FmpAdvancedData'
Assert-FmpTrue -Name 'Advanced executed without escape' -Condition (-not $advRes.Threw -and $null -eq $advRes.Escape)
Assert-FmpTrue -Name 'Advanced driver IsSigned=$null stays null (not false)' -Condition ($advRes.Output.data.driverInfo.items.Count -eq 1 -and $null -eq $advRes.Output.data.driverInfo.items[0].signed)
Assert-FmpEqual -Name 'Advanced PendingFileRenameOperations empty string is not pending reboot' -Expected $false -Actual $advRes.Output.data.pendingReboot.any
Assert-FmpEqual -Name 'Advanced HotFix chronological sort picks 2026-01-15 over 2025-12-01' -Expected 'KB5000002' -Actual (Get-FmpValue $advRes.Output 'data.hotfixes.items[0].hotFixId')
Assert-FmpTrue -Name 'Advanced partial uninstall access denied preserves HKLM64 apps' -Condition ($advRes.Output.data.installedApps.items.Count -eq 1)
Assert-FmpEqual -Name 'Advanced Authenticode remains not_collected' -Expected 'not_collected' -Actual $advRes.Output.data.signatures.status
Assert-FmpEqual -Name 'Advanced updates remains not_collected' -Expected 'not_collected' -Actual $advRes.Output.data.updates.status

# =====================================================================
Start-FmpSuite '7. End-to-End 6-collector pipeline + Simple/Full equivalence + Volume stress'
# =====================================================================

$ruleConfig = Get-FmpRuleConfig -Root $root
$locPt = (Read-FmpJsonFile -Path (Join-Path $root 'locales\pt-BR.json')).Data
$locEn = (Read-FmpJsonFile -Path (Join-Path $root 'locales\en.json')).Data

$e2eMeta = @{ Id = 'fmp-e2e-mock'; Mode = 'full'; Language = 'pt-BR'; Synthetic = $true; StartedAt = '2026-11-20T12:00:00.000Z' }
$mSys = (Invoke-FmpIsolatedCollector -CollectorFile 'System.ps1' -MockScript $sysWin11Mock -InvocationScript 'Get-FmpSystemData').Output
$mEv  = (Invoke-FmpIsolatedCollector -CollectorFile 'Events.ps1' -MockScript $eventsTruncMock -InvocationScript 'Get-FmpEventData -WindowDays 7 -Full:$true -MaxPerLog 5 -MaxGroups 2').Output
$mSu  = (Invoke-FmpIsolatedCollector -CollectorFile 'Startup.ps1' -MockScript $startupDupFolderMock -MissingCmdlets @('Get-ScheduledTask') -InvocationScript 'Get-FmpStartupData').Output
$mPf  = (Invoke-FmpIsolatedCollector -CollectorFile 'Performance.ps1' -MockScript $perfMock -InvocationScript 'Get-FmpPerformanceData').Output
$mSt  = (Invoke-FmpIsolatedCollector -CollectorFile 'Storage.ps1' -MockScript $storageEdgeMock -InvocationScript 'Get-FmpStorageData').Output
$mAd  = (Invoke-FmpIsolatedCollector -CollectorFile 'Advanced.ps1' -MockScript $advMock -InvocationScript 'Get-FmpAdvancedData').Output

$diagFull = Merge-FmpDiagnostics -Modules @($mSys, $mEv, $mSt, $mPf, $mSu, $mAd) -RunMeta $e2eMeta
$anFull = Invoke-FmpRules -Diagnostic $diagFull -RuleConfig $ruleConfig -Mode 'full'
$scFull = Get-FmpHealthScore -Analysis $anFull -RuleConfig $ruleConfig -Modules @($mSys, $mEv, $mSt, $mPf, $mSu, $mAd)
$diagFull['analysis'] = $anFull
$diagFull['healthScore'] = $scFull

$e2eMetaSimple = @{ Id = 'fmp-e2e-mock'; Mode = 'simple'; Language = 'pt-BR'; Synthetic = $true; StartedAt = '2026-11-20T12:00:00.000Z' }
$diagSimple = Merge-FmpDiagnostics -Modules @($mSys, $mEv, $mSt, $mPf, $mSu) -RunMeta $e2eMetaSimple
$anSimple = Invoke-FmpRules -Diagnostic $diagSimple -RuleConfig $ruleConfig -Mode 'simple'
$scSimple = Get-FmpHealthScore -Analysis $anSimple -RuleConfig $ruleConfig -Modules @($mSys, $mEv, $mSt, $mPf, $mSu)

Assert-FmpEqual -Name 'E2E Simple vs Full base score identical' -Expected $scSimple.score -Actual $scFull.score
Assert-FmpEqual -Name 'E2E Simple vs Full coverage identical' -Expected $scSimple.coveragePct -Actual $scFull.coveragePct
$sanFull = ConvertTo-FmpSanitizedDiagnostic -Diagnostic $diagFull -PrivateIdentifiers @('SYNTH-PC', 'SynthUser')
Set-FmpRenderLocale -Primary $locPt -Fallback $locEn -Language 'pt-BR'
$htmlFull = Get-FmpHtmlReportText -Diagnostic $sanFull -Synthetic:$true -RedactionCount (Get-FmpRedactionCount)
Assert-FmpTrue -Name 'E2E HTML renders process PID 4321' -Condition ($htmlFull -match '<td data-label="[^"]*">4321</td>')
Assert-FmpTrue -Name 'E2E HTML renders truncated event count as 5+' -Condition ($htmlFull -match '5\+')
Assert-FmpTrue -Name 'E2E HTML renders localized gpu_ram_uint32 limitation, never the key (FMP-04)' -Condition ($htmlFull -match 'VRAM acima de 4 GB' -and $htmlFull -notmatch 'gpu_ram_uint32' -and $htmlFull -notmatch 'OrderedDictionary')
Assert-FmpTrue -Name 'E2E HTML renders Build label cleanly' -Condition ($htmlFull -match 'Compila&#231;&#227;o / build|Compilação / build')

# Volume / stress test: 2000 events x 2 logs + 300 startup + 300 apps + 200 processes
$stressEventsMock = @'
function Get-Date { return [DateTime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc) }
function Get-WinEvent {
    param([hashtable]$FilterHashtable, [int]$MaxEvents, $ErrorAction)
    if ($FilterHashtable.LogName -in @('System', 'Application')) {
        $list = New-Object System.Collections.Generic.List[object]
        $base = [DateTime]::new(2026, 11, 20, 11, 0, 0, [DateTimeKind]::Utc)
        for ($i = 1; $i -le 2000; $i++) {
            $list.Add([pscustomobject]@{
                RecordId = $i; ProviderName = ('Provider-' + ($i % 50)); Id = (1000 + ($i % 50))
                Level = $(if ($i % 20 -eq 0) { 1 } else { 2 }); TimeCreated = $base.AddMinutes(-$i)
            })
        }
        return $list.ToArray()
    }
    return @()
}
function Get-CimInstance { param([string]$ClassName, [int]$OperationTimeoutSec, $ErrorAction) return @() }
'@
$swStress = [System.Diagnostics.Stopwatch]::StartNew()
$mEvStress = (Invoke-FmpIsolatedCollector -CollectorFile 'Events.ps1' -MockScript $stressEventsMock -InvocationScript 'Get-FmpEventData -WindowDays 7 -Full:$true').Output
$swStress.Stop()
$evStressJson = ConvertTo-FmpJsonText -Data $mEvStress
$evStressBytes = ([System.Text.UTF8Encoding]::new($false, $true).GetBytes($evStressJson)).Length
Assert-FmpEqual -Name 'Stress 2000 events System truncated=true' -Expected $true -Actual $mEvStress.data.logs.System.truncated
Assert-FmpEqual -Name 'Stress 2000 events capped at 40 groups' -Expected 40 -Actual $mEvStress.data.logs.System.groups.Count
Assert-FmpTrue -Name ('Stress 4000 events JSON well under 8 MiB (' + $evStressBytes + ' bytes, ' + $swStress.ElapsedMilliseconds + ' ms)') -Condition ($evStressBytes -lt 2MB)

# Exclusive lock concurrency test on Write-FmpUtf8File
$concDir = Join-Path $root ('out\fmp-conc-' + [Guid]::NewGuid().ToString('N'))
New-FmpOutputDirectory $concDir
$lockedFile = Join-Path $concDir 'locked.txt'
$lockStream = [System.IO.File]::Open($lockedFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
$concurrentBlocked = $false
try { Write-FmpUtf8File $lockedFile 'concurrent' } catch { $concurrentBlocked = $true }
finally {
    $lockStream.Dispose()
    Remove-Item -LiteralPath $concDir -Recurse -Force -ErrorAction SilentlyContinue
}
Assert-FmpTrue -Name 'Concurrent write on exclusively opened file is blocked' -Condition $concurrentBlocked

# =====================================================================
Write-Host ''
Write-Host ('==== COLLECTOR HARNESS RESUMO: ' + $script:PassCount + ' passaram, ' + $script:FailCount + ' falharam ====')
if ($script:FailCount -gt 0) {
    foreach ($f in $script:Failures) { Write-Host ('  FAIL: ' + $f) -ForegroundColor Red }
    exit 1
}
exit 0
