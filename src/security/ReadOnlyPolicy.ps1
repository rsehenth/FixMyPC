# =====================================================================
# FIX MY PC - ReadOnlyPolicy.ps1
#
# Enforces the read-only policy through static analysis of the project's
# own PowerShell source, BEFORE any collection runs:
#   1. AST scan of every command invocation against an explicit allowlist
#      (command name + allowed parameters). Anything not explicitly
#      allowed is a violation - "Get-*" prefix alone is NOT trusted.
#   2. Hard-banned command list (defense in depth).
#   3. Banned .NET method invocations (registry writes, process start,
#      file appends, network download methods...).
#   4. Text-level scans: forbidden data sources (Win32_Product),
#      network APIs, native write commands, dynamic invocation.
#   5. Dynamic invocation (& $var) is rejected - collectors must call
#      fixed, auditable commands.
#
# Writes of artifacts (report/JSON) are separated from collection:
# only files with the 'core' or 'writer' role may use file-write
# methods, and every write must pass Assert-FmpOutputPath (Common.ps1).
# No elevation, no network, no repair/clean actions. Ever.
# =====================================================================

# System-facing commands allowed for collectors. Parameter allowlist per
# command: anything outside the list is a violation.
$script:FmpAllowedCommands = @{
    'Get-CimInstance'           = @('ClassName', 'Namespace', 'Filter', 'Property', 'OperationTimeoutSec', 'ErrorAction', 'ErrorVariable')
    'Get-WinEvent'              = @('FilterHashtable', 'MaxEvents', 'Oldest', 'ErrorAction')
    'Get-Process'               = @('ErrorAction')
    'Get-Volume'                = @('ErrorAction')
    'Get-PhysicalDisk'          = @('ErrorAction')
    'Get-StorageReliabilityCounter' = @('PhysicalDisk', 'ErrorAction')
    'Get-ScheduledTask'         = @('ErrorAction')
    'Get-ItemProperty'          = @('Path', 'Name', 'ErrorAction', 'ErrorVariable')
    'Get-Item'                  = @('LiteralPath', 'Force', 'ErrorAction')
    'Get-ChildItem'             = @('LiteralPath', 'File', 'ErrorAction')
    'Get-MpComputerStatus'      = @('ErrorAction', 'ErrorVariable')
    'Get-HotFix'                = @('ErrorAction', 'ErrorVariable')
    'Start-Sleep'               = @('Seconds', 'Milliseconds')
}

# Keep side-effectful utility parameters excluded even for read commands.
$script:FmpSafeUtilityCommands = @{
    'Where-Object' = @('FilterScript')
    'ForEach-Object' = @('Process')
    'Select-Object' = @('First', 'Property')
    'Sort-Object' = @('Property', 'Descending', 'Unique')
    'Measure-Object' = @('Property', 'Average', 'Maximum', 'Minimum', 'Sum')
    'Out-Null' = @()
    'Write-Host' = @('ForegroundColor')
    'Write-Output' = @()
    'ConvertTo-Json' = @('InputObject', 'Depth')
    'ConvertFrom-Json' = @('ErrorAction', 'AsHashtable', 'DateKind', 'Depth', 'InputObject')
    'Join-Path' = @('Path', 'ChildPath')
    'Split-Path' = @('Parent', 'Path', 'Leaf', 'ErrorAction')
    'Get-Content' = @('LiteralPath', 'Raw', 'Encoding', 'ErrorAction')
    'Test-Path' = @('LiteralPath', 'PathType', 'ErrorAction')
    'Get-Date' = @()
    'Set-StrictMode' = @('Version')
    'Read-Host' = @()
    'New-Object' = @()
}

$script:FmpSourceFiles = @(
    'fixmypc.ps1',
    'src\common\Common.ps1', 'src\security\ReadOnlyPolicy.ps1', 'src\security\Privacy.ps1',
    'src\analysis\Evidence.ps1', 'src\analysis\Rules.ps1', 'src\analysis\HealthScore.ps1',
    'src\collectors\System.ps1', 'src\collectors\Events.ps1', 'src\collectors\Startup.ps1',
    'src\collectors\Performance.ps1', 'src\collectors\Storage.ps1', 'src\collectors\Advanced.ps1',
    'src\collectors\Observation.ps1', 'src\collectors\Investigations.ps1', 'src\analysis\Diagnosis.ps1',
    'src\analysis\Correlation.ps1', 'src\reports\HtmlRenderer.ps1'
)

$script:FmpStaticMembers = @(
    '[Environment]::UserInteractive', '[Environment]::GetCommandLineArgs', '[Console]::IsInputRedirected',
    '[Environment]::GetFolderPath', '[Environment]::Is64BitOperatingSystem', '[Environment]::Is64BitProcess',
    '[Environment+SpecialFolder]::CommonStartup', '[Environment+SpecialFolder]::Startup',
    '[Environment+SpecialFolderOption]::DoNotVerify',
    '[DateTime]::Parse', '[DateTime]::ParseExact', '[DateTime]::TryParseExact', '[DateTime]::UtcNow', '[Guid]::NewGuid',
    '[Math]::Abs', '[Math]::Floor', '[Math]::Max', '[Math]::Min', '[Math]::Round',
    '[double]::TryParse', '[double]::IsNaN', '[double]::IsInfinity',
    '[int]::TryParse', '[char]::IsHighSurrogate',
    '[string]::IsNullOrEmpty', '[string]::IsNullOrWhiteSpace',
    '[regex]::Escape', '[regex]::Replace',
    '[System.Globalization.CultureInfo]::InvariantCulture', '[System.Globalization.NumberStyles]::Any',
    '[System.Globalization.DateTimeStyles]::RoundtripKind', '[System.Net.WebUtility]::HtmlEncode',
    '[System.Diagnostics.Stopwatch]::StartNew',
    '[System.IO.Path]::GetFullPath', '[System.IO.Path]::GetDirectoryName',
    '[System.IO.DriveInfo]::new', '[System.IO.DriveType]::Fixed', '[System.IO.DriveType]::Removable',
    '[System.IO.FileAttributes]::ReparsePoint', '[System.IO.StreamReader]::new',
    '[System.IO.FileMode]::Open', '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileAccess]::Read', '[System.IO.FileAccess]::Write',
    '[System.IO.FileShare]::Read', '[System.IO.FileShare]::None',
    '[System.Text.UTF8Encoding]::new',
    '[System.Management.Automation.Language.Parser]::ParseFile'
)

$script:FmpPrivateDaclMembers = @(
    '[System.Security.AccessControl.DirectorySecurity]::new', '[System.Security.AccessControl.FileSystemAccessRule]::new',
    '[System.Security.AccessControl.FileSystemRights]::FullControl',
    '[System.Security.Principal.WindowsIdentity]::GetCurrent', '[System.Security.Principal.SecurityIdentifier]::new',
    '[System.Security.Principal.WellKnownSidType]::LocalSystemSid',
    # Read-only check that the reserved output folder is the private one this run created (C1).
    '[System.IO.Directory]::GetAccessControl'
)

$script:FmpInstanceMethods = @(
    'Add', 'AddDays', 'Append', 'Clear', 'Contains', 'ContainsKey', 'EndsWith', 'FindAll', 'GetBytes',
    'GetCommandName', 'GetType', 'Remove', 'Replace', 'Sort', 'Split', 'StartsWith', 'Stop', 'Substring',
    'ToArray', 'ToString', 'ToUniversalTime', 'ToXml', 'Trim', 'TrimEnd', 'TrimStart'
)

# Defense in depth: banned even if someone later adds them to the
# allowlist. Repair/clean/elevation/persistence commands live here.
$script:FmpHardBannedCommands = @(
    'Set-ExecutionPolicy', 'Invoke-Expression', 'Invoke-Command', 'Invoke-WebRequest',
    'Invoke-RestMethod', 'Invoke-WmiMethod', 'Invoke-CimMethod', 'Invoke-Item',
    'Start-Process', 'Stop-Process', 'Stop-Service', 'Start-Service', 'Restart-Service',
    'Set-Service', 'New-Service', 'Remove-Service', 'Remove-Item', 'Remove-ItemProperty',
    'Set-ItemProperty', 'Set-Item', 'Clear-Item', 'Clear-ItemProperty', 'Clear-Content',
    'Set-Content', 'Add-Content', 'Out-File', 'Export-Clixml', 'Export-Csv', 'Export-Counter',
    'Import-Clixml', 'Import-Csv', 'Import-Module', 'Restart-Computer', 'Stop-Computer',
    'Register-ScheduledTask', 'Unregister-ScheduledTask', 'Start-ScheduledTask',
    'Stop-ScheduledTask', 'Enable-ScheduledTask', 'Disable-ScheduledTask', 'Set-ScheduledTask',
    'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'Update-MpSignature',
    'Start-MpScan', 'Start-MpWDOScan', 'Set-LocalUser', 'Enable-LocalUser', 'Disable-LocalUser',
    'Set-LocalGroup', 'Add-LocalGroupMember', 'Remove-LocalGroupMember',
    'Enable-PSRemoting', 'Disable-PSRemoting', 'Enter-PSSession', 'New-PSSession',
    'Move-Item', 'Rename-Item', 'Rename-Computer', 'Add-Computer', 'Remove-Computer',
    'Set-Date', 'Set-TimeZone', 'Clear-EventLog', 'Limit-EventLog', 'Set-Clipboard',
    'Copy-Item', 'Compress-Archive', 'Expand-Archive', 'Initialize-Disk', 'Clear-Disk',
    'Format-Volume', 'Optimize-Volume', 'Repair-Volume', 'Set-Volume', 'Update-Disk',
    'Set-Disk', 'Set-Partition', 'Add-Partition', 'Remove-Partition', 'Write-VolumeCache',
    'Set-BitLockerVolume', 'Enable-BitLocker', 'Disable-BitLocker'
)

# .NET method invocations that are forbidden everywhere (except the
# role-gated exceptions below).
$script:FmpBannedMethods = @(
    'Invoke', 'InvokeMethod', 'InvokeMethodParameters', 'CreateSubKey', 'CreateSubkey',
    'SetValue', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree', 'Kill',
    'AppendAllText', 'AppendAllLines', 'WriteAllBytes', 'WriteAllLines',
    'OpenWrite', 'DownloadString', 'DownloadFile', 'DownloadData',
    'UploadString', 'UploadData', 'UploadFile', 'UploadValues',
    'SetAccessControl', 'MoveTo', 'Encrypt', 'Decrypt', 'CreateInstance',
    'Create', 'Delete', 'Start'
)

# Text-level patterns (case-insensitive) that must never appear in code
# that runs during an audit.
$script:FmpTextScanPatterns = @(
    @{ Id = 'win32_product';     Pattern = 'Win32_Product' },
    @{ Id = 'network_api';       Pattern = 'System\.Net\.WebClient|Net\.WebClient|HttpWebRequest|HttpClient|TcpClient|UdpClient|SmtpClient|System\.Net\.Sockets|System\.Net\.Dns|Start-BitsTransfer|curl\s|wget\s' },
    @{ Id = 'registry_dotnet';   Pattern = 'Microsoft\.Win32\.Registry' },
    @{ Id = 'native_write_cmd';  Pattern = '\bcmd(\.exe)?\s+/c\b|\breg(\.exe)?\s+(add|delete|restore|import|save|load|unload|compare)\b|\bnet(\.exe)?\s+(start|stop|user|localgroup|use)\b|\bschtasks(\.exe)?\s+/(create|change|delete|run|end)\b|\bwmic\b|\bmsiexec\b|\bregsvr32\b|\brundll32\b|\bbcdedit\b|\bchkdsk\b|\bdefrag\b|\bsfc(\.exe)?\b|\bdism\b|\bpowercfg\b|\bwevtutil\b|\btaskkill\b|\bshutdown(\.exe)?\b|\bdiskpart\b|\bvssadmin\b' },
    @{ Id = 'elevation';         Pattern = '-Verb\s+RunAs|Start-Process\s+-Verb' }
)

$script:FmpRoles = @('core', 'collector', 'analysis', 'security', 'writer', 'test')

function Get-FmpFileRole {
    param([Parameter(Mandatory)][string]$Path)
    $p = $Path -replace '/', '\'
    if ($p -match 'fixmypc\.ps1$') { return 'core' }
    if ($p -match '\\src\\collectors\\') { return 'collector' }
    if ($p -match '\\src\\analysis\\') { return 'analysis' }
    if ($p -match '\\src\\security\\') { return 'security' }
    if ($p -match '\\src\\reports\\') { return 'writer' }
    if ($p -match '\\src\\common\\') { return 'core' }
    if ($p -match '\\tests\\') { return 'test' }
    return 'collector'
}

# ---------------------------------------------------------------------
# FMP-02: receivers and setters are checked by TYPE, not by name.
# The scanner tracks, per function scope, what every local variable can
# hold (flow-insensitive: the union of ALL assignments). A variable is
# "proven data" only when every binding is a literal, a cast to a value
# type, a local container (@{}, [ordered]@{}, New-Object List/StringBuilder)
# or a typed parameter. Anything that can hold a live system object
# (Get-* results, loop variables, untyped parameters, unknown functions)
# carries the kind '?', and '?' is never accepted as a receiver or as the
# root of a setter.
# ---------------------------------------------------------------------
$script:FmpDataKinds = @('null', 'scalar', 'string', 'safepath', 'dict', 'obj', 'list', 'sb', 'stopwatch', 'array')
$script:FmpSettableKinds = @('dict', 'obj')
$script:FmpGuardedMethodKinds = @{
    'Add'     = @('list', 'dict', 'array')
    'Append'  = @('sb')
    'Clear'   = @('list', 'dict', 'sb')
    'Remove'  = @('list', 'dict', 'sb', 'string')
    'Replace' = @('string', 'sb')
    'Sort'    = @('list', 'array')
    'Stop'    = @('stopwatch')
}
# Internal functions whose result is known to be plain data (declared here, on purpose).
$script:FmpDataFunctions = @{
    'New-FmpCollectorContext'          = 'dict'
    'New-FmpShapeNode'                 = 'dict'
    'Get-FmpCheckedPath'               = 'safepath'
    'Get-FmpSafeRegistryPath'          = 'safepath'
    'Invoke-FmpCollector'              = 'dict'
    'Get-FmpSystemData'                = 'dict'
    'Get-FmpEventData'                 = 'dict'
    'Get-FmpStartupData'               = 'dict'
    'Get-FmpPerformanceData'           = 'dict'
    'Get-FmpStorageData'               = 'dict'
    'Get-FmpAdvancedData'              = 'dict'
    'Get-FmpObservationData'           = 'dict'
    'Get-FmpBootHistory'               = 'dict'
    'Get-FmpUnexpectedRestartContext'  = 'dict'
    'ConvertFrom-FmpEventXmlData'      = 'dict'
    'Get-FmpDiagnosis'                 = 'dict'
    'ConvertTo-FmpSerializable'        = @('dict', 'array', 'string', 'scalar', 'null')
    'ConvertTo-FmpSanitizedDiagnostic' = 'dict'
    'Hide-FmpSanitizedNode'            = @('dict', 'array', 'string', 'scalar', 'null')
    'Merge-FmpDiagnostics'             = 'dict'
}
$script:FmpBindingsBuilding = $false
$script:FmpScalarStaticDefault = 'scalar'
$script:FmpStaticKindOverrides = @{
    '[System.Diagnostics.Stopwatch]::StartNew'    = 'stopwatch'
    '[Environment]::GetFolderPath'                = 'string'
    '[Environment]::GetCommandLineArgs'           = 'array'
    '[regex]::Replace'                            = 'string'
    '[regex]::Escape'                             = 'string'
    '[System.IO.Path]::GetFullPath'               = 'string'
    '[System.IO.Path]::GetDirectoryName'          = 'string'
    '[System.Net.WebUtility]::HtmlEncode'         = 'string'
    '[System.IO.DriveInfo]::new'                  = '?'
    '[System.IO.StreamReader]::new'               = '?'
    '[System.IO.File]::Open'                      = '?'
    '[System.IO.Directory]::CreateDirectory'      = '?'
    '[System.Management.Automation.Language.Parser]::ParseFile' = '?'
}
$script:FmpStringMethods = @('ToString', 'ToXml', 'Trim', 'TrimStart', 'TrimEnd', 'Substring', 'GetCommandName')
$script:FmpArrayMethods = @('Split', 'ToArray', 'GetBytes', 'FindAll')
$script:FmpScalarMethods = @('Contains', 'ContainsKey', 'StartsWith', 'EndsWith', 'AddDays', 'ToUniversalTime', 'Add', 'Remove', 'Clear', 'Sort', 'Stop')
$script:FmpScalarTypes = @('int', 'int16', 'int32', 'int64', 'uint16', 'uint32', 'uint64', 'long', 'double', 'float', 'single', 'decimal',
    'bool', 'boolean', 'byte', 'char', 'datetime', 'timespan', 'guid', 'version', 'switch', 'regex')
$script:FmpAutoVariableKinds = @{
    'null' = 'null'; 'true' = 'scalar'; 'false' = 'scalar'; 'psscriptroot' = 'string'; 'pscommandpath' = 'string'
    'pshome' = 'string'; 'lastexitcode' = 'scalar'; 'matches' = 'dict'; 'psversiontable' = 'dict'; 'error' = 'array'
}
$script:FmpVariableBindingParameters = @('ErrorVariable', 'OutVariable', 'WarningVariable', 'InformationVariable', 'PipelineVariable', 'EV', 'OV', 'WV', 'IV', 'PV')

# ---------------------------------------------------------------------
# FMP-03: collection sources. Collectors may only read from these.
# ---------------------------------------------------------------------
$script:FmpAllowedRegistryPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$script:FmpAllowedCimClasses = @(
    'Win32_OperatingSystem', 'Win32_Processor', 'Win32_VideoController', 'Win32_DiskDrive', 'Win32_LogicalDisk',
    'Win32_DiskDriveToDiskPartition', 'Win32_LogicalDiskToPartition', 'Win32_PnPEntity', 'Win32_PnPSignedDriver',
    'Win32_Service', 'Win32_PageFileUsage', 'Win32_PerfFormattedData_PerfOS_Memory', 'Win32_PerfFormattedData_PerfOS_Processor',
    'Win32_PerfFormattedData_PerfProc_Process', 'Win32_ReliabilityRecords', 'Win32_ReliabilityStabilityMetrics',
    'Win32_PerfRawData_PerfOS_Processor', 'Win32_PerfRawData_PerfOS_Memory', 'Win32_PerfRawData_PerfDisk_PhysicalDisk',
    'Win32_PerfRawData_PerfProc_Process',
    'Win32_PerfRawData_GPUPerformanceCounters_GPUEngine', 'Win32_PerfRawData_GPUPerformanceCounters_GPUAdapterMemory',
    'MSFT_NetTCPConnection', 'MSFT_NetUDPEndpoint', 'MSFT_NetTCPSetting', 'MSFT_NetUDPSetting',
    'AntiVirusProduct', 'MSStorageDriver_FailurePredictStatus'
)
$script:FmpAllowedCimNamespaces = @('root\cimv2', 'root\SecurityCenter2', 'root\wmi', 'root\StandardCimv2')
# These classes also expose addresses, ports or adapter identifiers. -Property is mandatory, literal and limited to this list.
$script:FmpRestrictedCimProperties = @{
    'MSFT_NetTCPConnection' = @('State', 'OwningProcess')
    'MSFT_NetUDPEndpoint'   = @('OwningProcess')
    'MSFT_NetTCPSetting'    = @('SettingName', 'DynamicPortRangeStartPort', 'DynamicPortRangeNumberOfPorts')
    'MSFT_NetUDPSetting'    = @('DynamicPortRangeStartPort', 'DynamicPortRangeNumberOfPorts')
    'Win32_PerfRawData_GPUPerformanceCounters_GPUEngine'        = @('Name', 'UtilizationPercentage', 'Timestamp_Sys100NS')
    'Win32_PerfRawData_GPUPerformanceCounters_GPUAdapterMemory' = @('Name', 'DedicatedUsage', 'SharedUsage')
}
$script:FmpAllowedEventLogs = @('System', 'Application', 'Security', 'Microsoft-Windows-Diagnostics-Performance/Operational')
$script:FmpAllowedEventFilterKeys = @('LogName', 'ProviderName', 'Id', 'Level', 'StartTime', 'EndTime')
# Closed provider list of the diagnostic event catalog (Events.ps1). An ID alone is ambiguous: 153 is both nvlddmkm and disk.
$script:FmpAllowedEventProviders = @(
    'Display', 'nvlddmkm', 'disk', 'stornvme', 'storahci', 'Ntfs', 'Microsoft-Windows-Ntfs', 'Tcpip',
    'Microsoft-Windows-Kernel-Power', 'Microsoft-Windows-Kernel-General', 'User32', 'EventLog',
    'amdkmdag', 'amdkmdap', 'atikmdag', 'igfx', 'igfxn', 'Windows Error Reporting'
)
$script:FmpPathConsumers = @('Get-ChildItem', 'Get-Item', 'Get-ItemProperty', 'Get-Content', 'Test-Path')
$script:FmpPathParameters = @('Path', 'LiteralPath')
$script:FmpSwitchParameters = @('Force', 'File', 'Raw', 'Parent', 'Leaf', 'Descending', 'Unique', 'AsHashtable', 'Oldest')
# Literal strings that look like a filesystem/registry location (UNC, device, provider-qualified, drive, hive).
$script:FmpPathLikePattern = '^\s*(\\\\|//|[A-Za-z]:[\\/]|HK[A-Z_]+:|[A-Za-z0-9_.]*\\?(FileSystem|Registry|Certificate|Environment|Variable|Function|Alias|WSMan)::)'
$script:FmpSensitivePathPattern = '(^|[\\/])(\.ssh|\.aws|\.azure|\.gnupg|\.kube|\.docker|\.git-credentials|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|id_ecdsa|ntuser\.dat|ntds\.dit|unattend\.xml|sysprep\.inf|hiberfil\.sys|login data|logins\.json|key4\.db|local state)([\\/]|$)|config[\\/](sam|security|system|software|default)([\\/]|$)|\\microsoft\\(credentials|protect|vault)([\\/]|$)|\.(kdbx|pfx|p12|pem|ppk)$|[\\/]credentials$'

function Get-FmpScopeChain {
    # Function scopes enclosing a node, innermost first, ending with 'top'. Callers wrap the result in @().
    param([Parameter(Mandatory)][object]$Node)
    $chain = New-Object System.Collections.Generic.List[string]
    $cur = $Node.Parent
    while ($null -ne $cur) {
        if ($cur -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $chain.Add('f' + $cur.Extent.StartOffset) }
        $cur = $cur.Parent
    }
    $chain.Add('top')
    return $chain.ToArray()
}

function Get-FmpStatementExpression {
    # The single expression behind a pipeline/statement, or $null when it is anything else.
    param([object]$Node)
    $cur = $Node
    while ($null -ne $cur) {
        if ($cur -is [System.Management.Automation.Language.PipelineAst]) {
            if ($cur.PipelineElements.Count -ne 1) { return $null }
            $cur = $cur.PipelineElements[0]
        }
        elseif ($cur -is [System.Management.Automation.Language.CommandExpressionAst]) { return $cur.Expression }
        elseif ($cur -is [System.Management.Automation.Language.ParenExpressionAst]) { $cur = $cur.Pipeline }
        elseif ($cur -is [System.Management.Automation.Language.ExpressionAst]) { return $cur }
        else { return $null }
    }
    return $null
}

function Get-FmpBindingName {
    # Key used for a variable in the bindings table: '<scope>|<name>'; $script:/$global: live in 'top'.
    param([Parameter(Mandatory)][object]$Variable, [Parameter(Mandatory)][string]$Scope)
    $name = [string]$Variable.VariablePath.UserPath
    if ($Variable.VariablePath.IsScript -or $Variable.VariablePath.IsGlobal) { return ('top|' + ($name -replace '^(script|global):', '')) }
    return ($Scope + '|' + $name)
}

function Get-FmpVariableKey {
    # The innermost scope that binds the variable, or '' when nothing in the file ever binds it.
    param([Parameter(Mandatory)][object]$Variable, [Parameter(Mandatory)][hashtable]$Bindings, [Parameter(Mandatory)][string[]]$Chain)
    $name = [string]$Variable.VariablePath.UserPath
    if ($Variable.VariablePath.IsScript -or $Variable.VariablePath.IsGlobal) {
        $topKey = Get-FmpBindingName -Variable $Variable -Scope 'top'
        if ($Bindings.ContainsKey($topKey)) { return $topKey }
        return ''
    }
    foreach ($scope in $Chain) {
        if ($Bindings.ContainsKey($scope + '|' + $name)) { return ($scope + '|' + $name) }
    }
    return ''
}

function Get-FmpLiteralStrings {
    # Literal string values an expression is known to hold. Emits nothing when it is not provably literal.
    param([object]$Expr, [hashtable]$Bindings, [string[]]$Chain)
    $e = Get-FmpStatementExpression $Expr
    if ($null -eq $e) { return }
    if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return [string]$e.Value }
    $parts = @()
    if ($e -is [System.Management.Automation.Language.ArrayExpressionAst]) { $parts = @($e.SubExpression.Statements) }
    elseif ($e -is [System.Management.Automation.Language.ArrayLiteralAst]) { $parts = @($e.Elements) }
    elseif ($e -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $key = Get-FmpVariableKey $e $Bindings $Chain
        if ($key -eq '') { return }
        if (-not $Bindings[$key]['litsOk'] -or $Bindings[$key]['lits'].Count -eq 0) { return }
        return $Bindings[$key]['lits'].ToArray()
    }
    else { return }
    $acc = New-Object System.Collections.Generic.List[string]
    foreach ($part in $parts) {
        $inner = @(Get-FmpLiteralStrings $part $Bindings $Chain)
        if ($inner.Count -eq 0) { return }
        foreach ($s in $inner) { $acc.Add([string]$s) }
    }
    return $acc.ToArray()
}

function Get-FmpExprKinds {
    # What can this expression evaluate to? '?' = possibly a live object. Callers wrap the result in @().
    param([object]$Expr, [hashtable]$Bindings, [string[]]$Chain)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Expr) { $out.Add('null'); return $out.ToArray() }
    $e = $Expr
    if ($e -is [System.Management.Automation.Language.PipelineAst] -or $e -is [System.Management.Automation.Language.ParenExpressionAst] -or
        $e -is [System.Management.Automation.Language.CommandExpressionAst]) {
        $single = Get-FmpStatementExpression $e
        if ($null -ne $single) { return (Get-FmpExprKinds $single $Bindings $Chain) }
        if ($e -is [System.Management.Automation.Language.PipelineAst] -and $e.PipelineElements.Count -eq 1 -and
            $e.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
            return (Get-FmpExprKinds $e.PipelineElements[0] $Bindings $Chain)
        }
        $out.Add('?')
        return $out.ToArray()
    }
    if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $e -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $out.Add('string') }
    elseif ($e -is [System.Management.Automation.Language.ConstantExpressionAst]) { $out.Add('scalar') }
    elseif ($e -is [System.Management.Automation.Language.HashtableAst]) { $out.Add('dict') }
    elseif ($e -is [System.Management.Automation.Language.ArrayExpressionAst] -or $e -is [System.Management.Automation.Language.ArrayLiteralAst]) { $out.Add('array') }
    elseif ($e -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $vp = $e.VariablePath
        $plain = [string]$vp.UserPath
        if ($vp.IsDriveQualified -and $vp.DriveName -eq 'env') { $out.Add('string') }
        elseif ($script:FmpAutoVariableKinds.ContainsKey($plain)) { $out.Add([string]$script:FmpAutoVariableKinds[$plain]) }
        else {
            $key = Get-FmpVariableKey $e $Bindings $Chain
            if ($key -eq '') { $out.Add('?') }
            elseif ($Bindings[$key]['kinds'].Count -eq 0) { if (-not $script:FmpBindingsBuilding) { $out.Add('?') } }
            else { foreach ($k in $Bindings[$key]['kinds'].Keys) { $out.Add([string]$k) } }
        }
    }
    elseif ($e -is [System.Management.Automation.Language.ConvertExpressionAst]) {
        # A cast (or a typed declaration) yields an instance of that type: value types and dictionaries are plain data.
        $tn = [string]$e.Type.TypeName.Name
        if ($tn -in @('pscustomobject', 'psobject')) {
            if ($e.Child -is [System.Management.Automation.Language.HashtableAst]) { $out.Add('obj') } else { $out.Add('?') }
        }
        else { $out.Add((Get-FmpTypeKind $tn)) }
    }
    elseif ($e -is [System.Management.Automation.Language.BinaryExpressionAst]) {
        $op = [string]$e.Operator
        if ($op -eq 'Plus') {
            foreach ($k in @(Get-FmpExprKinds $e.Left $Bindings $Chain)) { $out.Add([string]$k) }
            foreach ($k in @(Get-FmpExprKinds $e.Right $Bindings $Chain)) { $out.Add([string]$k) }
        }
        elseif ($op -in @('Format', 'Join', 'Ireplace', 'Creplace', 'Replace')) { $out.Add('string') }
        elseif ($op -in @('Isplit', 'Csplit', 'Split')) { $out.Add('array') }
        else { $out.Add('scalar') }
    }
    elseif ($e -is [System.Management.Automation.Language.UnaryExpressionAst]) {
        if ([string]$e.TokenKind -eq 'Comma') { $out.Add('array') } elseif ([string]$e.TokenKind -eq 'Join') { $out.Add('string') } else { $out.Add('scalar') }
    }
    elseif ($e -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
        $mname = [string]$e.Member.Extent.Text
        if ($e.Static) {
            $skey = $e.Expression.Extent.Text + '::' + $mname
            if ($script:FmpStaticKindOverrides.ContainsKey($skey)) { $out.Add([string]$script:FmpStaticKindOverrides[$skey]) } else { $out.Add($script:FmpScalarStaticDefault) }
        }
        elseif ($mname -in $script:FmpStringMethods) { $out.Add('string') }
        elseif ($mname -in $script:FmpArrayMethods) { $out.Add('array') }
        elseif ($mname -in $script:FmpScalarMethods) { $out.Add('scalar') }
        elseif ($mname -eq 'Replace' -or $mname -eq 'Append') {
            foreach ($k in @(Get-FmpExprKinds $e.Expression $Bindings $Chain)) { $out.Add([string]$k) }
        }
        else { $out.Add('?') }
    }
    elseif ($e -is [System.Management.Automation.Language.MemberExpressionAst]) {
        if ($e.Static) { $out.Add($script:FmpScalarStaticDefault) }
        elseif ([string]$e.Member.Extent.Text -in @('Count', 'Length')) { $out.Add('scalar') }
        else {
            $mShape = Get-FmpExprShape -Expr $e -Bindings $Bindings -Chain $Chain
            if ($null -ne $mShape -and $mShape['kinds'].Count -gt 0) {
                foreach ($k in $mShape['kinds'].Keys) { $out.Add([string]$k) }
            }
            else { $out.Add('?') }
        }
    }
    elseif ($e -is [System.Management.Automation.Language.IndexExpressionAst]) {
        $iShape = Get-FmpExprShape -Expr $e -Bindings $Bindings -Chain $Chain
        if ($null -ne $iShape -and $iShape['kinds'].Count -gt 0) {
            foreach ($k in $iShape['kinds'].Keys) { $out.Add([string]$k) }
        }
        else { $out.Add('?') }
    }
    elseif ($e -is [System.Management.Automation.Language.CommandAst]) {
        $cname = [string]$e.GetCommandName()
        if ($cname -eq 'New-Object') {
            $tname = ''
            if ($e.CommandElements.Count -ge 2) { $tname = [string]$e.CommandElements[1].Extent.Text }
            if ($tname -eq 'System.Text.StringBuilder') { $out.Add('sb') }
            elseif ($tname -like 'System.Collections.Generic.List*') { $out.Add('list') }
            else { $out.Add('?') }
        }
        elseif ($cname -in @('Get-Date', 'Test-Path', 'Measure-Object')) { $out.Add('scalar') }
        elseif ($cname -in @('Join-Path', 'Split-Path', 'ConvertTo-Json', 'Read-Host', 'Get-Content')) { $out.Add('string') }
        elseif ($cname -eq 'ConvertFrom-Json') { $out.Add('obj') }
        elseif ($script:FmpDataFunctions.ContainsKey($cname)) {
            foreach ($fk in @($script:FmpDataFunctions[$cname])) { $out.Add([string]$fk) }
        }
        else { $out.Add('?') }
    }
    elseif ($e -is [System.Management.Automation.Language.IfStatementAst]) {
        $hadElse = $false
        foreach ($clause in $e.Clauses) {
            $last = $null
            if ($clause.Item2.Statements.Count -gt 0) { $last = $clause.Item2.Statements[$clause.Item2.Statements.Count - 1] }
            foreach ($k in @(Get-FmpExprKinds $last $Bindings $Chain)) { $out.Add([string]$k) }
        }
        if ($null -ne $e.ElseClause) {
            $hadElse = $true
            $last = $null
            if ($e.ElseClause.Statements.Count -gt 0) { $last = $e.ElseClause.Statements[$e.ElseClause.Statements.Count - 1] }
            foreach ($k in @(Get-FmpExprKinds $last $Bindings $Chain)) { $out.Add([string]$k) }
        }
        if (-not $hadElse) { $out.Add('null') }
    }
    else { $out.Add('?') }
    return $out.ToArray()
}

function New-FmpShapeNode {
    return @{ kinds = @{}; fields = @{}; dyn = $null; hasDyn = $false }
}

function Merge-FmpShape {
    param([hashtable]$Target, [hashtable]$Source, [int]$Depth = 0)
    $changed = $false
    foreach ($k in $Source['kinds'].Keys) {
        if (-not $Target['kinds'].ContainsKey($k)) { $Target['kinds'][$k] = $true; $changed = $true }
    }
    if ($Depth -ge 4) { return $changed }
    foreach ($fk in $Source['fields'].Keys) {
        if (-not $Target['fields'].ContainsKey($fk)) { $Target['fields'][$fk] = New-FmpShapeNode; $changed = $true }
        if (Merge-FmpShape -Target ([hashtable]$Target['fields'][$fk]) -Source ([hashtable]$Source['fields'][$fk]) -Depth ($Depth + 1)) { $changed = $true }
    }
    if ($Source['hasDyn']) {
        if (-not $Target['hasDyn']) { $Target['hasDyn'] = $true; $changed = $true }
        if ($null -eq $Target['dyn']) { $Target['dyn'] = New-FmpShapeNode; $changed = $true }
        if ($null -ne $Source['dyn']) {
            if (Merge-FmpShape -Target ([hashtable]$Target['dyn']) -Source ([hashtable]$Source['dyn']) -Depth ($Depth + 1)) { $changed = $true }
        }
    }
    return $changed
}

function Get-FmpMemberSegments {
    param([object]$Node)
    $cur = $Node
    $rev = New-Object System.Collections.Generic.List[object]
    while ($true) {
        if ($cur -is [System.Management.Automation.Language.IndexExpressionAst]) {
            if ($cur.Index -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $rev.Add(@{ const = $true; name = [string]$cur.Index.Value })
            }
            else {
                $rev.Add(@{ const = $false; name = '' })
            }
            $cur = $cur.Target
        }
        elseif ($cur -is [System.Management.Automation.Language.MemberExpressionAst] -and -not $cur.Static) {
            $rev.Add(@{ const = $true; name = [string]$cur.Member.Value })
            $cur = $cur.Expression
        }
        elseif ($cur -is [System.Management.Automation.Language.ParenExpressionAst]) {
            $cur = Get-FmpStatementExpression $cur
            if ($null -eq $cur) { break }
        }
        else { break }
    }
    $segs = New-Object System.Collections.Generic.List[object]
    for ($i = $rev.Count - 1; $i -ge 0; $i--) { $segs.Add($rev[$i]) }
    return @{ root = $cur; segments = $segs.ToArray() }
}

function Get-FmpExprShape {
    param([object]$Expr, [hashtable]$Bindings, [string[]]$Chain, [int]$Depth = 0)
    if ($null -eq $Expr -or $Depth -gt 6) { return $null }
    $e = Get-FmpStatementExpression $Expr
    if ($null -eq $e) {
        $res = New-FmpShapeNode
        foreach ($k in @(Get-FmpExprKinds $Expr $Bindings $Chain)) { $res['kinds'][$k] = $true }
        return $res
    }
    if ($e -is [System.Management.Automation.Language.ConvertExpressionAst] -and
        [string]$e.Type.TypeName.Name -eq 'ordered' -and
        $e.Child -is [System.Management.Automation.Language.HashtableAst]) {
        $e = $e.Child
    }
    if ($e -is [System.Management.Automation.Language.HashtableAst]) {
        $s = New-FmpShapeNode
        $s['kinds']['dict'] = $true
        foreach ($kv in $e.KeyValuePairs) {
            $valShape = Get-FmpExprShape -Expr $kv.Item2 -Bindings $Bindings -Chain $Chain -Depth ($Depth + 1)
            if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $kname = [string]$kv.Item1.Value
                if (-not $s['fields'].ContainsKey($kname)) { $s['fields'][$kname] = New-FmpShapeNode }
                if ($null -ne $valShape) { $null = Merge-FmpShape -Target ([hashtable]$s['fields'][$kname]) -Source $valShape }
                else { $s['fields'][$kname]['kinds']['?'] = $true }
            }
            else {
                $s['hasDyn'] = $true
                if ($null -eq $s['dyn']) { $s['dyn'] = New-FmpShapeNode }
                if ($null -ne $valShape) { $null = Merge-FmpShape -Target ([hashtable]$s['dyn']) -Source $valShape }
                else { $s['dyn']['kinds']['?'] = $true }
            }
        }
        return $s
    }
    if ($e -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $key = Get-FmpVariableKey $e $Bindings $Chain
        if ($key -ne '') { return ([hashtable]$Bindings[$key]['shape']) }
        $res = New-FmpShapeNode
        foreach ($k in @(Get-FmpExprKinds $e $Bindings $Chain)) { $res['kinds'][$k] = $true }
        return $res
    }
    if (($e -is [System.Management.Automation.Language.MemberExpressionAst] -and -not $e.Static -and
         $e -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) -or
        ($e -is [System.Management.Automation.Language.IndexExpressionAst])) {
        $targetExpr = if ($e -is [System.Management.Automation.Language.MemberExpressionAst]) { $e.Expression } else { $e.Target }
        $tShape = Get-FmpExprShape -Expr $targetExpr -Bindings $Bindings -Chain $Chain -Depth ($Depth + 1)
        if ($null -eq $tShape -or $tShape['kinds'].Count -eq 0) { return $null }
        if (-not (Test-FmpProvenData -Kinds @($tShape['kinds'].Keys) -Allowed $script:FmpSettableKinds)) { return $null }
        $isConstKey = $false
        $constName = ''
        if ($e -is [System.Management.Automation.Language.MemberExpressionAst]) { $isConstKey = $true; $constName = [string]$e.Member.Value }
        elseif ($e.Index -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $isConstKey = $true; $constName = [string]$e.Index.Value }
        $res = New-FmpShapeNode
        $found = $false
        if ($isConstKey) {
            if ($tShape['fields'].ContainsKey($constName)) {
                $null = Merge-FmpShape -Target $res -Source ([hashtable]$tShape['fields'][$constName])
                $found = $true
            }
            if ($tShape['hasDyn'] -and $null -ne $tShape['dyn']) {
                $null = Merge-FmpShape -Target $res -Source ([hashtable]$tShape['dyn'])
                $found = $true
            }
        }
        else {
            if ($tShape['hasDyn'] -and $null -ne $tShape['dyn']) {
                $null = Merge-FmpShape -Target $res -Source ([hashtable]$tShape['dyn'])
                $found = $true
            }
            foreach ($fk in $tShape['fields'].Keys) {
                $null = Merge-FmpShape -Target $res -Source ([hashtable]$tShape['fields'][$fk])
                $found = $true
            }
        }
        if (-not $found) { return $null }
        return $res
    }
    $res = New-FmpShapeNode
    foreach ($k in @(Get-FmpExprKinds $e $Bindings $Chain)) { $res['kinds'][$k] = $true }
    return $res
}

function Add-FmpBindingSite {
    # Registers what one assignment/parameter/loop can put into a variable. Returns $true when something new was learned.
    param([hashtable]$Bindings, [string]$Key, [string[]]$Kinds, [string[]]$Lits, [bool]$Literal)
    $changed = $false
    if (-not $Bindings.ContainsKey($Key)) {
        $Bindings[$Key] = @{ kinds = @{}; lits = (New-Object System.Collections.Generic.List[string]); litsOk = $true; shape = (New-FmpShapeNode) }
        $changed = $true
    }
    foreach ($k in $Kinds) {
        if (-not $Bindings[$Key]['kinds'].ContainsKey($k)) { $Bindings[$Key]['kinds'][$k] = $true; $changed = $true }
        if (-not $Bindings[$Key]['shape']['kinds'].ContainsKey($k)) { $Bindings[$Key]['shape']['kinds'][$k] = $true }
    }
    if ($Literal) {
        $litsList = New-Object System.Collections.Generic.List[string]
        foreach ($existingLit in @($Bindings[$Key]['lits'])) { $litsList.Add([string]$existingLit) }
        foreach ($l in $Lits) {
            if (-not $litsList.Contains([string]$l)) { $litsList.Add([string]$l); $changed = $true }
        }
        $Bindings[$Key]['lits'] = $litsList
    }
    elseif ($Bindings[$Key]['litsOk']) { $Bindings[$Key]['litsOk'] = $false; $changed = $true }
    return $changed
}

function Get-FmpTypeKind {
    # Kind implied by a type name used as cast, parameter type or variable constraint.
    param([string]$TypeName)
    if ($TypeName -in @('hashtable', 'System.Collections.Hashtable', 'System.Collections.IDictionary', 'System.Collections.Specialized.OrderedDictionary', 'ordered')) { return 'dict' }
    if ($TypeName -eq 'string') { return 'string' }
    if ($TypeName -match '\[\]$' -or $TypeName -eq 'array') { return 'array' }
    if (($TypeName -replace '^System\.', '') -in $script:FmpScalarTypes) { return 'scalar' }
    return '?'
}

function Get-FmpParameterKinds {
    param([object]$Parameter)
    foreach ($attr in $Parameter.Attributes) {
        if ($attr -isnot [System.Management.Automation.Language.TypeConstraintAst]) { continue }
        $kind = Get-FmpTypeKind ([string]$attr.TypeName.Name)
        if ($kind -ne '?') { return $kind }
    }
    return '?'
}

function Get-FmpBindings {
    # Fixed point over every assignment, parameter and loop in the file. Round -1 registers which names are bound and
    # settles the sites whose kinds never change (parameters, -ErrorVariable, [ref]); later rounds only re-evaluate
    # assignments and loops, because their kinds can depend on other variables.
    param([Parameter(Mandatory)][object]$Ast)
    $bindings = @{}
    $script:FmpBindingsBuilding = $true
    $sites = $Ast.FindAll({ param($a)
        $a -is [System.Management.Automation.Language.AssignmentStatementAst] -or
        $a -is [System.Management.Automation.Language.ParameterAst] -or
        $a -is [System.Management.Automation.Language.ForEachStatementAst] -or
        ($a -is [System.Management.Automation.Language.CommandAst] -and $a.CommandElements.Count -gt 2) -or
        ($a -is [System.Management.Automation.Language.ConvertExpressionAst] -and [string]$a.Type.TypeName.Name -eq 'ref')
    }, $true)
    $dynamic = New-Object System.Collections.Generic.List[object]
    foreach ($site in $sites) {
        $chain = @(Get-FmpScopeChain $site)
        $scope = $chain[0]
        if ($site -is [System.Management.Automation.Language.ParameterAst]) {
            $null = Add-FmpBindingSite $bindings (Get-FmpBindingName -Variable $site.Name -Scope $scope) @(Get-FmpParameterKinds $site) @() $false
        }
        elseif ($site -is [System.Management.Automation.Language.ConvertExpressionAst]) {
            if ($site.Child -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $null = Add-FmpBindingSite $bindings (Get-FmpBindingName -Variable $site.Child -Scope $scope) @('?') @() $false
            }
        }
        elseif ($site -is [System.Management.Automation.Language.CommandAst]) {
            for ($i = 1; $i -lt $site.CommandElements.Count - 1; $i++) {
                $el = $site.CommandElements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -in $script:FmpVariableBindingParameters) {
                    $nextEl = $site.CommandElements[$i + 1]
                    if ($nextEl -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        $null = Add-FmpBindingSite $bindings ($scope + '|' + ([string]$nextEl.Value -replace '^\+', '')) @('?') @() $false
                    }
                }
            }
        }
        elseif ($site -is [System.Management.Automation.Language.ForEachStatementAst]) {
            $target = Get-FmpBindingName -Variable $site.Variable -Scope $scope
            $null = Add-FmpBindingSite $bindings $target @() @() $true
            $dynamic.Add(@{ kind = 'foreach'; site = $site; chain = $chain; targets = @($target); declared = $null })
        }
        else {
            $left = $site.Left
            $declared = $null
            if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $declared = $left; $left = $left.Child }
            if ($left -is [System.Management.Automation.Language.MemberExpressionAst] -or $left -is [System.Management.Automation.Language.IndexExpressionAst]) {
                $segInfo = Get-FmpMemberSegments $left
                if ($segInfo.root -is [System.Management.Automation.Language.VariableExpressionAst] -and $segInfo.segments.Count -gt 0) {
                    $dynamic.Add(@{ kind = 'member_assign'; site = $site; chain = $chain; rootVar = $segInfo.root; segments = $segInfo.segments })
                }
                continue
            }
            $targets = New-Object System.Collections.Generic.List[string]
            if ($left -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                foreach ($el in $left.Elements) {
                    if ($el -is [System.Management.Automation.Language.VariableExpressionAst]) { $targets.Add((Get-FmpBindingName -Variable $el -Scope $scope)) }
                }
            }
            elseif ($left -is [System.Management.Automation.Language.VariableExpressionAst]) { $targets.Add((Get-FmpBindingName -Variable $left -Scope $scope)) }
            if ($targets.Count -eq 0) { continue }
            foreach ($target in $targets) { $null = Add-FmpBindingSite $bindings $target @() @() $true }
            $dynamic.Add(@{ kind = 'assign'; site = $site; chain = $chain; targets = $targets.ToArray(); declared = $declared; multi = ($left -is [System.Management.Automation.Language.ArrayLiteralAst]) })
        }
    }
    for ($round = 0; $round -lt 8; $round++) {
        $changed = $false
        foreach ($d in $dynamic) {
            $site = $d.site
            $chain = $d.chain
            if ($d.kind -eq 'member_assign') {
                $rootKey = Get-FmpVariableKey $d.rootVar $bindings $chain
                if ($rootKey -eq '') { continue }
                $cur = [hashtable]$bindings[$rootKey]['shape']
                foreach ($seg in $d.segments) {
                    if ($seg.const) {
                        if (-not $cur['fields'].ContainsKey($seg.name)) { $cur['fields'][$seg.name] = New-FmpShapeNode; $changed = $true }
                        $cur = [hashtable]$cur['fields'][$seg.name]
                    }
                    else {
                        if (-not $cur['hasDyn']) { $cur['hasDyn'] = $true; $changed = $true }
                        if ($null -eq $cur['dyn']) { $cur['dyn'] = New-FmpShapeNode; $changed = $true }
                        $cur = [hashtable]$cur['dyn']
                    }
                }
                $rhsShape = Get-FmpExprShape -Expr $site.Right -Bindings $bindings -Chain $chain
                if ($null -ne $rhsShape) {
                    if (Merge-FmpShape -Target $cur -Source $rhsShape) { $changed = $true }
                }
                elseif (-not $cur['kinds'].ContainsKey('?')) {
                    $cur['kinds']['?'] = $true
                    $changed = $true
                }
                continue
            }
            $kinds = @()
            $lits = @()
            $isLit = $false
            if ($d.kind -eq 'foreach') {
                $lits = @(Get-FmpLiteralStrings $site.Condition $bindings $chain)
                if ($lits.Count -gt 0) { $kinds = @('string'); $isLit = $true } else { $kinds = @('?') }
            }
            elseif ($d.multi) { $kinds = @('?') }
            else {
                $op = [string]$site.Operator
                if ($null -ne $d.declared) { $kinds = @(Get-FmpExprKinds $d.declared $bindings $chain) }
                elseif ($op -eq 'Equals' -or $op -eq 'QuestionQuestionEquals') { $kinds = @(Get-FmpExprKinds $site.Right $bindings $chain) }
                elseif ($op -eq 'PlusEquals') {
                    foreach ($k in @(Get-FmpExprKinds $site.Right $bindings $chain)) { if ($k -eq '?') { $kinds += 'array' } else { $kinds += $k } }
                }
                else { $kinds = @('scalar') }
                if ($op -eq 'Equals' -and $null -eq $d.declared) {
                    $lits = @(Get-FmpLiteralStrings $site.Right $bindings $chain)
                    $isLit = ($lits.Count -gt 0)
                }
            }
            foreach ($target in $d.targets) {
                if (Add-FmpBindingSite $bindings $target ([string[]]$kinds) ([string[]]$lits) $isLit) { $changed = $true }
                if ($d.kind -eq 'assign' -and -not $d.multi -and $null -eq $d.declared -and [string]$site.Operator -in @('Equals', 'QuestionQuestionEquals')) {
                    $rhsShape = Get-FmpExprShape -Expr $site.Right -Bindings $bindings -Chain $chain
                    if ($null -ne $rhsShape -and (Merge-FmpShape -Target ([hashtable]$bindings[$target]['shape']) -Source $rhsShape)) { $changed = $true }
                }
            }
        }
        if (-not $changed) { break }
    }
    $script:FmpBindingsBuilding = $false
    return $bindings
}

function Test-FmpProvenData {
    # $true when every kind is plain data (never '?', never empty) and, optionally, inside an allowed set.
    param([string[]]$Kinds, [string[]]$Allowed = @())
    if ($Kinds.Count -eq 0) { return $false }
    foreach ($k in $Kinds) {
        if ($k -notin $script:FmpDataKinds) { return $false }
        if ($Allowed.Count -gt 0 -and $k -notin $Allowed) { return $false }
    }
    return $true
}

function Get-FmpChainRoot {
    # Peels index/member links: $a['x'].y['z'] -> root $a plus the number of links.
    param([object]$Node)
    $cur = $Node
    $linkCount = 0
    while ($true) {
        if ($cur -is [System.Management.Automation.Language.IndexExpressionAst]) { $linkCount++; $cur = $cur.Target }
        elseif ($cur -is [System.Management.Automation.Language.MemberExpressionAst] -and -not $cur.Static) { $linkCount++; $cur = $cur.Expression }
        elseif ($cur -is [System.Management.Automation.Language.ParenExpressionAst]) { $cur = Get-FmpStatementExpression $cur; if ($null -eq $cur) { break } }
        else { break }
    }
    return @{ root = $cur; links = $linkCount }
}

function Get-FmpSetterProblem {
    # '' when an assignment target (or ++/--) only mutates local data; otherwise the violation type.
    param([object]$Target, [hashtable]$Bindings, [string[]]$Chain)
    $t = $Target
    if ($t -is [System.Management.Automation.Language.ConvertExpressionAst]) { $t = $t.Child }
    if ($t -is [System.Management.Automation.Language.VariableExpressionAst]) { return '' }
    if ($t -is [System.Management.Automation.Language.MemberExpressionAst]) {
        if ($t.Static) { return 'property_setter_not_allowed' }
        if ($t.Expression -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return 'property_setter_not_allowed' }
        $kinds = @(Get-FmpExprKinds $t.Expression $Bindings $Chain)
        if (Test-FmpProvenData -Kinds $kinds -Allowed $script:FmpSettableKinds) { return '' }
        return 'property_setter_not_allowed'
    }
    if ($t -is [System.Management.Automation.Language.IndexExpressionAst]) {
        $chainRoot = Get-FmpChainRoot $t
        if ($chainRoot.root -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return 'index_setter_not_allowed' }
        $kinds = @(Get-FmpExprKinds $chainRoot.root $Bindings $Chain)
        if (Test-FmpProvenData -Kinds $kinds) { return '' }
        return 'index_setter_not_allowed'
    }
    return 'property_setter_not_allowed'
}

function Get-FmpReceiverProblem {
    # '' when a guarded instance method (Add/Remove/Replace/...) is called on proven local data.
    param([object]$Member, [string]$Name, [hashtable]$Bindings, [string[]]$Chain)
    $receiver = $Member.Expression
    $allowedKinds = [string[]]$script:FmpGuardedMethodKinds[$Name]
    $direct = @(Get-FmpExprKinds $receiver $Bindings $Chain)
    if (Test-FmpProvenData -Kinds $direct -Allowed $allowedKinds) { return '' }
    return 'receiver_not_proven'
}

function Get-FmpLiteralPathProblem {
    # '' when a literal may appear as a path; otherwise 'path_not_allowed'.
    param([string]$Value, [string]$Role, [bool]$AsArgument)
    $v = $Value.Trim()
    if ($v -eq '') { return 'path_not_allowed' }
    if ($v -match '^(\\\\|//)') { return 'path_not_allowed' }
    if ($v -match '::') { return 'path_not_allowed' }
    if ($v -match '^HK[A-Z_]+:') {
        foreach ($allowed in $script:FmpAllowedRegistryPaths) { if ($v -ieq $allowed) { return '' } }
        return 'path_not_allowed'
    }
    if ($v -match $script:FmpSensitivePathPattern) { return 'path_not_allowed' }
    if (($v -match '^[A-Za-z]:' -or $AsArgument) -and $Role -eq 'collector') { return 'path_not_allowed' }
    return ''
}

function Get-FmpPathArgumentProblem {
    # Path-consuming cmdlets: a literal must be allowed; in collectors a variable must come from a checked-path producer.
    param([object]$Arg, [string]$Role, [hashtable]$Bindings, [string[]]$Chain)
    if ($Arg -is [System.Management.Automation.Language.ArrayLiteralAst]) {
        foreach ($el in $Arg.Elements) {
            $p = Get-FmpPathArgumentProblem $el $Role $Bindings $Chain
            if ($p -ne '') { return $p }
        }
        return ''
    }
    if ($Arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return (Get-FmpLiteralPathProblem -Value ([string]$Arg.Value) -Role $Role -AsArgument $true) }
    if ($Arg -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $Arg.NestedExpressions.Count -eq 0) {
        return (Get-FmpLiteralPathProblem -Value ([string]$Arg.Value) -Role $Role -AsArgument $true)
    }
    if ($Role -ne 'collector') { return '' }
    if ($Arg -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $kinds = @(Get-FmpExprKinds $Arg $Bindings $Chain)
        if ($kinds -contains 'safepath' -and (Test-FmpProvenData -Kinds $kinds -Allowed @('safepath', 'null'))) { return '' }
    }
    return 'path_argument_not_proven'
}

function Get-FmpCommandArguments {
    # Parameter/value pairs of one command (name $null = positional, value $null = switch). Callers wrap the result in @().
    param([Parameter(Mandatory)][object]$Command)
    $items = New-Object System.Collections.Generic.List[object]
    $i = 1
    while ($i -lt $Command.CommandElements.Count) {
        $el = $Command.CommandElements[$i]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
            if ($null -ne $el.Argument) { $items.Add(@{ name = [string]$el.ParameterName; value = $el.Argument }) }
            elseif ($el.ParameterName -in $script:FmpSwitchParameters) { $items.Add(@{ name = [string]$el.ParameterName; value = $null }) }
            elseif ($i + 1 -lt $Command.CommandElements.Count -and $Command.CommandElements[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) {
                $items.Add(@{ name = [string]$el.ParameterName; value = $Command.CommandElements[$i + 1] })
                $i++
            }
            else { $items.Add(@{ name = [string]$el.ParameterName; value = $null }) }
        }
        else { $items.Add(@{ name = $null; value = $el }) }
        $i++
    }
    return $items.ToArray()
}

function Get-FmpQueryProblems {
    # Get-WinEvent / Get-CimInstance: only allowlisted logs, filter keys, classes and namespaces.
    param([Parameter(Mandatory)][object]$Command, [string]$Name, [hashtable]$Bindings, [string[]]$Chain)
    $problems = New-Object System.Collections.Generic.List[string]
    $cmdArgs = @(Get-FmpCommandArguments $Command)
    if ($Name -eq 'Get-WinEvent') {
        $filter = $null
        $oldest = $false
        $maxEvents = $null
        foreach ($a in $cmdArgs) {
            if ($null -eq $a.name) { $problems.Add('Get-WinEvent positional argument'); continue }
            if ($a.name -eq 'FilterHashtable') { $filter = $a.value }
            elseif ($a.name -eq 'Oldest') { $oldest = $true; if ($null -ne $a.value) { $problems.Add('-Oldest takes no value') } }
            elseif ($a.name -eq 'MaxEvents') { $maxEvents = $a.value }
        }
        if ($filter -isnot [System.Management.Automation.Language.HashtableAst]) {
            $problems.Add('Get-WinEvent -FilterHashtable must be a literal hashtable')
            return $problems.ToArray()
        }
        $filterKeys = @($filter.KeyValuePairs | ForEach-Object { [string]$_.Item1.Extent.Text.Trim([char]39, [char]34) })
        # -Oldest exists only to read the single oldest record's time (log retention), never to walk a log from its start.
        if ($oldest) {
            if ($maxEvents -isnot [System.Management.Automation.Language.ConstantExpressionAst] -or [string]$maxEvents.Value -ne '1') { $problems.Add('-Oldest requires -MaxEvents 1') }
            if ($filterKeys.Count -ne 1 -or $filterKeys[0] -ne 'LogName') { $problems.Add('-Oldest allows only a LogName filter') }
        }
        foreach ($pair in $filter.KeyValuePairs) {
            $key = $pair.Item1
            if ($key -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or [string]$key.Value -notin $script:FmpAllowedEventFilterKeys) {
                $problems.Add('filter key not allowed: ' + $key.Extent.Text)
                continue
            }
            if ([string]$key.Value -eq 'LogName') {
                $vals = @(Get-FmpLiteralStrings $pair.Item2 $Bindings $Chain)
                if ($vals.Count -eq 0) { $problems.Add('LogName is not a known literal'); continue }
                foreach ($lv in $vals) { if ([string]$lv -notin $script:FmpAllowedEventLogs) { $problems.Add('log not allowed: ' + $lv) } }
            }
            elseif ([string]$key.Value -eq 'ProviderName') {
                if ('LogName' -notin $filterKeys) { $problems.Add('ProviderName requires a LogName') }
                $vals = @(Get-FmpLiteralStrings $pair.Item2 $Bindings $Chain)
                if ($vals.Count -eq 0) { $problems.Add('ProviderName is not a known literal'); continue }
                foreach ($pv in $vals) { if ([string]$pv -cnotin $script:FmpAllowedEventProviders) { $problems.Add('provider not allowed: ' + $pv) } }
            }
        }
    }
    elseif ($Name -eq 'Get-CimInstance') {
        $class = $null
        $propertyArg = $null
        foreach ($a in $cmdArgs) {
            if ($null -eq $a.name) { $problems.Add('Get-CimInstance positional argument'); continue }
            if ($a.name -eq 'ClassName') { $class = $a.value }
            elseif ($a.name -eq 'Property') { $propertyArg = $a.value }
            elseif ($a.name -eq 'Namespace') {
                $ns = @(Get-FmpLiteralStrings $a.value $Bindings $Chain)
                if ($ns.Count -ne 1 -or [string]$ns[0] -notin $script:FmpAllowedCimNamespaces) { $problems.Add('namespace not allowed: ' + $a.value.Extent.Text) }
            }
            elseif ($a.name -eq 'Filter') {
                $f = $a.value
                $constant = ($f -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or
                    ($f -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $f.NestedExpressions.Count -eq 0)
                if (-not $constant) { $problems.Add('Filter must be a constant string') }
            }
        }
        $cv = @()
        if ($null -ne $class) { $cv = @(Get-FmpLiteralStrings $class $Bindings $Chain) }
        if ($cv.Count -ne 1 -or [string]$cv[0] -notin $script:FmpAllowedCimClasses) { $problems.Add('class not allowed or not literal') }
        elseif ($script:FmpRestrictedCimProperties.ContainsKey([string]$cv[0])) {
            $restricted = $script:FmpRestrictedCimProperties[[string]$cv[0]]
            $props = @()
            if ($null -ne $propertyArg) { $props = @(Get-FmpLiteralStrings $propertyArg $Bindings $Chain) }
            if ($props.Count -eq 0) { $problems.Add('class requires a literal -Property list: ' + $cv[0]) }
            foreach ($pn in $props) { if ([string]$pn -cnotin $restricted) { $problems.Add('property not allowed: ' + $pn) } }
        }
    }
    return $problems.ToArray()
}

function Get-FmpSafeRegistryPath {
    # Runtime twin of the scanner rule: a registry key may only be read when it is on the allowlist.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    foreach ($allowed in $script:FmpAllowedRegistryPaths) {
        if ($Path -ieq $allowed) { return $allowed }
    }
    throw ('Registry path is not on the read-only allowlist: ' + $Path)
}

function Test-FmpScriptCompliance {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Role = '',
        [string[]]$InternalFunctions = @()
    )
    if ([string]::IsNullOrEmpty($Role)) { $Role = Get-FmpFileRole -Path $Path }
    $violations = New-Object System.Collections.Generic.List[object]

    function Add-FmpViolation([string]$Type, [string]$Detail, [int]$Line) {
        $violations.Add(@{ type = $Type; detail = $Detail; line = $Line; role = $Role })
    }

    # ---- 1. Text-level scans (skip pure comment lines; skipped for the
    # policy file itself and tests, which legitimately contain pattern text) ----
    if ($Role -ne 'test' -and (Split-Path -Path $Path -Leaf) -ne 'ReadOnlyPolicy.ps1') {
        $lines = [System.IO.File]::ReadAllLines($Path)
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $trimmed = $line.TrimStart()
            if ($trimmed.StartsWith('#')) { continue }
            foreach ($pat in $script:FmpTextScanPatterns) {
                if ($trimmed -match $pat.Pattern) {
                    Add-FmpViolation -Type ('text_' + $pat.Id) -Detail ($pat.Id + ': ' + $trimmed.Substring(0, [Math]::Min(120, $trimmed.Length))) -Line ($i + 1)
                }
            }
        }
    }

    # ---- 2. AST scans ----
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($null -eq $ast) {
        Add-FmpViolation -Type 'parse_failure' -Detail 'AST could not be produced' -Line 0
        return @{ Path = $Path; Role = $Role; Ok = $false; Violations = $violations.ToArray() }
    }
    foreach ($e in $parseErrors) {
        Add-FmpViolation -Type 'parse_error' -Detail $e.Message -Line $e.Extent.StartLineNumber
    }

    $leaf = Split-Path -Path $Path -Leaf
    $isCli = $Role -eq 'core' -and $leaf -eq 'fixmypc.ps1'
    $isCommon = $Role -eq 'core' -and $leaf -eq 'Common.ps1'
    $sourceLoads = @()
    if ($isCli) {
        $sourceLoads = @($script:FmpSourceFiles | Where-Object { $_ -ne 'fixmypc.ps1' } |
            ForEach-Object { ". (Join-Path " + '$script:FmpRoot' + " '" + $_ + "')" })
    }
    elseif ($Role -eq 'test') {
        $sourceLoads = @($script:FmpSourceFiles | Where-Object { $_ -notmatch '^(fixmypc|src\\collectors)' } |
            ForEach-Object { ". (Join-Path " + '$root' + " '" + $_ + "')" })
    }

    foreach ($node in $ast.FindAll({ param($a)
        $a -is [System.Management.Automation.Language.RedirectionAst] -or
        $a -is [System.Management.Automation.Language.UsingStatementAst] -or
        $a -is [System.Management.Automation.Language.TypeDefinitionAst] -or
        $a -is [System.Management.Automation.Language.AssignmentStatementAst] -or
        $a -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) {
        $kind = $node.GetType().Name
        if ($kind -eq 'AssignmentStatementAst') {
            if ($node.Left.Extent.Text -notmatch '\$(?:\{)?(?:global|env|function|alias|variable|registry|cert):') { continue }
        }
        elseif ($kind -eq 'FunctionDefinitionAst' -and $node.Name -match '^[A-Za-z]+-Fmp[A-Za-z0-9_]+$') { continue }
        elseif ($Role -eq 'test' -and $node.Extent.Text -eq '*> $null') { continue }
        Add-FmpViolation -Type 'syntax_not_allowed' -Detail $kind -Line $node.Extent.StartLineNumber
    }
    # ---- 2b. FMP-02: setters may only mutate local data (receiver type is proven, not assumed) ----
    $bindings = Get-FmpBindings -Ast $ast
    $receiverCache = @{}
    foreach ($node in $ast.FindAll({ param($a)
        $a -is [System.Management.Automation.Language.AssignmentStatementAst] -or
        ($a -is [System.Management.Automation.Language.UnaryExpressionAst] -and [string]$a.TokenKind -in @('PlusPlus', 'MinusMinus', 'PostfixPlusPlus', 'PostfixMinusMinus'))
    }, $true)) {
        $setterTargets = @()
        if ($node -is [System.Management.Automation.Language.AssignmentStatementAst]) { $setterTargets = @($node.Left) } else { $setterTargets = @($node.Child) }
        if ($setterTargets[0] -is [System.Management.Automation.Language.ArrayLiteralAst]) { $setterTargets = @($setterTargets[0].Elements) }
        foreach ($setterTarget in $setterTargets) {
            $setterProblem = Get-FmpSetterProblem -Target $setterTarget -Bindings $bindings -Chain @(Get-FmpScopeChain $node)
            if ($setterProblem -ne '') { Add-FmpViolation -Type $setterProblem -Detail $setterTarget.Extent.Text -Line $node.Extent.StartLineNumber }
        }
    }

    # ---- 2c. FMP-03: literal locations. UNC, device, provider-qualified, sensitive or non-allowlisted hive paths are never data ----
    if ($Role -ne 'test') {
        foreach ($lit in $ast.FindAll({ param($a)
            $a -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            ($a -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $a.NestedExpressions.Count -eq 0)
        }, $true)) {
            if ([string]$lit.Value -notmatch $script:FmpPathLikePattern) { continue }
            $holder = $lit.Parent
            if ($holder -is [System.Management.Automation.Language.ArrayLiteralAst]) { $holder = $holder.Parent }
            if ($holder -is [System.Management.Automation.Language.BinaryExpressionAst] -and $holder.Right.Extent.StartOffset -le $lit.Extent.StartOffset -and
                [string]$holder.Operator -match '^[ic]?(like|notlike|match|notmatch|replace|split|eq|ne|contains|notcontains|in|notin)$') { continue }
            if ((Get-FmpLiteralPathProblem -Value ([string]$lit.Value) -Role $Role -AsArgument $false) -ne '') {
                Add-FmpViolation -Type 'path_not_allowed' -Detail ([string]$lit.Value) -Line $lit.Extent.StartLineNumber
            }
        }
    }

    if ($null -ne $ast.ScriptRequirements) {
        Add-FmpViolation -Type 'script_requirements' -Detail 'Implicit imports or elevation are forbidden.' -Line 1
    }

    $commands = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commands) {
        $line = $cmd.Extent.StartLineNumber
        $name = $cmd.GetCommandName()
        if ($cmd.InvocationOperator -eq 'Dot' -and $cmd.Extent.Text -cin $sourceLoads) { continue }
        if ($cmd.InvocationOperator -eq 'Ampersand' -and $Role -eq 'analysis' -and
            $leaf -eq 'Evidence.ps1' -and $cmd.Extent.Text -ceq '& $Body $ctx') { continue }
        if ($cmd.InvocationOperator -eq 'Ampersand' -and $Role -eq 'test' -and $name -in @('powershell', 'pwsh')) { continue }
        if ($cmd.InvocationOperator -in @('Dot', 'Ampersand') -or [string]::IsNullOrEmpty($name)) {
            Add-FmpViolation -Type 'dynamic_invocation' -Detail 'Unexpected call operator or non-literal command.' -Line $line
            continue
        }
        if ($name -match '[\\\\/:]') {
            Add-FmpViolation -Type 'qualified_command' -Detail $name -Line $line
            continue
        }
        if ($script:FmpHardBannedCommands -contains $name) {
            Add-FmpViolation -Type 'hard_banned_command' -Detail $name -Line $line
            continue
        }
        if ($name -eq 'Read-Host' -and -not $isCli) {
            Add-FmpViolation -Type 'command_role' -Detail $name -Line $line
            continue
        }
        if ($name -in @('Write-FmpUtf8File', 'Write-FmpJsonFile', 'Set-FmpAllowedWriteRoot', 'New-FmpOutputDirectory', 'Write-FmpHtmlReport') -and
            -not ($isCli -or $isCommon -or $Role -in @('writer', 'test'))) {
            Add-FmpViolation -Type 'command_role' -Detail $name -Line $line
            continue
        }
        if ($name -eq 'Invoke-FmpCollector' -and ($Role -notin @('collector', 'test') -or
            @($cmd.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }).Count -ne 1)) {
            Add-FmpViolation -Type 'collector_body' -Detail 'Expected a literal collector body.' -Line $line
            continue
        }
        if ($script:FmpAllowedCommands.ContainsKey($name)) { $parameters = $script:FmpAllowedCommands[$name] }
        elseif ($script:FmpSafeUtilityCommands.ContainsKey($name)) { $parameters = $script:FmpSafeUtilityCommands[$name] }
        elseif ($name -in $InternalFunctions) { $parameters = $null }
        else {
            Add-FmpViolation -Type 'command_not_allowed' -Detail $name -Line $line
            continue
        }
        foreach ($element in $cmd.CommandElements) {
            if ($element -is [System.Management.Automation.Language.VariableExpressionAst] -and $element.Splatted) {
                Add-FmpViolation -Type 'splat_not_allowed' -Detail $name -Line $line
            }
            if ($null -ne $parameters -and $element -is [System.Management.Automation.Language.CommandParameterAst] -and
                $element.ParameterName -notin $parameters) {
                Add-FmpViolation -Type 'parameter_not_allowed' -Detail ($name + ' -' + $element.ParameterName) -Line $line
            }
        }
        if ($name -in $script:FmpPathConsumers) {
            $cmdChain = @(Get-FmpScopeChain $cmd)
            $positionalSeen = 0
            foreach ($cmdArg in @(Get-FmpCommandArguments $cmd)) {
                $isPathArg = $false
                if ($null -eq $cmdArg.name) { if ($positionalSeen -eq 0) { $isPathArg = $true }; $positionalSeen++ }
                elseif ($cmdArg.name -in $script:FmpPathParameters) { $isPathArg = $true }
                if (-not $isPathArg -or $null -eq $cmdArg.value) { continue }
                $pathProblem = Get-FmpPathArgumentProblem -Arg $cmdArg.value -Role $Role -Bindings $bindings -Chain $cmdChain
                if ($pathProblem -ne '') { Add-FmpViolation -Type $pathProblem -Detail ($name + ' ' + $cmdArg.value.Extent.Text) -Line $line }
            }
            $pipe = $cmd.Parent
            if ($pipe -is [System.Management.Automation.Language.PipelineAst] -and $pipe.PipelineElements.Count -gt 1 -and
                $pipe.PipelineElements[0].Extent.StartOffset -ne $cmd.Extent.StartOffset) {
                Add-FmpViolation -Type 'pipeline_path_input' -Detail $name -Line $line
            }
        }
        elseif ($name -in @('Get-WinEvent', 'Get-CimInstance')) {
            foreach ($queryProblem in @(Get-FmpQueryProblems -Command $cmd -Name $name -Bindings $bindings -Chain @(Get-FmpScopeChain $cmd))) {
                Add-FmpViolation -Type 'query_not_allowed' -Detail ($name + ': ' + $queryProblem) -Line $line
            }
        }
        if ($name -eq 'New-Object' -and ($cmd.CommandElements.Count -ne 2 -or
            $cmd.CommandElements[1].Extent.Text -notin @('System.Text.StringBuilder', 'System.Collections.Generic.List[object]', 'System.Collections.Generic.List[string]'))) {
            Add-FmpViolation -Type 'constructor_not_allowed' -Detail $name -Line $line
        }
    }

    foreach ($member in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
        $line = $member.Extent.StartLineNumber
        if ($member.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            Add-FmpViolation -Type 'dynamic_member' -Detail 'Unexpected dynamic member access.' -Line $line
            continue
        }
        $name = $member.Member.Value
        $target = $member.Expression.Extent.Text + '::' + $name
        if ($member.Static) {
            if ($target -in $script:FmpStaticMembers) { continue }
            if ($isCommon -and $target -in @('[System.IO.File]::Open', '[System.IO.Directory]::CreateDirectory')) { continue }
            # Common only: reject or flag a local incident time that a DST change makes nonexistent or ambiguous.
            if ($isCommon -and $target -eq '[TimeZoneInfo]::Local') { continue }
            # Common only: build the in-memory private DACL for NEW output folders (S11-01). Applying ACLs to existing
            # objects stays impossible: SetAccessControl is banned everywhere.
            if ($isCommon -and $target -in $script:FmpPrivateDaclMembers) { continue }
            if ($Role -eq 'test' -and $target -in @('[System.IO.File]::ReadAllText', '[Environment]::NewLine')) { continue }
            if ($Role -eq 'security' -and $target -eq '[System.IO.File]::ReadAllLines') { continue }
            # Report writer (CSP hash of the print script) and Common (consent scope token): pure in-memory hashing only.
            if (($Role -eq 'writer' -or $isCommon) -and $target -in @('[System.Security.Cryptography.SHA256]::Create', '[Convert]::ToBase64String')) { continue }
        }
        elseif (($Role -eq 'writer' -or $isCommon) -and $name -eq 'ComputeHash' -and $member -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $member.Expression.Extent.Text -eq '[System.Security.Cryptography.SHA256]::Create()') { continue }
        elseif ($member -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -or $name -in $script:FmpInstanceMethods) {
            if ($member -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $script:FmpGuardedMethodKinds.ContainsKey($name)) {
                $memberChain = @(Get-FmpScopeChain $member)
                $receiverKey = $memberChain[0] + '|' + $name + '|' + $member.Expression.Extent.Text
                if (-not $receiverCache.ContainsKey($receiverKey)) { $receiverCache[$receiverKey] = Get-FmpReceiverProblem -Member $member -Name $name -Bindings $bindings -Chain $memberChain }
                $receiverProblem = $receiverCache[$receiverKey]
                if ($receiverProblem -ne '') { Add-FmpViolation -Type $receiverProblem -Detail ($member.Expression.Extent.Text + '.' + $name) -Line $line }
            }
            continue
        }
        elseif ($isCommon -and $name -in @('Write', 'Dispose', 'ReadToEnd', 'SetAccessRuleProtection', 'AddAccessRule', 'IsInvalidTime', 'IsAmbiguousTime')) { continue }
        $type = 'member_not_allowed'
        if ($name -in $script:FmpBannedMethods) { $type = 'banned_method' }
        Add-FmpViolation -Type $type -Detail $name -Line $line
    }

    return @{ Path = $Path; Role = $Role; Ok = ($violations.Count -eq 0); Violations = $violations.ToArray() }
}

function Get-FmpCommandInventory {
    # Lists every system-facing (non-utility, non-internal) command used by
    # a script. Embedded into run metadata so each report shows exactly
    # which read-only commands were used (audit trail).
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $set = New-Object System.Collections.Generic.List[string]
    if ($null -ne $ast) {
        $commands = $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($cmd in $commands) {
            $name = $cmd.GetCommandName()
            if ([string]::IsNullOrEmpty($name)) { continue }
            $name = $name.Split('\')[-1]
            if ($name -like '*-Fmp*') { continue }
            if ($script:FmpAllowedCommands.ContainsKey($name) -and -not $set.Contains($name)) { $set.Add($name) }
        }
    }
    $set.Sort()
    return ,$set.ToArray()
}

function Test-FmpReadOnlyCompliance {
    # Scans all project source files (+ tests when asked). Returns a result
    # object; callers must refuse to run an audit when Ok is $false.
    param([Parameter(Mandatory)][string]$Root, [switch]$IncludeTests)
    $relativePaths = $script:FmpSourceFiles
    # Tests are development-only and absent from the runtime package; production sources stay mandatory below.
    $testPath = Join-Path $Root 'tests\Run.Tests.ps1'
    if ($IncludeTests -and (Test-Path -LiteralPath $testPath -PathType Leaf)) { $relativePaths += 'tests\Run.Tests.ps1' }
    $results = New-Object System.Collections.Generic.List[object]
    $functions = New-Object System.Collections.Generic.List[string]
    $violationCount = 0
    foreach ($relative in $relativePaths) {
        $path = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        foreach ($node in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            if ($node.Name -match '^[A-Za-z]+-Fmp[A-Za-z0-9_]+$') { $functions.Add($node.Name) }
        }
    }
    foreach ($relative in $relativePaths) {
        $path = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $r = @{ Path = $path; Ok = $false; Violations = @(@{ type = 'missing_source'; line = 0; detail = 'Required source file unavailable.' }) }
        }
        else { $r = Test-FmpScriptCompliance -Path $path -InternalFunctions ($functions.ToArray()) }
        $results.Add($r)
        $violationCount += $r.Violations.Count
    }
    return @{
        Ok              = ($violationCount -eq 0)
        FilesScanned    = $results.Count
        ViolationCount  = $violationCount
        Results         = $results.ToArray()
    }
}

function Get-FmpReadOnlyPolicySummary {
    # Machine-readable policy statement, embedded in every diagnostic JSON.
    return [ordered]@{
        readOnly            = $true
        collectionWrites    = $false
        networkAccess       = $false
        elevation           = $false
        artifactWritesOnly  = $true
        artifactWriteScope  = 'user-authorized output directory only'
        enforcement         = 'static AST allowlist scan before execution + tests'
        forbiddenExamples   = @(
            'registry/service/driver/policy changes', 'install/uninstall/update',
            'start/stop/reconfigure services', 'scheduled task changes',
            'disk or system repair (chkdsk/sfc/dism)', 'reboot/suspend/shutdown',
            'cache/temp/log cleanup', 'PowerShell ExecutionPolicy changes',
            'Win32_Product enumeration', 'powercfg /energy', 'perfmon /report',
            'commands from log content, web content or AI suggestions'
        )
    }
}
