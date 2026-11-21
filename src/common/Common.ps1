# =====================================================================
# FIX MY PC - Common.ps1
# Shared utilities: JSON I/O, null-safe value access, escaping,
# localization helpers, number formatting.
#
# Source policy: this file is ASCII-only on purpose (PowerShell 5.1
# reads BOM-less .ps1 as ANSI). All localized strings live in
# locales/*.json. No side effects, no system access, no writes except
# Write-FmpUtf8File / Write-FmpJsonFile (gated by Assert-FmpOutputPath).
# =====================================================================

$script:FmpToolVersion = '0.1.0'
$script:FmpSchemaVersion = '1.0.0'
$script:FmpMissingLocaleKeys = New-Object System.Collections.Generic.List[string]
$script:FmpAllowedWriteRoots = New-Object System.Collections.Generic.List[string]

function Get-FmpRoot {
    # Project root (this file lives in src/common/).
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

function Get-FmpTimestamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Get-FmpSystemDrive {
    return $env:SystemDrive
}

function Test-FmpIsWow64Process {
    return ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)
}

function Get-FmpCleanString {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    return $s
}

function ConvertTo-FmpNullableDouble {
    param([object]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $n = [double]0
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or
        $Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or
        $Value -is [uint64] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [byte]) {
        $n = [double]$Value
    }
    elseif (-not [double]::TryParse(([string]$Value).Trim(), [System.Globalization.NumberStyles]::Any,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
        return $null
    }
    if ([double]::IsNaN($n) -or [double]::IsInfinity($n)) { return $null }
    return $n
}

function ConvertTo-FmpNullableInt {
    param([object]$Value)
    $d = ConvertTo-FmpNullableDouble -Value $Value
    if ($null -eq $d -or $d -lt -2147483648 -or $d -gt 2147483647) { return $null }
    if ($d -ne [Math]::Floor($d)) { return $null }
    return [int]$d
}

function Get-FmpParsedDate {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    try {
        return [DateTime]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind)
    }
    catch { return $null }
}

function New-FmpRunId {
    return 'fmp-' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
}

function Get-FmpEntries {
    # Uniform key/value iteration over IDictionary and PSCustomObject nodes.
    # Returns an array of @{ Key; Value } - the leading comma prevents the
    # 1-element array unrolling on function return.
    param([object]$Data)
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Data) {
        if ($Data -is [System.Collections.IDictionary]) {
            foreach ($k in $Data.Keys) { $list.Add(@{ Key = [string]$k; Value = $Data[$k] }) }
        }
        else {
            foreach ($p in $Data.PSObject.Properties) { $list.Add(@{ Key = $p.Name; Value = $p.Value }) }
        }
    }
    return ,$list.ToArray()
}

# ---------------------------------------------------------------
# Null-safe deep value access on hashtables / PSCustomObjects / arrays.
# Example: Get-FmpValue $diag 'events.logs.System.status' -Default 'unknown'
# ---------------------------------------------------------------
function Get-FmpValue {
    param([object]$Data, [string]$Path, [object]$Default = $null)
    $current = $Data
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current -or $segment -eq '') { $current = $null; break }
        $index = $null
        if ($segment -match '^(.+)\[(\d+)\]$') {
            $segment = $Matches[1]
            $index = [int]$Matches[2]
        }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { $current = $null; break }
            $current = $current[$segment]
        }
        else {
            $prop = $current.PSObject.Properties[$segment]
            if ($null -eq $prop) { $current = $null; break }
            $current = $prop.Value
        }
        if ($null -ne $index) {
            if ($current -is [System.Collections.IList] -and $current.Count -gt $index) {
                $current = $current[$index]
            }
            else { $current = $null; break }
        }
    }
    if ($null -eq $current) {
        if ($null -ne $Default) { return $Default }
        return
    }
    # NOTE: plain return on purpose - callers that need an array wrap with
    # @(), which re-collects unrolled output correctly (including 1-element
    # arrays). Returning with a leading comma here would NEST arrays for
    # every @(Get-FmpValue ...) caller.
    return $current
}

# ---------------------------------------------------------------
# Normalizes an object graph to JSON-safe primitives (hashtables,
# arrays, strings, numbers, booleans). Converts DateTime/TimeSpan,
# truncates long strings, caps arrays.
# ---------------------------------------------------------------
function Limit-FmpString {
    param([string]$Value, [int]$Length)
    if ($Value.Length -le $Length) { return $Value }
    if ($Length -gt 0 -and [char]::IsHighSurrogate($Value[$Length - 1])) { $Length-- }
    return $Value.Substring(0, $Length)
}

function ConvertTo-FmpSerializable {
    param([object]$Value, [int]$MaxDepth = 20, [int]$Depth = 0,
          [int]$MaxStringLength = 4000, [int]$MaxArrayItems = 500, [switch]$RejectDeep)
    if ($Depth -gt $MaxDepth) {
        if ($RejectDeep) { throw 'JSON nesting exceeds the supported limit.' }
        return $null
    }
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
    if ($Value -is [timespan]) { return [double][Math]::Round($Value.TotalSeconds, 3) }
    if ($Value -is [string]) {
        return Limit-FmpString $Value $MaxStringLength
    }
    if ($Value -is [double] -or $Value -is [single]) {
        if ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value)) { return $null }
        return $Value
    }
    if ($Value -is [bool] -or $Value -is [byte] -or $Value -is [int] -or $Value -is [long] -or
        $Value -is [decimal] -or $Value -is [uint32] -or
        $Value -is [uint64] -or $Value -is [int16] -or $Value -is [uint16]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in $Value.Keys) {
            $out[[string]$k] = ConvertTo-FmpSerializable -Value $Value[$k] -MaxDepth $MaxDepth -Depth ($Depth + 1) `
                -MaxStringLength $MaxStringLength -MaxArrayItems $MaxArrayItems -RejectDeep:$RejectDeep
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($item in $Value) {
            if ($i -ge $MaxArrayItems -and -not $RejectDeep) { break }
            $list.Add((ConvertTo-FmpSerializable -Value $item -MaxDepth $MaxDepth -Depth ($Depth + 1) `
                -MaxStringLength $MaxStringLength -MaxArrayItems $MaxArrayItems -RejectDeep:$RejectDeep))
            $i++
        }
        # Leading comma prevents PowerShell from unrolling 1-element arrays.
        return ,$list.ToArray()
    }
    if ($Value -is [psobject] -or $Value -is [pscustomobject]) {
        $out = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) {
            $out[$p.Name] = ConvertTo-FmpSerializable -Value $p.Value -MaxDepth $MaxDepth -Depth ($Depth + 1) `
                -MaxStringLength $MaxStringLength -MaxArrayItems $MaxArrayItems -RejectDeep:$RejectDeep
        }
        return $out
    }
    # Enum / other leaf type: string fallback.
    return $Value.ToString()
}

function Test-FmpCollectionConsent {
    param([bool]$Explicit, [bool]$Interactive, [string]$Answer)
    return ($Explicit -or ($Interactive -and $Answer -match '^\s*(s|sim|y|yes)\s*$'))
}

function Test-FmpDiagnosticDocument {
    # Portable subset of the published schema, including fields trusted by the pipeline.
    param([object]$Data)
    if (($Data -isnot [System.Collections.IDictionary] -and $Data -isnot [pscustomobject]) -or
        (Get-FmpValue $Data 'schemaVersion') -cne $script:FmpSchemaVersion) { return $false }
    $run = Get-FmpValue $Data 'run'
    if ($run -isnot [System.Collections.IDictionary] -and $run -isnot [pscustomobject]) { return $false }
    foreach ($key in @('id', 'toolVersion')) {
        if ((Get-FmpValue $run $key) -isnot [string]) { return $false }
    }
    if ((Get-FmpValue $run 'mode') -cnotin @('simple', 'full') -or
        (Get-FmpValue $run 'language') -cnotin @('en', 'pt-BR') -or
        (Get-FmpValue $run 'synthetic') -isnot [bool]) { return $false }
    foreach ($key in @('startedAt', 'finishedAt')) {
        $at = Get-FmpValue $run $key
        if ($at -isnot [datetime] -and ($at -isnot [string] -or $at -notmatch '^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$')) { return $false }
        if ($null -eq (Get-FmpParsedDate $at)) { return $false }
    }
    foreach ($entry in (Get-FmpEntries $Data)) {
        if ($entry.Key -in @('system', 'events', 'startup', 'performance', 'storage', 'advanced') -and $null -ne $entry.Value -and
            $entry.Value -isnot [System.Collections.IDictionary] -and $entry.Value -isnot [pscustomobject]) { return $false }
        if ($entry.Key -in @('modules', 'subChecks', 'evidence') -and $entry.Value -isnot [System.Collections.IList]) { return $false }
    }
    foreach ($module in @(Get-FmpValue $Data 'modules')) {
        if ((Get-FmpValue $module 'id') -isnot [string] -or
            (Get-FmpValue $module 'status') -cnotin @('ok', 'partial', 'failed')) { return $false }
    }
    return $true
}

function ConvertTo-FmpJsonText {
    param([object]$Data, [int]$Depth = 24)
    $safe = ConvertTo-FmpSerializable -Value $Data
    return (ConvertTo-Json -InputObject $safe -Depth $Depth)
}

# ---------------------------------------------------------------
# Authorized artifact writing.
# Collection code must never call these; only the entry point and the
# HTML renderer do, and only inside roots registered via
# Set-FmpAllowedWriteRoot (the user-authorized output directory).
# ---------------------------------------------------------------
function Get-FmpLocalPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2) -match '[:*?"<>|\x00-\x1f]' -or
        $Path -match '(?:^|[\\/])(?:[^\\/]*[. ]|CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:[\\/]|$)' -or
        $Path -match '(?:^|[\\/])(?:CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])\.') {
        throw 'Expected a fully qualified local filesystem path without ambiguous components.'
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    $drive = [System.IO.DriveInfo]::new($full.Substring(0, 3))
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -and $drive.DriveType -ne [System.IO.DriveType]::Removable) {
        throw 'Expected a local, writable filesystem drive.'
    }
    return $full
}

function Get-FmpCheckedPath {
    # Check each existing component before traversing it.
    param([Parameter(Mandatory)][string]$Path)
    $full = Get-FmpLocalPath $Path
    $cursor = $full.Substring(0, 3)
    foreach ($part in $full.Substring(3).Split('\')) {
        if ($part -eq '') { continue }
        $cursor = Join-Path $cursor $part
        try { $node = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { return $full }
        if ($node.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Reparse points are forbidden in artifact and fixture paths.'
        }
    }
    return $full
}

function Set-FmpAllowedWriteRoot {
    param([Parameter(Mandatory)][string]$Root)
    $full = Get-FmpCheckedPath $Root
    if ($full.Length -le 3) { throw 'Choose an output directory below the drive root.' }
    if (-not $full.EndsWith('\')) { $full += '\' }
    $script:FmpAllowedWriteRoots.Clear()
    $script:FmpAllowedWriteRoots.Add($full)
}

function New-FmpOutputDirectory {
    # Every folder created here gets a protected DACL (current user + SYSTEM, inheritance from the parent cut), so
    # artifacts never inherit broader access. Existing folders are not touched; the CLI refuses an existing output folder.
    # The overload with DirectorySecurity exists only on .NET Framework (Windows PowerShell 5.1): elsewhere it fails closed.
    param([string]$Root)
    Set-FmpAllowedWriteRoot $Root
    $sec = [System.Security.AccessControl.DirectorySecurity]::new()
    $sec.SetAccessRuleProtection($true, $false)
    $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    foreach ($sid in @($owner, $system)) {
        $sec.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    $null = [System.IO.Directory]::CreateDirectory($script:FmpAllowedWriteRoots[0], $sec)
    $null = Get-FmpCheckedPath $script:FmpAllowedWriteRoots[0]
}

function Assert-FmpOutputPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = Get-FmpLocalPath $Path
    $parent = [System.IO.Path]::GetDirectoryName($full)
    foreach ($root in $script:FmpAllowedWriteRoots) {
        if (($parent + '\') -eq $root) {
            return (Get-FmpCheckedPath $full)
        }
    }
    throw "Write denied: path is outside the authorized output directory: $Path"
}

function Write-FmpUtf8File {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    $full = Assert-FmpOutputPath -Path $Path
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $bytes = $utf8.GetBytes($Text)
    if ($bytes.Length -gt 8MB) { throw 'Artifact exceeds the 8 MiB limit.' }
    $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
}

function Write-FmpJsonFile {
    param([Parameter(Mandatory)][string]$Path, [object]$Data, [int]$Depth = 24)
    Write-FmpUtf8File -Path $Path -Text (ConvertTo-FmpJsonText -Data $Data -Depth $Depth)
}

# ---------------------------------------------------------------
# JSON reading with graceful failure (never throws on malformed JSON).
# ---------------------------------------------------------------
function Read-FmpJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    $res = @{ Ok = $false; Data = $null; Error = $null; Path = $Path }
    try {
        $full = Get-FmpCheckedPath $Path
        $stream = [System.IO.File]::Open($full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            if ($stream.Length -gt 8MB) { throw 'JSON exceeds the 8 MiB limit.' }
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.UTF8Encoding]::new($true, $true), $false)
            try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        finally { $stream.Dispose() }
        if ($raw -notmatch '^\s*\{') { throw 'Expected a JSON object at the root.' }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $res.Data = ConvertFrom-Json -InputObject $raw -Depth 24 -ErrorAction Stop
        }
        else { $res.Data = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
        $null = ConvertTo-FmpSerializable -Value $res.Data -MaxDepth 24 -RejectDeep
        $res.Ok = $true
    }
    catch {
        $res.Error = $_.Exception.Message
    }
    return $res
}

# ---------------------------------------------------------------
# Localization. Locales are flat-key PSCustomObjects; lookup falls
# back through the list in priority order, then records the missing
# key and returns the key itself (visible, honest fallback).
# ---------------------------------------------------------------
function Reset-FmpMissingLocaleKeys {
    $script:FmpMissingLocaleKeys.Clear()
}

function Get-FmpMissingLocaleKeys {
    return ,$script:FmpMissingLocaleKeys.ToArray()
}

function Get-FmpLocaleString {
    param([object[]]$Locales, [Parameter(Mandatory)][string]$Key, [object[]]$Values = @())
    foreach ($loc in $Locales) {
        if ($null -eq $loc) { continue }
        $prop = $loc.PSObject.Properties[$Key]
        if ($null -ne $prop -and $null -ne $prop.Value) {
            if ($prop.Value -is [System.Array] -and $Values.Count -eq 0) {
                # List-valued keys (bullets, steps) stay lists; casting them to string fused every item into one.
                $items = New-Object System.Collections.Generic.List[string]
                foreach ($item in $prop.Value) { $items.Add([string]$item) }
                return $items.ToArray()
            }
            $t = [string]$prop.Value
            if ($Values.Count -gt 0) { $t = Format-FmpTemplate -Template $t -Values $Values }
            return $t
        }
    }
    if (-not $script:FmpMissingLocaleKeys.Contains($Key)) { $script:FmpMissingLocaleKeys.Add($Key) }
    return $Key
}

function Format-FmpTemplate {
    param([string]$Template, [object[]]$Values)
    if ([string]::IsNullOrEmpty($Template)) { return $Template }
    $out = $Template
    for ($i = 0; $i -lt $Values.Count; $i++) {
        $out = $out.Replace('{' + $i + '}', [string]$Values[$i])
    }
    return $out
}

# ---------------------------------------------------------------
# Formatting (locale-aware decimal separator; sizes from bytes).
# ---------------------------------------------------------------
function Format-FmpNumber {
    param([object]$Value, [int]$Decimals = 1, [string]$Language = 'pt-BR')
    if ($null -eq $Value) { return '-' }
    $n = [double]0
    $parsed = [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Any,
        [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)
    if (-not $parsed) { return [string]$Value }
    $s = [Math]::Round($n, $Decimals).ToString('0.###', [System.Globalization.CultureInfo]::InvariantCulture)
    if ($s -eq '') { $s = '0' }
    if ($Language -eq 'pt-BR') { $s = $s.Replace('.', ',') }
    return $s
}

function Format-FmpBytes {
    param([object]$Bytes, [string]$Language = 'pt-BR')
    if ($null -eq $Bytes) { return '-' }
    $b = [double]0
    $parsed = [double]::TryParse([string]$Bytes, [System.Globalization.NumberStyles]::Any,
        [System.Globalization.CultureInfo]::InvariantCulture, [ref]$b)
    if (-not $parsed) { return '-' }
    if ($b -lt 0) { return '-' }
    $units = @('B', 'KB', 'MB', 'GB', 'TB')
    $u = 0
    while ($b -ge 1024 -and $u -lt 4) { $b = $b / 1024; $u++ }
    $dec = 1
    if ($u -eq 0 -or $b -ge 100) { $dec = 0 }
    return (Format-FmpNumber -Value ([Math]::Round($b, 2)) -Decimals $dec -Language $Language) + ' ' + $units[$u]
}

function Format-FmpPercent {
    param([object]$Value, [string]$Language = 'pt-BR')
    if ($null -eq $Value) { return '-' }
    return (Format-FmpNumber -Value $Value -Decimals 1 -Language $Language) + '%'
}

# ---------------------------------------------------------------
# HTML escaping. Every dynamic value rendered into the report passes
# through this. Data is never inserted as markup, attributes without
# encoding, or JavaScript (the report contains no JavaScript).
# ---------------------------------------------------------------
function ConvertTo-FmpHtmlText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-FmpHtmlAttr {
    # .NET Framework's WebUtility has no HtmlAttributeEncode; HtmlEncode
    # also escapes double quotes, which is sufficient for attribute values.
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
