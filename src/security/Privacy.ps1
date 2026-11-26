# =====================================================================
# FIX MY PC - Privacy.ps1
#
# Produces the sanitized (shareable) diagnostic representation from the
# internal one. The internal JSON is written only to the user-authorized
# output directory; the sanitized JSON is what an agent may read.
#
# Strategy:
#   1. Field-level rules: fields known to hold accounts, device ids or
#      paths are replaced with placeholders.
#   2. Global regex scrubbing of every string: user profile paths,
#      computer/user names, SIDs, per-user service suffixes, IPs, MACs,
#      e-mails, GUIDs, credential-like assignments.
#   3. Size limits (string length, array caps) to bound report size.
# Collectors already minimize collection (no serials, no product keys,
# no process arguments, no network addresses).
# =====================================================================

$script:FmpRedactionCounts = 0

function Reset-FmpRedactionCount {
    $script:FmpRedactionCounts = 0
}

function Get-FmpRedactionCount {
    return $script:FmpRedactionCounts
}

function Hide-FmpSensitiveValue {
    param([object]$Value, [string]$FieldName = '', [string[]]$PrivateIdentifiers = @())
    if ($null -eq $Value) { return $null }
    if ($Value -isnot [string]) { return $Value }
    $s = $Value
    $count = 0

    # Field-level: full replacement, no content retained.
    switch -Regex ($FieldName) {
        '^(account|startName|startAccount)$' {
            if ($s -match '^(LocalSystem|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService|LocalService|NetworkService)$') { return $s }
            $script:FmpRedactionCounts++
            return '<Account>'
        }
        '^(deviceInstanceId|deviceId|instanceGuid)$' {
            $script:FmpRedactionCounts++
            return '<DeviceId>'
        }
        '^(sample|message|reason|reasonText|command|arguments|action|pathName|path|installLocation|serialNumber|productKey|computerName|userName|signer|label)$' {
            $script:FmpRedactionCounts++
            return '<Redacted>'
        }
        default { }
    }

    # Path-ish fields and any string: redact user profile first. The username
    # segment runs up to the next backslash (names may contain spaces).
    $profilePattern = '(?i)([A-Za-z]:\\Users\\[^\\/:*?"<>|]*)'
    if ($s -match $profilePattern) {
        $s = [regex]::Replace($s, $profilePattern, '<UserProfile>')
        $count++
    }

    # Credential-like content anywhere.
    $credPattern = '(?i)\b(password|passwd|senha|token|secret|apikey|api[_-]?key|credential)[a-z0-9_]*\s*[:=]\s*(?:"[^"]*"|''[^'']*''|\S+)'
    $new = [regex]::Replace($s, $credPattern, '$1=<Redacted>')
    if ($new -ne $s) { $count++; $s = $new }

    # FMP-08: account/machine SIDs (S-1-5-21-..., Azure AD S-1-12-1-...) identify one installation or user. Well-known
    # SIDs such as S-1-5-18 (LocalSystem) are public constants and stay readable.
    $new = [regex]::Replace($s, '\bS-1-(?:5-21|12-1)(?:-\d+){3,}\b', '<SID>')
    if ($new -ne $s) { $count++; $s = $new }

    # FMP-08: per-user service instances (CDPUserSvc_4a7f3c, CaptureService_9f2e1a, OneSyncSvc_1a2b3) carry a per-logon LUID suffix.
    # Only names that end in Svc/Service are touched globally; displayName correlation happens per service entry below.
    $new = [regex]::Replace($s, '(?i)\b([a-z0-9]*(?:svc|service))_[0-9a-f]{4,16}(?![\w])', '$1_<LUID>')
    if ($new -ne $s) { $count++; $s = $new }

    # GUIDs (device instance ids, correlation ids).
    $new = [regex]::Replace($s, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<Guid>')
    if ($new -ne $s) { $count++; $s = $new }

    # IPv4 addresses.
    $new = [regex]::Replace($s, '\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>')
    if ($new -ne $s) { $count++; $s = $new }

    # IPv6: full 8-group form, or any compressed form with "::" (times such as 11:54:00 never contain "::").
    $new = [regex]::Replace($s, '(?i)(?<![\w:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}))(?:%\w+)?(?![\w:])', '<IP>')
    if ($new -ne $s) { $count++; $s = $new }

    # MAC addresses.
    $new = [regex]::Replace($s, '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<MAC>')
    if ($new -ne $s) { $count++; $s = $new }

    # E-mail addresses.
    $new = [regex]::Replace($s, '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '<Email>')
    if ($new -ne $s) { $count++; $s = $new }

    $new = [regex]::Replace($s, '(?i)(?:<UserProfile>[\\/]|[a-z]:[\\/]|\\\\)[^;\r\n]+', '<Path>')
    if ($new -ne $s) { $count++; $s = $new }

    foreach ($identifier in $PrivateIdentifiers) {
        if ([string]::IsNullOrWhiteSpace($identifier)) { continue }
        $new = [regex]::Replace($s, ('(?i)(?<![\w.-])' + [regex]::Escape($identifier) + '(?![\w.-])'), '<Identifier>')
        if ($new -ne $s) { $count++; $s = $new }
    }

    $script:FmpRedactionCounts += $count
    return $s
}

function ConvertTo-FmpSanitizedDiagnostic {
    param(
        [Parameter(Mandatory)][object]$Diagnostic,
        [int]$MaxStringLength = 400,
        [int]$MaxArrayItems = 150,
        [string[]]$PrivateIdentifiers = @()
    )
    Reset-FmpRedactionCount
    $truncatedCollections = New-Object System.Collections.Generic.List[object]
    $truncatedByPath = @{}

    function Get-FmpServiceEntryLuids([object[]]$Entries) {
        $nameVal = $null
        $dispVal = $null
        $hasSvcHint = $false
        foreach ($e in $Entries) {
            if ($e.Key -ceq 'name' -and $e.Value -is [string]) { $nameVal = [string]$e.Value }
            elseif ($e.Key -ceq 'displayName' -and $e.Value -is [string]) { $dispVal = [string]$e.Value }
            elseif ($e.Key -in @('startMode', 'delayed', 'account')) { $hasSvcHint = $true }
        }
        $luids = New-Object System.Collections.Generic.List[string]
        if ($null -eq $nameVal -and $null -eq $dispVal) { return ,$luids.ToArray() }
        $pat = '(?<![0-9a-fA-F])_([0-9a-fA-F]{4,16})(?![\w])(.*)'
        $nameSet = @{}
        $rem = [string]$nameVal
        while ($null -ne $nameVal -and $rem -match $pat) {
            $nameSet[$Matches[1]] = $true
            $rem = $Matches[2]
        }
        $dispSet = @{}
        $rem = [string]$dispVal
        while ($null -ne $dispVal -and $rem -match $pat) {
            $dispSet[$Matches[1]] = $true
            $rem = $Matches[2]
        }
        foreach ($k in $nameSet.Keys) {
            if ($dispSet.ContainsKey($k) -and -not $luids.Contains($k)) { $luids.Add($k) }
        }
        foreach ($txt in @($nameVal, $dispVal)) {
            if ($null -eq $txt) { continue }
            $rem = [string]$txt
            while ($rem -match '(?i)\b[a-z0-9]*(?:svc|service)_([0-9a-f]{4,16})(?![\w])(.*)') {
                $sfx = $Matches[1]
                $rem = $Matches[2]
                $seen = $false
                foreach ($existing in $luids) { if ($existing -ieq $sfx) { $seen = $true; break } }
                if (-not $seen) { $luids.Add($sfx) }
            }
        }
        if (-not $hasSvcHint -and $luids.Count -eq 0) { return ,$luids.ToArray() }
        return ,$luids.ToArray()
    }

    function Hide-FmpSanitizedNode([object]$node, [string]$field, [int]$depth, [string]$path, [object[]]$serviceLuids = @()) {
        if ($null -eq $node) { return $null }
        if ($depth -gt 24) { return $null }
        if ($field -match '^(sample|message|command|arguments|action|pathName|path|installLocation|serialNumber|productKey|computerName|userName|signer|label)$') {
            return Hide-FmpSensitiveValue -Value '' -FieldName $field
        }

        # Pipeline output (Sort-Object, ForEach-Object) is wrapped in a PSObject, which is also
        # -is [pscustomobject]. Without this guard, numbers such as min/max/p90 become an empty object.
        if ($node -is [System.ValueType]) { return $node }

        if ($node -is [System.Collections.IDictionary] -or $node -is [pscustomobject]) {
            $entries = Get-FmpEntries $node
            $entryLuids = @()
            $isServiceEntry = ($field -eq 'autoServices')
            if (-not $isServiceEntry) {
                $hasName = $false; $hasDisp = $false; $hasSvcProp = $false
                foreach ($e in $entries) {
                    if ($e.Key -ceq 'name') { $hasName = $true }
                    elseif ($e.Key -ceq 'displayName') { $hasDisp = $true }
                    elseif ($e.Key -in @('startMode', 'delayed', 'account')) { $hasSvcProp = $true }
                }
                if ($hasName -and $hasDisp -and $hasSvcProp) { $isServiceEntry = $true }
            }
            if ($isServiceEntry) { $entryLuids = @(Get-FmpServiceEntryLuids $entries) }
            $out = [ordered]@{}
            foreach ($entry in $entries) {
                $key = Hide-FmpSensitiveValue -Value $entry.Key -PrivateIdentifiers $PrivateIdentifiers
                $childPath = if ($path -ne '') { $path + '.' + $entry.Key } else { [string]$entry.Key }
                $passLuids = if ($isServiceEntry -and $entry.Key -in @('name', 'displayName')) { $entryLuids } else { @() }
                $out[$key] = Hide-FmpSanitizedNode -node $entry.Value -field $entry.Key -depth ($depth + 1) -path $childPath -serviceLuids $passLuids
            }
            if ($out.Contains('truncated') -and ($out.Contains('items') -or $out.Contains('groups'))) {
                $arrKey = if ($out.Contains('items')) { 'items' } else { 'groups' }
                $arrPath = if ($path -ne '') { $path + '.' + $arrKey } else { $arrKey }
                $origTruncated = [bool]$out['truncated']
                $sanTruncated = $truncatedByPath.ContainsKey($arrPath)
                $presentedCount = @($out[$arrKey]).Count
                $out['collectionTruncated'] = $origTruncated
                $out['sanitizedTruncated'] = $sanTruncated
                $out['truncated'] = ($origTruncated -or $sanTruncated)
                $out['presentedCount'] = $presentedCount
            }
            return $out
        }
        if ($node -is [System.Collections.IEnumerable] -and $node -isnot [string]) {
            $list = New-Object System.Collections.Generic.List[object]
            $cap = $MaxArrayItems
            if ($path -eq 'evidence' -and $cap -gt 80) { $cap = 80 }
            $totalInNode = 0
            foreach ($item in $node) {
                if ($totalInNode -lt $cap) {
                    $itemPath = if ($path -ne '') { $path + '[' + $totalInNode + ']' } else { '[' + $totalInNode + ']' }
                    $list.Add((Hide-FmpSanitizedNode -node $item -field $field -depth ($depth + 1) -path $itemPath))
                }
                $totalInNode++
            }
            if ($totalInNode -gt $cap) {
                $rec = [ordered]@{
                    path          = $path
                    originalCount = $totalInNode
                    retainedCount = $list.Count
                }
                $truncatedCollections.Add($rec)
                $truncatedByPath[$path] = $rec
            }
            return ,$list.ToArray()
        }
        if ($node -is [string]) {
            $sIn = $node
            if ($null -ne $serviceLuids -and @($serviceLuids).Count -gt 0) {
                foreach ($sfx in $serviceLuids) {
                    if ([string]::IsNullOrEmpty($sfx)) { continue }
                    $sNew = [regex]::Replace($sIn, ('(?i)_' + [regex]::Escape($sfx) + '(?![\w])'), '_<LUID>')
                    if ($sNew -ne $sIn) {
                        $script:FmpRedactionCounts++
                        $sIn = $sNew
                    }
                }
            }
            # FMP-08: private identifiers (computer/user name) are scrubbed in EVERY string field, so a field the
            # collectors did not exist for yet cannot leak them. Identifiers shorter than 3 characters would shred
            # unrelated text, so they stay limited to the fields that always held names.
            $identifiers = @($PrivateIdentifiers | Where-Object { $_.Length -ge 3 })
            if ($field -in @('name', 'names', 'provider', 'displayName', 'friendlyName', 'deviceName', 'items', 'file', 'publisher', 'detail', 'note')) {
                $identifiers = $PrivateIdentifiers
            }
            $s = Hide-FmpSensitiveValue -Value $sIn -FieldName $field -PrivateIdentifiers $identifiers
            return Limit-FmpString $s $MaxStringLength
        }
        return $node
    }

    # Builds a new structure; the internal diagnostic object is untouched.
    $sanitized = Hide-FmpSanitizedNode -node $Diagnostic -field '' -depth 0 -path ''

    $sanitized['privacy'] = [ordered]@{
        sanitized            = $true
        redactionCount       = Get-FmpRedactionCount
        truncated            = ($truncatedCollections.Count -gt 0)
        truncatedCollections = $truncatedCollections.ToArray()
        notes                = @(
            'Event messages, command lines, arguments, paths and account identifiers are omitted or masked.',
            'Remaining product, process and provider names may identify installed software. Review before sharing.'
        )
    }
    return $sanitized
}
