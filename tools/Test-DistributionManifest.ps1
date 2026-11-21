# =====================================================================
# FIX MY PC - tools/Test-DistributionManifest.ps1   (DEVELOPMENT ONLY)
#
# Checks distribution-manifest.json against the files on disk. Read-only:
# it only lists and measures files under the project root. It builds no
# package, publishes nothing and touches nothing outside the repository.
# Exit code 1 when a check fails. ASCII-only on purpose (PowerShell 5.1).
#
# Run:  powershell -NoProfile -File tools\Test-DistributionManifest.ps1
# =====================================================================
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$m = Get-Content -LiteralPath (Join-Path $Root 'distribution-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$rootFull = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$files = @(Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\\.git\\' } |
    ForEach-Object { @{ rel = $_.FullName.Substring($rootFull.Length + 1).Replace('\', '/'); len = $_.Length } })
$fail = 0
function Test-Match { param([string]$Rel, [object[]]$Patterns) foreach ($p in $Patterns) { if ($Rel -like $p) { return $true } } return $false }

$groups = [ordered]@{ runtime = @($m.runtime); development = @($m.development); neverShip = @($m.neverShip) }
foreach ($g in $groups.Keys) {
    if ($g -eq 'neverShip') { continue }
    foreach ($p in $groups[$g]) {
        if (-not (@($files | Where-Object { $_.rel -like $p }).Count)) { Write-Host ('FAIL  [{0}] pattern matches nothing: {1}' -f $g, $p); $fail++ }
    }
}
$sizes = @{ runtime = 0; development = 0; neverShip = 0 }
foreach ($f in $files) {
    $hit = @($groups.Keys | Where-Object { Test-Match -Rel $f.rel -Patterns $groups[$_] })
    if ($hit.Count -eq 0) { Write-Host ('FAIL  unclassified file: ' + $f.rel); $fail++; continue }
    if ($hit.Count -gt 1) { Write-Host ('FAIL  file in more than one group (' + ($hit -join ',') + '): ' + $f.rel); $fail++; continue }
    $sizes[$hit[0]] += $f.len
    if ($hit[0] -eq 'runtime' -and (Test-Match -Rel $f.rel -Patterns @($m.forbiddenInRuntime))) { Write-Host ('FAIL  forbidden file in runtime package: ' + $f.rel); $fail++ }
}
foreach ($g in $sizes.Keys) { Write-Host ('{0,-12} {1,12:N0} B' -f $g, $sizes[$g]) }
Write-Host ('release blockers recorded: ' + @($m.releaseBlockers).Count + ' (' + ((@($m.releaseBlockers) | ForEach-Object { $_.id }) -join ', ') + ')')
if ($fail -gt 0) { Write-Host ('RESULT: FAIL (' + $fail + ')'); exit 1 }
Write-Host 'RESULT: PASS (every file classified once; no forbidden file in runtime). This is NOT release approval.'
