# =====================================================================
# FIX MY PC - tools/Optimize-Assets.ps1   (DEVELOPMENT / PACKAGING ONLY)
#
# Builds the optimized, embeddable variants of the official PNG assets.
# It is NOT part of the audit: it is never dot-sourced by fixmypc.ps1, is
# not in the read-only scan list and must never run on an audited machine.
# Uses only System.Drawing (ships with Windows PowerShell 5.1); installs
# nothing and touches no system data. The originals are never modified.
#
# Output (all under assets/optimized/):
#   branding/*.png, report/*.png   resized PNG variants (alpha preserved)
#   embed/<key>.b64                 Base64 payload read by the HTML renderer
#   manifest.json                   key, size, dimensions, SHA-256, source
#
# Run:  powershell -NoProfile -File tools\Optimize-Assets.ps1
# =====================================================================
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

# key -> source (relative; the v2 identity, FMP-10), target width. Height follows the aspect ratio.
$plan = [ordered]@{
    banner   = @{ src = 'assets\report\fixmypc-report-banner-v2.png'; w = 1440; dir = 'report'; fmt = 'jpeg'; q = 88 }
    logo     = @{ src = 'assets\branding\fixmypc-logo-v2.png';        w = 720;  dir = 'branding' }
    icon     = @{ src = 'assets\branding\fixmypc-icon-v2.png';        w = 96;   dir = 'branding' }
    overview = @{ src = 'assets\report\fixmypc-overview-v2.png';      w = 144;  dir = 'report' }
    findings = @{ src = 'assets\report\fixmypc-findings-v2.png';      w = 144;  dir = 'report' }
    hardware = @{ src = 'assets\report\fixmypc-hardware-v2.png';      w = 144;  dir = 'report' }
    storage  = @{ src = 'assets\report\fixmypc-storage-v2.png';       w = 144;  dir = 'report' }
    startup  = @{ src = 'assets\report\fixmypc-startup-v2.png';       w = 144;  dir = 'report' }
    privacy  = @{ src = 'assets\report\fixmypc-privacy-v2.png';       w = 144;  dir = 'report' }
}

$outRoot = Join-Path $Root 'assets\optimized'
foreach ($d in @('branding', 'report', 'embed')) {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $outRoot $d)
}

function Save-ResizedPng {
    param([string]$Source, [string]$Target, [int]$Width, [string]$Format = 'png', [int]$Quality = 88)
    $img = [System.Drawing.Image]::FromFile($Source)
    try {
        $h = [int][Math]::Round($img.Height * $Width / $img.Width)
        $bmp = New-Object System.Drawing.Bitmap($Width, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            try {
                $g.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
                $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $ia = New-Object System.Drawing.Imaging.ImageAttributes
                $ia.SetWrapMode([System.Drawing.Drawing2D.WrapMode]::TileFlipXY)
                $g.DrawImage($img, (New-Object System.Drawing.Rectangle(0, 0, $Width, $h)), 0, 0, $img.Width, $img.Height, [System.Drawing.GraphicsUnit]::Pixel, $ia)
            }
            finally { $g.Dispose() }
            if ($Format -eq 'jpeg') {
                # Opaque banner only: JPEG is ~10x smaller than PNG for its gradients.
                $codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
                $ep = New-Object System.Drawing.Imaging.EncoderParameters(1)
                $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]$Quality)
                $bmp.Save($Target, $codec, $ep)
            }
            else { $bmp.Save($Target, [System.Drawing.Imaging.ImageFormat]::Png) }
        }
        finally { $bmp.Dispose() }
        return @{ w = $Width; h = $h; sw = $img.Width; sh = $img.Height }
    }
    finally { $img.Dispose() }
}

$manifest = [ordered]@{
    schema      = 1
    generatedBy = 'tools/Optimize-Assets.ps1'
    note        = 'Development-time output. The renderer only reads manifest.json and embed/*.b64; it never processes images.'
    assets      = [ordered]@{}
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
$totalBefore = 0; $totalAfter = 0
foreach ($key in $plan.Keys) {
    $p = $plan[$key]
    $src = Join-Path $Root $p.src
    if (-not (Test-Path -LiteralPath $src)) { Write-Host ('MISSING source: ' + $p.src) -ForegroundColor Yellow; continue }
    $name = [System.IO.Path]::GetFileName($src)
    $fmt = 'png'; $mime = 'image/png'; $q = 88
    if ($p.ContainsKey('fmt')) { $fmt = $p.fmt; $q = $p.q }
    if ($fmt -eq 'jpeg') { $name = [System.IO.Path]::GetFileNameWithoutExtension($src) + '.jpg'; $mime = 'image/jpeg' }
    $rel = ('assets\optimized\' + $p.dir + '\' + $name)
    $dst = Join-Path $Root $rel
    $dim = Save-ResizedPng -Source $src -Target $dst -Width $p.w -Format $fmt -Quality $q
    $bytes = [System.IO.File]::ReadAllBytes($dst)
    $srcLen = (Get-Item -LiteralPath $src).Length
    $sha = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    [System.IO.File]::WriteAllText((Join-Path $outRoot ('embed\' + $key + '.b64')), [Convert]::ToBase64String($bytes), $utf8)
    $manifest.assets[$key] = [ordered]@{
        file = $rel.Replace('\', '/'); b64 = ('embed/' + $key + '.b64'); mime = $mime
        width = $dim.w; height = $dim.h; bytes = $bytes.Length; sha256 = $sha
        source = $p.src.Replace('\', '/'); sourceBytes = $srcLen; sourceSha256 = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant(); sourceWidth = $dim.sw; sourceHeight = $dim.sh
    }
    $totalBefore += $srcLen; $totalAfter += $bytes.Length
    Write-Host ('{0,-9} {1,5}x{2,-5} {3,9:N0} B  <- {4,10:N0} B  ({5:P0})' -f $key, $dim.w, $dim.h, $bytes.Length, $srcLen, ($bytes.Length / $srcLen))
}
[System.IO.File]::WriteAllText((Join-Path $outRoot 'manifest.json'), (ConvertTo-Json -InputObject $manifest -Depth 6), $utf8)
Write-Host ('TOTAL optimized {0:N0} B  <- originals {1:N0} B' -f $totalAfter, $totalBefore)
