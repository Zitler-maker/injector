param(
    [Parameter(Mandatory = $true)][string]$InputImage,
    [Parameter(Mandatory = $true)][string]$OutputIcon
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$source = [System.Drawing.Image]::FromFile($InputImage)
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$frames = New-Object System.Collections.Generic.List[byte[]]

foreach ($size in $sizes) {
    $bitmap = New-Object System.Drawing.Bitmap $size, $size
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.DrawImage($source, 0, 0, $size, $size)
    $graphics.Dispose()

    $stream = New-Object System.IO.MemoryStream
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $frames.Add($stream.ToArray())
    $stream.Dispose()
    $bitmap.Dispose()
}
$source.Dispose()

$icon = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter($icon)
$writer.Write([UInt16]0)
$writer.Write([UInt16]1)
$writer.Write([UInt16]$sizes.Count)

$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dimension = $sizes[$i]
    $encoded = if ($dimension -ge 256) { 0 } else { $dimension }
    $writer.Write([byte]$encoded)
    $writer.Write([byte]$encoded)
    $writer.Write([byte]0)
    $writer.Write([byte]0)
    $writer.Write([UInt16]1)
    $writer.Write([UInt16]32)
    $writer.Write([UInt32]$frames[$i].Length)
    $writer.Write([UInt32]$offset)
    $offset += $frames[$i].Length
}
foreach ($frame in $frames) {
    $writer.Write($frame)
}
$writer.Flush()
[System.IO.File]::WriteAllBytes($OutputIcon, $icon.ToArray())
$writer.Dispose()
$icon.Dispose()
Write-Host "icon written: $OutputIcon"
