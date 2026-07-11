[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $root "apps\desktop-windows\src-tauri\icons\icon.ico"
$bitmap = [Drawing.Bitmap]::new(256, 256)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([Drawing.Color]::FromArgb(9, 11, 16))
$purple = [Drawing.Pen]::new([Drawing.Color]::FromArgb(116, 92, 255), 18)
$green = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(86, 224, 189))
$dark = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(9, 11, 16))
$graphics.DrawEllipse($purple, 44, 44, 168, 168)
$graphics.FillEllipse($green, 88, 88, 80, 80)
$graphics.FillEllipse($dark, 128, 96, 32, 32)
$icon = [Drawing.Icon]::FromHandle($bitmap.GetHicon())
$stream = [IO.File]::Create($destination)
try { $icon.Save($stream) } finally {
    $stream.Dispose(); $icon.Dispose(); $purple.Dispose(); $green.Dispose(); $dark.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
Write-Host "Generated $destination"
