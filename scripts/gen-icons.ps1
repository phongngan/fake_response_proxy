# Generate placeholder icons for the Tauri build.
# Creates a simple coloured source PNG in scripts/source.png, then
# delegates to `npx tauri icon` which writes all required sizes/ICO.
#
# Usage:
#   pwsh -File scripts/gen-icons.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $src = Join-Path $PSScriptRoot "source.png"

    Add-Type -AssemblyName System.Drawing
    $w = 512; $h = 512
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = "AntiAlias"
    $g.Clear([System.Drawing.Color]::FromArgb(79, 140, 255))

    $font = New-Object System.Drawing.Font("Segoe UI", 200, [System.Drawing.FontStyle]::Bold)
    $brush = [System.Drawing.Brushes]::White
    $fmt = New-Object System.Drawing.StringFormat
    $fmt.Alignment = "Center"
    $fmt.LineAlignment = "Center"
    $rect = New-Object System.Drawing.RectangleF 0, 0, $w, $h
    $g.DrawString("FR", $font, $brush, $rect, $fmt)
    $g.Dispose()

    $bmp.Save($src, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Wrote $src"

    # Ensure dependencies are installed for `tauri icon`.
    if (-not (Test-Path "node_modules")) {
        Write-Host "Running npm install..."
        npm install
    }

    Write-Host "Running tauri icon..."
    npx tauri icon $src
}
finally {
    Pop-Location
}
