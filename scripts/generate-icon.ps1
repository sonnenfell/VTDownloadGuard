param(
    [string]$OutputIco = (Join-Path $PSScriptRoot "..\src\VTDownloadGuard\Assets\app.ico"),
    [string]$PreviewPng = ""
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

function New-ShieldBitmap {
    param([int]$Size)

    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)

        $s = [float]$Size

        # Outer shield polygon
        $shieldPoints = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF([float]($s * 0.50), [float]($s * 0.055))),
            (New-Object System.Drawing.PointF([float]($s * 0.895), [float]($s * 0.195))),
            (New-Object System.Drawing.PointF([float]($s * 0.865), [float]($s * 0.535))),
            (New-Object System.Drawing.PointF([float]($s * 0.720), [float]($s * 0.780))),
            (New-Object System.Drawing.PointF([float]($s * 0.50), [float]($s * 0.945))),
            (New-Object System.Drawing.PointF([float]($s * 0.280), [float]($s * 0.780))),
            (New-Object System.Drawing.PointF([float]($s * 0.135), [float]($s * 0.535))),
            (New-Object System.Drawing.PointF([float]($s * 0.105), [float]($s * 0.195)))
        )

        $shieldPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $shieldPath.AddLines($shieldPoints)
        $shieldPath.CloseFigure()

        # Cobalt blue gradient (#4F6BFF -> #1E3A8A)
        $gradRect = New-Object System.Drawing.RectangleF(0, 0, $s, $s)
        $topColor = [System.Drawing.Color]::FromArgb(255, 79, 107, 255)
        $bottomColor = [System.Drawing.Color]::FromArgb(255, 30, 58, 138)
        $fillBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $gradRect,
            $topColor,
            $bottomColor,
            [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal)
        $g.FillPath($fillBrush, $shieldPath)

        # Subtle VirusTotal-style left facet highlight
        $leftFacetPoints = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF([float]($s * 0.50), [float]($s * 0.055))),
            (New-Object System.Drawing.PointF([float]($s * 0.105), [float]($s * 0.195))),
            (New-Object System.Drawing.PointF([float]($s * 0.135), [float]($s * 0.535))),
            (New-Object System.Drawing.PointF([float]($s * 0.280), [float]($s * 0.780))),
            (New-Object System.Drawing.PointF([float]($s * 0.50), [float]($s * 0.945)))
        )
        $leftFacetPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $leftFacetPath.AddLines($leftFacetPoints)
        $leftFacetPath.CloseFigure()
        $facetBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(28, 255, 255, 255))
        $g.FillPath($facetBrush, $leftFacetPath)

        # Inner accent outline
        $innerPenWidth = [float][Math]::Max(1.0, $s * 0.025)
        $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(210, 147, 197, 253), $innerPenWidth)
        $borderPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawPath($borderPen, $shieldPath)

        # Geometric faceted prism / chevron check mark
        # Left wing (accent ice-blue) + full crisp white check ribbon
        $leftArmPoints = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF([float]($s * 0.265), [float]($s * 0.515))),
            (New-Object System.Drawing.PointF([float]($s * 0.340), [float]($s * 0.440))),
            (New-Object System.Drawing.PointF([float]($s * 0.460), [float]($s * 0.560))),
            (New-Object System.Drawing.PointF([float]($s * 0.460), [float]($s * 0.710)))
        )
        $leftArmPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $leftArmPath.AddLines($leftArmPoints)
        $leftArmPath.CloseFigure()
        $accentBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 191, 219, 254))
        $g.FillPath($accentBrush, $leftArmPath)

        $mainCheckPoints = [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF([float]($s * 0.460), [float]($s * 0.560))),
            (New-Object System.Drawing.PointF([float]($s * 0.675), [float]($s * 0.345))),
            (New-Object System.Drawing.PointF([float]($s * 0.750), [float]($s * 0.420))),
            (New-Object System.Drawing.PointF([float]($s * 0.460), [float]($s * 0.710)))
        )
        $mainCheckPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $mainCheckPath.AddLines($mainCheckPoints)
        $mainCheckPath.CloseFigure()
        $whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $g.FillPath($whiteBrush, $mainCheckPath)

        $whiteBrush.Dispose()
        $mainCheckPath.Dispose()
        $accentBrush.Dispose()
        $leftArmPath.Dispose()
        $borderPen.Dispose()
        $facetBrush.Dispose()
        $leftFacetPath.Dispose()
        $fillBrush.Dispose()
        $shieldPath.Dispose()
    }
    finally {
        $g.Dispose()
    }

    return $bmp
}

$sizes = @(16, 24, 32, 48, 64, 128, 256)
$pngFrames = New-Object 'System.Collections.Generic.List[byte[]]'

$outDir = Split-Path -Parent $OutputIco
if (-not [string]::IsNullOrWhiteSpace($outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

foreach ($sz in $sizes) {
    $bmp = New-ShieldBitmap -Size $sz
    try {
        if ($sz -eq 256 -and -not [string]::IsNullOrWhiteSpace($PreviewPng)) {
            $previewDir = Split-Path -Parent $PreviewPng
            if (-not [string]::IsNullOrWhiteSpace($previewDir)) {
                New-Item -ItemType Directory -Force -Path $previewDir | Out-Null
            }
            $bmp.Save($PreviewPng, [System.Drawing.Imaging.ImageFormat]::Png)
        }

        $ms = New-Object System.IO.MemoryStream
        try {
            $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $pngFrames.Add($ms.ToArray())
        }
        finally {
            $ms.Dispose()
        }
    }
    finally {
        $bmp.Dispose()
    }
}

$fs = [System.IO.File]::Create($OutputIco)
$bw = New-Object System.IO.BinaryWriter($fs)
try {
    # ICONDIR header
    $bw.Write([UInt16]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]$sizes.Count)

    $offset = 6 + (16 * $sizes.Count)
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $sz = $sizes[$i]
        $frame = $pngFrames[$i]
        $dim = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }

        $bw.Write($dim)
        $bw.Write($dim)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([UInt16]1)
        $bw.Write([UInt16]32)
        $bw.Write([UInt32]$frame.Length)
        $bw.Write([UInt32]$offset)

        $offset += $frame.Length
    }

    foreach ($frame in $pngFrames) {
        $bw.Write($frame)
    }
}
finally {
    $bw.Dispose()
    $fs.Dispose()
}

# Smoke-check that System.Drawing.Icon can parse the generated ICO
$iconStream = [System.IO.File]::OpenRead($OutputIco)
try {
    $testIcon = New-Object System.Drawing.Icon($iconStream, 32, 32)
    $testIcon.Dispose()
}
finally {
    $iconStream.Dispose()
}

Write-Output "Generated multi-resolution icon at $OutputIco ($((Get-Item $OutputIco).Length) bytes)"
