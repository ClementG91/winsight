[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BrandingPath,

    [Parameter(Mandatory)]
    [string[]]$ExecutablePaths
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Drawing

$branding = (Resolve-Path -LiteralPath $BrandingPath).Path
$masterPath = Join-Path $branding "winsight-logo.png"
$uiPath = Join-Path $branding "winsight-logo-256.png"
$iconPath = Join-Path $branding "winsight.ico"

foreach ($path in @($masterPath, $uiPath, $iconPath, (Join-Path $branding "README.md")))
{
    if (-not (Test-Path -LiteralPath $path -PathType Leaf))
    {
        throw "Required branding asset is missing: $path"
    }
}

function Read-ImageFrames([string]$Path)
{
    $stream = [System.IO.File]::OpenRead($Path)
    try
    {
        $decoder = [System.Windows.Media.Imaging.BitmapDecoder]::Create(
            $stream,
            [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat,
            [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad)
        return @($decoder.Frames)
    }
    finally
    {
        $stream.Dispose()
    }
}

function Assert-TransparentCorner([System.Windows.Media.Imaging.BitmapSource]$Frame, [string]$Name)
{
    $converted = [System.Windows.Media.Imaging.FormatConvertedBitmap]::new(
        $Frame, [System.Windows.Media.PixelFormats]::Bgra32, $null, 0)
    $pixel = [byte[]]::new(4)
    $converted.CopyPixels([System.Windows.Int32Rect]::new(0, 0, 1, 1), $pixel, 4, 0)
    if ($pixel[3] -ne 0)
    {
        throw "$Name must have a fully transparent top-left corner."
    }
}

$master = (Read-ImageFrames $masterPath)[0]
if ($master.PixelWidth -lt 1024 -or $master.PixelHeight -lt 1024)
{
    throw "The documentation logo must be at least 1024x1024."
}
Assert-TransparentCorner $master "winsight-logo.png"

$ui = (Read-ImageFrames $uiPath)[0]
if ($ui.PixelWidth -ne 256 -or $ui.PixelHeight -ne 256)
{
    throw "The UI logo must be exactly 256x256."
}
Assert-TransparentCorner $ui "winsight-logo-256.png"

$iconSizes = @(Read-ImageFrames $iconPath | ForEach-Object { $_.PixelWidth } | Sort-Object -Unique)
$requiredIconSizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
foreach ($size in $requiredIconSizes)
{
    if ($iconSizes -notcontains $size)
    {
        throw "winsight.ico is missing its ${size}x${size} frame."
    }
}

foreach ($executablePath in $ExecutablePaths)
{
    $executable = (Resolve-Path -LiteralPath $executablePath).Path
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($executable)
    if ($null -eq $icon)
    {
        throw "$executable has no extractable application icon."
    }

    try
    {
        $bitmap = $icon.ToBitmap()
        try
        {
            $hasBrandCyan = $false
            for ($x = 0; $x -lt $bitmap.Width -and -not $hasBrandCyan; $x++)
            {
                for ($y = 0; $y -lt $bitmap.Height; $y++)
                {
                    $pixel = $bitmap.GetPixel($x, $y)
                    if ($pixel.A -gt 128 -and $pixel.R -lt 100 -and $pixel.G -gt 140 -and $pixel.B -gt 140)
                    {
                        $hasBrandCyan = $true
                        break
                    }
                }
            }
            if (-not $hasBrandCyan)
            {
                throw "$executable does not expose the expected WinSight cyan icon pixels."
            }
        }
        finally
        {
            $bitmap.Dispose()
        }
    }
    finally
    {
        $icon.Dispose()
    }
}

Write-Output "Brand assets and embedded executable icons passed."
