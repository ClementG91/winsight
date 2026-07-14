[CmdletBinding()]
param(
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6"),
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$version = "6.7.3"
$uri = "https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe"
$expectedSha256 = "9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732"
$compiler = Join-Path $InstallDirectory "ISCC.exe"

if ((Test-Path -LiteralPath $compiler) -and -not $Force)
{
    Write-Output $compiler
    return
}

$downloadDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "winsight-inno-$version"
$installer = Join-Path $downloadDirectory "innosetup-$version.exe"
New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null

try
{
    Invoke-WebRequest -Uri $uri -OutFile $installer
    $actualSha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256)
    {
        throw "Inno Setup checksum mismatch. Expected $expectedSha256, got $actualSha256."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
    {
        throw "Inno Setup Authenticode signature is not valid: $($signature.Status)."
    }

    $process = Start-Process -FilePath $installer -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CURRENTUSER",
        "/DIR=`"$InstallDirectory`""
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0)
    {
        throw "Inno Setup installation failed with exit code $($process.ExitCode)."
    }
}
finally
{
    if (Test-Path -LiteralPath $downloadDirectory)
    {
        Remove-Item -LiteralPath $downloadDirectory -Recurse -Force
    }
}

if (-not (Test-Path -LiteralPath $compiler))
{
    throw "Inno Setup completed but ISCC.exe was not found at $compiler."
}

Write-Output $compiler
