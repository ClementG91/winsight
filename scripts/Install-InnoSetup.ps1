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
$uninstaller = Join-Path $InstallDirectory "unins000.exe"

function Test-ExpectedPublisher([string]$Path)
{
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
        $null -ne $signature.SignerCertificate -and
        $signature.SignerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false) -ceq 'Pyrsys B.V.'
}

function Test-InstalledCompiler
{
    if (-not (Test-ExpectedPublisher $compiler) -or
        -not (Test-ExpectedPublisher $uninstaller)) { return $false }
    return (Get-Item -LiteralPath $uninstaller).VersionInfo.ProductVersion.Trim() -ceq $version
}

if (-not $Force -and (Test-InstalledCompiler))
{
    Write-Output (Resolve-Path -LiteralPath $compiler).Path
    return
}
if (Test-Path -LiteralPath $compiler)
{
    Write-Warning "Existing Inno Setup installation is stale or cannot prove the pinned publisher/version; reinstalling it."
}

$downloadDirectory = Join-Path ([System.IO.Path]::GetTempPath()) (
    "winsight-inno-$version-" + [guid]::NewGuid().ToString('N'))
$installer = Join-Path $downloadDirectory "innosetup-$version.exe"
New-Item -ItemType Directory -Path $downloadDirectory -ErrorAction Stop | Out-Null

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

if (-not (Test-InstalledCompiler))
{
    throw "Inno Setup completed but the pinned compiler publisher/version could not be verified."
}

Write-Output (Resolve-Path -LiteralPath $compiler).Path
