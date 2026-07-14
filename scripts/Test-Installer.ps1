[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture,

    [ValidateSet("english", "french", "spanish")]
    [string]$InstallerLanguage = "english"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($osArchitecture -ne $Architecture)
{
    throw "Installer execution requires a native $Architecture host; this host is $osArchitecture."
}

$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$installDirectory = Join-Path $tempRoot "winsight-installer-test-$Architecture-$([Guid]::NewGuid().ToString('N'))"
$uninstaller = Join-Path $installDirectory "unins000.exe"

try
{
    $install = Start-Process -FilePath $installer -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/LANG=$InstallerLanguage",
        "/DIR=`"$installDirectory`""
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0)
    {
        throw "Installer failed with exit code $($install.ExitCode)."
    }

    $cli = Join-Path $installDirectory "winsight.exe"
    $dashboard = Join-Path $installDirectory "winsight-dashboard.exe"
    $actualVersion = & $cli --version
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne "winsight $Version")
    {
        throw "Expected winsight $Version, got '$actualVersion'."
    }

    foreach ($language in @("en", "fr", "es"))
    {
        & $dashboard --language $language --smoke-test
        if ($LASTEXITCODE -ne 0)
        {
            throw "Installed dashboard $language smoke test failed with exit code $LASTEXITCODE."
        }
    }

    $sbom = Join-Path $installDirectory "_manifest\spdx_2.2\manifest.spdx.json"
    if (-not (Test-Path -LiteralPath $sbom))
    {
        throw "Installed SPDX SBOM is missing."
    }
}
finally
{
    if (Test-Path -LiteralPath $uninstaller)
    {
        $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
        ) -Wait -PassThru
        if ($uninstall.ExitCode -ne 0)
        {
            throw "Uninstaller failed with exit code $($uninstall.ExitCode)."
        }
    }

    if (Test-Path -LiteralPath $installDirectory)
    {
        $resolvedInstallDirectory = [System.IO.Path]::GetFullPath($installDirectory)
        $expectedPrefix = Join-Path $tempRoot "winsight-installer-test-$Architecture-"
        if (-not $resolvedInstallDirectory.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase))
        {
            throw "Refusing to clean unexpected path: $resolvedInstallDirectory"
        }

        # Windows Defender or single-file extraction cleanup can retain a just-run
        # executable for a few hundred milliseconds after the process and Inno
        # uninstaller exit. Retry the verified temporary path, but still fail if a
        # lock persists: a production uninstall must not silently leave binaries.
        $removed = $false
        for ($attempt = 1; $attempt -le 20; $attempt++)
        {
            try
            {
                Remove-Item -LiteralPath $resolvedInstallDirectory -Recurse -Force -ErrorAction Stop
                $removed = -not (Test-Path -LiteralPath $resolvedInstallDirectory)
                if ($removed) { break }
            }
            catch
            {
                if ($attempt -eq 20) { throw }
                Start-Sleep -Milliseconds 500
            }
        }
        if (-not $removed)
        {
            throw "Installer cleanup still contains locked files after 10 seconds: $resolvedInstallDirectory"
        }
    }
}

Write-Output "$Architecture installer lifecycle and en/fr/es dashboard smoke tests passed."
