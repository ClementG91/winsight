[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PreviousInstallerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$PreviousVersion,

    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$Version
)

# Upgrade in place from a published release, per user, the way most people get a new version: the
# previous installation is replaced, not duplicated, the new version runs, no file of the old one is
# left behind that a fresh install of the new one would not have, and the uninstall removes it all.
#
# It installs WinSight for the current user under the same AppId as a real installation, so it
# replaces that installation's registration: run it in a disposable VM, never on a machine where
# WinSight is installed.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$UninstallKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8D72DC5E-7BBE-4CF4-9D8B-A76F06C2A614}_is1"
foreach ($path in $PreviousInstallerPath, $InstallerPath)
{
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Not found: $path" }
}
if (Test-Path -LiteralPath $UninstallKey) { throw "WinSight is already installed for this user; this needs a clean machine." }

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$upgraded = Join-Path $tempRoot "winsight-upgrade-test-$([Guid]::NewGuid().ToString('N'))"
$fresh = Join-Path $tempRoot "winsight-upgrade-fresh-$([Guid]::NewGuid().ToString('N'))"

function Install-WinSight([string]$Installer, [string]$Directory)
{
    $install = Start-Process -FilePath $Installer -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$Directory`""
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "$Installer failed with exit code $($install.ExitCode)." }
}

function Uninstall-WinSight([string]$Directory)
{
    $uninstaller = Join-Path $Directory "unins000.exe"
    if (-not (Test-Path -LiteralPath $uninstaller)) { return }
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) { throw "Uninstaller failed with exit code $($uninstall.ExitCode)." }
    $deadline = (Get-Date).AddSeconds(60)
    while ((Test-Path -LiteralPath $UninstallKey) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Test-Path -LiteralPath $UninstallKey) { throw "The uninstall did not complete within 60 seconds." }
}

function Assert-Version([string]$Directory, [string]$Expected)
{
    $actual = & (Join-Path $Directory "winsight.exe") --version
    if ($LASTEXITCODE -ne 0 -or $actual -ne "winsight $Expected") { throw "Expected winsight $Expected in $Directory, got '$actual'." }
    $registered = (Get-ItemProperty -LiteralPath $UninstallKey -Name DisplayVersion).DisplayVersion
    if ($registered -ne $Expected) { throw "The uninstall entry says $registered, not $Expected." }
}

function Get-RelativeFiles([string]$Directory)
{
    $prefix = $Directory.TrimEnd('\').Length + 1
    return @(Get-ChildItem -LiteralPath $Directory -Recurse -File |
        ForEach-Object { $_.FullName.Substring($prefix) } |
        Where-Object { $_ -notlike 'unins*' } | Sort-Object)
}

function Remove-TestDirectory([string]$Directory)
{
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    if (-not ([IO.Path]::GetFullPath($Directory)).StartsWith((Join-Path $tempRoot 'winsight-upgrade-'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected path: $Directory"
    }
    for ($attempt = 1; $attempt -le 20 -and (Test-Path -LiteralPath $Directory); $attempt++)
    {
        Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Directory) { Start-Sleep -Milliseconds 500 }
    }
    if (Test-Path -LiteralPath $Directory) { throw "Locked files remain in $Directory." }
}

try
{
    # The file set a fresh install of the new version has, to tell a leftover from a new file.
    Install-WinSight $InstallerPath $fresh
    Assert-Version $fresh $Version
    $expectedFiles = Get-RelativeFiles $fresh
    Uninstall-WinSight $fresh
    Remove-TestDirectory $fresh

    Install-WinSight $PreviousInstallerPath $upgraded
    Assert-Version $upgraded $PreviousVersion
    $previousFiles = Get-RelativeFiles $upgraded
    "installed $PreviousVersion ($($previousFiles.Count) files)"

    Install-WinSight $InstallerPath $upgraded
    Assert-Version $upgraded $Version
    $entries = @(Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
        Where-Object { $_.PSChildName -like '{8D72DC5E-7BBE-4CF4-9D8B-A76F06C2A614}*' })
    if ($entries.Count -ne 1) { throw "The upgrade left $($entries.Count) uninstall entries." }
    $upgradedFiles = Get-RelativeFiles $upgraded
    $stale = @($upgradedFiles | Where-Object { $expectedFiles -notcontains $_ })
    $missing = @($expectedFiles | Where-Object { $upgradedFiles -notcontains $_ })
    if ($missing.Count -gt 0) { throw "The upgrade is missing files a fresh install has: $($missing -join ', ')" }
    if ($stale.Count -gt 0) { throw "The upgrade left files of $PreviousVersion that $Version does not ship: $($stale -join ', ')" }
    "upgraded in place to ${Version}: one uninstall entry, $($upgradedFiles.Count) files, none stale"

    Uninstall-WinSight $upgraded
    $left = if (Test-Path -LiteralPath $upgraded) { @(Get-ChildItem -LiteralPath $upgraded -Recurse -File) } else { @() }
    if ($left.Count -gt 0) { throw "The uninstall after the upgrade left files: $($left.FullName -join ', ')" }
    "uninstalled: registration and files removed"
}
finally
{
    foreach ($directory in $upgraded, $fresh)
    {
        if (Test-Path -LiteralPath (Join-Path $directory "unins000.exe")) { try { Uninstall-WinSight $directory } catch { Write-Warning $_ } }
        Remove-TestDirectory $directory
    }
}
