[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$Version,

    # A winsight-firewall-service.exe outside the installation, in an admin-protected folder. With it,
    # the negative case runs too: a service registered from another location must survive the
    # application's uninstall.
    [string]$ForeignServicePath
)

# WS-63. Uninstalling an all-users installation must remove the firewall service registered from it,
# and only that one. This installs a LocalSystem service and changes WFP state: run it in a disposable
# VM (docs/validation/VM_QUALIFICATION_KIT.md), never on a workstation.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ServiceName = "WinSightFirewall"
$ScExe = Join-Path $env:SystemRoot "System32\sc.exe"
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8D72DC5E-7BBE-4CF4-9D8B-A76F06C2A614}_is1"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw "An all-users installation and a service registration need an elevated console."
}
foreach ($path in @($InstallerPath) + @($ForeignServicePath | Where-Object { $_ }))
{
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Not found: $path" }
}
if (Test-Path -LiteralPath $UninstallKey) { throw "WinSight is already installed for all users; this needs a clean machine." }
& $ScExe query $ServiceName *> $null
if ($LASTEXITCODE -ne 1060) { throw "A $ServiceName service already exists; this needs a clean machine." }

# Under Program Files, so the folder inherits the administrators-only ACL the service insists on.
$installDirectory = Join-Path $env:ProgramFiles "WinSight-ServiceUninstallTest-$([Guid]::NewGuid().ToString('N'))"
$serviceExe = Join-Path $installDirectory "winsight-firewall-service.exe"
$uninstaller = Join-Path $installDirectory "unins000.exe"
$log = Join-Path ([IO.Path]::GetTempPath()) "winsight-service-uninstall-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $log | Out-Null

function Get-ServiceImage
{
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    return (Get-ItemProperty -LiteralPath $key -Name ImagePath).ImagePath
}

function Assert-ServiceAbsent([string]$Because)
{
    & $ScExe query $ServiceName *> $null
    if ($LASTEXITCODE -ne 1060) { throw "$ServiceName is still registered ($Because; sc exit $LASTEXITCODE)." }
}

function Install-Application
{
    $install = Start-Process -FilePath $InstallerPath -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/ALLUSERS",
        "/DIR=`"$installDirectory`"", "/LOG=`"$(Join-Path $log 'install.log')`""
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "Installer failed with exit code $($install.ExitCode)." }
    if (-not (Test-Path -LiteralPath $UninstallKey)) { throw "The installation is not registered for all users." }
    $actual = & (Join-Path $installDirectory "winsight.exe") --version
    if ($actual -ne "winsight $Version") { throw "Expected winsight $Version, got '$actual'." }
}

# The Inno uninstaller relaunches itself from a temporary copy; the process the caller starts may exit
# before the work is done. The registration key and the folder are what prove it finished.
function Uninstall-Application([string]$LogName)
{
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG=`"$(Join-Path $log $LogName)`""
    ) -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) { throw "Uninstaller failed with exit code $($uninstall.ExitCode)." }
    $deadline = (Get-Date).AddSeconds(60)
    while ((Test-Path -LiteralPath $UninstallKey) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Test-Path -LiteralPath $UninstallKey) { throw "The uninstall did not complete within 60 seconds." }
    while ((Test-Path -LiteralPath $serviceExe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Test-Path -LiteralPath $serviceExe) { throw "The uninstall left $serviceExe behind (still locked by the service?)." }
}

function Register-Service([string]$Executable)
{
    & $Executable install *> (Join-Path $log "service-install-$([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($Executable))).txt")
    if ($LASTEXITCODE -ne 0) { throw "Service registration from $Executable failed (exit $LASTEXITCODE)." }
    $image = Get-ServiceImage
    if ($image -notlike "*$Executable*") { throw "The service runs '$image', not $Executable." }
}

try
{
    # 1. The service of this installation goes with it.
    Install-Application
    Register-Service $serviceExe
    Uninstall-Application "uninstall.log"
    Assert-ServiceAbsent "the uninstall of the installation it runs from"
    $uninstallLog = Get-Content -LiteralPath (Join-Path $log "uninstall.log") -Raw
    if ($uninstallLog -notmatch [regex]::Escape("Removed the WinSight firewall service of this installation.")) {
        throw "The uninstall log does not record the service removal."
    }
    if (Test-Path -LiteralPath $installDirectory) {
        $left = @(Get-ChildItem -LiteralPath $installDirectory -Recurse -File | ForEach-Object FullName)
        if ($left.Count -gt 0) { throw "The uninstall left files: $($left -join ', ')" }
    }
    "PASS own-service: registered from the installation, removed by its uninstall, no file left"

    # 2. A service registered from anywhere else is not the installation's to remove.
    if ($ForeignServicePath)
    {
        Register-Service $ForeignServicePath
        Install-Application
        Uninstall-Application "uninstall-foreign.log"
        $image = Get-ServiceImage
        if ($null -eq $image -or $image -notlike "*$ForeignServicePath*") {
            throw "The uninstall removed or changed a service it does not own (now '$image')."
        }
        & $ForeignServicePath uninstall *> (Join-Path $log "foreign-service-uninstall.txt")
        if ($LASTEXITCODE -ne 0) { throw "The foreign service's own uninstall failed (exit $LASTEXITCODE)." }
        Assert-ServiceAbsent "the foreign service's own uninstall verb"
        "PASS foreign-service: left in place by the application's uninstall, removed by its own verb"
    }
    else
    {
        "NOT_RUN foreign-service: no -ForeignServicePath"
    }
}
finally
{
    # Never leave a LocalSystem service or a half-removed installation behind, whatever failed above.
    $image = Get-ServiceImage
    if ($image -like "*$installDirectory*" -and (Test-Path -LiteralPath $serviceExe)) { & $serviceExe uninstall *> $null }
    elseif ($image -and $ForeignServicePath -and $image -like "*$ForeignServicePath*") { & $ForeignServicePath uninstall *> $null }
    if ((Test-Path -LiteralPath $UninstallKey) -and (Test-Path -LiteralPath $uninstaller)) {
        Start-Process -FilePath $uninstaller -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait | Out-Null
    }
    if (Test-Path -LiteralPath $installDirectory) { Remove-Item -LiteralPath $installDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    "logs: $log"
}
