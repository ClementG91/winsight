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
    [string]$InstallerLanguage = "english",

    [ValidateSet("CurrentUser", "AllUsers")]
    [string]$InstallScope = "CurrentUser",

    [switch]$RequireSigned,

    [string]$ExpectedPublisher
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-ExpectedAuthenticodeSignature
{
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
    {
        throw "Expected a valid Authenticode signature for $Path; got $($signature.Status)."
    }
    if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -cne $ExpectedPublisher)
    {
        throw "Expected exact Authenticode publisher '$ExpectedPublisher' for $Path."
    }
    if ($null -eq $signature.TimeStamperCertificate)
    {
        throw "Expected a timestamped Authenticode signature for $Path."
    }
}

if ($RequireSigned -and [string]::IsNullOrWhiteSpace($ExpectedPublisher))
{
    throw "-ExpectedPublisher is mandatory when -RequireSigned is specified."
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
if ($RequireSigned)
{
    # Verify before the installer process itself can execute. The signed release gate has no
    # meaning if an unverified setup gets to unpack or launch candidate binaries first.
    Assert-ExpectedAuthenticodeSignature -Path $installer
}
$processorArchitectures = @(
    Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        ForEach-Object { [int]$_.Architecture } |
        Select-Object -Unique
)
if ($processorArchitectures.Count -ne 1)
{
    throw "Installer execution requires one unambiguous Win32_Processor Architecture value; found: $($processorArchitectures -join ', ')."
}

$osArchitecture = switch ($processorArchitectures[0])
{
    9 { "x64" }
    12 { "arm64" }
    default { throw "Installer execution supports only Win32_Processor Architecture 9 (x64) or 12 (arm64); this host reports $($processorArchitectures[0])." }
}
if ($osArchitecture -ne $Architecture)
{
    throw "Installer execution requires a native $Architecture host; this host is $osArchitecture."
}

$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$installDirectory = Join-Path $tempRoot "winsight-installer-test-$Architecture-$([Guid]::NewGuid().ToString('N'))"
$uninstaller = Join-Path $installDirectory "unins000.exe"

# The Explorer "Check signature with WinSight" verb is per-user. A real install on the machine running
# this test would own it already, so its command is remembered and put back afterwards rather than
# destroyed by the test's uninstall.
function Get-SignatureVerbCommand
{
    $hive = if ($InstallScope -eq "AllUsers") {
        [Microsoft.Win32.RegistryHive]::LocalMachine
    } else {
        [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    # Through the registry API: the '*' class key is a wildcard to the PowerShell provider, and
    # StrictMode refuses a property read on the null an absent key returns.
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $base.OpenSubKey('Software\Classes\*\shell\WinSight.Signature\command')
        if ($null -eq $key) { return $null }
        try { return $key.GetValue('') } finally { $key.Dispose() }
    } finally {
        $base.Dispose()
    }
}
function Set-SignatureVerbCommand
{
    param([Parameter(Mandatory)][string]$Command)
    $hive = if ($InstallScope -eq "AllUsers") {
        [Microsoft.Win32.RegistryHive]::LocalMachine
    } else {
        [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $verb = $base.CreateSubKey('Software\Classes\*\shell\WinSight.Signature', $true)
        try {
            $verb.SetValue('', 'Check signature with WinSight')
            if ($Command -match '^"(?<exe>[^"]+)"')
            {
                $verb.SetValue('Icon', "`"$($Matches.exe)`",0")
            }
            $commandKey = $verb.CreateSubKey('command', $true)
            try { $commandKey.SetValue('', $Command) } finally { $commandKey.Dispose() }
        } finally {
            $verb.Dispose()
        }
    } finally {
        $base.Dispose()
    }
}
$previousSignatureVerb = Get-SignatureVerbCommand

try
{
    $scopeArgument = if ($InstallScope -eq "AllUsers") { "/ALLUSERS" } else { "/CURRENTUSER" }
    $install = Start-Process -FilePath $installer -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        $scopeArgument,
        "/LANG=$InstallerLanguage",
        "/DIR=`"$installDirectory`""
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0)
    {
        throw "Installer failed with exit code $($install.ExitCode)."
    }

    $cli = Join-Path $installDirectory "winsight.exe"
    $dashboard = Join-Path $installDirectory "winsight-dashboard.exe"
    $service = Join-Path $installDirectory "winsight-firewall-service.exe"
    foreach ($candidateExecutable in @($cli, $dashboard, $service))
    {
        & (Join-Path $PSScriptRoot "Test-PeArchitecture.ps1") -Path $candidateExecutable -Architecture $Architecture
    }
    if ($RequireSigned)
    {
        foreach ($candidateExecutable in @($cli, $dashboard, $service))
        {
            Assert-ExpectedAuthenticodeSignature -Path $candidateExecutable
        }
    }
    $actualVersion = & $cli --version
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne "winsight $Version")
    {
        throw "Expected winsight $Version, got '$actualVersion'."
    }

    & (Join-Path $PSScriptRoot "Test-McpServer.ps1") -ServerPath $cli -Version $Version

    foreach ($language in @("en", "fr", "es"))
    {
        # PowerShell does not reliably wait for a Windows GUI application when it is invoked with
        # the call operator. Waiting for the concrete process prevents the uninstaller from racing
        # the dashboard's WPF/tray cleanup and then reporting a locked installed executable.
        $dashboardSmoke = Start-Process -FilePath $dashboard -ArgumentList @(
            "--language", $language, "--smoke-test"
        ) -Wait -PassThru
        $dashboardExitCode = $dashboardSmoke.ExitCode
        $dashboardSmoke.Dispose()
        if ($dashboardExitCode -ne 0)
        {
            throw "Installed dashboard $language smoke test failed with exit code $dashboardExitCode."
        }
    }

    $sbom = Join-Path $installDirectory "_manifest\spdx_2.2\manifest.spdx.json"
    if (-not (Test-Path -LiteralPath $sbom))
    {
        throw "Installed SPDX SBOM is missing."
    }

    foreach ($brandAsset in @("winsight-logo.png", "winsight-logo-256.png", "winsight.ico", "README.md"))
    {
        $assetPath = Join-Path $installDirectory "assets\branding\$brandAsset"
        if (-not (Test-Path -LiteralPath $assetPath))
        {
            throw "Installed brand asset is missing: $assetPath"
        }
    }

    # Setup's default tasks register the verb; it must point at this installation's dashboard.
    $registeredVerb = Get-SignatureVerbCommand
    $expectedVerb = "`"$dashboard`" --signature `"%1`""
    if ($registeredVerb -ne $expectedVerb)
    {
        throw "Explorer signature verb was not registered for this installation (found '$registeredVerb')."
    }
}
finally
{
    if (Test-Path -LiteralPath $uninstaller)
    {
        if ($RequireSigned)
        {
            Assert-ExpectedAuthenticodeSignature -Path $uninstaller
        }
        $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
        ) -Wait -PassThru
        if ($uninstall.ExitCode -ne 0)
        {
            throw "Uninstaller failed with exit code $($uninstall.ExitCode)."
        }

        # Uninstall must not leave a context-menu entry pointing at a deleted executable.
        $leftoverVerb = Get-SignatureVerbCommand
        if ($null -ne $previousSignatureVerb)
        {
            Set-SignatureVerbCommand -Command $previousSignatureVerb
        }
        if ($null -ne $leftoverVerb)
        {
            throw "Uninstall left the Explorer signature verb behind: '$leftoverVerb'."
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

Write-Output "$Architecture $InstallScope installer lifecycle and en/fr/es dashboard smoke tests passed."
