[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [ValidateSet("x64", "arm64")]
    [string[]]$Architectures = @("x64", "arm64"),

    [string]$OutputPath = "out\release",
    [string]$InnoCompiler,
    [switch]$SkipInstaller,
    [switch]$SkipSbom
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputPath))
if (-not $outputRoot.StartsWith($repoRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))
{
    throw "OutputPath must stay inside the repository: $outputRoot"
}

if (Test-Path -LiteralPath $outputRoot)
{
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $outputRoot | Out-Null

$nativeArchitecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString())
{
    "X64" { "x64" }
    "Arm64" { "arm64" }
    default { $null }
}

if (-not $SkipSbom)
{
    dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed." }
}

if (-not $SkipInstaller)
{
    if ([string]::IsNullOrWhiteSpace($InnoCompiler))
    {
        $InnoCompiler = & (Join-Path $PSScriptRoot "Install-InnoSetup.ps1")
        if ($LASTEXITCODE -ne 0) { throw "Unable to install or locate Inno Setup." }
        $InnoCompiler = $InnoCompiler | Select-Object -Last 1
    }
    $InnoCompiler = (Resolve-Path -LiteralPath $InnoCompiler).Path
}

foreach ($architecture in $Architectures)
{
    $rid = "win-$architecture"
    $workRoot = Join-Path $outputRoot "work\$rid"
    $cliRoot = Join-Path $workRoot "cli"
    $dashboardRoot = Join-Path $workRoot "dashboard"
    $serviceRoot = Join-Path $workRoot "service"
    $packageRoot = Join-Path $outputRoot "package\$rid"
    New-Item -ItemType Directory -Path $cliRoot, $dashboardRoot, $serviceRoot, $packageRoot -Force | Out-Null

    dotnet publish (Join-Path $repoRoot "src\WinSight.Cli\WinSight.Cli.csproj") `
        -c Release -r $rid --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true -o $cliRoot
    if ($LASTEXITCODE -ne 0) { throw "CLI publish failed for $rid." }

    dotnet publish (Join-Path $repoRoot "src\WinSight.Dashboard\WinSight.Dashboard.csproj") `
        -c Release -r $rid --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true -o $dashboardRoot
    if ($LASTEXITCODE -ne 0) { throw "Dashboard publish failed for $rid." }

    dotnet publish (Join-Path $repoRoot "src\WinSight.FirewallService\WinSight.FirewallService.csproj") `
        -c Release -r $rid --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true -o $serviceRoot
    if ($LASTEXITCODE -ne 0) { throw "Firewall service publish failed for $rid." }

    Copy-Item -LiteralPath (Join-Path $cliRoot "winsight.exe") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $dashboardRoot "winsight-dashboard.exe") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $serviceRoot "winsight-firewall-service.exe") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "docs\INSTALLATION.md") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "docs\DETECTIONS.md") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "docs\MCP.md") -Destination $packageRoot
    Copy-Item -LiteralPath (Join-Path $repoRoot "assets\branding") `
        -Destination (Join-Path $packageRoot "assets\branding") -Recurse

    & (Join-Path $PSScriptRoot "Test-PeArchitecture.ps1") `
        -Path (Join-Path $packageRoot "winsight.exe") -Architecture $architecture
    & (Join-Path $PSScriptRoot "Test-PeArchitecture.ps1") `
        -Path (Join-Path $packageRoot "winsight-dashboard.exe") -Architecture $architecture
    & (Join-Path $PSScriptRoot "Test-PeArchitecture.ps1") `
        -Path (Join-Path $packageRoot "winsight-firewall-service.exe") -Architecture $architecture
    & (Join-Path $PSScriptRoot "Test-Branding.ps1") `
        -BrandingPath (Join-Path $packageRoot "assets\branding") `
        -ExecutablePaths @(
            (Join-Path $packageRoot "winsight.exe"),
            (Join-Path $packageRoot "winsight-dashboard.exe"))
    if ($architecture -eq $nativeArchitecture)
    {
        & (Join-Path $PSScriptRoot "Test-McpServer.ps1") `
            -ServerPath (Join-Path $packageRoot "winsight.exe") -Version $Version
    }
    else
    {
        Write-Output "Skipping the $architecture MCP execution test on this $nativeArchitecture host; native CI runs it."
    }

    if (-not $SkipSbom)
    {
        $namespace = "https://github.com/ClementG91/winsight/releases/tag/v$Version/$rid"
        dotnet tool run sbom-tool generate `
            -b $packageRoot -bc (Join-Path $repoRoot "src") -pn WinSight -pv $Version `
            -ps "WinSight contributors" -nsb $namespace -D true `
            -cd "--DirectoryExclusionList **/bin/**"
        if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed for $rid." }

        $sbomName = "winsight-v$Version-$rid.spdx.json"
        $sbomPath = Join-Path $outputRoot $sbomName
        $packageSbomPath = Join-Path $packageRoot "_manifest\spdx_2.2\manifest.spdx.json"
        $sbom = Get-Content -LiteralPath $packageSbomPath -Raw | ConvertFrom-Json
        $sbomPackageNames = @($sbom.packages | ForEach-Object name)
        if ($sbomPackageNames -notcontains "WinSight")
        {
            throw "SBOM does not identify the WinSight package."
        }
        if ($sbomPackageNames -notcontains "Microsoft.NETCore.App.Runtime.$rid")
        {
            throw "SBOM does not contain the expected $rid .NET runtime pack."
        }
        if ($sbomPackageNames | Where-Object { $_ -match '^(xunit|Microsoft\.NET\.Test\.Sdk)' })
        {
            throw "SBOM unexpectedly contains test-only packages."
        }

        Copy-Item -LiteralPath $packageSbomPath -Destination $sbomPath
        if ((Get-Item -LiteralPath $sbomPath).Length -gt 16MB)
        {
            throw "SBOM exceeds GitHub's 16 MB attestation limit."
        }
        $sbomHash = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$sbomPath.sha256" -Value "$sbomHash  $sbomName" -Encoding ascii
    }

    $archiveName = "winsight-v$Version-$rid.zip"
    $archivePath = Join-Path $outputRoot $archiveName
    Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archivePath -CompressionLevel Optimal
    $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
    try
    {
        $archiveEntries = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
        $requiredEntries = @(
            "winsight.exe",
            "winsight-dashboard.exe",
            "README.md",
            "LICENSE",
            "INSTALLATION.md",
            "DETECTIONS.md",
            "MCP.md",
            "assets/branding/winsight-logo.png",
            "assets/branding/winsight-logo-256.png",
            "assets/branding/winsight.ico",
            "assets/branding/README.md"
        )
        if (-not $SkipSbom)
        {
            $requiredEntries += "_manifest/spdx_2.2/manifest.spdx.json"
        }
        foreach ($requiredEntry in $requiredEntries)
        {
            if ($archiveEntries -notcontains $requiredEntry)
            {
                throw "$archiveName is missing required entry $requiredEntry."
            }
        }
    }
    finally
    {
        $archive.Dispose()
    }
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$archivePath.sha256" -Value "$archiveHash  $archiveName" -Encoding ascii

    if (-not $SkipInstaller)
    {
        & $InnoCompiler (Join-Path $repoRoot "installer\WinSight.iss") `
            "/DMyAppVersion=$Version" `
            "/DMyArchitecture=$architecture" `
            "/DMySourceDir=$packageRoot" `
            "/DMyOutputDir=$outputRoot" `
            "/DMyRepoRoot=$repoRoot"
        if ($LASTEXITCODE -ne 0) { throw "Installer build failed for $rid." }

        $installerName = "winsight-v$Version-$rid-setup.exe"
        $installerPath = Join-Path $outputRoot $installerName
        & (Join-Path $PSScriptRoot "Test-Branding.ps1") `
            -BrandingPath (Join-Path $packageRoot "assets\branding") `
            -ExecutablePaths @($installerPath)
        $installerHash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$installerPath.sha256" -Value "$installerHash  $installerName" -Encoding ascii
    }
}

Write-Output "Release artifacts created in $outputRoot"
