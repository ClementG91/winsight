<#
.SYNOPSIS
    Runs the test suite with line coverage and reports it per assembly.

.DESCRIPTION
    Uses the coverage collector already bundled with Microsoft.NET.Test.Sdk, so no extra package
    reference is needed.

    Read the per-assembly numbers, not the total. WinSight's uncovered code is concentrated in
    places a unit test genuinely cannot reach — WFP P/Invoke declarations, the Windows service
    host, and WPF code-behind — which are covered by VM validation and the packaged-installer
    tests instead. Chasing a single global percentage would mean writing assertions against
    P/Invoke signatures, which buys a number rather than confidence. The detection engine
    libraries are the ones worth holding to a real bar.

.EXAMPLE
    ./scripts/Measure-Coverage.ps1
    ./scripts/Measure-Coverage.ps1 -EngineMinimum 80
#>
[CmdletBinding()]
param(
    # Kept under out/ because that path is git-ignored.
    [string]$ResultsDirectory = "out/coverage",

    # Fails the run if any engine library drops below this line coverage. 0 disables the gate.
    [ValidateRange(0, 100)]
    [double]$EngineMinimum = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# The libraries holding detection and policy logic: pure enough that a real bar is meaningful.
$engineAssemblies = @(
    "WinSight.Core"
    "WinSight.Persistence"
    "WinSight.Ransomware"
    "WinSight.Firewall"
    "WinSight.Reporting"
    "WinSight.Certificates"
    "WinSight.Hosts"
    "WinSight.Modules"
    "WinSight.Browser"
    "WinSight.Processes"
)

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try
{
    if (Test-Path $ResultsDirectory)
    {
        Remove-Item $ResultsDirectory -Recurse -Force
    }

    dotnet test winsight.sln `
        --collect:"Code Coverage;Format=cobertura" `
        --results-directory $ResultsDirectory `
        --nologo
    if ($LASTEXITCODE -ne 0)
    {
        throw "Tests failed; coverage numbers would be meaningless."
    }

    $report = Get-ChildItem $ResultsDirectory -Recurse -Filter *.cobertura.xml |
        Select-Object -First 1
    if (-not $report)
    {
        throw "No cobertura report was produced under $ResultsDirectory."
    }

    [xml]$coverage = Get-Content $report.FullName
    $rows = foreach ($package in $coverage.coverage.packages.package)
    {
        $lines = @($package.classes.class.lines.line)
        $covered = @($lines | Where-Object { [int]$_.hits -gt 0 }).Count
        [pscustomobject]@{
            Assembly = $package.name
            Lines    = $lines.Count
            Covered  = $covered
            Percent  = if ($lines.Count) { [math]::Round(100 * $covered / $lines.Count, 1) } else { 0 }
            Engine   = $engineAssemblies -contains $package.name
        }
    }

    # Test assemblies are themselves near-100% covered, so counting them would flatter the total
    # into meaninglessness. Only shipped code is measured.
    $production = @($rows | Where-Object { $_.Assembly -like "winsight*" -and $_.Assembly -notlike "*.Tests" })
    # Rendered to a string so callers can pipe or filter this output without tripping over
    # PowerShell's format objects.
    ($production |
        Sort-Object Percent |
        Format-Table Assembly, Lines, Covered, Percent, Engine -AutoSize |
        Out-String).TrimEnd() | Write-Output

    $totalLines = ($production | Measure-Object Lines -Sum).Sum
    $totalCovered = ($production | Measure-Object Covered -Sum).Sum
    if ($totalLines)
    {
        "Overall production: {0}/{1} lines ({2}%)" -f `
            $totalCovered, $totalLines, [math]::Round(100 * $totalCovered / $totalLines, 1) | Write-Output
    }

    $engine = @($production | Where-Object Engine)
    $engineLines = ($engine | Measure-Object Lines -Sum).Sum
    $engineCovered = ($engine | Measure-Object Covered -Sum).Sum
    if ($engineLines)
    {
        "Engine libraries:   {0}/{1} lines ({2}%)" -f `
            $engineCovered, $engineLines, [math]::Round(100 * $engineCovered / $engineLines, 1) | Write-Output
    }

    if ($EngineMinimum -gt 0)
    {
        $below = @($engine | Where-Object { $_.Percent -lt $EngineMinimum })
        if ($below)
        {
            $names = ($below | ForEach-Object { "$($_.Assembly) $($_.Percent)%" }) -join ", "
            throw "Below the $EngineMinimum% engine bar: $names"
        }
        "All engine libraries are at or above $EngineMinimum%." | Write-Output
    }
}
finally
{
    Pop-Location
}
