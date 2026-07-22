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

    This is the suite's only coverage gate, so it runs the tests itself rather than assuming a
    previous run. CI calls it in place of a plain `dotnet test`, which keeps one test run in the
    pipeline instead of two.

.EXAMPLE
    ./scripts/Measure-Coverage.ps1
    ./scripts/Measure-Coverage.ps1 -EngineMinimum 0        # report only, no gate
    ./scripts/Measure-Coverage.ps1 -TrxLogFilePrefix tests-x64
#>
[CmdletBinding()]
param(
    # Kept under out/ because that path is git-ignored.
    [string]$ResultsDirectory = "out/coverage",

    # Fails the run if any engine library drops below this line coverage. 0 disables the gate.
    #
    # Defaults to the bar the project claims rather than to 0. It defaulted to 0 — the gate off —
    # and nothing in CI passed a value, so the "engine libraries are held to 80%" rule was a number
    # in a document that no run could ever contradict. A bar nothing enforces is not a bar.
    [ValidateRange(0, 100)]
    [double]$EngineMinimum = 80,

    # Emits a trx alongside the coverage report so CI can publish test results from this same run.
    [string]$TrxLogFilePrefix,

    # Matches the configuration CI builds, so this step reuses those binaries instead of compiling
    # the whole solution a second time in Debug.
    [string]$Configuration = "Release"
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

    $testArguments = @(
        "test", "winsight.sln"
        "-c", $Configuration
        "--collect:Code Coverage;Format=cobertura"
        "--results-directory", $ResultsDirectory
        "--nologo"
    )
    if ($TrxLogFilePrefix)
    {
        $testArguments += @("--logger", "trx;LogFilePrefix=$TrxLogFilePrefix")
    }

    & dotnet @testArguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "Tests failed; coverage numbers would be meaningless."
    }

    # The collector writes one cobertura file per test project, and each describes only the
    # assemblies that project happened to load. This used to read `Select-Object -First 1`, so the
    # gate measured whichever file the filesystem enumerated first — on one local run that was a
    # single assembly, 100 lines out of 11,584, and it still printed "all engine libraries are at or
    # above 80%". A gate that reports a pass while looking at 1% of the code is worse than no gate.
    #
    # Every report is therefore merged, unioning per (assembly, file, line): a line counts as
    # covered if any test project reached it.
    $reports = @(Get-ChildItem $ResultsDirectory -Recurse -Filter *.cobertura.xml)
    if ($reports.Count -eq 0)
    {
        throw "No cobertura report was produced under $ResultsDirectory."
    }

    $hits = @{}
    foreach ($file in $reports)
    {
        [xml]$coverage = Get-Content $file.FullName
        foreach ($package in $coverage.SelectNodes('//package'))
        {
            $assembly = $package.GetAttribute('name')
            foreach ($class in $package.SelectNodes('.//class'))
            {
                $filename = $class.GetAttribute('filename')
                foreach ($line in $class.SelectNodes('.//line'))
                {
                    $key = "$assembly|$filename|$($line.GetAttribute('number'))"
                    $lineHits = [int]$line.GetAttribute('hits')
                    if (-not $hits.ContainsKey($key) -or $hits[$key] -lt $lineHits)
                    {
                        $hits[$key] = $lineHits
                    }
                }
            }
        }
    }

    $totals = @{}
    foreach ($entry in $hits.GetEnumerator())
    {
        $assembly = $entry.Key.Split('|')[0]
        if (-not $totals.ContainsKey($assembly))
        {
            $totals[$assembly] = [pscustomobject]@{ Lines = 0; Covered = 0 }
        }
        $totals[$assembly].Lines++
        if ($entry.Value -gt 0) { $totals[$assembly].Covered++ }
    }

    $rows = foreach ($assembly in $totals.Keys)
    {
        $total = $totals[$assembly]
        [pscustomobject]@{
            Assembly = $assembly
            Lines    = $total.Lines
            Covered  = $total.Covered
            Percent  = if ($total.Lines) { [math]::Round(100 * $total.Covered / $total.Lines, 1) } else { 0 }
            Engine   = $engineAssemblies -contains $assembly
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
        # An engine library absent from the merged report was never measured, which is not the same
        # as being covered — and it is exactly how a gate ends up passing while looking at nothing.
        # Naming the expected set turns a silent omission into a red build.
        $measured = @($engine | ForEach-Object { $_.Assembly })
        $unmeasured = @($engineAssemblies | Where-Object { $measured -notcontains $_ })
        if ($unmeasured)
        {
            throw ("No coverage was recorded at all for: {0}. Either the assembly was renamed or " +
                   "no test project loaded it; both mean this gate cannot vouch for it." -f ($unmeasured -join ", "))
        }

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
