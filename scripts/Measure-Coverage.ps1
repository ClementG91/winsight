<#
.SYNOPSIS
    Runs the test suite with line coverage and reports it per assembly.

.DESCRIPTION
    Uses the coverage collector already bundled with Microsoft.NET.Test.Sdk, so no extra package
    reference is needed.

    Read the per-assembly numbers, not the total. WinSight's uncovered code is concentrated in
    places a unit test genuinely cannot reach -- WFP P/Invoke declarations, the Windows service
    host, and WPF code-behind -- which are covered by VM validation and the packaged-installer
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
    # Defaults to the bar the project claims rather than to 0. It defaulted to 0 -- the gate off --
    # and nothing in CI passed a value, so the "engine libraries are held to 80%" rule was a number
    # in a document that no run could ever contradict. A bar nothing enforces is not a bar.
    [ValidateRange(0, 100)]
    [double]$EngineMinimum = 80,

    # The floor for the SYSTEM-privileged component, applied to its managed half only -- the native
    # WFP/SCM boundary is qualified by the VM protocol instead. Same 80% as the engine libraries,
    # because on that half the number means the same thing. Pass 0 to report without gating.
    [double]$PrivilegedMinimum = 80,

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

# The component that runs as SYSTEM and drives WFP. It had no floor at all while the pure detection
# libraries above -- the ones that cannot break anything -- were held to 80%, which protects the
# inverse of the risk.
$privilegedAssemblies = @(
    "winsight-firewall-service"
)

# Measured whole, this assembly reads 54%, and that number is an average of two incomparable things.
# Split it and the picture is the opposite of what the average suggests:
#
#   managed policy logic      940/1050 lines   89.5%   <- already above the engine bar
#   native/WFP/SCM/entry      108/885  lines   12.2%   <- only the VM protocol can reach it
#
# The files below are that second half: P/Invoke marshalling into fwpuclnt.dll and advapi32, WFP
# provisioning, SCM installation, and the process entry point. Holding them to a unit-test percentage
# would buy mock-heavy tests that assert against the mock rather than against Windows -- the exact
# metric-gaming this project avoids elsewhere. They are not untested: they are qualified by the VM
# protocol in docs/validation/VM_QUALIFICATION_KIT.md, which is evidence of a different kind and is
# recorded as such.
#
# So the gate measures the half where a percentage means something, and holds it to the same 80% as
# the engine libraries. Excluding a file from the count is a claim that something else covers it; if
# that stops being true, the exclusion is the bug.
$privilegedNativeFiles = @(
    "Program.cs"
    "WfpProvisioning.cs"
    "WfpSelfTest.cs"
    "WfpOutboundFirewallEngine.cs"
    "FirewallServiceInstaller.cs"
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
    # gate measured whichever file the filesystem enumerated first -- on one local run that was a
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
    # The privileged assembly measured with its native boundary removed, which is the only figure a
    # unit-test percentage can honestly speak for. Accumulated in the same pass; see the note above.
    $privilegedManaged = [pscustomobject]@{ Lines = 0; Covered = 0 }
    foreach ($entry in $hits.GetEnumerator())
    {
        $parts = $entry.Key.Split('|')
        $assembly = $parts[0]
        if (-not $totals.ContainsKey($assembly))
        {
            $totals[$assembly] = [pscustomobject]@{ Lines = 0; Covered = 0 }
        }
        $totals[$assembly].Lines++
        if ($entry.Value -gt 0) { $totals[$assembly].Covered++ }

        if ($privilegedAssemblies -contains $assembly)
        {
            $leaf = Split-Path -Leaf $parts[1]
            # `*.g.cs` is source-generator output: the LibraryImport marshalling stubs and the
            # LoggerMessage shims. Holding hand-written tests against a generator's emitted code
            # measures the generator, not this project -- and the marshalling stubs in particular are
            # the same native boundary as the files listed above, just emitted rather than typed.
            if ($privilegedNativeFiles -notcontains $leaf -and $leaf -notlike '*.g.cs')
            {
                $privilegedManaged.Lines++
                if ($entry.Value -gt 0) { $privilegedManaged.Covered++ }
            }
        }
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
            Privileged = $privilegedAssemblies -contains $assembly
        }
    }

    # Test assemblies are themselves near-100% covered, so counting them would flatter the total
    # into meaninglessness. Only shipped code is measured.
    $production = @($rows | Where-Object { $_.Assembly -like "winsight*" -and $_.Assembly -notlike "*.Tests" })
    # Rendered to a string so callers can pipe or filter this output without tripping over
    # PowerShell's format objects.
    ($production |
        Sort-Object Percent |
        Format-Table Assembly, Lines, Covered, Percent, Engine, Privileged -AutoSize |
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
        # as being covered -- and it is exactly how a gate ends up passing while looking at nothing.
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

    if ($PrivilegedMinimum -gt 0)
    {
        # Same absence check as the engine tier, for the same reason: an assembly missing from the
        # report was never measured, and a gate that vouches for nothing is worse than no gate.
        $privileged = @($production | Where-Object Privileged)
        $measuredPrivileged = @($privileged | ForEach-Object { $_.Assembly })
        $unmeasuredPrivileged = @($privilegedAssemblies | Where-Object { $measuredPrivileged -notcontains $_ })
        if ($unmeasuredPrivileged)
        {
            throw ("No coverage was recorded at all for the privileged component: {0}. Either the " +
                   "assembly was renamed or no test project loaded it; both mean this gate cannot " +
                   "vouch for the code that runs as SYSTEM." -f ($unmeasuredPrivileged -join ", "))
        }

        if (-not $privilegedManaged.Lines)
        {
            throw ("The privileged component's managed half measured zero lines. Either every file " +
                   "was excluded as native or the exclusion list no longer matches any filename; " +
                   "both mean this gate is measuring nothing.")
        }

        $managedPercent = [math]::Round(100 * $privilegedManaged.Covered / $privilegedManaged.Lines, 1)
        "Privileged managed logic: {0}/{1} lines ({2}%), native/WFP/SCM boundary excluded and qualified by the VM protocol." -f `
            $privilegedManaged.Covered, $privilegedManaged.Lines, $managedPercent | Write-Output

        if ($managedPercent -lt $PrivilegedMinimum)
        {
            throw ("Below the $PrivilegedMinimum% privileged bar: the managed half of the SYSTEM " +
                   "component is at $managedPercent%. The native boundary is excluded on the grounds " +
                   "that the VM protocol covers it; the rest has no such excuse.")
        }
        "Privileged managed logic is at or above $PrivilegedMinimum%." | Write-Output
    }
}
finally
{
    Pop-Location
}
