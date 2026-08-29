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

# Every library holding detection, policy or composition logic.
#
# This list used to name ten of them and stop. The ten were not chosen for being riskier -- they were
# the ten already above the bar. WinSight.NetMonitor sat at 63%, WinSight.Attribution at 66% and
# WinSight.InputHooks at 78%, and the gate said "all engine libraries are at or above 80%" on every
# run, because it was not looking at them. That is the same failure mode as reading one cobertura
# file and reporting a pass: a number that cannot be contradicted.
#
# A library is on this list unless it is an entry point (the CLI's Program.cs), WPF code-behind, or
# the SYSTEM service -- which has its own tier below. Being hard to test is not a reason to be
# absent; it is a reason to name the untestable files explicitly, which is what
# $engineExcludedFiles does.
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
    "WinSight.NetMonitor"
    "WinSight.Attribution"
    "WinSight.InputHooks"
    "WinSight.Presence"
    "WinSight.AvMonitor"
    "WinSight.Drivers"
    "WinSight.Hijack"
    "WinSight.CodeIntegrity"
    "WinSight.Application"
    "WinSight.Mcp"
    # The dashboard was absent for the reason the ten were: its assembly-wide number is 53%, because
    # MainWindow.xaml.cs is a thousand lines of WPF code-behind at zero. Omitting the whole assembly
    # to avoid that also stopped anyone measuring DashboardFindingPresenter, which is pure logic, is
    # what every operator actually reads, and sat at 70% with six of its tool arms never executed at
    # all. The rule this file already states applies: name the untestable files, do not drop the
    # library.
    "winsight-dashboard"
)

# The live ETW capture boundary, excluded from the engine tier for exactly the reason the native
# WFP/SCM files are excluded from the privileged tier: creating a kernel trace session requires
# Administrator, and a unit test that mocks TraceEvent asserts against the mock rather than against
# Windows. Each of these files is a session opened against a real provider and a callback fed by it;
# the decision logic they depend on -- EtwSessionLifecycle, the failure classifier, the process
# identity probe, the correlation index -- is ordinary code and is held to the bar like everything
# else.
#
# What covers them instead is section 6 of docs/validation/VM_QUALIFICATION_KIT.md, which starts the
# real sessions in a disposable VM, kills owners, and requires that orphans are reclaimed and live
# sessions are not stopped. That is evidence of a different kind, and it is recorded as such.
#
# Excluding a file is a claim that something else covers it. If that stops being true, the exclusion
# is the bug -- not the percentage.
# WPF code-behind is excluded on the same terms. A window class is instantiated by the framework
# against a live visual tree and a message pump; a unit test that stands one up asserts against its
# own harness. What keeps them honest is section 3 of docs/validation/VM_QUALIFICATION_KIT.md, which
# drives the real dashboard. Everything these files call into - the presenter, the settings stores,
# the localization manager, the palette - is ordinary code and is held to the bar like the rest.
$engineExcludedFiles = @{
    "WinSight.NetMonitor" = @("OutboundConnectionWatcher.cs", "DnsEtwWatcher.cs")
    "WinSight.Attribution" = @("WriteAttributionWatcher.cs")
    "winsight-dashboard" = @("MainWindow.xaml.cs", "App.xaml.cs", "VirusTotalSettingsWindow.xaml.cs")
}

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
    # Engine assemblies measured with their live-ETW boundary removed, which is the only figure a
    # unit-test percentage can honestly speak for. The raw number stays in the table above it, so the
    # exclusion is visible rather than folded away.
    $engineGated = @{}
    $engineExcluded = 0
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

        if ($engineAssemblies -contains $assembly)
        {
            if (-not $engineGated.ContainsKey($assembly))
            {
                $engineGated[$assembly] = [pscustomobject]@{ Lines = 0; Covered = 0 }
            }
            $excludedForAssembly = @()
            if ($engineExcludedFiles.ContainsKey($assembly)) { $excludedForAssembly = $engineExcludedFiles[$assembly] }
            $leaf = Split-Path -Leaf $parts[1]
            if ($excludedForAssembly -contains $leaf)
            {
                $engineExcluded++
            }
            else
            {
                $engineGated[$assembly].Lines++
                if ($entry.Value -gt 0) { $engineGated[$assembly].Covered++ }
            }
        }

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
    if ($engineExcluded)
    {
        ("Excluded from the engine gate: {0} lines of live ETW capture and WPF code-behind, " +
         "each named above and qualified by the VM protocol.") -f $engineExcluded | Write-Output
    }

    # The gated view, which is what the bar is actually applied to.
    $gatedRows = foreach ($assembly in $engineGated.Keys)
    {
        $gated = $engineGated[$assembly]
        [pscustomobject]@{
            Assembly = $assembly
            Lines    = $gated.Lines
            Covered  = $gated.Covered
            Percent  = if ($gated.Lines) { [math]::Round(100 * $gated.Covered / $gated.Lines, 1) } else { 0 }
        }
    }
    $gatedRows = @($gatedRows)

    # Printed whenever it differs from the raw table. Without this, an assembly whose raw number is
    # below the bar sits in the table directly above the line "all engine libraries are at or above
    # 80%", and a reader has to take it on faith that two different things are being measured. A
    # gate that looks like it is lying is not much better than one that is.
    $adjusted = @($gatedRows | Where-Object {
        $raw = $production | Where-Object Assembly -EQ $_.Assembly
        $raw -and $raw.Lines -ne $_.Lines
    })
    if ($adjusted.Count -gt 0)
    {
        "" | Write-Output
        "Gated view (live ETW capture removed) -- these are the numbers the bar is applied to:" | Write-Output
        ($adjusted |
            Sort-Object Percent |
            Format-Table Assembly, Lines, Covered, Percent -AutoSize |
            Out-String).TrimEnd() | Write-Output
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

        # An exclusion that matches no file is a stale claim: the file was renamed or deleted, and
        # the entry now quietly protects nothing while reading as though it protects something.
        foreach ($assembly in $engineExcludedFiles.Keys)
        {
            foreach ($excludedFile in $engineExcludedFiles[$assembly])
            {
                $matched = @($hits.Keys | Where-Object {
                    $key = $_.Split('|')
                    $key[0] -eq $assembly -and (Split-Path -Leaf $key[1]) -eq $excludedFile
                })
                if ($matched.Count -eq 0)
                {
                    throw ("The engine exclusion {0}/{1} matches no measured file. Either it " +
                           "was renamed or it no longer exists; both mean the exclusion is now a " +
                           "claim about nothing." -f $assembly, $excludedFile)
                }
            }
        }

        $below = @($gatedRows | Where-Object { $_.Percent -lt $EngineMinimum })
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
