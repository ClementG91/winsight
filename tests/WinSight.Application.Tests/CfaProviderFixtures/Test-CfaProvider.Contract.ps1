<#
.SYNOPSIS
    Deterministic fixture tests for scripts/Test-CfaProvider.ps1.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$probe = Join-Path $repoRoot 'scripts\Test-CfaProvider.ps1'
$fixtureRoot = Join-Path $PSScriptRoot 'cfa-provider'
$powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $powershell -PathType Leaf)) {
    throw "Windows PowerShell 5.1 is required and was not found at: $powershell"
}

function Test-ExactProperties([object]$Object, [string[]]$Expected) {
    if ($null -eq $Object) { return $false }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if ($actual -cnotcontains $name) { return $false } }
    return $true
}

function Test-Evidence([object]$Evidence, [hashtable]$Expected) {
    if (-not (Test-ExactProperties -Object $Evidence -Expected @(
                'SchemaVersion', 'Probe', 'Source', 'CliExitCode', 'ReportNotableCount', 'OperatingSystem', 'ControlledFolderAccess'))) { return $false }
    if (-not (Test-ExactProperties -Object $Evidence.OperatingSystem -Expected @('Product', 'Version', 'Build', 'Architecture'))) { return $false }
    if (-not (Test-ExactProperties -Object $Evidence.ControlledFolderAccess -Expected @(
                'State', 'Concern', 'RawStateValue', 'RuntimeSupportsProtection', 'AllowedApplicationsVisibility', 'ProtectedFolderCount'))) { return $false }
    if ($Evidence.SchemaVersion -ne 1 -or $Evidence.Probe -cne 'cfa-provider' -or $Evidence.Source -cne 'fixture') { return $false }
    if ($Evidence.OperatingSystem.Product -cne 'Fixture Windows 11' -or
        $Evidence.OperatingSystem.Version -cne '10.0.99999.0' -or
        $Evidence.OperatingSystem.Build -cne '99999' -or $Evidence.OperatingSystem.Architecture -cne 'x64') { return $false }
    foreach ($name in @('CliExitCode', 'ReportNotableCount')) {
        if ($Evidence.$name -ne $Expected.$name) { return $false }
    }
    foreach ($name in @('State', 'Concern', 'RawStateValue', 'RuntimeSupportsProtection', 'AllowedApplicationsVisibility', 'ProtectedFolderCount')) {
        $actualValue = $Evidence.ControlledFolderAccess.$name
        $expectedValue = $Expected.$name
        if ($expectedValue -is [string]) {
            if ($actualValue -cne $expectedValue) { return $false }
        }
        elseif ($actualValue -ne $expectedValue) { return $false }
    }
    return $true
}

function New-LiveCliHelper([string]$Directory) {
    $helper = Join-Path $Directory 'CFA helper & literal.exe'
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

public static class CfaProviderTestCli
{
    private const string Report = "[{\"tool\":\"integrity\",\"summary\":\"ok\",\"items\":[{\"severity\":\"info\",\"title\":\"Controlled Folder Access (ransomware shield)\",\"detail\":\"protecting\",\"fields\":{\"protection\":\"Controlled Folder Access\",\"state\":\"Enabled\",\"rawStateValue\":\"1\",\"concern\":\"Protecting\",\"runtimeSupportsProtection\":\"True\",\"amRunningMode\":\"Normal\",\"antivirusEnabled\":\"True\",\"realTimeProtectionEnabled\":\"True\",\"protectedFolders\":\"0\",\"allowedApplicationsVisibility\":\"Visible\",\"settingsDeepLink\":\"windowsdefender://RansomwareProtection\"}}],\"notableCount\":0}]";

    public static int Main(string[] args)
    {
        var log = Environment.GetEnvironmentVariable("WINSIGHT_CFA_TEST_LOG");
        if (args.Length != 2 || args[0] != "integrity" || args[1] != "--json")
        {
            Console.Error.Write("argument mismatch");
            return 9;
        }
        if (Environment.GetEnvironmentVariable("WINSIGHT_CFA_TEST_CHILD") == "1")
        {
            if (!String.IsNullOrEmpty(log)) File.AppendAllText(log, "child=" + Process.GetCurrentProcess().Id + Environment.NewLine);
            Thread.Sleep(60000);
            return 0;
        }
        var mode = Environment.GetEnvironmentVariable("WINSIGHT_CFA_TEST_MODE") ?? "normal";
        if (!String.IsNullOrEmpty(log)) File.WriteAllText(log, "args=" + args[0] + "|" + args[1] + Environment.NewLine);
        if (mode == "stderr-only") { Console.Error.Write(Report); return 0; }
        if (mode == "stdout-and-stderr") { Console.Out.Write(Report); Console.Error.Write("diagnostic"); return 0; }
        if (mode == "overflow-stdout") { Console.Out.Write(Report.Replace("\"ok\"", "\"" + new String('x', 4096) + "\"")); return 0; }
        if (mode == "overflow-stderr") { Console.Out.Write(Report); Console.Error.Write(new String('x', 4096)); return 0; }
        if (mode == "timeout-tree")
        {
            var child = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "integrity --json") { UseShellExecute = false };
            child.EnvironmentVariables["WINSIGHT_CFA_TEST_CHILD"] = "1";
            Process.Start(child);
            Thread.Sleep(60000);
            return 0;
        }
        if (mode == "exit-handle-tree")
        {
            var child = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "integrity --json") { UseShellExecute = false };
            child.EnvironmentVariables["WINSIGHT_CFA_TEST_CHILD"] = "1";
            Process.Start(child);
            return 0;
        }
        Console.Out.Write(Report);
        return 0;
    }
}
'@ -OutputAssembly $helper -OutputType ConsoleApplication
    return $helper
}

function Test-ProcessAbsent([int]$ProcessId) {
    try { Get-Process -Id $ProcessId -ErrorAction Stop | Out-Null; return $false }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] { return $true }
    catch [System.ArgumentException] { return $true }
}

function Assert-OwnedLiveTempDirectory([string]$Directory) {
    $fullDirectory = [System.IO.Path]::GetFullPath($Directory)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $fullDirectory.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Live helper directory is outside the temporary root: $fullDirectory"
    }
    $leaf = [System.IO.Path]::GetFileName($fullDirectory)
    if ($leaf -notmatch '^winsight-cfa-live-contract-[0-9a-f]{32}$') {
        throw "Live helper directory has an unexpected name: $leaf"
    }
}

function Invoke-LiveCliCase([string]$Helper, [string]$Directory, [hashtable]$Case) {
    $output = Join-Path $Directory ($Case.Name + '.evidence.json')
    $log = Join-Path $Directory ($Case.Name + '.log')
    $oldMode = $env:WINSIGHT_CFA_TEST_MODE
    $oldLog = $env:WINSIGHT_CFA_TEST_LOG
    $oldChild = $env:WINSIGHT_CFA_TEST_CHILD
    try {
        $env:WINSIGHT_CFA_TEST_MODE = $Case.Mode
        $env:WINSIGHT_CFA_TEST_LOG = $log
        Remove-Item Env:WINSIGHT_CFA_TEST_CHILD -ErrorAction SilentlyContinue
        & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $probe -CliPath $Helper -OutputPath $output -TestCaptureTimeoutMilliseconds $Case.Timeout -TestMaximumCaptureCharacters $Case.MaximumCharacters | Out-Null
        $exitCode = $LASTEXITCODE
        $hasEvidence = Test-Path -LiteralPath $output -PathType Leaf
        $passed = $exitCode -eq $Case.ExpectedExit -and $hasEvidence -eq $Case.ExpectedEvidence
        if ($passed -and $Case.ExpectedEvidence) {
            $evidence = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            $passed = $evidence.Source -ceq 'live-cli' -and $evidence.CliExitCode -eq 0
        }
        if ($Case.Mode -in @('timeout-tree', 'exit-handle-tree')) {
            $childLine = $null
            if (Test-Path -LiteralPath $log -PathType Leaf) {
                $childLine = Get-Content -LiteralPath $log -ErrorAction Stop | Where-Object { $_ -like 'child=*' } | Select-Object -Last 1
            }
            if ([string]::IsNullOrWhiteSpace($childLine)) { $passed = $false }
            else {
                $childId = [int]($childLine.Substring(6))
                $passed = $passed -and (Test-ProcessAbsent $childId)
            }
        }
        else {
            $passed = $passed -and (Test-Path -LiteralPath $log -PathType Leaf) -and
                ((Get-Content -LiteralPath $log -Raw) -ceq "args=integrity|--json`r`n")
        }
        return $passed
    }
    finally {
        $env:WINSIGHT_CFA_TEST_MODE = $oldMode
        $env:WINSIGHT_CFA_TEST_LOG = $oldLog
        $env:WINSIGHT_CFA_TEST_CHILD = $oldChild
    }
}

$cases = @(
    @{ Name = 'green-protecting.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 0; ReportNotableCount = 0; State = 'Enabled'; Concern = 'Protecting'; RawStateValue = 1; RuntimeSupportsProtection = $true; AllowedApplicationsVisibility = 'RequiresElevation'; ProtectedFolderCount = 2 },
    @{ Name = 'green-protecting-other-notable.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Enabled'; Concern = 'Protecting'; RawStateValue = 1; RuntimeSupportsProtection = $true; AllowedApplicationsVisibility = 'Visible'; ProtectedFolderCount = 0 },
    @{ Name = 'green-runtime-shortfall.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Enabled'; Concern = 'RuntimeRequirementsNotMet'; RawStateValue = 1; RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = 'Visible'; ProtectedFolderCount = 0 },
    @{ Name = 'green-audit.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Audit'; Concern = 'AuditOnly'; RawStateValue = 2; RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = 'Visible'; ProtectedFolderCount = 0 },
    @{ Name = 'green-unavailable.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Unavailable'; Concern = 'Unavailable'; RawStateValue = $null; RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = 'Unavailable'; ProtectedFolderCount = 0 },
    # A machine whose antivirus is a non-Microsoft product. Both of these were rejected as unknown
    # vocabulary before the running-mode set covered every mode Defender documents, which turned the
    # commonest non-default configuration into an unreadable posture.
    @{ Name = 'green-defender-not-running.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Disabled'; Concern = 'DefenderNotRunning'; RawStateValue = 0; RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = 'Visible'; ProtectedFolderCount = 0 },
    @{ Name = 'green-passive-spelling.json'; ExpectedExit = 0; ExpectedEvidence = $true; CliExitCode = 1; ReportNotableCount = 1; State = 'Enabled'; Concern = 'RuntimeRequirementsNotMet'; RawStateValue = 1; RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = 'Visible'; ProtectedFolderCount = 1 },
    @{ Name = 'red-missing-cfa.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-duplicate-cfa.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-unknown-vocabulary.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-protecting-runtime.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-unavailable-hidden.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-not-running-reported-as-off.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-invalid-raw.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-notable-count-mismatch.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-sensitive-field.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-bad-exit.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-exit-mismatch.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-malformed-json.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-stderr-only.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-duplicate-report-member.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-duplicate-item-member.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-duplicate-cfa-field-member.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-escaped-duplicate-cfa-field-member.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-report-property-casing.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-item-property-casing.json'; ExpectedExit = 1; ExpectedEvidence = $false },
    @{ Name = 'red-cfa-field-property-casing.json'; ExpectedExit = 1; ExpectedEvidence = $false }
)

$failures = 0
foreach ($case in $cases) {
    $outputDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('winsight-cfa-contract-{0}' -f [guid]::NewGuid().ToString('N'))
    $output = Join-Path $outputDirectory 'evidence.json'
    $fixture = Join-Path $fixtureRoot $case.Name
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $probe -CliPath 'fixture-only' -OutputPath $output -InputJsonPath $fixture | Out-Null
    $actualExit = $LASTEXITCODE
    $hasEvidence = Test-Path -LiteralPath $output -PathType Leaf
    $passed = $actualExit -eq $case.ExpectedExit -and $hasEvidence -eq $case.ExpectedEvidence
    if ($passed -and $hasEvidence) {
        try {
            $evidence = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            $passed = Test-Evidence $evidence $case
            if ($passed) {
                $evidence.ControlledFolderAccess | Add-Member -NotePropertyName AllowedApplications -NotePropertyValue 'sensitive' -Force
                $passed = -not (Test-Evidence $evidence $case)
            }
        }
        catch { $passed = $false }
    }
    if ($hasEvidence) { Remove-Item -LiteralPath $output -Force }
    if (Test-Path -LiteralPath $outputDirectory -PathType Container) { Remove-Item -LiteralPath $outputDirectory -Force }
    if ($passed) { Write-Output ('[PASS] {0}' -f $case.Name) }
    else {
        $failures++
        [Console]::Error.WriteLine(('[FAIL] {0}: exit {1}, evidence {2}' -f $case.Name, $actualExit, $hasEvidence))
    }
}

$liveDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('winsight-cfa-live-contract-{0}' -f [guid]::NewGuid().ToString('N'))
$liveDirectoryCleaned = $false
[System.IO.Directory]::CreateDirectory($liveDirectory) | Out-Null
try {
    $helper = New-LiveCliHelper $liveDirectory

    # Pay the cold start once, outside every timed case. The first launch of a freshly written
    # .NET Framework executable costs JIT, image load and the antivirus's first scan of a brand-new
    # binary, and on 2026-07-28 that pushed `live-literal-path-and-arguments` past its budget on the
    # native Arm64 runner - the first live case failed while every later one passed, which is the
    # signature of a cold start rather than of a broken contract. Warming removes the confound
    # instead of hiding it behind a larger number.
    $warmMode = $env:WINSIGHT_CFA_TEST_MODE
    $warmLog = $env:WINSIGHT_CFA_TEST_LOG
    $warmChild = $env:WINSIGHT_CFA_TEST_CHILD
    try {
        # All three are cleared, not just the mode: a stale WINSIGHT_CFA_TEST_CHILD would make the
        # warm-up sleep for a minute, and a stale log path would let it write a transcript that a
        # later case then asserts against.
        $env:WINSIGHT_CFA_TEST_MODE = 'normal'
        Remove-Item Env:WINSIGHT_CFA_TEST_LOG -ErrorAction SilentlyContinue
        Remove-Item Env:WINSIGHT_CFA_TEST_CHILD -ErrorAction SilentlyContinue
        & $helper integrity --json | Out-Null
    }
    finally {
        $env:WINSIGHT_CFA_TEST_MODE = $warmMode
        $env:WINSIGHT_CFA_TEST_LOG = $warmLog
        $env:WINSIGHT_CFA_TEST_CHILD = $warmChild
    }

    # Two budgets, and the difference is deliberate. For the timeout-tree cases below the timeout *is*
    # the behaviour under test, so it stays short. For these it is only a safety net - the assertion
    # is about stream and exit-code handling, never about latency - so it is generous enough that a
    # slow runner cannot turn a passing contract into a red build.
    $streamTimeout = 20000
    $liveCases = @(
        @{ Name = 'live-literal-path-and-arguments'; Mode = 'normal'; Timeout = $streamTimeout; MaximumCharacters = 65536; ExpectedExit = 0; ExpectedEvidence = $true },
        @{ Name = 'live-json-on-stderr-only'; Mode = 'stderr-only'; Timeout = $streamTimeout; MaximumCharacters = 65536; ExpectedExit = 1; ExpectedEvidence = $false },
        @{ Name = 'live-stdout-plus-stderr'; Mode = 'stdout-and-stderr'; Timeout = $streamTimeout; MaximumCharacters = 65536; ExpectedExit = 1; ExpectedEvidence = $false },
        @{ Name = 'live-stdout-overflow'; Mode = 'overflow-stdout'; Timeout = $streamTimeout; MaximumCharacters = 1024; ExpectedExit = 1; ExpectedEvidence = $false },
        @{ Name = 'live-stderr-overflow'; Mode = 'overflow-stderr'; Timeout = $streamTimeout; MaximumCharacters = 1024; ExpectedExit = 1; ExpectedEvidence = $false },
        @{ Name = 'live-timeout-tree-cleanup'; Mode = 'timeout-tree'; Timeout = 1000; MaximumCharacters = 65536; ExpectedExit = 1; ExpectedEvidence = $false },
        @{ Name = 'live-parent-exit-stream-timeout-tree-cleanup'; Mode = 'exit-handle-tree'; Timeout = 1000; MaximumCharacters = 65536; ExpectedExit = 1; ExpectedEvidence = $false }
    )
    foreach ($case in $liveCases) {
        if (Invoke-LiveCliCase $helper $liveDirectory $case) { Write-Output ('[PASS] {0}' -f $case.Name) }
        else {
            $failures++
            [Console]::Error.WriteLine(('[FAIL] {0}' -f $case.Name))
        }
    }
}
finally {
    if (Test-Path -LiteralPath $liveDirectory -PathType Container) {
        Assert-OwnedLiveTempDirectory $liveDirectory
        Remove-Item -LiteralPath $liveDirectory -Force -Recurse
        $liveDirectoryCleaned = -not (Test-Path -LiteralPath $liveDirectory)
    }
}

if (-not $liveDirectoryCleaned) { throw 'Live helper temporary directory was not cleaned' }
if ($failures -ne 0) { throw "$failures CFA provider contract fixture test(s) failed" }
Write-Output ('CFA provider contract fixtures: {0}/{0} passed; {1}/{1} live CliPath checks passed.' -f $cases.Count, $liveCases.Count)
