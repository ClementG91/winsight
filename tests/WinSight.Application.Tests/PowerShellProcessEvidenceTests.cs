using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using Xunit;
using Xunit.Abstractions;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed class PowerShellProcessEvidenceTests(ITestOutputHelper output)
{
    private const string FrameworkProfileBaseline = "WINSIGHT_TEST_FRAMEWORK_PROFILE_BASELINE";
    private static readonly string[] ComparisonOperations = ["management", "json"];
    private static readonly bool[][] ComparisonOrders = [[false, true], [true, false]];
    private static readonly string[] BooleanTokens = ["True", "False"];
    private const string FrameworkObservation = """

        function Get-WinSightComparisonFlag([string]$Name) {
            $value=[Environment]::GetEnvironmentVariable($Name)
            if ($null -eq $value) { return 'absent' }
            if ($value -ceq '0') { return 'zero' }
            if ($value -ceq '1') { return 'one' }
            return 'other'
        }
        $knownEngine=$false
        foreach ($loaded in [Diagnostics.Process]::GetCurrentProcess().Modules) {
            if ($loaded.ModuleName.IndexOf('InstrumentationEngine',[StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $loaded.ModuleName.StartsWith('Microsoft.CodeCoverage',[StringComparison]::OrdinalIgnoreCase)) { $knownEngine=$true }
        }
        [Console]::WriteLine('WSPROFILER:'+(Get-WinSightComparisonFlag 'COR_ENABLE_PROFILING')+':'+(Get-WinSightComparisonFlag 'CORECLR_ENABLE_PROFILING')+':'+$knownEngine+':'+[Environment]::Version.Major+':'+[Environment]::Is64BitProcess)

        """;

    [Fact]
    public async Task ARealFloodIsDrainedWhileRetainedOutputIsBounded()
    {
        var start = PowerShellProcessEvidence.StartInfo();
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude + "[Console]::Out.Write(('x' * 100000)); [Console]::Error.Write(('y' * 100000)); [Console]::Out.WriteLine(); Write-TestPhase 'body-end'");
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.Equal(0, result.ExitCode);
        Assert.InRange(result.Stdout.Length, 0, PowerShellProcessEvidence.OutputLimit);
        Assert.InRange(result.Stderr.Length, 0, PowerShellProcessEvidence.OutputLimit);
        Assert.Contains("body-end=", result.Summary, StringComparison.Ordinal);
        Assert.Contains("stdout-truncated=True", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SameEncodedCommandNoopRecordsOrderedHostReceptionPhases()
    {
        var start = PowerShellProcessEvidence.StartInfo();
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude + "Write-TestPhase 'body-begin'; Write-TestPhase 'body-end'");
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.Equal(0, result.ExitCode);
        var entered = result.Summary.IndexOf("entered=", StringComparison.Ordinal);
        var body = result.Summary.IndexOf("body-begin=", StringComparison.Ordinal);
        var end = result.Summary.IndexOf("body-end=", StringComparison.Ordinal);
        Assert.True(entered >= 0 && entered < body && body < end, result.Summary);
        Assert.Contains("stdout-eof=True", result.Summary, StringComparison.Ordinal);
        Assert.Contains("stderr-eof=True", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FailedChildRetainsItsNonzeroExitAndSyntheticError()
    {
        var start = PowerShellProcessEvidence.StartInfo();
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude + "Write-TestPhase 'body-begin'; [Console]::Error.WriteLine('synthetic-test-error'); exit 7");
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.Equal(7, result.ExitCode);
        Assert.Contains("synthetic-test-error", result.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("body-end=", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ABlockedChildKeepsItsTimeoutWhenCleanupAlsoThrows()
    {
        var start = PowerShellProcessEvidence.StartInfo();
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude + "Write-TestPhase 'body-begin'; [Console]::Error.Write('synthetic-partial-error'); [Console]::Error.Flush(); [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)");
        var pid = 0;
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PowerShellProcessEvidence.Run(
            start, TimeSpan.FromSeconds(30), output.WriteLine, p =>
            {
                pid = p.Id;
                p.Kill(entireProcessTree: true);
                throw new InvalidOperationException("injected secondary cleanup failure");
            }));
        Assert.NotEqual(0, pid);
        Assert.Contains("body-begin", Assert.IsType<string>(exception.Data["PowerShellEvidence"]), StringComparison.Ordinal);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("synthetic-partial-error"))),
            Assert.IsType<string>(exception.Data["PowerShellStderrPrefixSha256"]));
        Assert.True(HasExited(pid), "The child must be observed stopped even when the cleanup callback fails.");
    }

    private static bool HasExited(int pid)
    {
        try { using var process = Process.GetProcessById(pid); return process.HasExited; }
        catch (ArgumentException) { return true; }
    }

    [Fact]
    public async Task PhaseInstrumentationPreservesAFinalNativeFailure()
    {
        var baseline = PowerShellProcessEvidence.StartInfo();
        var instrumented = PowerShellProcessEvidence.StartInfo();
        const string body = "$ErrorActionPreference='Stop'; & $env:ComSpec /c exit 7";
        PowerShellProcessEvidence.EncodedCommand(baseline, body);
        PowerShellProcessEvidence.EncodedCommand(instrumented, PowerShellProcessEvidence.Prelude + body + PowerShellProcessEvidence.BodyEnd);
        var original = await PowerShellProcessEvidence.Run(baseline, TimeSpan.FromSeconds(30), output.WriteLine);
        var measured = await PowerShellProcessEvidence.Run(instrumented, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.NotEqual(0, original.ExitCode);
        Assert.Equal(original.ExitCode, measured.ExitCode);
    }

    [Theory]
    [InlineData("management")]
    [InlineData("json")]
    [InlineData("compiler")]
    public async Task FirstAndRepeatedRuntimeOperationsRetainNativeAndChildClockEvidence(string operation)
    {
        _ = await ObserveRuntime(operation);
    }

    [Fact]
    public async Task ExplicitFrameworkComparisonPreservesCoreClrAndOriginalRuntimeOracles()
    {
        var budget = Stopwatch.StartNew();
        var applied = 0;
        var captures = 0;
        var expectedControls = Environment.GetEnvironmentVariable(FrameworkProfileBaseline) == "unconfigured"
            && Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING") == "1";
        foreach (var operation in ComparisonOperations)
        {
            for (var trial = 0; trial < ComparisonOrders.Length; trial++)
            {
                foreach (var disableRequested in ComparisonOrders[trial])
                {
                    // Admission and post-return checks are not a hard bound on synchronous Start/Kill.
                    Assert.True(TimeSpan.FromSeconds(120) - budget.Elapsed >= TimeSpan.FromSeconds(36),
                        "The comparison cannot admit another complete 30 s oracle and its existing 6 s cleanup reserve.");
                    var controlApplied = false;
                    var expectedFramework = "unobserved";
                    var expectedCore = "unobserved";
                    ushort targetMachine = 0;
                    var result = await ObserveRuntime(operation, start =>
                    {
                        var before = ProfileSnapshot(start);
                        start.Environment.TryGetValue("COR_ENABLE_PROFILING", out var framework);
                        start.Environment.TryGetValue("CORECLR_ENABLE_PROFILING", out var core);
                        targetMachine = FrameworkTargetMachine(start);
                        controlApplied = disableRequested && CanCompareOwnedFrameworkRoute(start, targetMachine);
                        if (controlApplied) { start.Environment["COR_ENABLE_PROFILING"] = "0"; }
                        expectedFramework = Flag(controlApplied ? "0" : framework);
                        expectedCore = Flag(core);
                        var after = ProfileSnapshot(start);
                        Assert.True(before.Count == after.Count && before.All(pair =>
                            after.TryGetValue(pair.Key, out var value)
                            && value == (controlApplied && pair.Key.Equals("COR_ENABLE_PROFILING", StringComparison.OrdinalIgnoreCase) ? "0" : pair.Value)),
                            "A profiling value outside the explicit Framework control changed.");
                    }, observeFramework: true);
                    Assert.True(budget.Elapsed <= TimeSpan.FromSeconds(120), "The comparison exceeded its aggregate observation budget.");
                    var metadata = Assert.Single(result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                        .Select(line => line.TrimEnd('\r')), line => line.StartsWith("WSPROFILER:", StringComparison.Ordinal));
                    var fields = metadata.Split(':');
                    Assert.Equal(6, fields.Length);
                    Assert.Equal(expectedFramework, fields[1]);
                    Assert.Equal(expectedCore, fields[2]);
                    Assert.Contains(fields[3], BooleanTokens);
                    Assert.Equal("4", fields[4]);
                    Assert.Contains(fields[5], BooleanTokens);
                    output.WriteLine(FormattableString.Invariant($"framework-comparison operation={operation};trial={trial};requested={disableRequested};applied={controlApplied};targetMachine={targetMachine:X4};{metadata}"));
                    captures++;
                    if (controlApplied) { applied++; }
                }
            }
        }
        Assert.Equal(8, captures);
        output.WriteLine($"framework-comparison captures={captures};applied={applied};environment-contrast-established={applied == 4}");
        if (expectedControls) { Assert.Equal(4, applied); }
        Assert.True(budget.Elapsed <= TimeSpan.FromSeconds(120), "The comparison exceeded its aggregate observation budget.");
    }

    private async Task<PowerShellProcessEvidence.Result> ObserveRuntime(string operation,
        Action<ProcessStartInfo>? configure = null, bool observeFramework = false)
    {
        // A new process measures its first call, without assuming cold OS/JIT/compiler caches.
        var body = operation switch
        {
            "management" => """
                $expected=[IO.Path]::Combine([IO.Path]::GetTempPath(),'winsight-runtime-probe')
                $first=Join-Path ([IO.Path]::GetTempPath()) 'winsight-runtime-probe'
                if (-not [string]::Equals($first,$expected,[StringComparison]::OrdinalIgnoreCase)) {throw 'ASSERT: first path resolution changed'}
                Write-TestPhase 'probe-first-complete'
                $again=Join-Path ([IO.Path]::GetTempPath()) 'winsight-runtime-probe'
                if (-not [string]::Equals($again,$expected,[StringComparison]::OrdinalIgnoreCase)) {throw 'ASSERT: repeated path resolution changed'}
                """,
            "json" => """
                $first=@{value=7;name='runtime-probe'}|ConvertTo-Json -Compress|ConvertFrom-Json
                if ($first.value -ne 7 -or $first.name -cne 'runtime-probe') {throw 'ASSERT: first JSON roundtrip changed'}
                Write-TestPhase 'probe-first-complete'
                $again=@{value=8;name='runtime-probe'}|ConvertTo-Json -Compress|ConvertFrom-Json
                if ($again.value -ne 8 -or $again.name -cne 'runtime-probe') {throw 'ASSERT: repeated JSON roundtrip changed'}
                """,
            "compiler" => """
                $firstName='WinSightRuntimeFirst'+[guid]::NewGuid().ToString('N')
                $first=Add-Type -TypeDefinition ('public static class '+$firstName+' { public static int Value() { return 7; } }') -PassThru
                if ($first.GetMethod('Value').Invoke($null,@()) -ne 7) {throw 'ASSERT: first compiled method changed'}
                Write-TestPhase 'probe-first-complete'
                $againName='WinSightRuntimeAgain'+[guid]::NewGuid().ToString('N')
                $again=Add-Type -TypeDefinition ('public static class '+$againName+' { public static int Value() { return 7; } }') -PassThru
                if ($againName -ceq $firstName -or $again.GetMethod('Value').Invoke($null,@()) -ne 7) {throw 'ASSERT: repeated distinct compiled method changed'}
                """,
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
        var start = PowerShellProcessEvidence.StartInfo();
        configure?.Invoke(start);
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude
            + "$ErrorActionPreference='Stop'; Write-TestPhase 'body-begin'; Write-TestPhase 'probe-begin'\n"
            + body + "\nWrite-TestPhase 'probe-repeat-complete'" + (observeFramework ? FrameworkObservation : "")
            + PowerShellProcessEvidence.BodyEnd + "\nexit 0");
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.Equal(0, result.ExitCode);

        var native = EvidenceFields(result.Summary, "native-process-final");
        Assert.Equal(4, native.Count);
        Assert.Equal("True", native["exited"]);
        Assert.Equal("0", native["exitCode"]);
        foreach (var name in new[] { "startUtc", "exitUtc" })
        {
            Assert.True(DateTime.TryParseExact(native[name], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc));
            Assert.Equal(DateTimeKind.Utc, utc.Kind);
        }
        var armed = EvidenceFields(result.Summary, "host-armed");
        Assert.Equal(4, armed.Count);
        Assert.True(DateTime.TryParseExact(armed["utc"], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var armUtc));
        Assert.Equal(DateTimeKind.Utc, armUtc.Kind);
        Assert.True(double.TryParse(armed["elapsedMs"], NumberStyles.Float, CultureInfo.InvariantCulture, out var armMs) && double.IsFinite(armMs) && armMs >= 0);
        Assert.True(CanonicalNonnegativeLong(armed["frequency"]) > 0);
        CanonicalNonnegativeLong(armed["counter"]);
        foreach (var section in new[] { "pool-launch", "pool-final" })
        {
            var pool = EvidenceFields(result.Summary, section);
            Assert.Equal(6, pool.Count);
            foreach (var field in new[] { "count", "pending", "availableWorker", "availableIo", "maximumWorker", "maximumIo" })
            {
                CanonicalNonnegativeLong(pool[field]);
            }
        }

        const string clockPrefix = "__WINSIGHT_TEST_CHILD_CLOCK__:";
        var frames = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd('\r')).Where(line => line.StartsWith(clockPrefix, StringComparison.Ordinal))
            .Select(line => line[clockPrefix.Length..].Split(':')).ToArray();
        var names = new[] { "probe-begin", "probe-first-complete", "probe-repeat-complete" };
        Assert.Equal(names, frames.Where(frame => names.Contains(frame[0], StringComparer.Ordinal)).Select(frame => frame[0]));
        long? frequency = null;
        long previous = 0;
        var previousHost = -1;
        foreach (var frame in frames)
        {
            Assert.Equal(4, frame.Length);
            Assert.InRange(CanonicalNonnegativeLong(frame[1]), DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks);
            var counter = CanonicalNonnegativeLong(frame[2]);
            var currentFrequency = CanonicalNonnegativeLong(frame[3]);
            Assert.True(currentFrequency > 0 && counter >= previous);
            frequency ??= currentFrequency;
            Assert.Equal(frequency.Value, currentFrequency);
            previous = counter;
        }
        foreach (var name in names)
        {
            var index = result.Summary.IndexOf(name + "=", StringComparison.Ordinal);
            Assert.True(index > previousHost, result.Summary);
            previousHost = index;
            Assert.Contains(name + ":", result.Summary, StringComparison.Ordinal);
        }
        return result;
    }

    private static Dictionary<string, string?> ProfileSnapshot(ProcessStartInfo start) => start.Environment
        .Where(pair => pair.Key.StartsWith("COR_", StringComparison.OrdinalIgnoreCase)
            || pair.Key.StartsWith("CORECLR_", StringComparison.OrdinalIgnoreCase)
            || pair.Key.StartsWith("MicrosoftInstrumentationEngine_", StringComparison.OrdinalIgnoreCase))
        .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

    private static bool CanCompareOwnedFrameworkRoute(ProcessStartInfo start, ushort targetMachine)
    {
        if (Environment.GetEnvironmentVariable(FrameworkProfileBaseline) != "unconfigured"
            || !start.Environment.TryGetValue("COR_ENABLE_PROFILING", out var enabled) || enabled != "1"
            || !start.Environment.TryGetValue("COR_PROFILER", out var profiler)
            || !Guid.TryParse(profiler, out var id) || id != new Guid("324f817a-7420-4e6d-b3c1-143fbed6d855"))
        {
            return false;
        }
        // Ambiguous managed x86/hybrid images are not sufficient evidence of CLR architecture.
        if (targetMachine is not (0x8664 or 0xaa64)) { return false; }
        string? packageRoot = null;
        var paths = 0;
        var applicable = false;
        foreach (var pair in start.Environment)
        {
            if (pair.Key.StartsWith("MicrosoftInstrumentationEngine_RawProfilerHook", StringComparison.OrdinalIgnoreCase)
                || pair.Key.StartsWith("MicrosoftInstrumentationEngine_Host", StringComparison.OrdinalIgnoreCase)) { return false; }
            if (!pair.Key.StartsWith("COR_PROFILER_PATH", StringComparison.OrdinalIgnoreCase)) { continue; }
            var leaf = pair.Key.ToUpperInvariant() switch
            {
                "COR_PROFILER_PATH_32" => @"x86\MicrosoftInstrumentationEngine_x86.dll",
                "COR_PROFILER_PATH_64" => @"x64\MicrosoftInstrumentationEngine_x64.dll",
                "COR_PROFILER_PATH_ARM64" => @"arm64\MicrosoftInstrumentationEngine_arm64.dll",
                "COR_PROFILER_PATH" => targetMachine switch
                {
                    0x8664 => @"x64\MicrosoftInstrumentationEngine_x64.dll",
                    0xaa64 => @"arm64\MicrosoftInstrumentationEngine_arm64.dll",
                    _ => null,
                },
                _ => null,
            };
            if (leaf is null || !KnownCoveragePath(pair.Value, leaf, ref packageRoot)) { return false; }
            applicable |= pair.Key.Equals("COR_PROFILER_PATH", StringComparison.OrdinalIgnoreCase)
                || (targetMachine == 0x8664 && pair.Key.Equals("COR_PROFILER_PATH_64", StringComparison.OrdinalIgnoreCase))
                || (targetMachine == 0xaa64 && pair.Key.Equals("COR_PROFILER_PATH_ARM64", StringComparison.OrdinalIgnoreCase));
            paths++;
        }
        // This is an explicit comparison of the route introduced by this test launch, not a
        // default policy or proof that the engine has no additional filesystem-discovered client.
        return paths > 0 && applicable;
    }

    private static ushort FrameworkTargetMachine(ProcessStartInfo start)
    {
        var path = start.FileName.Replace('/', '\\');
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') { return 0; }
        try
        {
            using var content = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> dos = stackalloc byte[64];
            content.ReadExactly(dos);
            if (dos[0] != 'M' || dos[1] != 'Z') { return 0; }
            var offset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(dos[0x3c..]);
            if (offset is < 64 or > 1024 * 1024 || offset > content.Length - 6) { return 0; }
            content.Position = offset;
            Span<byte> pe = stackalloc byte[6];
            content.ReadExactly(pe);
            if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) { return 0; }
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(pe[4..]);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            return 0;
        }
    }

    private static bool KnownCoveragePath(string? value, string leaf, ref string? packageRoot)
    {
        if (string.IsNullOrEmpty(value) || !Path.IsPathFullyQualified(value)) { return false; }
        string normalized;
        try { normalized = Path.GetFullPath(value).Replace('/', '\\'); }
        catch (Exception failure) when (failure is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
        if (normalized.Length < 3 || !char.IsAsciiLetter(normalized[0]) || normalized[1] != ':' || normalized[2] != '\\') { return false; }
        if (!normalized.Equals(value.Replace('/', '\\'), StringComparison.OrdinalIgnoreCase)) { return false; }
        const string package = @"\microsoft.codecoverage\18.9.0\build\netstandard2.0\";
        if (!normalized.EndsWith(package + leaf, StringComparison.OrdinalIgnoreCase)) { return false; }
        var root = normalized[..^leaf.Length];
        if (packageRoot is not null && !packageRoot.Equals(root, StringComparison.OrdinalIgnoreCase)) { return false; }
        var expectedHash = leaf switch
        {
            @"x86\MicrosoftInstrumentationEngine_x86.dll" => "164844e7e460fa93bb5a1ded8dfcd66644a017d426bfab5214389e2591000842",
            @"x64\MicrosoftInstrumentationEngine_x64.dll" => "d538979eef2ba49bf1a5c84f8c70f4588ffff2671399e46af033ee5238667a07",
            @"arm64\MicrosoftInstrumentationEngine_arm64.dll" => "eb27e2943934aeaafd551f8ca50fcffd9543d35c9ed9840b78703c822670715a",
            _ => null,
        };
        if (expectedHash is null) { return false; }
        try
        {
            if (new DriveInfo(normalized[..3]).DriveType != DriveType.Fixed) { return false; }
            using var content = new FileStream(normalized, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (content.Length is < 1 or > 16 * 1024 * 1024
                || !Convert.ToHexString(SHA256.HashData(content)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) { return false; }
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            return false;
        }
        packageRoot = root;
        return true;
    }

    private static string Flag(string? value) => value switch { null => "absent", "0" => "zero", "1" => "one", _ => "other" };

    private static Dictionary<string, string> EvidenceFields(string summary, string section)
    {
        var prefix = section + "=[";
        Assert.Contains(prefix, summary, StringComparison.Ordinal);
        var begin = summary.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length;
        var end = summary.IndexOf(']', begin);
        Assert.True(end > begin, summary);
        return summary[begin..end].Split(';', StringSplitOptions.TrimEntries)
            .Select(field => field.Split('=', 2)).ToDictionary(field => field[0], field => field[1], StringComparer.Ordinal);
    }

    private static long CanonicalNonnegativeLong(string value)
    {
        Assert.True(long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= 0);
        Assert.Equal(parsed.ToString(CultureInfo.InvariantCulture), value);
        return parsed;
    }
}
