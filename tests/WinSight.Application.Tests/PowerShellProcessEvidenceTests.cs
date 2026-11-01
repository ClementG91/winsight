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
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude
            + "$ErrorActionPreference='Stop'; Write-TestPhase 'body-begin'; Write-TestPhase 'probe-begin'\n"
            + body + "\nWrite-TestPhase 'probe-repeat-complete'" + PowerShellProcessEvidence.BodyEnd + "\nexit 0");
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
    }

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
