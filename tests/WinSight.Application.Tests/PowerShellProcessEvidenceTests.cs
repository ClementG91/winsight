using System.Diagnostics;
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
}
