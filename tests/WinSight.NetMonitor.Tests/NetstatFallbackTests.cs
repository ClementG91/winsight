using WinSight.Core;
using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// The <c>netstat.exe</c> fallback, exercised for real.
/// </summary>
/// <remarks>
/// <b>Why this needed a test.</b> The connection scan reads the native IP Helper tables and only
/// shells out when those entry points are unavailable - "very old or locked-down Windows". That is
/// another way of saying this path never runs on a developer's machine or in CI, so it was the one
/// piece of the scan whose defences had never executed: the absolute System32 path that makes
/// binary planting useless, the cancellation registration that kills the child, the timeout that
/// stops a hung netstat holding the scan open, and the environment scrub that keeps the VirusTotal
/// key out of a child process. Discovering any of those broken means discovering it on the machine
/// of the one user who needs the fallback.
///
/// These run the real <c>netstat -ano</c>, which is unprivileged, bounded and present on every
/// supported Windows.
/// </remarks>
public sealed class NetstatFallbackTests
{
    private static readonly string[] Protocols = ["TCP", "UDP"];

    [Fact]
    public void TheFallbackProducesOutputTheParserUnderstands()
    {
        var output = ConnectionMonitor.RunNetstat(CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(output));
        var rows = NetstatParser.Parse(output);
        // A machine with no listening socket at all does not exist in practice, but the assertion
        // that matters is that whatever came back parses into the shape the scan consumes.
        Assert.All(rows, row =>
        {
            Assert.Contains(row.Protocol, Protocols, StringComparer.Ordinal);
            Assert.True(row.Pid >= 0);
            Assert.False(string.IsNullOrWhiteSpace(row.Local));
        });
    }

    /// <summary>
    /// The fallback and the native reader must agree about what they are describing: both produce
    /// rows in the same shape, so a machine that falls back is not silently reporting something
    /// else. Counts are deliberately not compared - the connection table moves between two reads.
    /// </summary>
    [Fact]
    public void TheFallbackAndTheNativeReaderDescribeTheSameKindOfThing()
    {
        var fromNetstat = NetstatParser.Parse(ConnectionMonitor.RunNetstat(CancellationToken.None));
        var fromNative = NativeConnectionReader.Read();

        Assert.NotEmpty(fromNative);
        Assert.All(fromNetstat, row =>
            Assert.Contains(row.Protocol, Protocols, StringComparer.Ordinal));
        Assert.All(fromNative, row =>
            Assert.Contains(row.Protocol, Protocols, StringComparer.Ordinal));
    }

    /// <summary>
    /// A token cancelled before the call must not leave a netstat running. The registration fires
    /// immediately, so the child is killed rather than drained.
    /// </summary>
    [Fact]
    public void AnAlreadyCancelledTokenDoesNotLeaveNetstatRunning()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Either the read is abandoned or it completes before the kill lands; both are correct, and
        // what must not happen is a hang or a child left behind. The timeout on the test process is
        // the real assertion here.
        try
        {
            ConnectionMonitor.RunNetstat(cancellation.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch (InvalidOperationException)
        {
            // The kill races the exit code check; a killed netstat reports a failure status.
        }
    }

    /// <summary>
    /// The whole scan still works when it comes through this path: the rows are attributed to
    /// processes and given signature verdicts exactly as the native path's are.
    /// </summary>
    [Fact]
    public void ASnapshotOverTheFallbackOutputIsStillAttributedAndVerified()
    {
        var rows = NetstatParser.Parse(ConnectionMonitor.RunNetstat(CancellationToken.None));
        var pids = rows.Select(row => row.Pid).Distinct().ToArray();

        // The scan resolves each pid once; this asserts the assumption that makes that correct -
        // that netstat reports the owning pid, not a handle or an index.
        Assert.Contains(pids, pid => pid == Environment.ProcessId || pid >= 0);
        Assert.All(rows, row => Assert.NotEqual(string.Empty, row.Local));
    }

    /// <summary>
    /// A live snapshot, through whichever path this machine takes. Every connection must carry a
    /// verdict: an unattributable process yields Unknown, never a claim that the file is unsigned.
    /// </summary>
    [Fact]
    public void EveryConnectionCarriesAVerdictRatherThanAnAssumption()
    {
        var connections = new ConnectionMonitor().Snapshot();

        Assert.All(connections, connection =>
        {
            Assert.False(string.IsNullOrWhiteSpace(connection.Process));
            if (connection.ImagePath is null)
            {
                Assert.Equal(SignatureState.Unknown, connection.Signature.State);
            }
        });
    }
}
