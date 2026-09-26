using Xunit;

namespace WinSight.Response.Tests;

/// <summary>
/// The real Restart Manager against a file this test process holds open. Unelevated: it only names
/// the current user's own process, which is exactly the RansomWhere?-parity identification path.
/// </summary>
public sealed class RestartManagerRealTests
{
    [Fact]
    public void ItNamesTheProcessHoldingAFileOpen()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-rm-{Guid.NewGuid():N}.dat");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
        try
        {
            var holders = new RestartManagerInspector().ProcessesHolding([path]);

            var self = Assert.Single(holders, h => h.Pid == Environment.ProcessId);
            // The Restart Manager start time is the raw creation FILETIME, the same value the inspector
            // reads, so an identity captured for the pid it named revalidates cleanly.
            var captured = new Win32ProcessInspector().Capture(Environment.ProcessId);
            Assert.NotNull(captured);
            Assert.Equal(captured!.StartTimestampUtcTicks, self.StartTimestampUtcTicks);
        }
        finally
        {
            stream.Dispose();
            File.Delete(path);
        }
    }

    [Fact]
    public void TheIdentifierNeverOffersItsOwnHostingProcessAsACandidate()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-rm-{Guid.NewGuid():N}.dat");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite);
        try
        {
            var identifier = new FileHolderIdentifier(new RestartManagerInspector(), new Win32ProcessInspector());

            var identification = identifier.Identify([path]);

            Assert.DoesNotContain(identification.Candidates, c => c.Identity.Pid == Environment.ProcessId);
            Assert.Equal(IdentificationConfidence.None, identification.Confidence);
            Assert.Contains("protected", identification.Reason, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            stream.Dispose();
            File.Delete(path);
        }
    }

    [Fact]
    public void AnUnheldFileNamesNoProcess()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-rm-{Guid.NewGuid():N}.dat");
        File.WriteAllText(path, "not held open");
        try
        {
            var holders = new RestartManagerInspector().ProcessesHolding([path]);
            Assert.DoesNotContain(holders, h => h.Pid == Environment.ProcessId);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
