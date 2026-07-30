using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// Guards the three production watcher edges. The lifecycle is only effective if every watcher
/// reaches it; these are deliberately source contracts because opening a watcher would allocate a
/// privileged machine-global ETW session.
/// </summary>
public sealed class EtwWatcherCompositionTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Theory]
    [InlineData("src/WinSight.Attribution/WriteAttributionWatcher.cs", "EtwSessionProfile.Attribution")]
    [InlineData("src/WinSight.NetMonitor/OutboundConnectionWatcher.cs", "EtwSessionProfile.Outbound")]
    [InlineData("src/WinSight.NetMonitor/DnsEtwWatcher.cs", "EtwSessionProfile.Dns")]
    public void EveryProductionWatcherUsesItsClosedLifecycleProfile(string relativePath, string profile)
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, relativePath.Replace('/', Path.DirectorySeparatorChar)));

        Assert.Contains($"EtwSessionLifecycle.OpenNative({profile})", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new TraceEventSession(", source, StringComparison.Ordinal);
    }
}
