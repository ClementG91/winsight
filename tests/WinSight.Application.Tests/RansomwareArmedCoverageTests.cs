using WinSight.Application;
using WinSight.Ransomware;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Preserved files from an earlier run can occupy every decoy name. The directory watch still
/// opens, so a badge built on the watch count read "active" while no decoy existed.
/// </summary>
public sealed class RansomwareArmedCoverageTests : IDisposable
{
    private static readonly byte[] Seed = new byte[32];
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"wsg-armed-{Guid.NewGuid():N}");

    public RansomwareArmedCoverageTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void PreservedFilesOnEveryDecoyNameAreFailedCoverageNotActive()
    {
        var blocked = Folder("blocked");
        var userData = OccupyDecoyNames(blocked, CanaryIdentity.PerDirectory);

        using var monitor = Monitor(blocked);
        monitor.Start();

        Assert.Equal(1, monitor.WatchedDirectoryCount); // what the old badge measured
        Assert.Equal(0, monitor.ArmedDirectoryCount);
        Assert.Empty(monitor.Canaries);
        Assert.Equal(ProtectionState.Failed, RansomwareHost.Health(monitor, 0).State);
        // The fix is in what is reported: the preserved files are never deleted to make room.
        Assert.All(userData, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
    }

    [Fact]
    public void AnIncompleteDecoySetMakesThatDirectoryPartial()
    {
        var blocked = Folder("one-name-taken");
        var clean = Folder("clean");
        OccupyDecoyNames(blocked, 1);

        using var monitor = Monitor(blocked, clean);
        monitor.Start();

        Assert.Equal(2, monitor.WatchedDirectoryCount);
        Assert.Equal(1, monitor.ArmedDirectoryCount);
        var health = RansomwareHost.Health(monitor, 0);
        Assert.Equal(ProtectionState.Partial, health.State);
        Assert.Equal((1, 2), (health.Armed, health.Requested));
    }

    [Fact]
    public void FullyPlantedWatchedDirectoriesAreActive()
    {
        using var monitor = Monitor(Folder("a"), Folder("b"));
        monitor.Start();

        Assert.Equal(ProtectionState.Active, RansomwareHost.Health(monitor, 0).State);
        Assert.Equal(ProtectionState.Off, RansomwareHost.Health(null, 2).State);
    }

    [Fact]
    public void ADecoyThatDisappearsAfterStartupNoLongerCountsAsArmed()
    {
        var folder = Folder("later-loss");
        using var monitor = Monitor(folder);
        monitor.Start();
        Assert.Equal(1, monitor.ArmedDirectoryCount);

        File.Delete(monitor.Canaries[0]); // deleted by the operator, a sync client, or an attack

        Assert.Equal(0, monitor.ArmedDirectoryCount);
        Assert.Equal(ProtectionState.Failed, RansomwareHost.Health(monitor, 0).State);
    }

    private RansomwareMonitor Monitor(params string[] directories) =>
        new(directories, null, Seed, Path.Combine(_root, $"manifest-{Guid.NewGuid():N}.json"));

    private string Folder(string name)
    {
        var path = Path.Combine(_root, name);
        System.IO.Directory.CreateDirectory(path);
        return path;
    }

    private Dictionary<string, byte[]> OccupyDecoyNames(string directory, int count)
    {
        // A previous session's decoys, which the operator has since edited: cleanup preserves them.
        var previous = new CanaryManager(Seed, Path.Combine(_root, $"old-{Guid.NewGuid():N}.json"));
        var planted = previous.Plant([directory]);
        var kept = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in planted.Take(count))
        {
            File.AppendAllText(path, "operator notes");
            kept[path] = File.ReadAllBytes(path);
        }
        previous.Remove();
        return kept;
    }

    public void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A watcher handle can outlive the test by a moment; the temp folder is disposable.
        }
    }
}
