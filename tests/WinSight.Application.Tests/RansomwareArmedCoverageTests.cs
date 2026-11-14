using System.Security.AccessControl;
using System.Security.Principal;
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
    private readonly string _root = Directory.CreateTempSubdirectory("wsg-armed-private-").FullName;

    public RansomwareArmedCoverageTests()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User ?? throw new InvalidOperationException("No token SID.");
            var actualOwner = new DirectoryInfo(_root).GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier));
            Assert.Contains(actualOwner, new[] { user,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) });
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }.Distinct())
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }
            new DirectoryInfo(_root).SetAccessControl(security);
            var applied = new DirectoryInfo(_root).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.True(applied.AreAccessRulesProtected);
            Assert.Equal(actualOwner, applied.GetOwner(typeof(SecurityIdentifier)));
            Assert.All(applied.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule =>
            {
                Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
                Assert.Contains(rule.IdentityReference, new[] { user,
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) });
                Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            });
            Directory.CreateDirectory(Path.Combine(_root, "state"));
        }
        catch (Exception primary)
        {
            try { Directory.Delete(_root, true); }
            catch (Exception cleanup) { throw new AggregateException("Private fixture setup and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

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
        new(directories, null, Seed, Path.Combine(_root, "state", $"manifest-{Guid.NewGuid():N}.json"));

    private string Folder(string name)
    {
        var path = Path.Combine(_root, name);
        System.IO.Directory.CreateDirectory(path);
        return path;
    }

    private Dictionary<string, byte[]> OccupyDecoyNames(string directory, int count)
    {
        // A previous session's decoys, which the operator has since edited: cleanup preserves them.
        var previous = new CanaryManager(Seed, Path.Combine(_root, "state", $"old-{Guid.NewGuid():N}.json"));
        try
        {
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
        finally { previous.EndSessionWithoutCleanup(); }
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);
}
