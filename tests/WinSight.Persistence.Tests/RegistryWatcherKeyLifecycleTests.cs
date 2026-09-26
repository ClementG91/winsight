using Microsoft.Win32;

using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// A watched key that does not exist yet, or that is deleted and recreated, is still watched.
/// </summary>
/// <remarks>
/// <b>The blind spot.</b> A key that could not be opened at start was skipped, and a key whose
/// re-arm failed after deletion was dropped while still counted as armed. Several autostart keys are
/// absent on an ordinary machine (<c>Policies\Explorer\Run</c> in both hives, <c>RunServices</c>),
/// so creating one and writing a value into it raised nothing until the dashboard next started; and
/// deleting then recreating the user's Run key blinded the live watch on it for the rest of the
/// session. Driven against real HKCU keys, because the property is about what Windows signals.
/// </remarks>
public sealed class RegistryWatcherKeyLifecycleTests : IDisposable
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(30);
    private readonly string _root = $@"Software\WinSight.Tests\KeyLifecycle\{Guid.NewGuid():N}";

    public RegistryWatcherKeyLifecycleTests() => Registry.CurrentUser.CreateSubKey(_root).Dispose();

    public void Dispose() => Registry.CurrentUser.DeleteSubKeyTree(_root, throwOnMissingSubKey: false);

    [Fact]
    public void AKeyCreatedAfterStartIsWatchedFromItsAncestorAndThenDirectly()
    {
        var target = $@"{_root}\Policies\Explorer\Run";
        var fired = 0;
        using var watcher = Watch(target, () => Interlocked.Increment(ref fired));

        watcher.Start();
        Assert.Equal(1, watcher.ArmedLocations);
        Assert.Equal(1, watcher.AwaitingCreationCount);

        using (var created = Registry.CurrentUser.CreateSubKey(target, writable: true))
        {
            created.SetValue("Payload", @"C:\evil.exe");
        }
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) >= 1, Deadline),
            "creating the watched key and writing a value into it raised nothing");
        Assert.True(SpinWait.SpinUntil(() => watcher.AwaitingCreationCount == 0, Deadline),
            "the watch never moved onto the key once it existed");

        // Now armed on the key itself: a value written later fires on its own.
        var before = Volatile.Read(ref fired);
        SetValue(target, "Second");
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) > before, Deadline),
            "a value written into the created key raised nothing");
        Assert.Equal(1, watcher.ArmedLocations);
    }

    [Fact]
    public void AKeyDeletedAndRecreatedIsStillWatched()
    {
        var target = $@"{_root}\Run";
        Registry.CurrentUser.CreateSubKey(target).Dispose();
        var fired = 0;
        using var watcher = Watch(target, () => Interlocked.Increment(ref fired));

        watcher.Start();
        Assert.Equal(0, watcher.AwaitingCreationCount);

        Registry.CurrentUser.DeleteSubKeyTree(target);
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) >= 1, Deadline),
            "deleting the watched key raised nothing");
        Assert.True(SpinWait.SpinUntil(() => watcher.AwaitingCreationCount == 1, Deadline),
            "a deleted key was not watched for its re-creation");
        Assert.Equal(1, watcher.ArmedLocations);

        var before = Volatile.Read(ref fired);
        using (var recreated = Registry.CurrentUser.CreateSubKey(target, writable: true))
        {
            recreated.SetValue("Payload", @"C:\evil.exe");
        }
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) > before, Deadline),
            "re-creating the watched key raised nothing");
        Assert.True(SpinWait.SpinUntil(() => watcher.AwaitingCreationCount == 0, Deadline));

        before = Volatile.Read(ref fired);
        SetValue(target, "Second");
        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref fired) > before, Deadline),
            "a value written into the re-created key raised nothing");
    }

    [Fact]
    public void AnUnrelatedSiblingUnderTheAncestorIsNotReportedAsAChange()
    {
        var target = $@"{_root}\Absent";
        var fired = 0;
        using var watcher = Watch(target, () => Interlocked.Increment(ref fired));
        watcher.Start();
        Assert.Equal(1, watcher.AwaitingCreationCount);

        Registry.CurrentUser.CreateSubKey($@"{_root}\Sibling").Dispose();

        // Give the watch time to wake and re-arm; it must not report the target as changed.
        Thread.Sleep(500);
        Assert.Equal(0, Volatile.Read(ref fired));
        Assert.Equal(1, watcher.AwaitingCreationCount);
    }

    [Fact]
    public void AnInitiallyUnarmedTargetIsRetriedAndReconciledWhenItBecomesAvailable()
    {
        // A single-component target has no subkey ancestor to watch. This deterministically models
        // an initially unavailable target without changing ACLs on a shared key.
        var target = $"WinSight.Tests.Recovery.{Guid.NewGuid():N}";
        var fired = 0;
        using var watcher = new RegistryChangeWatcher(
            [PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, target)],
            recoveryInterval: TimeSpan.FromHours(1));
        watcher.SurfaceChanged += (_, _) => Interlocked.Increment(ref fired);
        try
        {
            watcher.Start();
            Assert.Equal(0, watcher.ArmedLocations);
            Assert.Equal(SensorLifecycle.Failed, watcher.SensorHealth.Lifecycle);

            Registry.CurrentUser.CreateSubKey(target).Dispose();
            watcher.RetryUnarmed();

            Assert.Equal(1, watcher.ArmedLocations);
            Assert.Equal(1, Volatile.Read(ref fired));
            Assert.Equal(SensorLifecycle.Running, watcher.SensorHealth.Lifecycle);
            Assert.Equal(1, watcher.SensorHealth.RecoveryAttempts);
            Assert.Equal(1, watcher.SensorHealth.SuccessfulRecoveries);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(target, throwOnMissingSubKey: false);
        }
    }

    [Theory]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    public void OnlyAConfirmedMissingComponentMayRemainCoveredByItsAncestor(
        bool nextExists, bool accessDenied, bool expected)
    {
        Assert.Equal(expected, RegistryChangeWatcher.MayRemainOnAncestor(nextExists, accessDenied));
    }

    private static RegistryChangeWatcher Watch(string path, Action onChange)
    {
        var watcher = new RegistryChangeWatcher(
            [PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, path)]);
        watcher.SurfaceChanged += (_, _) => onChange();
        return watcher;
    }

    private static void SetValue(string path, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path, writable: true)!;
        key.SetValue(name, "1");
    }
}
