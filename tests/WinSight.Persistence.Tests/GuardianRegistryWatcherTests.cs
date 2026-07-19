using Microsoft.Win32;

using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class WatchTargetContractTests
{
    [Fact]
    public void RunKeyEnumerator_WatchesRunKeysAcrossHivesAndViews()
    {
        var targets = new RunKeyEnumerator().WatchTargets;

        Assert.NotEmpty(targets);
        Assert.All(targets, t => Assert.Equal(PersistenceWatchKind.Registry, t.Kind));
        Assert.Contains(targets, t =>
            t.Hive == RegistryHive.CurrentUser &&
            t.Path.EndsWith(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(targets, t => t.Hive == RegistryHive.LocalMachine);
        Assert.Contains(targets, t => t.View == RegistryView.Registry32);
    }

    [Fact]
    public void ServiceEnumerator_WatchesServicesSubtree()
    {
        var target = Assert.Single(new ServiceEnumerator().WatchTargets);

        Assert.True(target.Recursive);
        Assert.EndsWith("Services", target.Path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WinlogonEnumerator_WatchesBothHives()
    {
        var targets = new WinlogonEnumerator().WatchTargets;

        Assert.Contains(targets, t => t.Hive == RegistryHive.LocalMachine);
        Assert.Contains(targets, t => t.Hive == RegistryHive.CurrentUser);
    }

    [Fact]
    public void UnwatchedSurface_DefaultsToEmpty_NotNull()
    {
        // A surface with no registry/file backing (WMI) has not opted into live watching; it is
        // still covered by the on-start reconciliation diff.
        IAutostartEnumerator unwatched = new WmiSubscriptionEnumerator();
        Assert.Empty(unwatched.WatchTargets);
    }
}

public sealed class RegistryChangeWatcherTests
{
    [Fact]
    public void RegistryTargets_DropsFilesystemTargets_AndDeduplicates()
    {
        var targets = new[]
        {
            PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, @"Software\A"),
            PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, @"software\a"),
            PersistenceWatchTarget.FileSystem(@"C:\Startup"),
        };

        var filtered = RegistryChangeWatcher.RegistryTargets(targets);

        Assert.Single(filtered);
        Assert.Equal(PersistenceWatchKind.Registry, filtered[0].Kind);
    }

    [Fact]
    public void EmptyTargets_StartAndDispose_AreNoOps()
    {
        using var watcher = new RegistryChangeWatcher(Array.Empty<PersistenceWatchTarget>());
        watcher.Start();
        watcher.Start(); // idempotent

        Assert.Equal(0, watcher.ArmedKeyCount);
    }

    [Fact]
    public void FromEnumerators_ArmsTheDefaultAutostartKeys_UnderTheWaitAnyCap()
    {
        using var watcher = RegistryChangeWatcher.FromEnumerators(
            new IAutostartEnumerator[] { new RunKeyEnumerator(), new WinlogonEnumerator() });
        watcher.Start();

        Assert.InRange(watcher.ArmedKeyCount, 1, 63);
    }

    [Fact]
    public void DefaultEnumerators_ExposeLiveCoverageForHighValueRegistrySurfaces()
    {
        var byType = PersistenceScanner.DefaultEnumerators().ToDictionary(e => e.GetType());

        void HasRegistryTarget<T>() where T : IAutostartEnumerator =>
            Assert.Contains(byType[typeof(T)].WatchTargets, t => t.Kind == PersistenceWatchKind.Registry);

        HasRegistryTarget<ImageHijackEnumerator>();
        HasRegistryTarget<AppInitDllsEnumerator>();
        HasRegistryTarget<ActiveSetupEnumerator>();
        HasRegistryTarget<SilentProcessExitEnumerator>();
        HasRegistryTarget<LsaPackagesEnumerator>();
        HasRegistryTarget<CredentialProviderEnumerator>();
        HasRegistryTarget<BrowserHelperObjectEnumerator>();
        HasRegistryTarget<WindowsLoadRunEnumerator>();
    }

    [Fact]
    public void FromEnumerators_AllDefaultSurfaces_ArmWithoutExceedingTheCap()
    {
        // Arming the whole default set opens dozens of real HKLM keys; it must stay within the
        // WaitAny cap and never throw, whatever this machine allows the current user to watch.
        using var watcher = RegistryChangeWatcher.FromEnumerators(PersistenceScanner.DefaultEnumerators());
        watcher.Start();

        Assert.InRange(watcher.ArmedKeyCount, 1, 63);
    }

    [Fact]
    public void ChangingAWatchedKey_RaisesSurfaceChanged()
    {
        // A real end-to-end check of RegNotifyChangeKeyValue against a private HKCU key. HKCU is
        // writable by the running user, so this runs on any Windows (dev + CI), not only a VM.
        var subPath = $@"Software\WinSightGuardianTest-{Guid.NewGuid():N}";
        using var created = Registry.CurrentUser.CreateSubKey(subPath, writable: true);

        var fired = new ManualResetEventSlim(false);
        using var watcher = new RegistryChangeWatcher(new[]
        {
            PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, subPath),
        });
        watcher.SurfaceChanged += (_, _) => fired.Set();

        try
        {
            watcher.Start();
            Assert.Equal(1, watcher.ArmedKeyCount);

            created!.SetValue("Payload", @"C:\evil.exe");

            Assert.True(fired.Wait(TimeSpan.FromSeconds(5)),
                "RegNotifyChangeKeyValue did not signal within 5s of a value write.");
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(subPath, throwOnMissingSubKey: false);
        }
    }
}
