using Microsoft.Win32;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Real registry notifications on a temporary HKCU test key. The watcher's wait loop owns a dedicated
/// thread, where an escaping subscriber exception terminated the process (reproduced before the fix).
/// </summary>
public sealed class RegistryWatcherFailureTests : IDisposable
{
    private readonly string _path = $@"Software\WinSight.Tests\RegistryWatcherFailure\{Guid.NewGuid():N}";

    public RegistryWatcherFailureTests() => Registry.CurrentUser.CreateSubKey(_path).Dispose();

    public void Dispose() => Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);

    [Fact]
    public void ASubscriberFaultIsCountedAndTheWatchKeepsSignalling()
    {
        var calls = 0;
        using var second = new ManualResetEventSlim();
        using var watcher = new RegistryChangeWatcher(
            [PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, _path, watchSubtree: false)]);
        watcher.SurfaceChanged += (_, _) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                throw new InvalidOperationException("subscriber fault");
            }
            second.Set();
        };
        watcher.Start();
        Assert.Equal(1, watcher.ArmedKeyCount);

        SetValue("first");
        Assert.True(SpinWait.SpinUntil(() => calls >= 1, TimeSpan.FromSeconds(30)));
        SetValue("second");

        Assert.True(second.Wait(TimeSpan.FromSeconds(30)), "the registry watch stopped after a subscriber fault");
        Assert.Equal(1, watcher.NotificationFailures);
    }

    [Fact]
    public void AFileSystemSubscriberFaultIsCountedAndDoesNotEndTheProcess()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-fswatch-fault-").FullName;
        try
        {
            var calls = 0;
            using var second = new ManualResetEventSlim();
            using var watcher = new FileSystemPersistenceWatcher([PersistenceWatchTarget.FileSystem(directory)]);
            watcher.SurfaceChanged += (_, _) =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    throw new InvalidOperationException("subscriber fault");
                }
                second.Set();
            };
            watcher.Start();

            File.WriteAllText(Path.Combine(directory, "first.lnk"), "x");
            Assert.True(SpinWait.SpinUntil(() => calls >= 1, TimeSpan.FromSeconds(30)));
            File.WriteAllText(Path.Combine(directory, "second.lnk"), "y");

            Assert.True(second.Wait(TimeSpan.FromSeconds(30)));
            Assert.True(watcher.NotificationFailures >= 1);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private void SetValue(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_path, writable: true)!;
        key.SetValue(name, "1");
    }
}
