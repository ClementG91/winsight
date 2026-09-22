using Microsoft.Win32;

using WinSight.Core;

using Xunit;

namespace WinSight.Core.Tests;

/// <summary>The generic registry-change watcher against an isolated HKCU test key, unelevated.</summary>
public sealed class RegistryKeyWatcherRealTests
{
    [Fact]
    public void ItFiresWhenTheWatchedSubtreeChanges()
    {
        var sub = $@"Software\WinSight.Tests\KeyWatch\{Guid.NewGuid():N}";
        Registry.CurrentUser.CreateSubKey(sub).Dispose();
        try
        {
            using var watcher = new RegistryKeyWatcher(RegistryHive.CurrentUser, sub);
            using var fired = new ManualResetEventSlim(false);
            watcher.Changed += fired.Set;

            Assert.True(watcher.Start());

            var deadline = DateTime.UtcNow.AddSeconds(6);
            var i = 0;
            while (!fired.IsSet && DateTime.UtcNow < deadline)
            {
                using (var key = Registry.CurrentUser.OpenSubKey(sub, writable: true))
                {
                    key!.SetValue("v", i++, RegistryValueKind.DWord);
                }
                fired.Wait(400);
            }

            Assert.True(fired.IsSet, "the watcher did not fire on a change to the watched key");
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        }
    }

    /// <summary>
    /// A caller that polls rarely because the watch is armed must be able to tell when it no
    /// longer is. Deleting the watched key ends the watch: the pending notification fires, re-arming
    /// on the deleted key fails, and the loop stops - silently, before this was observable.
    /// </summary>
    [Fact]
    public void IsWatchingFollowsTheWatchFromArmedToStopped()
    {
        var sub = $@"Software\WinSight.Tests\KeyWatch\{Guid.NewGuid():N}";
        Registry.CurrentUser.CreateSubKey(sub).Dispose();
        try
        {
            var watcher = new RegistryKeyWatcher(RegistryHive.CurrentUser, sub);
            Assert.False(watcher.IsWatching);

            Assert.True(watcher.Start());
            Assert.True(SpinWait.SpinUntil(() => watcher.IsWatching, TimeSpan.FromSeconds(5)), "never armed");

            Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
            Assert.True(
                SpinWait.SpinUntil(() => !watcher.IsWatching, TimeSpan.FromSeconds(10)),
                "the watch of a deleted key still claims to be armed");

            watcher.Dispose();
            Assert.False(watcher.IsWatching);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void IsWatchingIsFalseAfterDisposal()
    {
        var sub = $@"Software\WinSight.Tests\KeyWatch\{Guid.NewGuid():N}";
        Registry.CurrentUser.CreateSubKey(sub).Dispose();
        try
        {
            var watcher = new RegistryKeyWatcher(RegistryHive.CurrentUser, sub);
            Assert.True(watcher.Start());
            Assert.True(SpinWait.SpinUntil(() => watcher.IsWatching, TimeSpan.FromSeconds(5)), "never armed");

            watcher.Dispose();

            Assert.False(watcher.IsWatching);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void StartReturnsFalseForAMissingKey()
    {
        using var watcher = new RegistryKeyWatcher(
            RegistryHive.CurrentUser, $@"Software\WinSight.Tests\Missing\{Guid.NewGuid():N}");

        Assert.False(watcher.Start());
    }

    [Fact]
    public void AThrowingSubscriberDoesNotBlindTheWatch()
    {
        var sub = $@"Software\WinSight.Tests\KeyWatch\{Guid.NewGuid():N}";
        Registry.CurrentUser.CreateSubKey(sub).Dispose();
        try
        {
            using var watcher = new RegistryKeyWatcher(RegistryHive.CurrentUser, sub);
            using var recovered = new ManualResetEventSlim(false);
            var throwPending = 1;
            watcher.Changed += () =>
            {
                if (Interlocked.Exchange(ref throwPending, 0) == 1)
                {
                    throw new InvalidOperationException("faulting subscriber");
                }
                recovered.Set();
            };

            Assert.True(watcher.Start());

            // Keep changing the key: the first notification throws (and must be contained), a later
            // one must still be delivered - proof the watch thread survived the fault.
            var deadline = DateTime.UtcNow.AddSeconds(8);
            var i = 0;
            while (!recovered.IsSet && DateTime.UtcNow < deadline)
            {
                using (var key = Registry.CurrentUser.OpenSubKey(sub, writable: true))
                {
                    key!.SetValue("v", i++, RegistryValueKind.DWord);
                }
                recovered.Wait(400);
            }

            Assert.True(recovered.IsSet, "the watch stopped after a subscriber threw");
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
        }
    }
}
