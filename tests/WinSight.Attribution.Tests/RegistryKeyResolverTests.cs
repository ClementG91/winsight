using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The join that makes a live registry write resolvable at all. Its failure mode is silence — an
/// unresolved handle produces no finding and no error — so the cases that must return null are
/// pinned as carefully as the ones that must resolve.
/// </summary>
public sealed class RegistryKeyResolverTests
{
    private const ulong Handle = 0xDEAD_BEEF;
    private const string RunKey = @"\REGISTRY\USER\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void AWriteResolvesToTheKeyTheKernelAnnouncedForItsHandle()
    {
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, RunKey);

        Assert.Equal(RunKey, resolver.Resolve(Handle, relativeName: null));
    }

    [Fact]
    public void ARelativeNameIsAppendedToTheAnnouncedKey()
    {
        // The common shape: the handle names the key, the event names the value written under it.
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, RunKey);

        Assert.Equal($@"{RunKey}\Updater", resolver.Resolve(Handle, "Updater"));
    }

    [Fact]
    public void AnAlreadyAbsoluteNameIsNotAppendedToAnything()
    {
        // Some events carry the whole path. Joining it onto a base would invent a key that does
        // not exist, which is worse than not resolving.
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, @"\REGISTRY\MACHINE\SOFTWARE\Something");

        Assert.Equal(RunKey, resolver.Resolve(Handle, RunKey));
        Assert.Equal(@"HKLM\SOFTWARE\Other", resolver.Resolve(Handle, @"HKLM\SOFTWARE\Other"));
    }

    [Fact]
    public void AnUnannouncedHandleResolvesToNothing()
    {
        // The key was opened before the session started and never reopened. Null is the honest
        // answer; guessing would put a wrong key next to a real process name.
        Assert.Null(new RegistryKeyResolver().Resolve(Handle, "Updater"));
    }

    [Fact]
    public void AClosedHandleIsForgotten()
    {
        // Handles are reused. Keeping a stale mapping would attribute a write to whatever key used
        // to live at that handle.
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, RunKey);

        resolver.Forget(Handle);

        Assert.Null(resolver.Resolve(Handle, "Updater"));
    }

    [Fact]
    public void ReannouncingAHandleReplacesTheOldKey()
    {
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, RunKey);

        resolver.Track(Handle, @"\REGISTRY\MACHINE\SOFTWARE\Reused");

        Assert.Equal(@"\REGISTRY\MACHINE\SOFTWARE\Reused", resolver.Resolve(Handle, relativeName: null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AnAnnouncementWithoutAKeyIsIgnored(string? keyName)
    {
        var resolver = new RegistryKeyResolver();

        resolver.Track(Handle, keyName);

        Assert.Equal(0, resolver.Count);
        Assert.Null(resolver.Resolve(Handle, "Updater"));
    }

    [Fact]
    public void AZeroHandleIsIgnored()
    {
        var resolver = new RegistryKeyResolver();

        resolver.Track(0, RunKey);

        Assert.Equal(0, resolver.Count);
    }

    [Fact]
    public void SeparatorsAreNotDoubledWhenJoining()
    {
        var resolver = new RegistryKeyResolver();
        resolver.Track(Handle, RunKey + @"\");

        Assert.Equal($@"{RunKey}\Updater", resolver.Resolve(Handle, @"\Updater"));
    }

    [Fact]
    public void TheMapStaysBoundedOnABusyMachine()
    {
        // A machine opens and closes keys constantly. An unbounded map would be a slow leak in a
        // process meant to run all day; losing resolution briefly is recoverable, because the
        // kernel re-announces a key the next time it is opened.
        var resolver = new RegistryKeyResolver();

        for (var i = 0UL; i < RegistryKeyResolver.MaxTracked + 100; i++)
        {
            resolver.Track(i + 1, $@"\REGISTRY\MACHINE\SOFTWARE\Key{i}");
        }

        Assert.True(
            resolver.Count <= RegistryKeyResolver.MaxTracked,
            $"Tracked {resolver.Count}, which is past the {RegistryKeyResolver.MaxTracked} ceiling.");
    }
}
