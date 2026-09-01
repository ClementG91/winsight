using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// A drive letter that belongs to a logon session cannot become a filter.
/// </summary>
/// <remarks>
/// <b>The silent mismatch.</b> The service resolves a drive letter in session 0, where the user's
/// own mappings do not exist. A policy on a SUBST or a mapped network drive therefore produced an
/// application identity that corresponds to nothing - and because the verification applies the same
/// derivation, it agreed with itself: the state declared exact while the filter matched nothing.
/// The operator is told the application is blocked and it is not.
///
/// Refusing is the only honest answer. An identity that cannot be established must not become a
/// filter that claims to block something.
/// </remarks>
public sealed class SessionLocalDriveTests
{
    private static Func<string, string?> Resolves(string device) => _ => device;

    [Fact]
    public void ALocalVolumeStillDerives()
    {
        var derived = WfpApplicationId.TryDerive(
            @"C:\apps\a.exe", Resolves(@"\Device\HarddiskVolume3"), out var appId);

        Assert.True(derived);
        Assert.NotEmpty(appId);
    }

    /// <summary>
    /// A mapped network drive reaches the redirector, not a volume. Whatever the service sees in
    /// session 0, it is not the file the operator meant.
    /// </summary>
    [Theory]
    [InlineData(@"\Device\LanmanRedirector\;Z:0000000000012345\server\share")]
    [InlineData(@"\Device\Mup\server\share")]
    public void AMappedNetworkDriveIsRefused(string device) =>
        Assert.False(WfpApplicationId.TryDerive(@"Z:\apps\a.exe", Resolves(device), out _));

    /// <summary>
    /// A SUBST target resolves to an object-manager path rather than a device, and the mapping
    /// belongs to the session that created it.
    /// </summary>
    [Fact]
    public void ASubstDriveIsRefused() =>
        Assert.False(WfpApplicationId.TryDerive(
            @"S:\apps\a.exe", Resolves(@"\??\C:\some\folder"), out _));

    /// <summary>
    /// A refusal produces no app id at all, so nothing downstream can install a filter from a
    /// partially-derived identity.
    /// </summary>
    [Fact]
    public void ARefusalYieldsNoIdentity()
    {
        WfpApplicationId.TryDerive(@"Z:\apps\a.exe", Resolves(@"\Device\Mup\server\share"), out var appId);

        Assert.Empty(appId);
    }
}
