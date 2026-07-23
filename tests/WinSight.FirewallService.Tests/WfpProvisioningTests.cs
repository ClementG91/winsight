using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class WfpProvisioningTests
{
    [Fact]
    public void WfpObjectKeys_AreStableAndDistinct()
    {
        var keys = new[]
        {
            WfpProvisioning.ProviderKey, WfpProvisioning.SublayerKey,
            WfpProvisioning.PermitFilterKeyV4, WfpProvisioning.PermitFilterKeyV6,
        };
        Assert.DoesNotContain(Guid.Empty, keys);
        Assert.Equal(keys.Length, keys.Distinct().Count());
    }

    [Fact]
    public void BlockFilterKeys_AreStablePerPath_DistinctPerLayer_AndDifferBetweenApps()
    {
        var a1 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var a2 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var b = WfpProvisioning.BlockFilterKeys(@"C:\apps\b.exe");

        Assert.Equal(a1, a2);                    // stable across calls
        Assert.NotEqual(a1.V4, a1.V6);           // IPv4 and IPv6 keys differ
        Assert.NotEqual(a1.V4, b.V4);            // different apps get different keys
        Assert.NotEqual(Guid.Empty, a1.V4);
    }

    [Fact]
    public void BlockFilterKeys_AreCaseInsensitiveOnPath()
    {
        Assert.Equal(
            WfpProvisioning.BlockFilterKeys(@"C:\Apps\A.exe"),
            WfpProvisioning.BlockFilterKeys(@"c:\apps\a.exe"));
    }

    [Fact]
    public void BlockFilterKeys_CanonicalizeQuotedAndRelativeSegments_SameAsClean()
    {
        // Quoted and dot-segmented forms must derive the same key as the clean canonical
        // path, or a block installed via one form is orphaned when re-applied via another.
        var clean = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys("\"C:\\apps\\a.exe\""));
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys(@"C:\apps\.\a.exe"));
    }

    [Fact]
    public void BlockFilterKeys_RejectsRelativePath() =>
        Assert.Throws<ArgumentException>(() => WfpProvisioning.BlockFilterKeys(@"a.exe"));
}
