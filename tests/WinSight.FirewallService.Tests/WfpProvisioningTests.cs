using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class WfpProvisioningTests
{
    [Fact]
    public void ProductionSession_IsDynamicWithABoundedTransactionWait()
    {
        Assert.Equal(0x00000001u, WfpProvisioning.ProductionSessionFlags);
        Assert.InRange(WfpProvisioning.ProductionTransactionWaitMilliseconds, 1u, 30_000u);
    }

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

    [Fact]
    public void InterpretLookupResult_OnlyTreatsTheExpectedNotFoundCodeAsAbsent()
    {
        const uint expectedNotFound = 0x80320003;

        Assert.True(WfpProvisioning.InterpretLookupResult(0, expectedNotFound));
        Assert.False(WfpProvisioning.InterpretLookupResult(expectedNotFound, expectedNotFound));
        var error = Assert.Throws<Win32Exception>(
            () => WfpProvisioning.InterpretLookupResult(5, expectedNotFound));
        Assert.Equal(5, error.NativeErrorCode);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, true, true)]
    public void RequireConsistentIpPair_ReturnsTheSharedState(
        bool ipv4, bool ipv6, bool expected) =>
        Assert.Equal(
            expected,
            WfpProvisioning.RequireConsistentIpPair(ipv4, ipv6, "test object"));

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void RequireConsistentIpPair_RejectsPartialState(bool ipv4, bool ipv6) =>
        Assert.Throws<InvalidDataException>(
            () => WfpProvisioning.RequireConsistentIpPair(ipv4, ipv6, "test object"));
}
