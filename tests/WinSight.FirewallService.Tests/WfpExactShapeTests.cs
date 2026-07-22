using WinSight.Firewall;
using WinSight.FirewallService;

using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The predicate that decides whether the kernel's filter state matches what WinSight asked for.
/// </summary>
/// <remarks>
/// <b>Why this is the most consequential pure function in the privileged service.</b> Everything the
/// firewall claims rests on it: <c>VerifyExact</c> calls it to decide whether enforcement reads as
/// <i>Active</i> or collapses to <i>Degraded</i>, and a Degraded verdict triggers a rollback that
/// removes every block on the machine. Too strict and working protection is torn down — which has
/// already happened once here, when the check required <c>Flags == 0</c> and every real block reads
/// back with the INDEXED flag WFP sets itself. Too loose and a filter somebody else installed, or one
/// WinSight left behind in the wrong shape, is accepted as proof that the machine is protected.
///
/// <b>What this replaces.</b> The predicate was private, so it was guarded by asserting that its
/// source text contained twelve expected substrings. That guard is honest about being a proxy, and it
/// is a weak one: it cannot see a clause combined with the wrong operator, a clause that short-
/// circuits before it is ever evaluated, or a filter whose condition count says one while its
/// condition is null. Every clause below is now falsified independently against real behaviour.
/// </remarks>
public sealed class WfpExactShapeTests
{
    private static readonly Guid LayerKey = new("b5b23f2c-0e1f-4a0c-9b1a-000000000001");
    private static readonly byte[] AppId = [1, 2, 3, 4];

    /// <summary>A filter in exactly the shape WinSight creates. Every test below mutates one field.</summary>
    private static WfpProvisioning.OwnedFilter Valid() => new(
        FilterKey: Guid.NewGuid(),
        ProviderKey: WfpProvisioning.ProviderKey,
        LayerKey: LayerKey,
        SubLayerKey: WfpProvisioning.SublayerKey,
        Flags: 0,
        ActionType: WfpProvisioning.FwpActionBlock,
        ConditionCount: 1,
        Condition: new WfpProvisioning.FilterCondition(
            WfpProvisioning.AleAppIdCondition,
            WfpProvisioning.FwpMatchEqual,
            WfpProvisioning.FwpByteBlobType,
            [1, 2, 3, 4]));

    private static WfpProvisioning.ExpectedFilter Expected() => new(LayerKey, AppId);

    /// <summary>
    /// The baseline must pass, or every negative case below proves nothing.
    /// </summary>
    [Fact]
    public void AFilterInTheShapeWinSightCreatesIsAccepted()
        => Assert.True(WfpProvisioning.FilterHasExactShape(Valid(), Expected()));

    /// <summary>
    /// The regression that tore down working protection on a live machine.
    /// </summary>
    /// <remarks>
    /// WFP sets FWPM_FILTER_FLAG_INDEXED (0x40) on any app-id filter itself, so a correctly applied
    /// block always reads back with it. Requiring <c>Flags == 0</c> rejected every genuine block and
    /// turned live enforcement into a false "degraded" — with the rollback that follows.
    /// </remarks>
    [Fact]
    public void TheIndexFlagWfpSetsItselfIsAccepted()
        => Assert.True(WfpProvisioning.FilterHasExactShape(
            Valid() with { Flags = 0x00000040 }, Expected()));

    [Theory]
    // PERSISTENT, BOOTTIME, DISABLED: WinSight never creates such a filter, so one carrying them is
    // not ours to vouch for however else it matches.
    [InlineData(0x00000001u)]
    [InlineData(0x00000002u)]
    [InlineData(0x00000008u)]
    [InlineData(0x00000041u)]
    public void AnyFlagWinSightNeverSetsIsRejected(uint flags)
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Flags = flags }, Expected()));

    // ---- Ownership: a filter that is not ours proves nothing about our protection ---------------

    [Fact]
    public void AFilterFromAnotherProviderIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { ProviderKey = Guid.NewGuid() }, Expected()));

    [Fact]
    public void AFilterWithNoProviderAtAllIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { ProviderKey = null }, Expected()));

    [Fact]
    public void AFilterInAnotherSublayerIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { SubLayerKey = Guid.NewGuid() }, Expected()));

    [Fact]
    public void AFilterOnTheWrongLayerIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { LayerKey = Guid.NewGuid() }, Expected()));

    // ---- Effect: a filter that does not block is not a block -----------------------------------

    [Fact]
    public void AFilterThatPermitsRatherThanBlocksIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { ActionType = 0x00001002 }, Expected()));

    // ---- Scope: the condition is what confines a block to one application ----------------------

    [Theory]
    [InlineData(0u)]
    [InlineData(2u)]
    public void AFilterWithAnythingOtherThanExactlyOneConditionIsRejected(uint count)
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { ConditionCount = count }, Expected()));

    /// <summary>
    /// A count of one with no condition behind it is the dangerous shape: unconditioned, it would
    /// block every program on the machine.
    /// </summary>
    [Fact]
    public void AFilterClaimingOneConditionButCarryingNoneIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = null }, Expected()));

    [Fact]
    public void AConditionOnAFieldOtherThanTheApplicationIdIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { FieldKey = Guid.NewGuid() } },
            Expected()));

    [Fact]
    public void AConditionThatDoesNotMatchOnEqualityIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { MatchType = 1 } }, Expected()));

    [Fact]
    public void AConditionOfTheWrongValueTypeIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { Type = 1 } }, Expected()));

    // ---- Identity: which application this block actually confines -------------------------------

    [Fact]
    public void AConditionWithNoValueIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { Value = null } }, Expected()));

    [Fact]
    public void AConditionNamingADifferentApplicationIsRejected()
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { Value = [9, 9, 9, 9] } },
            Expected()));

    /// <summary>
    /// A prefix of the expected application id is a different application.
    /// </summary>
    /// <remarks>
    /// Comparing lengths matters: an app-id blob is a device path, and one that is a truncation of
    /// another would confine the block to the wrong program while comparing equal byte for byte over
    /// its own length.
    /// </remarks>
    [Theory]
    [InlineData(new byte[] { 1, 2, 3 })]
    [InlineData(new byte[] { 1, 2, 3, 4, 5 })]
    [InlineData(new byte[0])]
    public void AConditionValueOfADifferentLengthIsRejected(byte[] value)
        => Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { Condition = Valid().Condition! with { Value = value } }, Expected()));

    /// <summary>
    /// The predicate must not be uniformly permissive.
    /// </summary>
    /// <remarks>
    /// Without this, a body that returned <c>true</c> unconditionally would pass both positive tests
    /// above while every negative one failed — but a body that returned <c>false</c> unconditionally
    /// would pass all fifteen negatives. Asserting both directions in one place makes that
    /// impossible to fake.
    /// </remarks>
    [Fact]
    public void ThePredicateDiscriminatesInBothDirections()
    {
        Assert.True(WfpProvisioning.FilterHasExactShape(Valid(), Expected()));
        Assert.False(WfpProvisioning.FilterHasExactShape(
            Valid() with { ActionType = 0x00001002 }, Expected()));
    }
}

/// <summary>
/// Which stored policies become kernel filters, and which are deliberately not.
/// </summary>
/// <remarks>
/// The translation from operator intent to WFP state. A policy silently dropped here is a block the
/// operator asked for and never got, reported as applied — and a duplicate that slipped through
/// would derive the same filter key twice, so the second apply would overwrite the first and one of
/// the two apps would go unfiltered while both read as blocked.
/// </remarks>
public sealed class WfpDesiredBlocksTests
{
    private static AppFirewallPolicy Policy(
        string path, OutboundAction action = OutboundAction.Block, bool enabled = true) =>
        new(path, action, enabled);

    [Fact]
    public void OnlyEnabledBlocksBecomeFilters()
    {
        var blocks = WfpProvisioning.DesiredBlocks(
        [
            Policy(@"C:\apps\blocked.exe"),
            Policy(@"C:\apps\allowed.exe", OutboundAction.Allow),
            Policy(@"C:\apps\asked.exe", OutboundAction.Ask),
            Policy(@"C:\apps\disabled.exe", enabled: false),
        ]);

        Assert.Equal([@"C:\apps\blocked.exe"], blocks.Select(block => block.Path));
    }

    [Fact]
    public void PathsAreCanonicalisedSoOneAppNeverGetsTwoFilters()
    {
        var blocks = WfpProvisioning.DesiredBlocks([Policy(@"C:\apps\..\apps\blocked.exe")]);

        var block = Assert.Single(blocks);
        Assert.Equal(@"C:\apps\blocked.exe", block.Path);
        Assert.Equal(WfpProvisioning.BlockFilterKeys(@"C:\apps\blocked.exe").V4, block.KeyV4);
        Assert.Equal(WfpProvisioning.BlockFilterKeys(@"C:\apps\blocked.exe").V6, block.KeyV6);
    }

    /// <summary>
    /// Two spellings of one path are refused outright rather than silently collapsed.
    /// </summary>
    /// <remarks>
    /// They derive the same filter key, so applying both would have the second overwrite the first.
    /// Refusing is right: a policy set that says the same thing twice is a store WinSight should not
    /// be quietly reinterpreting, and the transition fails closed instead.
    /// </remarks>
    [Theory]
    [InlineData(@"C:\apps\a.exe", @"c:\APPS\A.EXE")]
    [InlineData(@"C:\apps\a.exe", @"C:\apps\.\a.exe")]
    [InlineData(@"C:\apps\a.exe", @"C:\apps\b\..\a.exe")]
    public void ADuplicatePathIsRefusedRatherThanAppliedTwice(string first, string second)
        => Assert.Throws<InvalidDataException>(
            () => WfpProvisioning.DesiredBlocks([Policy(first), Policy(second)]));

    [Fact]
    public void TwoDifferentAppsGetTwoDistinctFilterKeys()
    {
        var blocks = WfpProvisioning.DesiredBlocks(
            [Policy(@"C:\apps\a.exe"), Policy(@"C:\apps\b.exe")]);

        Assert.Equal(2, blocks.Count);
        Assert.NotEqual(blocks[0].KeyV4, blocks[1].KeyV4);
        Assert.NotEqual(blocks[0].KeyV6, blocks[1].KeyV6);
        // The two layers must never share a key either, or removing one would remove both.
        Assert.NotEqual(blocks[0].KeyV4, blocks[0].KeyV6);
    }

    [Fact]
    public void AnEmptyPolicySetProducesNoFilters()
        => Assert.Empty(WfpProvisioning.DesiredBlocks([]));
}
