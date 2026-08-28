using WinSight.Attribution;
using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The control-set fold, without which no service and no driver installation was ever attributable.
/// </summary>
/// <remarks>
/// <c>ServiceEnumerator</c> emits <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;name&gt;</c>; the
/// kernel reports <c>\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\&lt;name&gt;</c>. The matcher
/// requires the observed key to be a prefix of the reported one, and those two strings diverge at
/// the eighth character - so two of the most interesting targets of the whole feature were silently
/// out of reach while every part of the plumbing appeared to work.
/// </remarks>
public sealed class ControlSetNormalizationTests
{
    private static KernelPathNormalizer Normalizer(int? currentControlSet = 1) =>
        new(deviceToDrive: null, currentUserSid: null, currentControlSet: currentControlSet);

    [Fact]
    public void TheActiveControlSetIsFoldedIntoCurrentControlSet() =>
        Assert.Equal(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Foo",
            Normalizer().NormalizeRegistryKey(@"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Foo"));

    [Fact]
    public void ADoubleDigitControlSetIsFoldedToo() =>
        Assert.Equal(
            @"HKLM\SYSTEM\CurrentControlSet\Services\Foo",
            Normalizer(12).NormalizeRegistryKey(@"\REGISTRY\MACHINE\SYSTEM\ControlSet012\Services\Foo"));

    /// <summary>
    /// A write to a control set that is not the running one is a different key with different
    /// consequences. Naming a program the author of a change it did not make to the live
    /// configuration is exactly the wrong kind of confident.
    /// </summary>
    [Fact]
    public void AnInactiveControlSetIsLeftAlone() =>
        Assert.Equal(
            @"HKLM\SYSTEM\ControlSet002\Services\Foo",
            Normalizer(1).NormalizeRegistryKey(@"\REGISTRY\MACHINE\SYSTEM\ControlSet002\Services\Foo"));

    /// <summary>
    /// When the active set is unknown, nothing is folded: the write stays unattributed, which is the
    /// same answer as before and is honest rather than merely unhelpful.
    /// </summary>
    [Fact]
    public void AnUnknownControlSetFoldsNothing() =>
        Assert.Equal(
            @"HKLM\SYSTEM\ControlSet001\Services\Foo",
            Normalizer(null).NormalizeRegistryKey(@"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Foo"));

    /// <summary>Only the control-set component is rewritten; nothing else about the key changes.</summary>
    [Theory]
    [InlineData(@"\REGISTRY\MACHINE\SOFTWARE\ControlSet001\X", @"HKLM\SOFTWARE\ControlSet001\X")]
    [InlineData(@"\REGISTRY\MACHINE\SYSTEM\ControlSetXXX\Services", @"HKLM\SYSTEM\ControlSetXXX\Services")]
    [InlineData(@"\REGISTRY\MACHINE\SYSTEM\Setup", @"HKLM\SYSTEM\Setup")]
    [InlineData(@"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\X", @"HKLM\SOFTWARE\WOW6432Node\X")]
    public void NothingElseIsRewritten(string kernel, string expected) =>
        Assert.Equal(expected, Normalizer().NormalizeRegistryKey(kernel));

    /// <summary>The bare control set with no trailing key is still the same key.</summary>
    [Fact]
    public void TheControlSetRootAloneIsFolded() =>
        Assert.Equal(
            @"HKLM\SYSTEM\CurrentControlSet",
            Normalizer().NormalizeRegistryKey(@"\REGISTRY\MACHINE\SYSTEM\ControlSet001"));
}
