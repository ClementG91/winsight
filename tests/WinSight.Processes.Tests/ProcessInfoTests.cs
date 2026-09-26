using WinSight.Core;

using Xunit;

namespace WinSight.Processes.Tests;

/// <summary>
/// The rule that decides whether a running process is worth an operator's attention.
/// </summary>
/// <remarks>
/// <see cref="ProcessInfo.Unsigned"/> is the only judgement this module makes, and it had no test
/// of its own — the existing coverage exercised the WMI snapshot and asserted shape, never the
/// verdict. The rule matters in both directions: missing a genuinely unsigned process defeats the
/// feature, and flagging a protected process whose image simply cannot be read would put a red mark
/// on something innocent, which is the failure this project treats as the worse one.
/// </remarks>
public sealed class ProcessInfoTests
{
    private static ProcessInfo Process(string? path, SignatureState state) =>
        new(1234, "thing.exe", path, 4, "thing.exe --run", new SignatureVerdict(state, null));

    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    public void AResolvableImageWithoutValidTrustIsFlagged(SignatureState state)
        => Assert.True(Process(@"C:\Users\me\AppData\Local\thing.exe", state).Unsigned);

    [Theory]
    [InlineData(SignatureState.SignedTrusted)]
    // Unknown means verification could not be completed. Treating it as suspicious would cry wolf
    // over files WinSight simply failed to check.
    [InlineData(SignatureState.Unknown)]
    [InlineData(SignatureState.Missing)]
    public void AResolvableImageThatIsTrustedOrUndeterminedIsNotFlagged(SignatureState state)
    {
        var process = Process(@"C:\Windows\System32\thing.exe", state);

        Assert.False(process.Unsigned);
        Assert.False(process.Flagged);
    }

    /// <summary>
    /// A signature that validates only through a root the user could have installed reads as valid
    /// everywhere, and minting one takes no privilege. Only the persistence scan used to say so.
    /// </summary>
    [Fact]
    public void AnImageTrustedOnlyThroughAUserInstalledRootIsFlaggedWithoutBeingCalledUnsigned()
    {
        var process = new ProcessInfo(
            1234, "thing.exe", @"C:\Users\me\AppData\Local\thing.exe", 4, null,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Windows", SignatureTrustAnchor.UserInstalledRoot));

        Assert.False(process.Unsigned);
        Assert.True(process.TrustedOnlyThroughUserRoot);
        Assert.True(process.Flagged);
    }

    [Fact]
    public void AnImageTrustedThroughAMachineRootIsNotFlagged()
    {
        var process = new ProcessInfo(
            1234, "thing.exe", @"C:\Program Files\Vendor\thing.exe", 4, null,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Vendor", SignatureTrustAnchor.MachineRoot));

        Assert.False(process.TrustedOnlyThroughUserRoot);
        Assert.False(process.Flagged);
    }

    /// <summary>
    /// A process whose image cannot be resolved is never flagged, whatever verdict came back.
    /// </summary>
    /// <remarks>
    /// Protected and system processes routinely expose no ExecutablePath. Their verdict defaults to
    /// <see cref="SignatureState.Unknown"/>, and "the file is missing" would read as "the binary was
    /// deleted" rather than "we were not allowed to look" — naming a path WinSight never saw.
    /// </remarks>
    [Theory]
    [InlineData(SignatureState.Missing)]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    public void AProcessWithNoResolvableImageIsNeverFlagged(SignatureState state)
        => Assert.False(Process(null, state).Unsigned);
}

/// <summary>
/// How WMI's boxed numeric properties are read, including what happens when one cannot be.
/// </summary>
public sealed class ProcessListerNumericTests
{
    [Fact]
    public void ReadsEveryCimNumericTypeAProviderMayBox()
    {
        Assert.True(ProcessLister.TryToUint(4321u, out var fromUint));
        Assert.True(ProcessLister.TryToUint(4321, out var fromInt));
        Assert.True(ProcessLister.TryToUint((ushort)4321, out var fromUshort));
        Assert.True(ProcessLister.TryToUint(4321L, out var fromLong));
        Assert.All([fromUint, fromInt, fromUshort, fromLong], value => Assert.Equal(4321u, value));
    }

    /// <summary>
    /// An unreadable id is rejected rather than being fabricated as the System Idle Process.
    /// </summary>
    /// <remarks>
    /// Win32_Process declares these fields as uint32. A provider returning something else is a
    /// coverage gap; the scanner drops only that row and keeps the rest of the snapshot.
    /// </remarks>
    [Fact]
    public void AnUnreadableIdIsRejectedRatherThanRelabelledAsPidZero()
    {
        Assert.False(ProcessLister.TryToUint(null, out _));
        Assert.False(ProcessLister.TryToUint("not a number", out _));
        Assert.False(ProcessLister.TryToUint(-1, out _));
        Assert.True(ProcessLister.TryToUint(4321u, out var pid));
        Assert.Equal(4321u, pid);
    }
}
