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
        => Assert.False(Process(@"C:\Windows\System32\thing.exe", state).Unsigned);

    /// <summary>
    /// A process whose image cannot be resolved is never flagged, whatever verdict came back.
    /// </summary>
    /// <remarks>
    /// Protected and system processes routinely expose no ExecutablePath. Their verdict defaults to
    /// <see cref="SignatureState.Missing"/>, and "the file is missing" would read as "the binary was
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
        Assert.Equal(4321u, ProcessLister.ToUint(4321u));
        Assert.Equal(4321u, ProcessLister.ToUint(4321));
        Assert.Equal(4321u, ProcessLister.ToUint((ushort)4321));
        Assert.Equal(4321u, ProcessLister.ToUint(4321L));
    }

    /// <summary>
    /// An unreadable id becomes 0 — the System Idle Process — rather than failing the snapshot.
    /// </summary>
    /// <remarks>
    /// Pinned because it is a real mislabel, not because it is desirable: a row WinSight cannot read
    /// an id for is attributed to pid 0. It is kept only because losing every process in the
    /// snapshot over one malformed row is worse, and Win32_Process declares these as uint32 so the
    /// arm should never fire in practice. If this ever starts firing, the answer is to drop the row,
    /// not to keep renaming it.
    /// </remarks>
    [Fact]
    public void AnUnreadableIdFallsBackToZeroRatherThanFailingTheSnapshot()
    {
        Assert.Equal(0u, ProcessLister.ToUint(null));
        Assert.Equal(0u, ProcessLister.ToUint("not a number"));
    }
}
