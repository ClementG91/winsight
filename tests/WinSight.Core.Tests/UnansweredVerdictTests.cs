using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// What the cache reports when the inner verifier answered nothing for a path.
/// </summary>
/// <remarks>
/// <b>The stronger claim.</b> It returned <see cref="SignatureState.Missing"/>, which means "the
/// file is not there". The thing that actually happened is "the batch produced no verdict for this
/// path" - which says nothing about whether the file exists. This codebase draws that distinction
/// carefully everywhere else, and it was inverted at both places a dictionary lookup could miss.
/// </remarks>
public sealed class UnansweredVerdictTests
{
    [Fact]
    public void APathTheInnerVerifierDidNotAnswerIsUnknownNotMissing()
    {
        var caching = new CachingSignatureVerifier(new SilentVerifier());

        var verdict = caching.Verify(@"C:\Windows\System32\kernel32.dll");

        Assert.Equal(SignatureState.Unknown, verdict.State);
        Assert.NotEqual(SignatureState.Missing, verdict.State);
    }

    /// <summary>A verifier that answers nothing at all, which is the condition under test.</summary>
    private sealed class SilentVerifier : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            SignatureVerdict.Unknown;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
    }
}
