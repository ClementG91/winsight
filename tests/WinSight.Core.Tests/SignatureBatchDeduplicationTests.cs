using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// A batch verifies each file once, however many entries name it.
/// </summary>
/// <remarks>
/// <b>The cost this pins.</b> A persistence report names the same image many times: measured on a
/// real desktop, 4 533 autostart entries resolved to 438 distinct files, and 3 842 of them to a single
/// COM server DLL. The batch passed every mention through to the native verifier, so a cold scan -
/// which is every command-line run - repeated the same WinVerifyTrust call thousands of times.
/// </remarks>
public sealed class SignatureBatchDeduplicationTests
{
    [Fact]
    public void RepeatedAndDifferentlyCasedMentionsReachTheInnerVerifierOnce()
    {
        var file = Path.GetTempFileName();
        try
        {
            var inner = new CountingVerifier();
            var caching = new CachingSignatureVerifier(inner);
            var mentions = new[] { file, file, file.ToUpperInvariant(), file.ToLowerInvariant(), file };

            var verdicts = caching.VerifyMany(mentions);

            Assert.Equal(1, inner.Asked.Count(path => string.Equals(path, file, StringComparison.OrdinalIgnoreCase)));
            // Every mention, whatever its casing, still finds the verdict.
            Assert.All(mentions, mention => Assert.Equal(SignatureState.Unsigned, verdicts[mention].State));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void TheNativeBatchAnswersEveryMentionOfAFileItVerifiedOnce()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var kernel32 = Path.Combine(system, "kernel32.dll");
        var mentions = new[] { kernel32, kernel32.ToUpperInvariant(), kernel32 };

        var verdicts = new NativeSignatureVerifier().VerifyMany(mentions);

        var first = verdicts[kernel32].State;
        Assert.Equal(SignatureState.SignedTrusted, first);
        Assert.All(mentions, mention => Assert.Equal(first, verdicts[mention].State));
    }

    /// <summary>Records every path it is asked about and answers "unsigned".</summary>
    private sealed class CountingVerifier : ISignatureVerifier
    {
        public List<string> Asked { get; } = [];

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            VerifyMany([path], cancellationToken)[path];

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            Asked.AddRange(paths);
            return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(
                path => path, _ => SignatureVerdict.Unsigned, StringComparer.OrdinalIgnoreCase);
        }
    }
}
