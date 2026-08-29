using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

public sealed class AutomaticFileAccessTests
{
    [Theory]
    [InlineData(@"\\server\share\payload.dll")]
    [InlineData("//server/share/payload.dll")]
    [InlineData(@"\\?\UNC\server\share\payload.dll")]
    [InlineData(@"\??\UNC\server\share\payload.dll")]
    [InlineData(@"\Device\Mup\server\share\payload.dll")]
    public void NetworkAndDevicePathsAreRefused(string path) =>
        Assert.False(AutomaticFileAccess.IsLocal(path));

    [Fact]
    public void TheWindowsDirectoryIsLocal() =>
        Assert.True(AutomaticFileAccess.IsLocal(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)));

    [Fact]
    public void ARelativePathStaysWithinTheLocalWorkingDirectory() =>
        Assert.True(AutomaticFileAccess.IsLocal(@"bin\tool.exe"));

    [Fact]
    public void SignatureVerificationDoesNotCallADelegateForARemotePath()
    {
        var inner = new CountingVerifier();
        var verifier = new CachingSignatureVerifier(inner);

        var verdict = verifier.Verify(@"\\server\share\payload.dll");

        Assert.Equal(SignatureState.Unknown, verdict.State);
        Assert.Equal(0, inner.Calls);
    }

    private sealed class CountingVerifier : ISignatureVerifier
    {
        public int Calls { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            return AutomaticFileAccess.IsLocal(path)
                ? SignatureVerdict.Unsigned
                : SignatureVerdict.Unknown;
        }

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths,
            CancellationToken cancellationToken = default) =>
            paths.ToDictionary(
                path => path,
                path => Verify(path, cancellationToken),
                StringComparer.OrdinalIgnoreCase);
    }
}
