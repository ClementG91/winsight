using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

public sealed class CatalogSignatureVerifierTests
{
    private static readonly string CatalogSignedSystemBinary = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "kernel32.dll");

    [Fact]
    public void LocalSystemCatalogMembershipIsVerifiedWithoutPowerShell()
    {
        Assert.True(File.Exists(CatalogSignedSystemBinary));

        var verdict = new CatalogSignatureVerifier().Verify(CatalogSignedSystemBinary);

        Assert.Equal(SignatureState.SignedTrusted, verdict.State);
        Assert.Contains("Microsoft", verdict.Signer ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ModifyingACatalogSignedCopyInvalidatesItsTrust()
    {
        var directory = Path.Combine(Path.GetTempPath(), "winsight-catalog-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var copy = Path.Combine(directory, "kernel32.dll");
        try
        {
            File.Copy(CatalogSignedSystemBinary, copy);
            Assert.Equal(SignatureState.SignedTrusted, new CatalogSignatureVerifier().Verify(copy).State);

            using (var stream = new FileStream(copy, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                // Change bytes inside a mapped section. PE checksum/certificate-table fields and
                // some trailing padding are deliberately excluded from Authenticode hashing.
                stream.Position = stream.Length / 2;
                var original = stream.ReadByte();
                stream.Position = stream.Length / 2;
                stream.WriteByte((byte)(original ^ 0xFF));
            }

            Assert.NotEqual(SignatureState.SignedTrusted, new CatalogSignatureVerifier().Verify(copy).State);
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A virus scanner can briefly retain the test copy; the OS temp cleanup owns it.
            }
        }
    }

    [Fact]
    public void CancellationIsObservedBeforeOpeningTheFile()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(
            () => new CatalogSignatureVerifier().Verify(CatalogSignedSystemBinary, cancellation.Token));
    }
}
