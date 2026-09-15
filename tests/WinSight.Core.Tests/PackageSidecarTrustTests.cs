using System.Security.Cryptography.X509Certificates;

using WinSight.Core;
using Xunit;

namespace WinSight.Core.Tests;

public sealed class PackageSidecarTrustTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-sidecar-tests-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicCertificateSidecarCannotMakeUnsignedFileTrusted(bool nested)
    {
        var targetDirectory = nested ? Directory.CreateDirectory(Path.Combine(_directory, "nested")).FullName : _directory;
        var path = Path.Combine(targetDirectory, "unsigned.dll");
        // The test assembly is a real, unsigned PE, with no catalog entry. No program is run.
        File.Copy(typeof(PackageSidecarTrustTests).Assembly.Location, path);
        var verifier = new NativeSignatureVerifier();
        Assert.Equal(SignatureState.Unsigned, verifier.Verify(path).State);

        WritePublicCertificateSidecar();

        var verdict = verifier.Verify(path);
        Assert.Equal(SignatureState.Unsigned, verdict.State);
        Assert.Equal(SignatureTrustAnchor.Unspecified, verdict.Anchor);
        Assert.Null(verdict.Signer);
    }

    [Fact]
    public void CatalogSignedFileKeepsVerifiedCatalogVerdictBesideUnrelatedSidecar()
    {
        var path = Path.Combine(_directory, "kernel32.dll");
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"), path);
        var verifier = new NativeSignatureVerifier();
        var before = verifier.Verify(path);
        Assert.Equal(SignatureState.SignedTrusted, before.State);

        WritePublicCertificateSidecar();

        Assert.Equal(before, verifier.Verify(path));
    }

    private void WritePublicCertificateSidecar()
    {
        // Export only a public trusted root, with no private key and no CMS signature. The old
        // fallback accepted this certificate bag as proof of a file/package signature.
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var roots = store.Certificates;
        try
        {
            Assert.NotEmpty(roots);
            var bag = new X509Certificate2Collection(roots[0]);
            var encoded = bag.Export(X509ContentType.Pkcs7);
            Assert.NotNull(encoded);
            File.WriteAllBytes(Path.Combine(_directory, "AppxSignature.p7x"), [0x50, 0x4B, 0x43, 0x58, .. encoded]);
        }
        finally
        {
            foreach (var root in roots)
            {
                root.Dispose();
            }
        }
    }
}
