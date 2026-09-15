using System.Security.Cryptography.X509Certificates;

using WinSight.Core;
using Xunit;
using Xunit.Abstractions;

namespace WinSight.Core.Tests;

/// <summary>
/// Real Windows packaging API and real installed Store packages, read-only. Tampering is exercised
/// on copies in a temporary directory; nothing under WindowsApps is modified.
/// </summary>
public sealed class PackageContentSignatureTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-msix-tests-").FullName;

    public PackageContentSignatureTests(ITestOutputHelper output) => _output = output;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void AnInstalledStorePackageMemberVerifiesAsTrustedPackageContent()
    {
        if (StorePackage() is not { } package)
        {
            _output.WriteLine("No installed Store package with an executable member on this machine.");
            return;
        }

        var verdict = new NativeSignatureVerifier().Verify(package.Executable);

        Assert.Equal(SignatureState.SignedTrusted, verdict.State);
        Assert.Contains("MSIX package", verdict.Signer);
        Assert.Contains("content verified", verdict.Signer);
        Assert.NotEqual(SignatureTrustAnchor.UserInstalledRoot, verdict.Anchor);
    }

    [Fact]
    public void ACopiedPackageVerifiesBecauseItsBytesAreGenuine_AndOneChangedByteDoesNot()
    {
        if (CopyPackage() is not { } copy)
        {
            return;
        }
        Assert.Equal(SignatureState.SignedTrusted, PackageContentSignatureVerifier.Verify(copy.Executable)!.Value.State);

        FlipByte(copy.Executable, 4096);

        var tampered = PackageContentSignatureVerifier.Verify(copy.Executable);
        Assert.Equal(SignatureState.SignedUntrusted, tampered!.Value.State);
        Assert.Equal(SignatureState.SignedUntrusted, new NativeSignatureVerifier().Verify(copy.Executable).State);
    }

    [Fact]
    public void CopiedSidecarsDoNotVouchForAnUnrelatedExecutable()
    {
        if (CopyPackage() is not { } copy)
        {
            return;
        }
        var unrelated = typeof(PackageContentSignatureTests).Assembly.Location;

        // Under the member's own name the hash is checked and fails.
        File.Copy(unrelated, copy.Executable, overwrite: true);
        Assert.Equal(SignatureState.SignedUntrusted, PackageContentSignatureVerifier.Verify(copy.Executable)!.Value.State);

        // Under a name the block map does not list, the package makes no claim at all.
        var planted = Path.Combine(copy.Root, "planted.exe");
        File.Copy(unrelated, planted);
        Assert.Null(PackageContentSignatureVerifier.Verify(planted));
        Assert.Equal(SignatureState.Unsigned, new NativeSignatureVerifier().Verify(planted).State);
    }

    [Fact]
    public void AnAlteredBlockMapOrACertificateBagSignatureMakesNoClaim()
    {
        if (CopyPackage() is not { } copy)
        {
            return;
        }
        var blockMap = Path.Combine(copy.Root, "AppxBlockMap.xml");
        var original = File.ReadAllText(blockMap);
        var hash = original.IndexOf("Hash=\"", StringComparison.Ordinal) + 6;
        File.WriteAllText(blockMap, original[..hash] + (original[hash] == 'A' ? 'B' : 'A') + original[(hash + 1)..]);
        Assert.Null(PackageContentSignatureVerifier.Verify(copy.Executable));

        File.WriteAllText(blockMap, original);
        WriteCertificateBagSignature(copy.Root);
        Assert.Null(PackageContentSignatureVerifier.Verify(copy.Executable));
    }

    [Fact]
    public void AManifestThatNoLongerMatchesTheSignedBlockMapIsNeverTrusted()
    {
        if (CopyPackage() is not { } copy)
        {
            return;
        }
        var manifest = Path.Combine(copy.Root, "AppxManifest.xml");
        File.AppendAllText(manifest, "<!-- altered -->");

        var verdict = PackageContentSignatureVerifier.Verify(copy.Executable);

        Assert.Equal(SignatureState.SignedUntrusted, verdict!.Value.State);
    }

    [Fact]
    public void ReplacingThePackageMetadataWithAnotherPackagesRemovesTheClaim()
    {
        var packages = StorePackages().Take(2).ToList();
        if (packages.Count < 2 || CopyPackage(packages[0]) is not { } copy)
        {
            return;
        }
        foreach (var name in new[] { "AppxBlockMap.xml", "AppxSignature.p7x", "AppxManifest.xml" })
        {
            File.Copy(Path.Combine(packages[1].Root, name), Path.Combine(copy.Root, name), overwrite: true);
        }

        var verdict = PackageContentSignatureVerifier.Verify(copy.Executable);

        Assert.True(verdict is null || verdict.Value.State != SignatureState.SignedTrusted);
    }

    [Fact]
    public void AFileOutsideAnyPackageIsNotAffected()
    {
        var path = Path.Combine(_directory, "plain.dll");
        File.Copy(typeof(PackageContentSignatureTests).Assembly.Location, path);

        Assert.Null(PackageContentSignatureVerifier.Verify(path));
        Assert.Null(PackageContentSignatureVerifier.Verify(@"\\untrusted.invalid\share\app.exe"));
    }

    [Fact]
    public void AGenuinelySignedPackageFromAnUntrustedSignerClaimingMicrosoftIsNotTrusted()
    {
        // A real package, really signed, by a self-signed key whose subject copies Microsoft's: the
        // manifest publisher matches the signer, but the chain does not reach a trusted root. Measured:
        // CreateValidatedBlockMapReader itself refuses it (0x800B0109, CERT_E_UNTRUSTEDROOT), so the
        // package makes no claim and the member stays unsigned. No trust store is modified.
        var sdk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            @"Windows Kits\10\bin\10.0.26100.0\x64");
        var makeAppx = Path.Combine(sdk, "makeappx.exe");
        var signTool = Path.Combine(sdk, "signtool.exe");
        if (!File.Exists(makeAppx) || !File.Exists(signTool))
        {
            _output.WriteLine("Windows SDK packaging tools are not installed; package signing not exercised.");
            return;
        }
        const string publisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        var content = Directory.CreateDirectory(Path.Combine(_directory, "content")).FullName;
        File.Copy(typeof(PackageContentSignatureTests).Assembly.Location, Path.Combine(content, "app.exe"));
        // A 1x1 transparent PNG: the schema requires an image logo.
        File.WriteAllBytes(Path.Combine(content, "logo.png"), Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="));
        File.WriteAllText(Path.Combine(content, "AppxManifest.xml"), $"""
            <?xml version="1.0" encoding="utf-8"?>
            <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
              <Identity Name="WinSight.Tests.Forged" Publisher="{publisher}" Version="1.0.0.0" ProcessorArchitecture="x64" />
              <Properties><DisplayName>Forged</DisplayName><PublisherDisplayName>Forged</PublisherDisplayName><Logo>logo.png</Logo></Properties>
              <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0" /></Dependencies>
              <Resources><Resource Language="en-us" /></Resources>
            </Package>
            """);
        var package = Path.Combine(_directory, "forged.msix");
        Run(makeAppx, $"pack /d \"{content}\" /p \"{package}\" /nv /o");

        using (var key = System.Security.Cryptography.RSA.Create(3072))
        {
            var request = new CertificateRequest(publisher, key,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.3")], critical: false));
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
            var pfxPassword = Guid.NewGuid().ToString("N"); // a throwaway key generated by this test
            var pfx = Path.Combine(_directory, "forged.pfx");
            File.WriteAllBytes(pfx, certificate.Export(X509ContentType.Pfx, pfxPassword));
            Run(signTool, $"sign /fd SHA256 /f \"{pfx}\" /p {pfxPassword} \"{package}\"");
        }

        var unpacked = Path.Combine(_directory, "unpacked");
        Run(makeAppx, $"unpack /p \"{package}\" /d \"{unpacked}\" /nv /o");
        var member = Path.Combine(unpacked, "app.exe");

        var verdict = PackageContentSignatureVerifier.Verify(member);

        Assert.Null(verdict);
        Assert.Equal(SignatureState.Unsigned, new NativeSignatureVerifier().Verify(member).State);
    }

    private static void Run(string tool, string arguments)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tool, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), $"{Path.GetFileName(tool)} timed out");
        Assert.True(process.ExitCode == 0,
            $"{Path.GetFileName(tool)} exited {process.ExitCode}: {output.Result}{error.Result}");
    }

    private sealed record InstalledPackage(string Root, string Executable);

    private static IEnumerable<InstalledPackage> StorePackages()
    {
        var manager = new Windows.Management.Deployment.PackageManager();
        IEnumerable<Windows.ApplicationModel.Package> packages;
        try
        {
            packages = manager.FindPackagesForUser(string.Empty).ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            yield break;
        }
        foreach (var package in packages.OrderByDescending(p => p.Id.Name == "Microsoft.Paint"))
        {
            string root;
            try
            {
                if (package.SignatureKind != Windows.ApplicationModel.PackageSignatureKind.Store
                    || package.IsBundle || package.IsResourcePackage)
                {
                    continue;
                }
                root = package.InstalledPath;
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or FileNotFoundException)
            {
                continue;
            }
            if (!File.Exists(Path.Combine(root, "AppxBlockMap.xml")) || !File.Exists(Path.Combine(root, "AppxSignature.p7x")))
            {
                continue;
            }
            string? executable = null;
            try
            {
                executable = Directory.EnumerateFiles(root, "*.exe", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = 2,
                    IgnoreInaccessible = true,
                }).FirstOrDefault(file => new FileInfo(file).Length < 64 * 1024 * 1024 && !HasEmbeddedSignature(file));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
            if (executable is not null)
            {
                yield return new InstalledPackage(root, executable);
            }
        }
    }

    /// <summary>
    /// Many Store members also carry their own Authenticode signature, which the native verifier
    /// reports first; only a member without one exercises the package evidence.
    /// </summary>
    private static bool HasEmbeddedSignature(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new System.Reflection.PortableExecutable.PEReader(stream);
            return reader.PEHeaders.PEHeader is not { CertificateTableDirectory.Size: 0 };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or BadImageFormatException)
        {
            return true; // unreadable or not a PE image: not a usable member
        }
    }

    private InstalledPackage? StorePackage() => StorePackages().FirstOrDefault();

    private InstalledPackage? CopyPackage(InstalledPackage? source = null)
    {
        source ??= StorePackage();
        if (source is null)
        {
            _output.WriteLine("No installed Store package with an executable member on this machine.");
            return null;
        }
        var root = Path.Combine(_directory, "package");
        Directory.CreateDirectory(root);
        foreach (var name in new[] { "AppxBlockMap.xml", "AppxSignature.p7x", "AppxManifest.xml" })
        {
            File.Copy(Path.Combine(source.Root, name), Path.Combine(root, name));
        }
        var relative = Path.GetRelativePath(source.Root, source.Executable);
        var executable = Path.Combine(root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(executable)!);
        File.Copy(source.Executable, executable);
        return new InstalledPackage(root, executable);
    }

    private static void FlipByte(string path, int offset)
    {
        var bytes = File.ReadAllBytes(path);
        bytes[Math.Min(offset, bytes.Length - 1)] ^= 0xFF;
        File.WriteAllBytes(path, bytes);
    }

    private static void WriteCertificateBagSignature(string root)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var roots = store.Certificates;
        try
        {
            var encoded = new X509Certificate2Collection(roots[0]).Export(X509ContentType.Pkcs7)!;
            File.WriteAllBytes(Path.Combine(root, "AppxSignature.p7x"), [0x50, 0x4B, 0x43, 0x58, .. encoded]);
        }
        finally
        {
            foreach (var certificate in roots)
            {
                certificate.Dispose();
            }
        }
    }
}
