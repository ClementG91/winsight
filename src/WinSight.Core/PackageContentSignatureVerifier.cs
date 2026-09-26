using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace WinSight.Core;

/// <summary>
/// Signature evidence for a file that belongs to an MSIX/AppX package and carries no individual
/// Authenticode or catalog signature (for example <c>WindowsApps\Microsoft.Paint_…\PaintApp\mspaint.exe</c>).
/// </summary>
/// <remarks>
/// <para><b>What an earlier fallback got wrong.</b> It imported the certificates in a neighbouring
/// <c>AppxSignature.p7x</c> and trusted the chain, without verifying any signature or binding it to the
/// file. A copied sidecar, or a bag of public certificates, made any executable "signed by Microsoft".
/// That fallback was removed and is not reintroduced here.</para>
/// <para><b>What this establishes, and how.</b> Every step uses the Windows packaging API or CMS
/// verification; none relies on a name, a <c>WindowsApps</c> path, or the presence of a certificate:</para>
/// <list type="number">
/// <item><c>IAppxFactory::CreateValidatedBlockMapReader</c> verifies that the package signature covers
/// <c>AppxBlockMap.xml</c> (a modified block map or a certificate bag fails with TRUST_E_BAD_DIGEST), and
/// also refuses a signer whose chain does not reach a trusted root (a self-signed package claiming
/// Microsoft's name fails with CERT_E_UNTRUSTEDROOT), so such a package makes no claim at all.</item>
/// <item>The CMS signer of that same signature file must verify, carry the code-signing EKU and chain
/// to a trusted root without network access, evaluated at its RFC 3161 timestamp when one verifies
/// (Store signing certificates are routinely expired) and at the current time otherwise.</item>
/// <item><c>AppxManifest.xml</c> must match its block-map hash, and its <c>Identity/@Publisher</c> must
/// equal the signer's subject, which is the package-identity rule Windows applies at installation.</item>
/// <item>The scanned file must appear in the block map under its path relative to the package root,
/// and <c>IAppxBlockMapFile::ValidateFileHash</c> must accept its current bytes.</item>
/// </list>
/// <para><b>What it does not establish.</b> That the package is registered or installed for any user,
/// that it has not been revoked (no network is used), or anything about files outside the block map.
/// A copied package directory verifies, because its bytes genuinely are the publisher's. Handles on
/// the signature, block map and file deny writers and deletion while they are checked; a change after
/// the check is the caller's cache concern, as for any file verdict.</para>
/// </remarks>
public static class PackageContentSignatureVerifier
{
    private const string BlockMapFile = "AppxBlockMap.xml";
    private const string SignatureFile = "AppxSignature.p7x";
    private const string ManifestFile = "AppxManifest.xml";
    private const int MaxRootDepth = 16;
    private const long MaxSignatureBytes = 1024 * 1024;
    private const long MaxManifestBytes = 16 * 1024 * 1024;
    private static readonly byte[] SignatureMagic = "PKCX"u8.ToArray();
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";
    private const string TimestampingEku = "1.3.6.1.5.5.7.3.8";
    private const string Rfc3161CounterSignature = "1.3.6.1.4.1.311.3.3.1";

    /// <summary>
    /// Per-batch memo of package roots, so a package is validated once per scan. Dispose it: each
    /// validated package holds a block-map reader whose stream keeps the block map open.
    /// </summary>
    public sealed class Batch : IDisposable
    {
        internal Dictionary<string, PackageEvidence?> Roots { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void Dispose()
        {
            foreach (var evidence in Roots.Values)
            {
                Release(evidence?.Reader);
            }
            Roots.Clear();
        }
    }

    internal sealed record PackageEvidence(
        string Root,
        string Signer,
        string PackageName,
        bool Trusted,
        SignatureTrustAnchor Anchor,
        IAppxBlockMapReader Reader);

    /// <summary>
    /// The package verdict for <paramref name="path"/>, or null when no verified package claims the
    /// file. Null keeps the caller's own verdict (normally unsigned); it is never a trust claim.
    /// </summary>
    public static SignatureVerdict? Verify(string path, Batch? batch = null)
    {
        if (batch is not null)
        {
            return Verify(path, UserInstalledRoots.ReadSnapshot(), batch);
        }
        using var single = new Batch();
        return Verify(path, UserInstalledRoots.ReadSnapshot(), single);
    }

    internal static SignatureVerdict? Verify(string path, UserInstalledRoots.RootSnapshot roots, Batch batch)
    {
        ArgumentNullException.ThrowIfNull(batch);
        try
        {
            using var memberLease = AutomaticFileAccess.TryAcquire(path);
            if (memberLease is null || memberLease.IsDirectory)
            {
                return null;
            }
            var full = memberLease.FullPath;
            if (FindRoot(full) is not { } root)
            {
                return null;
            }
            var relative = Path.GetRelativePath(root, full);
            if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative))
            {
                return null;
            }
            if (!batch.Roots.TryGetValue(root, out var evidence))
            {
                evidence = ValidatePackage(root, roots);
                batch.Roots[root] = evidence;
            }
            if (evidence is null)
            {
                return null;
            }

            if (evidence.Reader.GetFile(relative, out var entry) < 0 || entry is null)
            {
                return null; // Not a member of this package: the package says nothing about it.
            }
            bool? intact;
            try
            {
                intact = ValidateHash(entry, full);
            }
            finally
            {
                Release(entry);
            }
            if (intact is null)
            {
                return null;
            }
            if (!memberLease.IsCurrent())
            {
                return null;
            }
            var signer = $"{evidence.Signer} (MSIX package {evidence.PackageName}, content verified)";
            return intact.Value && evidence.Trusted
                ? new SignatureVerdict(SignatureState.SignedTrusted, signer, evidence.Anchor)
                : new SignatureVerdict(SignatureState.SignedUntrusted, signer);
        }
        catch (Exception ex) when (IsVerificationFailure(ex))
        {
            return null;
        }
    }

    private static bool IsVerificationFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or COMException or CryptographicException or XmlException or ArgumentException
            or NotSupportedException or InvalidCastException;

    /// <summary>Deepest ancestor directory holding both a block map and a package signature.</summary>
    private static string? FindRoot(string fullPath)
    {
        var directory = Path.GetDirectoryName(fullPath);
        for (var depth = 0; depth < MaxRootDepth && !string.IsNullOrEmpty(directory); depth++)
        {
            if (AutomaticFileAccess.FileExists(Path.Combine(directory, BlockMapFile))
                && AutomaticFileAccess.FileExists(Path.Combine(directory, SignatureFile)))
            {
                return directory;
            }
            directory = Path.GetDirectoryName(directory);
        }
        return null;
    }

    private static PackageEvidence? ValidatePackage(string root, UserInstalledRoots.RootSnapshot roots)
    {
        var signaturePath = Path.Combine(root, SignatureFile);
        var blockMapPath = Path.Combine(root, BlockMapFile);
        // Held for the whole validation: no writer can change, and no rename can replace, the files
        // the packaging API and the CMS decoder each read.
        using var signatureLease = AutomaticFileAccess.TryAcquire(signaturePath);
        using var blockMapLease = AutomaticFileAccess.TryAcquire(blockMapPath);
        if (signatureLease is null || signatureLease.IsDirectory
            || blockMapLease is null || blockMapLease.IsDirectory)
        {
            return null;
        }
        using var signatureHandle = signatureLease.OpenRead();
        using var blockMapHandle = blockMapLease.OpenRead();
        if (signatureHandle.Length <= SignatureMagic.Length || signatureHandle.Length > MaxSignatureBytes)
        {
            return null;
        }
        var signature = new byte[signatureHandle.Length];
        signatureHandle.ReadExactly(signature);
        if (!signature.AsSpan(0, SignatureMagic.Length).SequenceEqual(SignatureMagic))
        {
            return null;
        }

        var factory = (IAppxFactory)new AppxFactory();
        var blockMapStream = new ManagedReadOnlyIStream(blockMapHandle);
        IAppxBlockMapReader? reader;
        try
        {
            if (factory.CreateValidatedBlockMapReader(blockMapStream, signaturePath, out reader) < 0 || reader is null)
            {
                return null; // The signature does not cover this block map.
            }
        }
        finally
        {
            Release(factory);
        }
        if (!signatureLease.IsCurrent() || !blockMapLease.IsCurrent())
        {
            Release(reader);
            return null;
        }
        try
        {
            return ValidateSigner(root, signature, reader, roots);
        }
        catch
        {
            Release(reader);
            throw;
        }
    }

    private static PackageEvidence? ValidateSigner(
        string root, byte[] signature, IAppxBlockMapReader reader, UserInstalledRoots.RootSnapshot roots)
    {

        var cms = new SignedCms();
        cms.Decode(signature.AsSpan(SignatureMagic.Length));
        if (cms.SignerInfos.Count != 1 || cms.SignerInfos[0].Certificate is not { } signerCertificate)
        {
            Release(reader);
            return null;
        }
        var signerInfo = cms.SignerInfos[0];
        signerInfo.CheckSignature(verifySignatureOnly: true);

        if (!ManifestPublisherMatches(root, reader, signerCertificate, out var packageName))
        {
            // A validly signed block map whose manifest is altered or names another publisher is
            // not a package Windows would accept: members are reported, but never as trusted.
            return new PackageEvidence(root, signerCertificate.Subject, packageName, Trusted: false,
                SignatureTrustAnchor.Unspecified, reader);
        }

        var verificationTime = VerifiedTimestamp(signerInfo, cms.Certificates) ?? DateTime.Now;
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.AddRange(cms.Certificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = verificationTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigningEku));
        var trusted = chain.Build(signerCertificate);
        var anchor = SignatureTrustAnchor.Unspecified;
        if (trusted && roots.IsComplete && chain.ChainElements.Count > 0)
        {
            // X509Chain consults CurrentUser\Root like WinVerifyTrust does, so say which store the
            // trust came from, exactly as the Authenticode path does.
            var rootThumbprint = chain.ChainElements[^1].Certificate.Thumbprint;
            anchor = roots.UserThumbprints.Contains(rootThumbprint)
                ? SignatureTrustAnchor.UserInstalledRoot
                : roots.MachineThumbprints.Contains(rootThumbprint)
                    ? SignatureTrustAnchor.MachineRoot
                    : SignatureTrustAnchor.Unspecified;
        }
        return new PackageEvidence(root, signerCertificate.Subject, packageName, trusted, anchor, reader);
    }

    /// <summary>The RFC 3161 time of a timestamp that verifies against this signer, or null.</summary>
    private static DateTime? VerifiedTimestamp(SignerInfo signerInfo, X509Certificate2Collection extra)
    {
        foreach (var attribute in signerInfo.UnsignedAttributes)
        {
            if (attribute.Oid.Value != Rfc3161CounterSignature)
            {
                continue;
            }
            foreach (var value in attribute.Values)
            {
                if (!Rfc3161TimestampToken.TryDecode(value.RawData, out var token, out _)
                    || !token.VerifySignatureForSignerInfo(signerInfo, out var tsaCertificate, extra)
                    || tsaCertificate is null)
                {
                    continue;
                }
                using (tsaCertificate)
                {
                    var time = token.TokenInfo.Timestamp.UtcDateTime;
                    using var chain = new X509Chain();
                    chain.ChainPolicy.ExtraStore.AddRange(extra);
                    var tokenCertificates = token.AsSignedCms().Certificates;
                    chain.ChainPolicy.ExtraStore.AddRange(tokenCertificates);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    chain.ChainPolicy.VerificationTime = time.ToLocalTime();
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimestampingEku));
                    if (chain.Build(tsaCertificate))
                    {
                        return time.ToLocalTime();
                    }
                }
            }
        }
        return null;
    }

    private static bool ManifestPublisherMatches(
        string root, IAppxBlockMapReader reader, X509Certificate2 signer, out string packageName)
    {
        packageName = "unknown";
        var manifestPath = Path.Combine(root, ManifestFile);
        if (reader.GetFile(ManifestFile, out var manifestEntry) < 0 || manifestEntry is null)
        {
            return false;
        }
        try
        {
            if (ValidateHash(manifestEntry, manifestPath) != true)
            {
                return false;
            }
        }
        finally
        {
            Release(manifestEntry);
        }
        using var manifestLease = AutomaticFileAccess.TryAcquire(manifestPath);
        if (manifestLease is null || manifestLease.IsDirectory)
        {
            return false;
        }
        using var manifest = manifestLease.OpenRead();
        if (manifest.Length > MaxManifestBytes)
        {
            return false;
        }
        using var xml = XmlReader.Create(manifest, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        });
        while (xml.Read())
        {
            if (xml.NodeType != XmlNodeType.Element || xml.LocalName != "Identity")
            {
                continue;
            }
            var name = xml.GetAttribute("Name");
            var version = xml.GetAttribute("Version");
            var publisher = xml.GetAttribute("Publisher");
            packageName = $"{name} {version}".Trim();
            return publisher is not null
                && manifestLease.IsCurrent()
                && SameDistinguishedName(publisher, signer.SubjectName);
        }
        return false;
    }

    private static bool SameDistinguishedName(string publisher, X500DistinguishedName subject)
    {
        try
        {
            return string.Equals(
                new X500DistinguishedName(publisher).Format(false),
                subject.Format(false),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>True/false from the packaging API; null when the file could not be read.</summary>
    private static bool? ValidateHash(IAppxBlockMapFile entry, string path)
    {
        using var lease = AutomaticFileAccess.TryAcquire(path);
        if (lease is null || lease.IsDirectory)
        {
            return null;
        }
        using var file = lease.OpenRead();
        var stream = new ManagedReadOnlyIStream(file);
        bool? result = entry.ValidateFileHash(stream, out var valid) < 0 ? null : valid != 0;
        return lease.IsCurrent() ? result : null;
    }

    /// <summary>Releases a COM reference now, so file handles behind it do not wait for the GC.</summary>
    private static void Release(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }

    /// <summary>Minimal read-only COM stream over a handle-bound managed stream.</summary>
    private sealed class ManagedReadOnlyIStream(Stream stream) : IStream
    {
        public void Read(byte[] pv, int cb, IntPtr pcbRead)
        {
            var read = stream.Read(pv, 0, Math.Min(cb, pv.Length));
            if (pcbRead != IntPtr.Zero)
            {
                Marshal.WriteInt32(pcbRead, read);
            }
        }

        public void Write(byte[] pv, int cb, IntPtr pcbWritten) =>
            Marshal.ThrowExceptionForHR(unchecked((int)0x80030005));

        public void Seek(long dlibMove, int dwOrigin, IntPtr plibNewPosition)
        {
            var origin = dwOrigin switch
            {
                0 => SeekOrigin.Begin,
                1 => SeekOrigin.Current,
                2 => SeekOrigin.End,
                _ => throw new ArgumentOutOfRangeException(nameof(dwOrigin)),
            };
            var position = stream.Seek(dlibMove, origin);
            if (plibNewPosition != IntPtr.Zero)
            {
                Marshal.WriteInt64(plibNewPosition, position);
            }
        }

        public void SetSize(long libNewSize) =>
            Marshal.ThrowExceptionForHR(unchecked((int)0x80030005));

        public void CopyTo(IStream pstm, long cb, IntPtr pcbRead, IntPtr pcbWritten)
        {
            var buffer = new byte[81920];
            long total = 0;
            while (total < cb)
            {
                var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, cb - total));
                if (read == 0)
                {
                    break;
                }
                pstm.Write(buffer, read, IntPtr.Zero);
                total += read;
            }
            if (pcbRead != IntPtr.Zero)
            {
                Marshal.WriteInt64(pcbRead, total);
            }
            if (pcbWritten != IntPtr.Zero)
            {
                Marshal.WriteInt64(pcbWritten, total);
            }
        }

        public void Commit(int grfCommitFlags)
        {
        }

        public void Revert() =>
            Marshal.ThrowExceptionForHR(unchecked((int)0x80004001));

        public void LockRegion(long libOffset, long cb, int dwLockType) =>
            Marshal.ThrowExceptionForHR(unchecked((int)0x80004001));

        public void UnlockRegion(long libOffset, long cb, int dwLockType) =>
            Marshal.ThrowExceptionForHR(unchecked((int)0x80004001));

        public void Stat(out STATSTG pstatstg, int grfStatFlag) =>
            pstatstg = new STATSTG { type = 2, cbSize = stream.Length };

        public void Clone(out IStream ppstm)
        {
            ppstm = null!;
            Marshal.ThrowExceptionForHR(unchecked((int)0x80004001));
        }
    }

    // Declarations from the Windows SDK's AppxPackaging.h (10.0.26100), in vtable order. Only the
    // members used are called; the preceding slots are declared to keep the layout exact.
    [ComImport, Guid("5842a140-ff9f-4166-8f5c-62f5b7b0c781")]
    private class AppxFactory
    {
    }

    [ComImport, Guid("beb94909-e451-438b-b5a7-d79e767b75d8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IAppxFactory
    {
        [PreserveSig] int CreatePackageWriter(IntPtr outputStream, IntPtr settings, out IntPtr packageWriter);
        [PreserveSig] int CreatePackageReader(IntPtr inputStream, out IntPtr packageReader);
        [PreserveSig] int CreateManifestReader(IntPtr inputStream, out IntPtr manifestReader);
        [PreserveSig] int CreateBlockMapReader(IStream inputStream, out IAppxBlockMapReader? blockMapReader);
        [PreserveSig]
        int CreateValidatedBlockMapReader(
            IStream blockMapStream,
            [MarshalAs(UnmanagedType.LPWStr)] string signatureFileName,
            out IAppxBlockMapReader? blockMapReader);
    }

    [ComImport, Guid("5efec991-bca3-42d1-9ec2-e92d609ec22a"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IAppxBlockMapReader
    {
        [PreserveSig] int GetFile([MarshalAs(UnmanagedType.LPWStr)] string filename, out IAppxBlockMapFile? file);
    }

    [ComImport, Guid("277672ac-4f63-42c1-8abc-beae3600eb59"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IAppxBlockMapFile
    {
        [PreserveSig] int GetBlocks(out IntPtr blocks);
        [PreserveSig] int GetLocalFileHeaderSize(out uint size);
        [PreserveSig] int GetName(out IntPtr name);
        [PreserveSig] int GetUncompressedSize(out ulong size);
        [PreserveSig] int ValidateFileHash(IStream fileStream, out int isValid);
    }
}
