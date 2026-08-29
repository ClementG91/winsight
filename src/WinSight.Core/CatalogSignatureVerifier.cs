using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Win32.SafeHandles;

namespace WinSight.Core;

/// <summary>
/// Verifies membership in the local Windows system catalogs and the catalog signature itself.
/// All trust evaluation is cache-only: a scan never downloads certificates or revocation data.
/// </summary>
public sealed class CatalogSignatureVerifier : ISignatureVerifier
{
    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default)
    {
        using var batch = new CatalogBatch();
        return Verify(path, batch, cancellationToken);
    }

    private static SignatureVerdict Verify(
        string path, CatalogBatch batch, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return SignatureVerdict.Missing;
        }

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 1,
                FileOptions.RandomAccess);
            return VerifyOpenFile(path, stream.SafeFileHandle, batch, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or DllNotFoundException
                                     or EntryPointNotFoundException
                                     or MarshalDirectiveException)
        {
            return SignatureVerdict.Unknown;
        }
    }

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var distinct = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        if (distinct.Length == 0)
        {
            return results;
        }

        // Verified in parallel, like the embedded path beside it, and for the same reason: each file
        // is an independent WinVerifyTrust call dominated by reading the image off disk.
        //
        // One context per worker rather than one shared across them. CryptCATAdmin handles carry no
        // documented thread-safety guarantee, and a security tool is the wrong place to assume one
        // from the absence of a warning - the failure mode of guessing wrong is a wrong verdict, not
        // a crash. Each worker therefore acquires its own context and its own signer cache, which
        // costs one acquisition per worker instead of one per file.
        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Math.Min(Environment.ProcessorCount, 8),
        };
        var verified = new ConcurrentBag<(string Path, SignatureVerdict Verdict)>();
        Parallel.ForEach(
            distinct,
            options,
            () => new CatalogBatch(),
            (path, _, batch) =>
            {
                verified.Add((path, Verify(path, batch, cancellationToken)));
                return batch;
            },
            batch => batch.Dispose());

        // Reassembled in the caller's order, so a scan's output does not vary run to run.
        var byPath = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, verdict) in verified)
        {
            byPath[path] = verdict;
        }
        foreach (var path in distinct)
        {
            if (byPath.TryGetValue(path, out var verdict))
            {
                results[path] = verdict;
            }
        }
        return results;
    }

    /// <summary>
    /// The per-batch state: one <c>CryptCATAdmin</c> context, and the signer of each catalog already
    /// read.
    /// </summary>
    /// <remarks>
    /// <b>What this changes.</b> Every file used to acquire and release its own catalog admin
    /// context, and re-read the signing certificate of whatever catalog it landed in. On a
    /// persistence scan that is thousands of acquisitions of a context Windows builds by opening the
    /// catalog store, and thousands of certificate parses of the same handful of catalog files -
    /// almost every Microsoft binary on the machine is a member of one of a few dozen catalogs, so
    /// the same certificate was read hundreds of times over.
    ///
    /// Both are now established once per batch. The context is per-batch rather than shared for the
    /// process because <c>CryptCATAdmin</c> handles carry no documented thread-safety guarantee, and
    /// a batch runs on one thread; the signer cache is per-batch for the same reason it is per-scan
    /// elsewhere - a catalog replaced between two scans must be read again.
    /// </remarks>
    private sealed class CatalogBatch : IDisposable
    {
        private readonly Dictionary<string, string?> _signers =
            new(StringComparer.OrdinalIgnoreCase);
        private IntPtr _admin;
        private bool _attempted;

        /// <summary>
        /// The shared context, acquired on first use. <see cref="IntPtr.Zero"/> when Windows refused,
        /// which every caller already treats as "no verdict".
        /// </summary>
        internal IntPtr Admin
        {
            get
            {
                if (!_attempted)
                {
                    _attempted = true;
                    if (!NativeMethods.CryptCATAdminAcquireContext2(
                            out var acquired, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                    {
                        acquired = IntPtr.Zero;
                    }
                    _admin = acquired;
                }
                return _admin;
            }
        }

        /// <summary>The signer of a catalog, read once however many members point at it.</summary>
        internal string? SignerOf(string catalogPath)
        {
            if (_signers.TryGetValue(catalogPath, out var signer))
            {
                return signer;
            }
            signer = SignerOfCatalog(catalogPath);
            _signers[catalogPath] = signer;
            return signer;
        }

        public void Dispose()
        {
            if (_admin != IntPtr.Zero)
            {
                _ = NativeMethods.CryptCATAdminReleaseContext(_admin, 0);
                _admin = IntPtr.Zero;
            }
        }
    }

    private static SignatureVerdict VerifyOpenFile(
        string path,
        SafeFileHandle file,
        CatalogBatch batch,
        CancellationToken cancellationToken)
    {
        var catalogAdmin = batch.Admin;
        if (catalogAdmin == IntPtr.Zero)
        {
            return SignatureVerdict.Unknown;
        }

        IntPtr catalog = IntPtr.Zero;
        try
        {
            uint hashLength = 0;
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(
                    catalogAdmin, file, ref hashLength, null, 0)
                || hashLength is 0 or > 128)
            {
                return SignatureVerdict.Unknown;
            }

            var hash = new byte[hashLength];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(
                    catalogAdmin, file, ref hashLength, hash, 0))
            {
                return SignatureVerdict.Unknown;
            }
            if (hashLength != hash.Length)
            {
                Array.Resize(ref hash, checked((int)hashLength));
            }

            var memberTag = Convert.ToHexString(hash);
            var foundCatalog = false;
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Passing the previous context lets Windows advance the enumeration and release
                // that context. Only the final live handle is released in the finally block.
                catalog = NativeMethods.CryptCATAdminEnumCatalogFromHash(
                    catalogAdmin, hash, hashLength, 0, ref catalog);
                if (catalog == IntPtr.Zero)
                {
                    break;
                }
                foundCatalog = true;

                var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!NativeMethods.CryptCATCatalogInfoFromContext(catalog, ref info, 0)
                    || string.IsNullOrWhiteSpace(info.wszCatalogFile))
                {
                    return SignatureVerdict.Unknown;
                }

                var result = unchecked((uint)VerifyCatalog(
                    path, file.DangerousGetHandle(), hash, memberTag, info.wszCatalogFile, catalogAdmin));
                var state = NativeSignatureVerifier.MapResult(result);
                if (state is SignatureState.SignedTrusted or SignatureState.SignedUntrusted)
                {
                    return new SignatureVerdict(state.Value, batch.SignerOf(info.wszCatalogFile));
                }
                // A machine can contain more than one catalog for the same member. An unusable
                // first catalog must not hide a valid later one.
            }
            while (catalog != IntPtr.Zero);

            return foundCatalog ? SignatureVerdict.Unknown : SignatureVerdict.Unsigned;
        }
        finally
        {
            if (catalog != IntPtr.Zero)
            {
                _ = NativeMethods.CryptCATAdminReleaseCatalogContext(catalogAdmin, catalog, 0);
            }
            // The admin context belongs to the batch and is released when the batch ends, not here.
        }
    }

    private static string? SignerOfCatalog(string catalogPath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(catalogPath));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static int VerifyCatalog(
        string memberPath,
        IntPtr memberFile,
        byte[] hash,
        string memberTag,
        string catalogPath,
        IntPtr catalogAdmin)
    {
        var hashBuffer = Marshal.AllocHGlobal(hash.Length);
        var catalogInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        var trustDataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
        try
        {
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);
            var catalogInfo = new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                pcwszCatalogFilePath = catalogPath,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = memberPath,
                hMemberFile = memberFile,
                pbCalculatedFileHash = hashBuffer,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = catalogAdmin,
            };
            Marshal.StructureToPtr(catalogInfo, catalogInfoPointer, false);

            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeWholeChain,
                dwUnionChoice = WtdChoiceCatalog,
                pInfo = catalogInfoPointer,
                dwStateAction = WtdStateActionVerify,
                // Same policy as the embedded verifier: revocation is checked against the local
                // cache only, so a revoked signing certificate is seen while no request leaves the
                // machine. See NativeSignatureVerifier for why WTD_REVOKE_NONE was wrong.
                dwProvFlags = WtdCacheOnlyUrlRetrieval
                    | WtdDisableMd2Md4,
            };
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            var result = NativeMethods.WinVerifyTrust(
                IntPtr.Zero, ref _actionGenericVerifyV2, trustDataPointer);

            trustData = Marshal.PtrToStructure<WinTrustData>(trustDataPointer);
            trustData.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(trustData, trustDataPointer, false);
            _ = NativeMethods.WinVerifyTrust(
                IntPtr.Zero, ref _actionGenericVerifyV2, trustDataPointer);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustCatalogInfo>(catalogInfoPointer);
            Marshal.FreeHGlobal(catalogInfoPointer);
            Marshal.FreeHGlobal(trustDataPointer);
            Marshal.FreeHGlobal(hashBuffer);
        }
    }

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 0x00000001;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint WtdDisableMd2Md4 = 0x2000;

    private static Guid _actionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    private static class NativeMethods
    {
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptCATAdminAcquireContext2(
            out IntPtr phCatAdmin,
            IntPtr pgSubsystem,
            string pwszHashAlgorithm,
            IntPtr pStrongHashPolicy,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptCATAdminCalcHashFromFileHandle2(
            IntPtr hCatAdmin,
            SafeFileHandle hFile,
            ref uint pcbHash,
            [Out] byte[]? pbHash,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        internal static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin,
            byte[] pbHash,
            uint cbHash,
            uint dwFlags,
            ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo,
            ref CatalogInfo psCatInfo,
            uint dwFlags);

        [DllImport("wintrust.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptCATAdminReleaseCatalogContext(
            IntPtr hCatAdmin,
            IntPtr hCatInfo,
            uint dwFlags);

        [DllImport("wintrust.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);
    }
}
