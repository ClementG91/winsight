using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Core;

/// <summary>
/// Native Authenticode verification via WinVerifyTrust (wintrust.dll), the OS API,
/// fast and no process spawn. It checks the EMBEDDED signature (PE hash + certificate
/// chain + policy), so it detects tampering and trusts real embedded signatures
/// directly. A file with no embedded signature is deferred to the native, cache-only
/// <see cref="CatalogSignatureVerifier"/>. No PowerShell process or network retrieval is used.
///
/// The interop uses only the stable WINTRUST_DATA/WINTRUST_FILE_INFO layouts (all
/// DWORD/pointer fields, one IN-only path string), no fragile out-struct marshalling.
/// </summary>
public sealed class NativeSignatureVerifier : ISignatureVerifier
{
    private readonly ISignatureVerifier _catalogFallback;

    public NativeSignatureVerifier(ISignatureVerifier? catalogFallback = null) =>
        _catalogFallback = catalogFallback ?? new CatalogSignatureVerifier();

    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
        VerifyMany([path], cancellationToken).TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        var deferToCatalog = new List<string>();

        // Verified in parallel. Each file is an independent WinVerifyTrust call - the API is
        // thread-safe and the work is dominated by reading the image off disk - so the batch was
        // spending nearly all of its time waiting, one file at a time. This is what VerifyMany
        // existed for and it was looping serially: 4 300 autostart entries at ~19 ms each is over a
        // minute of a scan the operator is watching.
        //
        // Bounded rather than unbounded: the point is to keep several reads in flight, not to hand
        // every core to a security scan running beside the operator's own work.
        var options = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Math.Min(Environment.ProcessorCount, 8),
        };
        var verified = new System.Collections.Concurrent.ConcurrentBag<(string Path, SignatureVerdict? Verdict)>();
        Parallel.ForEach(paths, options, path => verified.Add((path, VerifyEmbedded(path))));

        // Reassembled in the caller's order so a scan's output does not vary run to run.
        var byPath = new Dictionary<string, SignatureVerdict?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, verdict) in verified)
        {
            byPath[path] = verdict;
        }
        foreach (var path in paths)
        {
            if (byPath.TryGetValue(path, out var verdict) && verdict is { } v)
            {
                results[path] = v;
            }
            else
            {
                deferToCatalog.Add(path); // no embedded signature (maybe catalog) or an error
            }
        }

        if (deferToCatalog.Count > 0)
        {
            foreach (var kv in _catalogFallback.VerifyMany(deferToCatalog, cancellationToken))
            {
                results[kv.Key] = kv.Value;
            }
        }
        return results;
    }

    // Embedded-signature verdict, or null when the file has no embedded signature or
    // the native check could not run (both defer to the catalog fallback).
    private static SignatureVerdict? VerifyEmbedded(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return SignatureVerdict.Missing;
        }
        try
        {
            var result = (uint)WinVerifyTrustFile(path);
            var state = MapResult(result);
            var revocation = MapRevocation(result);
            return state switch
            {
                SignatureState.SignedTrusted => new SignatureVerdict(
                    SignatureState.SignedTrusted,
                    SignerOf(path),
                    // Asked only when the machine actually has a user-installed root, so a healthy
                    // machine pays nothing for it. WinVerifyTrust consults CurrentUser\Root, which
                    // any account writes without elevation; the verdict has to say when that is
                    // where its trust came from.
                    UserInstalledRoots.TrustsAUserInstalledRoot(path)
                        ? SignatureTrustAnchor.UserInstalledRoot
                        : SignatureTrustAnchor.MachineRoot,
                    revocation),
                SignatureState.SignedUntrusted => new SignatureVerdict(
                    SignatureState.SignedUntrusted,
                    SignerOf(path),
                    SignatureTrustAnchor.Unspecified,
                    revocation),
                // No embedded signature. Before the catalog, ask whether this file belongs to an
                // installed MSIX package: those are signed once as a package, so their executables
                // carry no embedded signature and appear in no catalog. Without this the chain ran
                // out of options and concluded "unsigned" for every Store application on the
                // machine, Microsoft's own included.
                _ => MsixPackageSignature.Verify(path), // null here still falls through to the catalog
            };
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            return null;
        }
    }

    /// <summary>
    /// Maps a WinVerifyTrust result to a verdict state, or null when the result means
    /// "no embedded signature / unknown" (the caller then tries the catalog).
    /// </summary>
    /// <remarks>
    /// <b>The three "revocation could not be checked" codes are not failures.</b> Revocation runs
    /// cache-only (see the provider flags below), so on a machine with no cached CRL or OCSP
    /// response WinVerifyTrust reports the check as undetermined rather than as a bad chain. They
    /// must map to <see cref="SignatureState.SignedTrusted"/>: falling through to
    /// <see langword="null"/> would defer a genuinely embedded-signed file to the catalog verifier,
    /// which has no entry for it, and the file would be reported <i>unsigned</i>. That would have
    /// been a false accusation against ordinary signed software on every offline machine.
    /// </remarks>
    public static SignatureState? MapResult(uint result) => result switch
    {
        0x00000000 => SignatureState.SignedTrusted,      // ERROR_SUCCESS
        0x80096010 => SignatureState.SignedUntrusted,    // TRUST_E_BAD_DIGEST (tampered)
        0x800B0004 => SignatureState.SignedUntrusted,    // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B0111 => SignatureState.SignedUntrusted,    // TRUST_E_EXPLICIT_DISTRUST
        0x800B010C => SignatureState.SignedUntrusted,    // CERT_E_REVOKED
        0x800B0101 => SignatureState.SignedUntrusted,    // CERT_E_EXPIRED
        0x800B0109 => SignatureState.SignedUntrusted,    // CERT_E_UNTRUSTEDROOT
        0x800B010A => SignatureState.SignedUntrusted,    // CERT_E_CHAINING
        0x80096004 => SignatureState.SignedUntrusted,    // TRUST_E_CERT_SIGNATURE
        0x800B010E => SignatureState.SignedTrusted,      // CERT_E_REVOCATION_FAILURE (offline)
        0x80092012 => SignatureState.SignedTrusted,      // CRYPT_E_NO_REVOCATION_CHECK
        0x80092013 => SignatureState.SignedTrusted,      // CRYPT_E_REVOCATION_OFFLINE
        0x800B0100 => null,                              // TRUST_E_NOSIGNATURE -> try catalog
        _ => null,                                       // unknown -> try catalog
    };

    /// <summary>
    /// What the same result code says about revocation.
    /// </summary>
    /// <remarks>
    /// The information was already in hand and discarded. <see cref="MapResult"/> deliberately maps
    /// the three "could not check" codes to trusted - refusing to trust ordinary signed software on
    /// every offline machine would be a false accusation - and in doing so it erased the difference
    /// between "revocation was checked" and "revocation could not be". A stolen signing certificate
    /// produces exactly the second, for months, and the report said "signature valid" either way.
    /// </remarks>
    public static RevocationStanding MapRevocation(uint result) => result switch
    {
        0x00000000 => RevocationStanding.NotRevoked,     // checked against the cache, not revoked
        0x800B010C => RevocationStanding.Revoked,        // CERT_E_REVOKED
        0x800B010E => RevocationStanding.NotChecked,     // CERT_E_REVOCATION_FAILURE
        0x80092012 => RevocationStanding.NotChecked,     // CRYPT_E_NO_REVOCATION_CHECK
        0x80092013 => RevocationStanding.NotChecked,     // CRYPT_E_REVOCATION_OFFLINE
        // Every other code is a verdict about the signature itself, and says nothing either way
        // about revocation. Claiming otherwise would put a fact in the report that was never
        // established.
        _ => RevocationStanding.Unspecified,
    };

    private static string? SignerOf(string path)
    {
        try
        {
            // X509CertificateLoader cannot extract an Authenticode signer from a
            // signed PE image; CreateFromSignedFile remains the dedicated API.
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            // No extractable signer, or the file vanished between the trust check and
            // here (TOCTOU), the verdict stands, only the signer name is absent.
            return null;
        }
    }

    // ---- WinVerifyTrust interop (stable structs only) ----

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 0x00000001;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint WtdDisableMd2Md4 = 0x2000;

    private static Guid _actionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
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
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    private static int WinVerifyTrustFile(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        var pData = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeWholeChain,
                dwUnionChoice = WtdChoiceFile,
                pFile = pFile,
                dwStateAction = WtdStateActionVerify,
                // WinSight promises no automatic outbound traffic. Microsoft documents that
                // WTD_CACHE_ONLY_URL_RETRIEVAL is required to guarantee WinVerifyTrust does not
                // fetch trust material, so revocation runs against what Windows has already
                // cached and never reaches the network. Obsolete MD2/MD4 signatures are rejected.
                // WTD_SAFER_FLAG used here before is documented as unsupported and hardened nothing.
                //
                // WTD_REVOKE_WHOLECHAIN replaces WTD_REVOKE_NONE, which had been paired with
                // WTD_REVOCATION_CHECK_NONE: revocation was switched off twice over, so the
                // CERT_E_REVOKED branch in MapResult was unreachable code and a stolen signing
                // certificate kept verifying long after it was revoked - the ordinary outcome, since
                // campaigns using stolen certificates run for months past revocation. Cache-only was
                // always enough to honour the no-network promise on its own; disabling the check as
                // well went beyond it and cost the product a real detection.
                dwProvFlags = WtdCacheOnlyUrlRetrieval
                    | WtdDisableMd2Md4,
            };
            Marshal.StructureToPtr(data, pData, false);

            var result = WinVerifyTrust(IntPtr.Zero, ref _actionGenericVerifyV2, pData);

            // Free the state data WinVerifyTrust allocated.
            data = Marshal.PtrToStructure<WinTrustData>(pData);
            data.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(data, pData, true);
            _ = WinVerifyTrust(IntPtr.Zero, ref _actionGenericVerifyV2, pData);

            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(pFile);
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pData);
        }
    }
}
