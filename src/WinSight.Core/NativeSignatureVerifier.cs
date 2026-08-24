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

        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var verdict = VerifyEmbedded(path);
            if (verdict is { } v)
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
            var state = MapResult((uint)WinVerifyTrustFile(path));
            return state switch
            {
                SignatureState.SignedTrusted => new SignatureVerdict(SignatureState.SignedTrusted, SignerOf(path)),
                SignatureState.SignedUntrusted => new SignatureVerdict(SignatureState.SignedUntrusted, SignerOf(path)),
                _ => null, // NOSIGNATURE / unknown -> catalog fallback
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
        0x800B0100 => null,                              // TRUST_E_NOSIGNATURE -> try catalog
        _ => null,                                       // unknown -> try catalog
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
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
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
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = pFile,
                dwStateAction = WtdStateActionVerify,
                // WinSight promises no automatic outbound traffic. Microsoft documents that
                // WTD_CACHE_ONLY_URL_RETRIEVAL is required to guarantee WinVerifyTrust does not
                // fetch trust material. Revocation is therefore explicitly cache-only/offline,
                // while obsolete MD2/MD4 signatures are rejected. WTD_SAFER_FLAG used here before
                // this change is documented as unsupported and provided no hardening.
                dwProvFlags = WtdRevocationCheckNone
                    | WtdCacheOnlyUrlRetrieval
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
