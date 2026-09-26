namespace WinSight.Core;

/// <summary>
/// Whether Windows itself ships an image: the question behind "expected" in the driver and
/// input-filter scans, asked one way in both.
/// </summary>
/// <remarks>
/// <b>Why it is an exact certificate-subject test.</b> Windows' own binaries carry the subject
/// <c>CN=Microsoft Windows</c>. Drivers that somebody else wrote and Microsoft merely attested carry
/// a longer name off the same issuer - <c>Microsoft Windows Hardware Compatibility Publisher</c>,
/// <c>... Early Launch Anti-malware Publisher</c> - every one of which a substring match on
/// "Microsoft Windows" swallows whole. Bring-your-own-vulnerable-driver attacks live in exactly that
/// gap. So the common name is compared entire, and the image must also sit inside the System32 tree:
/// a real Microsoft binary running from a download folder is a finding, not an expectation.
/// </remarks>
public static class WindowsImage
{
    /// <summary>The certificate common name Windows signs its own in-box binaries with.</summary>
    public const string SigningIdentity = "Microsoft Windows";

    /// <summary>
    /// Whether Windows itself provides <paramref name="imagePath"/>: signed by the Windows identity,
    /// chain validated to a root the machine trusts, and living inside
    /// <paramref name="systemDirectory"/>.
    /// </summary>
    /// <remarks>
    /// The system directory is passed in rather than read from the environment so the judgement
    /// stays pure and the near-miss cases can be tested. A chain that validates only through a root
    /// in the scanning account's own store does not count: any account can install one, and a
    /// certificate reading "Microsoft Windows" is trivial to mint under it.
    /// </remarks>
    public static bool IsWindowsProvided(string? imagePath, SignatureVerdict signature, string systemDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(systemDirectory);

        return signature.State == SignatureState.SignedTrusted
            && !signature.RestsOnUserInstalledTrust
            && string.Equals(
                CertificateSubject.CommonName(signature.Signer), SigningIdentity, StringComparison.OrdinalIgnoreCase)
            && IsInside(imagePath, systemDirectory);
    }

    /// <summary>
    /// Whether <paramref name="path"/> sits inside <paramref name="directory"/>. The separator is
    /// part of the comparison, so <c>System32Extra</c> is not System32.
    /// </summary>
    /// <remarks>
    /// <b>Both sides are resolved before they are compared.</b> A raw prefix test fails in both
    /// directions, and one of them fails open: <c>C:\Windows\System32\..\..\Users\Public\evil.sys</c>
    /// starts with the System32 prefix while demonstrably living in a user-writable folder, so a
    /// Microsoft-signed driver loaded from there would be filed as one Windows ships and vanish from
    /// the operator's view - which is precisely the bring-your-own-vulnerable-driver case this check
    /// exists to keep visible. The other direction is quieter: <c>C:/Windows/System32/...</c> and
    /// <c>C:\Windows\.\System32\...</c> name the same place and a literal comparison rejects both.
    ///
    /// An unresolvable path answers <c>false</c>. Failing closed is right: an image whose location
    /// cannot be established must not be presented as shipped by Windows.
    /// </remarks>
    public static bool IsInside(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        string resolvedPath;
        string root;
        try
        {
            resolvedPath = Path.GetFullPath(path);
            root = Path.GetFullPath(directory)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return resolvedPath.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }
}
