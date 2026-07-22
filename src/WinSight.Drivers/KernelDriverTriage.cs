using System.Text;

using WinSight.Core;

namespace WinSight.Drivers;

/// <summary>How much attention a registered kernel driver deserves.</summary>
public enum KernelDriverConcern
{
    /// <summary>Windows ships this image itself. Expected on every machine.</summary>
    WindowsProvided,

    /// <summary>A driver signed by somebody other than Windows. Context, not alarm.</summary>
    ThirdParty,

    /// <summary>Kernel code that is unsigned, or whose chain did not validate.</summary>
    Untrusted,

    /// <summary>Verification could not be completed, so nothing is known either way.</summary>
    Unverified,

    /// <summary>A driver registration whose image file is not on disk.</summary>
    Missing,
}

/// <summary>
/// Decides what a registered kernel driver means. Pure, so the judgement can be argued
/// with in tests rather than only observed on a live machine.
/// </summary>
/// <remarks>
/// <b>Why the kernel is worth a scanner of its own.</b> A driver runs with the same
/// authority as Windows itself: it can hide files from every enumeration WinSight
/// performs, unlink its own process from the list, and read any memory on the machine.
/// That is precisely why a rootkit ends up here, and why an unsigned driver is the
/// loudest single thing this program can find. Everything above the kernel can be made
/// to lie; the registration that loaded the liar usually cannot.
///
/// <b>Why there is no vendor allowlist.</b> Storage, GPU, audio, VPN and anti-cheat
/// vendors all legitimately ship kernel drivers, and it is tempting to hard-code the
/// familiar names as benign. Nothing stops a rootkit calling itself <c>nvlddmkm</c>.
/// Only cryptographic standing and provenance decide anything here; the name is a label.
///
/// <b>Why "Windows ships this" is an exact certificate-subject test.</b> Windows' own
/// drivers carry the subject <c>CN=Microsoft Windows</c>. Drivers that somebody else
/// wrote and Microsoft merely attested carry a longer name off the same issuer —
/// <c>Microsoft Windows Hardware Compatibility Publisher</c>, <c>… Hardware Abstraction
/// Layer Publisher</c>, <c>… Early Launch Anti-malware Publisher</c> — every one of which
/// a substring match on "Microsoft Windows" swallows whole. Bring-your-own-vulnerable-
/// driver attacks live in exactly that gap: a genuinely Microsoft-attested driver, loaded
/// on purpose for what it lets an attacker do. So the common name is compared entire, and
/// the image must also sit inside the System32 tree — a real Microsoft driver running
/// from a download folder is a finding, not an expectation.
///
/// <b>Why an unverifiable driver gets its own answer rather than being called
/// third-party.</b> Not flagging <see cref="SignatureState.Unknown"/> is the project rule
/// and it holds here, but silently filing it under "third-party" would state something
/// that was never established. It also hides a condition worth seeing: when catalog
/// verification stops working on a machine, it stops for *every* catalog-signed file at
/// once, and the two genuinely unsigned drivers found on the development machine
/// disappeared into that fog until it was cleared. An operator who sees a few hundred
/// unverifiable drivers is looking at a broken verifier, not a clean machine, and the
/// report should let them tell the difference.
///
/// <b>Why signed third-party drivers are listed but not flagged.</b> The input-filter
/// scan flags every driver Windows did not install, because that list is two lines long.
/// This one is several hundred: every disk, display and network component registers a
/// driver. A flagged view that answers with eighty rows teaches the operator to stop
/// opening it, so only the two conditions that cannot be explained away survive it — an
/// image whose signature does not stand up, and a registration whose image is gone.
/// Signed third-party drivers stay in the full listing, where they are context.
/// </remarks>
public static class KernelDriverTriage
{
    /// <summary>The certificate common name Windows signs its own in-box drivers with.</summary>
    public const string WindowsSigningIdentity = "Microsoft Windows";

    /// <summary>
    /// Whether Windows itself provides <paramref name="imagePath"/>: signed by the
    /// Windows identity, chain validated, and living inside
    /// <paramref name="systemDirectory"/>.
    /// </summary>
    /// <remarks>
    /// The system directory is passed in rather than read from the environment so the
    /// whole judgement stays pure and the near-miss cases can be tested. Callers supply
    /// a fully-qualified path; no normalisation happens here.
    /// </remarks>
    public static bool IsWindowsProvided(string? imagePath, SignatureVerdict signature, string systemDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(systemDirectory);

        return signature.State == SignatureState.SignedTrusted
            && string.Equals(SignerCommonName(signature.Signer), WindowsSigningIdentity, StringComparison.OrdinalIgnoreCase)
            && IsInside(imagePath, systemDirectory);
    }

    /// <summary>What the driver means for the operator.</summary>
    public static KernelDriverConcern Concern(KernelDriver driver)
    {
        ArgumentNullException.ThrowIfNull(driver);

        if (driver.IsWindowsProvided)
        {
            return KernelDriverConcern.WindowsProvided;
        }
        return driver.Signature.State switch
        {
            SignatureState.Missing => KernelDriverConcern.Missing,
            SignatureState.Unsigned or SignatureState.SignedUntrusted => KernelDriverConcern.Untrusted,
            // Unknown means verification could not run, which is not evidence of anything. Treating
            // it as suspicious would cry wolf on files WinSight simply failed to check.
            SignatureState.Unknown => KernelDriverConcern.Unverified,
            _ => KernelDriverConcern.ThirdParty,
        };
    }

    /// <summary>Whether a finding should survive the flagged-only filter.</summary>
    public static bool IsNotable(KernelDriverConcern concern) =>
        concern is KernelDriverConcern.Untrusted or KernelDriverConcern.Missing;

    /// <summary>
    /// The common name from an X.500 certificate subject, or null when there is none.
    /// </summary>
    /// <remarks>
    /// The whole point of reading the subject is to compare the common name *entire*, so
    /// this stops at the attribute boundary rather than matching loosely: quoted values
    /// may contain the comma that otherwise ends an attribute, and a backslash escapes
    /// the character after it. <c>CN=</c> is only honoured where an attribute may start,
    /// so a subject such as <c>O=ACN=Ltd</c> cannot smuggle one in.
    /// </remarks>
    public static string? SignerCommonName(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }

        var start = AttributeStart(subject);
        if (start < 0)
        {
            return null;
        }

        var value = new StringBuilder();
        var index = start;
        var quoted = index < subject.Length && subject[index] == '"';
        if (quoted)
        {
            index++;
        }
        for (; index < subject.Length; index++)
        {
            var character = subject[index];
            if (character == '\\' && index + 1 < subject.Length)
            {
                value.Append(subject[++index]);
                continue;
            }
            if (quoted ? character == '"' : character is ',' or '+')
            {
                break;
            }
            value.Append(character);
        }
        return value.ToString().Trim() is { Length: > 0 } commonName ? commonName : null;
    }

    /// <summary>Index just past the first <c>CN=</c> that genuinely starts an attribute.</summary>
    private static int AttributeStart(string subject)
    {
        const string marker = "CN=";
        for (var search = 0; search <= subject.Length - marker.Length;)
        {
            var found = subject.IndexOf(marker, search, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
            {
                return -1;
            }
            var preceding = subject[..found].AsSpan().TrimEnd();
            if (preceding.IsEmpty || preceding[^1] is ',' or '+')
            {
                return found + marker.Length;
            }
            search = found + marker.Length;
        }
        return -1;
    }

    /// <summary>
    /// Whether <paramref name="path"/> sits inside <paramref name="directory"/>. The
    /// separator is part of the comparison, so <c>System32Extra</c> is not System32.
    /// </summary>
    /// <remarks>
    /// <b>Both sides are resolved before they are compared.</b> A raw prefix test fails in both
    /// directions, and one of them fails open: <c>C:\Windows\System32\..\..\Users\Public\evil.sys</c>
    /// starts with the System32 prefix while demonstrably living in a user-writable folder, so a
    /// Microsoft-signed driver loaded from there would be filed as one Windows ships and vanish from
    /// the operator's view — which is precisely the bring-your-own-vulnerable-driver case this check
    /// exists to keep visible. The other direction is quieter: <c>C:/Windows/System32/...</c> and
    /// <c>C:\Windows\.\System32\...</c> name the same place and a literal comparison rejects both,
    /// adding an in-box driver to a list several hundred rows long.
    ///
    /// <see cref="KernelDriverScanner"/> already calls <see cref="Path.GetFullPath(string)"/> before
    /// reaching here, so nothing was exploitable through it. That made the rule safe by a caller's
    /// habit rather than by its own construction, and this method is public.
    ///
    /// An unresolvable path answers <c>false</c>. Failing closed is right: a driver whose location
    /// cannot be established must not be presented as shipped by Windows. It then falls through to
    /// the signature-based verdict, where it is reported as context instead of hidden.
    /// </remarks>
    private static bool IsInside(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path))
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
