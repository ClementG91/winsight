
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

    /// <summary>
    /// A registration whose image is named by something no local path reaches (a share, a device
    /// or volume name), so it could not be verified. In-box and vendor drivers do not register
    /// their images this way.
    /// </summary>
    Unresolvable,
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
/// third-party.</b> Not calling <see cref="SignatureState.Unknown"/> an untrusted driver is the
/// project rule, but silently filing it under "third-party" would state something
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
/// opening it, so only the conditions that cannot be explained away survive it — an
/// image whose signature does not stand up, a registration whose image is gone, and one
/// whose image is registered where nothing here can reach it.
/// Signed third-party drivers stay in the full listing, where they are context.
/// </remarks>
public static class KernelDriverTriage
{
    /// <summary>The certificate common name Windows signs its own in-box drivers with.</summary>
    public const string WindowsSigningIdentity = WindowsImage.SigningIdentity;

    /// <summary>
    /// Whether Windows itself provides <paramref name="imagePath"/>: signed by the
    /// Windows identity, chain validated, and living inside
    /// <paramref name="systemDirectory"/>.
    /// </summary>
    /// <remarks>
    /// The rule moved to <see cref="WindowsImage"/> when the input-filter scan needed to ask the
    /// same question about the class drivers, which it had been answering from their names alone.
    /// This forwards, so every caller and every test here is unchanged.
    /// </remarks>
    public static bool IsWindowsProvided(string? imagePath, SignatureVerdict signature, string systemDirectory) =>
        WindowsImage.IsWindowsProvided(imagePath, signature, systemDirectory);

    /// <summary>What the driver means for the operator.</summary>
    public static KernelDriverConcern Concern(KernelDriver driver)
    {
        ArgumentNullException.ThrowIfNull(driver);

        if (driver.ImageSource == DriverImageSource.Unresolvable)
        {
            return KernelDriverConcern.Unresolvable;
        }
        if (driver.IsWindowsProvided)
        {
            return KernelDriverConcern.WindowsProvided;
        }
        return driver.Signature.State switch
        {
            SignatureState.Missing => KernelDriverConcern.Missing,
            SignatureState.Unsigned or SignatureState.SignedUntrusted => KernelDriverConcern.Untrusted,
            // Unknown means verification could not run, which is not evidence against this driver.
            // The adapter separately raises the aggregate verification-coverage gap.
            SignatureState.Unknown => KernelDriverConcern.Unverified,
            // Kernel code integrity never consults a user's root store: this chain validates only for
            // the account running the scan, which could have installed its root without privilege.
            _ when driver.Signature.RestsOnUserInstalledTrust => KernelDriverConcern.Untrusted,
            _ => KernelDriverConcern.ThirdParty,
        };
    }

    /// <summary>Whether a finding should survive the flagged-only filter.</summary>
    /// <remarks>
    /// An unresolvable image is notable although nothing was proven against it: it is the one way
    /// a registration can keep its image out of reach of every check here, and legitimate drivers
    /// have no reason to use it. Before it had its own answer it surfaced as a missing image - or,
    /// when a same-named file existed in System32\drivers, as that file.
    /// </remarks>
    public static bool IsNotable(KernelDriverConcern concern) =>
        concern is KernelDriverConcern.Untrusted or KernelDriverConcern.Missing or KernelDriverConcern.Unresolvable;

    /// <summary>
    /// The common name from an X.500 certificate subject, or null when there is none.
    /// </summary>
    /// <remarks>
    /// The careful parsing moved to <see cref="CertificateSubject"/> when a second scan needed the
    /// same question asked the same way. This forwards, so every caller and every test here is
    /// unchanged, and there is exactly one implementation to be right.
    /// </remarks>
    public static string? SignerCommonName(string? subject) =>
        CertificateSubject.CommonName(subject);
}
