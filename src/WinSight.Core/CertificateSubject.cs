using System.Text;

namespace WinSight.Core;

/// <summary>
/// Reading an X.500 certificate subject, and recognising Microsoft's own code-signing identities.
/// </summary>
/// <remarks>
/// Extracted from the kernel-driver triage, which is where the careful version of this parsing was
/// written and where it stayed. A second scan needed the same question - "who actually signed this,
/// compared exactly" - and the honest answer was to share the implementation rather than write a
/// looser one beside it. <c>KernelDriverTriage.SignerCommonName</c> now forwards here, so its
/// callers and its tests are untouched.
/// </remarks>
public static class CertificateSubject
{
    /// <summary>
    /// The code-signing common names Microsoft uses for software it wrote.
    /// </summary>
    /// <remarks>
    /// <b>An exact allowlist, deliberately, and not a substring match.</b> A subject containing
    /// "Microsoft Windows" is not the same as a subject equal to it: Microsoft attests third-party
    /// code under longer names off the same issuer - <c>Microsoft Windows Hardware Compatibility
    /// Publisher</c>, <c>… Hardware Abstraction Layer Publisher</c>, <c>… Early Launch Anti-malware
    /// Publisher</c> - and every one of those means "somebody else wrote this and Microsoft signed
    /// it". A substring test swallows them whole, which is the gap bring-your-own-vulnerable-driver
    /// attacks live in.
    ///
    /// <c>Microsoft Windows</c> and <c>Microsoft Windows Publisher</c> sign in-box components;
    /// <c>Microsoft Corporation</c> signs Microsoft products that ship separately. All three are
    /// Microsoft's own code, which is the question being asked.
    /// </remarks>
    private static readonly HashSet<string> MicrosoftSigningIdentities =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Windows",
            "Microsoft Windows Publisher",
            "Microsoft Corporation",
        };

    /// <summary>
    /// The common name from an X.500 certificate subject, or null when there is none.
    /// </summary>
    /// <remarks>
    /// The whole point of reading the subject is to compare the common name <i>entire</i>, so this
    /// stops at the attribute boundary rather than matching loosely: quoted values may contain the
    /// comma that otherwise ends an attribute, and a backslash escapes the character after it.
    /// <c>CN=</c> is only honoured where an attribute may start, so a subject such as
    /// <c>O=ACN=Ltd</c> cannot smuggle one in.
    /// </remarks>
    public static string? CommonName(string? subject)
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

    /// <summary>
    /// Whether <paramref name="signature"/> is a trust-validated signature by Microsoft itself.
    /// </summary>
    /// <remarks>
    /// Trust must have been established, and it must not rest on a root any account can install -
    /// a certificate whose common name reads "Microsoft Corporation" is trivial to mint, and only
    /// the chain makes the name mean anything.
    /// </remarks>
    public static bool IsMicrosoft(SignatureVerdict signature) =>
        signature.State == SignatureState.SignedTrusted
            && !signature.RestsOnUserInstalledTrust
            && CommonName(signature.Signer) is { } name
            && MicrosoftSigningIdentities.Contains(name);

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
}
