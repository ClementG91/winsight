using System.Security.AccessControl;
using System.Security.Principal;

namespace WinSight.Hijack;

/// <summary>
/// Answers "could an <i>unprivileged</i> principal create a file in this directory" by reading the
/// directory's DACL, for the case where creating one with the current token would answer a
/// different question entirely.
/// </summary>
/// <remarks>
/// <b>Why this exists.</b> <see cref="WritabilityProbe"/> answers by really creating a file, which
/// is the right method — effective access on Windows is the sum of inherited allow and deny entries
/// across every group in the token, plus privileges that override both, and reconstructing that
/// from a security descriptor is where this kind of check quietly gets it wrong. But it answers for
/// <i>the current token</i>. Run elevated — which is the mode WinSight recommends for attribution
/// and for scheduled tasks — an administrator can create a file in <c>C:\</c>, in
/// <c>C:\Program Files</c>, in <c>System32</c> and in every machine PATH entry. Every unquoted
/// service path then graded Exploitable, every service directory writable, every PATH entry
/// reported. The measurement the design rests on ("18 PATH entries and 88 services, none writable")
/// only holds in a non-elevated session.
///
/// <b>Why the DACL, here specifically.</b> The real-attempt argument does not survive the change of
/// question: WinSight cannot create a file <i>as somebody else</i> without impersonating a token it
/// has no business fabricating. Reading the ACL is what remains, so it is done narrowly and
/// conservatively rather than generally.
///
/// <b>Conservative by construction.</b> A grant is claimed only when an explicit Allow gives a
/// file-creating right to one of the well-known unprivileged principals and no Deny takes it back.
/// Anything it cannot read or cannot parse is <see langword="false"/>, because an unproven "yes" is
/// a false accusation against installed software — the same rule the real-attempt probe follows.
/// </remarks>
public static class UnprivilegedWriteAccess
{
    /// <summary>
    /// Principals that stand for "anyone with a session on this machine". A grant to any of these
    /// is a grant to an attacker who has landed as a standard user.
    /// </summary>
    /// <remarks>
    /// Deliberately excludes <c>Administrators</c> and <c>SYSTEM</c>: those are supposed to be able
    /// to write here, and counting them would reproduce the very false positive this fixes.
    /// </remarks>
    private static readonly WellKnownSidType[] UnprivilegedPrincipals =
    [
        WellKnownSidType.BuiltinUsersSid,          // S-1-5-32-545
        WellKnownSidType.AuthenticatedUserSid,     // S-1-5-11
        WellKnownSidType.WorldSid,                 // S-1-1-0
        WellKnownSidType.InteractiveSid,           // S-1-5-4
    ];

    // The rights that let somebody place a new file (or a new directory) in this one. WriteData and
    // CreateFiles are the same bit on a directory; both spellings are listed because a descriptor
    // may carry either, and GenericWrite maps onto this set.
    private const FileSystemRights PlantingRights =
        FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories | FileSystemRights.Write;

    /// <summary>
    /// Whether an unprivileged principal is granted a file-creating right on
    /// <paramref name="directory"/>. False whenever that cannot be established.
    /// </summary>
    public static bool IsGrantedIn(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }
        try
        {
            var security = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Access);
            return IsGrantedBy(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or IOException
                                     or PlatformNotSupportedException
                                     or NotSupportedException
                                     or ArgumentException
                                     or System.Security.SecurityException)
        {
            // A descriptor WinSight cannot read is not evidence of anything.
            return false;
        }
    }

    /// <summary>
    /// The decision itself, over a descriptor rather than a path, so it is testable against
    /// constructed ACLs without needing a directory whose real ACL says the right thing.
    /// </summary>
    public static bool IsGrantedBy(FileSystemSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);

        var principals = ResolvePrincipals();
        if (principals.Count == 0)
        {
            return false;
        }

        AuthorizationRuleCollection rules;
        try
        {
            rules = security.GetAccessRules(
                includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        }
        catch (Exception ex) when (ex is InvalidOperationException or IdentityNotMappedException)
        {
            return false;
        }

        var allowed = false;
        foreach (var rule in rules)
        {
            if (rule is not FileSystemAccessRule access
                || access.IdentityReference is not SecurityIdentifier sid
                || !principals.Contains(sid)
                || (access.FileSystemRights & PlantingRights) == 0)
            {
                continue;
            }

            // Deny is evaluated after every Allow rather than in ACE order. Canonical ACLs put deny
            // first anyway, and a non-canonical one is exactly where an order-sensitive reading
            // would produce the confident wrong answer this check must not make.
            if (access.AccessControlType == AccessControlType.Deny)
            {
                return false;
            }
            allowed = true;
        }
        return allowed;
    }

    private static HashSet<SecurityIdentifier> ResolvePrincipals()
    {
        var principals = new HashSet<SecurityIdentifier>();
        foreach (var wellKnown in UnprivilegedPrincipals)
        {
            try
            {
                principals.Add(new SecurityIdentifier(wellKnown, null));
            }
            catch (Exception ex) when (ex is ArgumentException or PlatformNotSupportedException)
            {
                // A SID this platform does not define simply is not consulted.
            }
        }
        return principals;
    }
}
