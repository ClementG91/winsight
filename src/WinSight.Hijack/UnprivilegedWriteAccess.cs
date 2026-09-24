using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

using Microsoft.Win32.SafeHandles;

using WinSight.Core;

namespace WinSight.Hijack;

/// <summary>What a writability question is about: a new file, or a new subdirectory.</summary>
/// <remarks>
/// Windows grants the two separately (<c>FILE_ADD_FILE</c> and <c>FILE_ADD_SUBDIRECTORY</c>), and
/// the default ACL on the system drive root grants a standard user the second and not the first.
/// </remarks>
public enum PlantedObject
{
    File,
    Directory,
}

/// <summary>How a writability answer was reached.</summary>
public enum WriteAccessEvaluation
{
    /// <summary>Windows <c>AccessCheck</c> with the current user's complete non-elevated token.</summary>
    EffectiveAccess,

    /// <summary>
    /// The DACL and owner read for the well-known unprivileged groups (Users, Authenticated Users,
    /// Everyone, Interactive), because the process has no non-elevated token to ask Windows about:
    /// SYSTEM, a service account, or an administrator with UAC disabled.
    /// </summary>
    WellKnownPrincipals,
}

/// <summary>
/// Answers whether the current interactive user, with elevation removed, can create an object in a
/// directory. Production uses Windows <c>AccessCheck</c> with the complete token and exact DACL.
/// </summary>
/// <remarks>
/// <b>Why Windows is asked.</b> Effective access is the sum of inherited allow and deny entries
/// across every group in the token, plus privileges that override both, and reconstructing that
/// from a security descriptor is where this kind of check quietly gets it wrong. <c>AccessCheck</c>
/// performs the evaluation Windows itself performs. It replaced creating and deleting a probe file,
/// which answered the same question but wrote into <c>Program Files</c>, service directories and
/// PATH entries on every scan.
///
/// <b>Why the non-elevated token.</b> Elevated, the process token can create a file in <c>C:\</c>,
/// in <c>Program Files</c> and in <c>System32</c>: every unquoted service path would grade
/// Exploitable. The question is what an attacker who landed as this user could do, so an elevated
/// token is exchanged for its linked, filtered one.
///
/// <b>Without such a token</b> - SYSTEM, a service account, an administrator with UAC disabled - the
/// DACL is read for the well-known unprivileged groups instead (<see cref="IsGrantedBy(FileSystemSecurity, PlantedObject)"/>).
/// That model claims a grant only when an explicit Allow gives the right to one of those groups on
/// the directory itself and no Deny takes it back, or when one of them owns the directory or may
/// take it, and the answer says which method produced it.
///
/// <b>A right to plant includes the rights that grant it.</b> WRITE_DAC lets its holder add the
/// create right to the DACL, and WRITE_OWNER lets them become the owner, who holds WRITE_DAC without
/// any entry granting it. An explicit Deny does not take the owner's WRITE_DAC away; an OWNER RIGHTS
/// entry does, by stating what the owner holds instead (both measured on Windows 11 26200). Asking
/// Windows about the create right alone read a directory a standard user owns - created by them,
/// then locked down by an administrator who kept the owner - as not plantable by the very user who
/// can reopen it. Both methods now count all three, and honour OWNER RIGHTS.
///
/// <b>The mandatory label is part of the answer.</b> A directory labelled above Medium refuses a
/// standard user's token every write, whatever its DACL grants. The descriptor is read with its
/// label: <c>AccessCheck</c> applies it, and the well-known-group model refuses such a directory.
///
/// <b>Conservative either way.</b> Anything that cannot be read or evaluated is
/// <see langword="false"/> and counted as unreadable, because an unproven "yes" is a false
/// accusation against installed software.
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

    // The right that lets somebody place a new file, or a new subdirectory, in a directory. On a
    // directory WriteData is CreateFiles (FILE_ADD_FILE) and AppendData is CreateDirectories
    // (FILE_ADD_SUBDIRECTORY). They were one set, and they are not interchangeable: the default ACL
    // on the system drive root grants Authenticated Users CreateDirectories and nothing that creates
    // a file, so reading either bit as "can plant a file" graded C:\Program.exe - the first candidate
    // of every unquoted service path - as creatable by a standard user who cannot create it.
    //
    // GenericWrite does not map onto these bits on its own. The generic bits live in the high word
    // and share nothing with the specific rights, so an ACE granting Users GENERIC_WRITE - what
    // `icacls /grant Users:(GW)` and an SDDL `GW` produce - read as granting no planting right at
    // all, and a real DLL side-loading point was reported as safe. Every mask is expanded through
    // the file generic mapping first.
    private static FileSystemRights PlantingRights(PlantedObject planted) => planted == PlantedObject.Directory
        ? FileSystemRights.CreateDirectories
        : FileSystemRights.CreateFiles;

    /// <summary>OWNER RIGHTS (S-1-3-4): entries for it replace the owner's implicit rights.</summary>
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    /// <summary>
    /// Whether an unprivileged principal is granted a file-creating right on
    /// <paramref name="directory"/>. False whenever that cannot be established.
    /// </summary>
    public static bool IsGrantedIn(string directory) => IsGrantedIn(directory, PlantedObject.File);

    /// <summary>
    /// Whether an unprivileged principal is granted the right to create <paramref name="planted"/>
    /// in <paramref name="directory"/>. False whenever that cannot be established.
    /// </summary>
    public static bool IsGrantedIn(string directory, PlantedObject planted) =>
        TryIsGrantedIn(directory, planted, out var granted) && granted;

    /// <summary>
    /// Evaluates the directory DACL with the complete non-elevated current token. Returns false
    /// when the descriptor or a suitable token cannot be acquired; <paramref name="granted"/> then
    /// carries no evidence and remains false.
    /// </summary>
    public static bool TryIsGrantedIn(
        string directory,
        PlantedObject planted,
        out bool granted) =>
        TryIsGrantedIn(directory, planted, out granted, out _);

    /// <summary>
    /// As <see cref="TryIsGrantedIn(string, PlantedObject, out bool)"/>, and says which method
    /// produced the answer.
    /// </summary>
    /// <remarks>
    /// <b>Why there is a second method at all.</b> <c>AccessCheck</c> needs a token to ask about,
    /// and the honest one is the current user's with elevation removed. SYSTEM, a service account
    /// and an administrator with UAC disabled have no such token - and that is exactly how a
    /// scheduled scan runs. Refusing to answer there made the scan report nothing in the context it
    /// is most often automated in. Those processes fall back to reading the DACL for the well-known
    /// unprivileged groups: narrower than a real user's token (a grant to one named user is not
    /// seen) and conservative in the same direction, never claiming a grant it cannot show.
    /// </remarks>
    public static bool TryIsGrantedIn(
        string directory,
        PlantedObject planted,
        out bool granted,
        out WriteAccessEvaluation evaluation)
    {
        granted = false;
        evaluation = WriteAccessEvaluation.EffectiveAccess;
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }
        try
        {
            var descriptor = AutomaticFileAccess.TryReadDirectorySecurityDescriptor(directory);
            return descriptor is not null
                && TryIsGrantedByDescriptor(descriptor, planted, out granted, out evaluation);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or IOException
                                     or PlatformNotSupportedException
                                     or NotSupportedException
                                     or ArgumentException
                                     or System.Security.SecurityException)
        {
            // A descriptor WinSight cannot read is not evidence of anything.
            granted = false;
            return false;
        }
    }

    /// <summary>
    /// The decision over a self-relative security descriptor as read from a directory handle
    /// (owner, group and DACL), by whichever method the current token allows.
    /// </summary>
    internal static bool TryIsGrantedByDescriptor(
        byte[] descriptor,
        PlantedObject planted,
        out bool granted,
        out WriteAccessEvaluation evaluation)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        granted = false;
        evaluation = WriteAccessEvaluation.EffectiveAccess;
        var state = TryOpenUnprivilegedImpersonationToken(out var token);
        using (token)
        {
            switch (state)
            {
                case TokenState.Available when token is { IsInvalid: false }:
                    return TryAccessCheck(descriptor, token, planted, out granted);
                case TokenState.PrivilegedUnsplit:
                    evaluation = WriteAccessEvaluation.WellKnownPrincipals;
                    granted = IsGrantedByDescriptor(descriptor, planted);
                    return true;
                default:
                    return false;
            }
        }
    }

    /// <summary>
    /// The well-known-group decision over a self-relative security descriptor, as read from a
    /// directory handle.
    /// </summary>
    internal static bool IsGrantedByDescriptor(byte[] descriptor, PlantedObject planted)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (LabelAboveMedium(descriptor))
        {
            return false;
        }
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(
            descriptor, AccessControlSections.Access | AccessControlSections.Owner);
        return IsGrantedBy(security, planted);
    }

    /// <summary>
    /// Whether the directory itself carries a mandatory label above Medium, the integrity level of a
    /// standard user's token.
    /// </summary>
    /// <remarks>
    /// Such a label refuses that token every write - the create rights, WRITE_DAC and WRITE_OWNER,
    /// owner or not - whatever the DACL grants and whatever flags the label carries, because every
    /// standard token has its own no-write-up policy (measured with <c>AccessCheck</c>, which applies
    /// the label by itself; the well-known-group model has to be told). A label that only describes
    /// children does not apply to the directory.
    /// </remarks>
    private static bool LabelAboveMedium(byte[] descriptor)
    {
        var sacl = new RawSecurityDescriptor(descriptor, 0).SystemAcl;
        if (sacl is null)
        {
            return false;
        }
        foreach (var ace in sacl)
        {
            // .NET has no type for SYSTEM_MANDATORY_LABEL_ACE and hands it back as a custom entry
            // whose data is the policy mask followed by the label SID, S-1-16-<level>.
            if ((int)ace.AceType != SystemMandatoryLabelAceType
                || (ace.AceFlags & AceFlags.InheritOnly) != 0
                || ace is not CustomAce label
                || label.GetOpaque() is not { Length: >= sizeof(uint) + LabelSidBytes } data)
            {
                continue;
            }
            var parts = new SecurityIdentifier(data, sizeof(uint)).Value.Split('-');
            if (parts is [_, _, "16", var level]
                && uint.TryParse(level, out var integrity)
                && integrity > MediumIntegrityLevel)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// The decision itself, over a descriptor rather than a path, so it is testable against
    /// constructed ACLs without needing a directory whose real ACL says the right thing.
    /// </summary>
    public static bool IsGrantedBy(FileSystemSecurity security) => IsGrantedBy(security, PlantedObject.File);

    /// <summary>
    /// The decision for <paramref name="planted"/>, over a descriptor rather than a path.
    /// </summary>
    public static bool IsGrantedBy(FileSystemSecurity security, PlantedObject planted)
    {
        ArgumentNullException.ThrowIfNull(security);
        // What plants directly, or lets its holder grant itself what plants.
        var enabling = PlantingRights(planted) | FileSystemRights.ChangePermissions;
        var relevant = enabling | FileSystemRights.TakeOwnership;

        var principals = ResolvePrincipals();
        if (principals.Count == 0)
        {
            return false;
        }

        AuthorizationRuleCollection rules;
        SecurityIdentifier? owner;
        try
        {
            rules = security.GetAccessRules(
                includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
            owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IdentityNotMappedException)
        {
            return false;
        }

        FileSystemRights allowed = 0, denied = 0, ownerAllowed = 0, ownerDenied = 0;
        var ownerRightsNamed = false;
        foreach (var rule in rules)
        {
            if (rule is not FileSystemAccessRule access
                || access.IdentityReference is not SecurityIdentifier sid)
            {
                continue;
            }
            var forOwner = sid.Equals(OwnerRights);
            // Any OWNER RIGHTS entry, even one that only describes children, is taken to replace the
            // owner's implicit rights: that reading can only understate what ownership gives.
            ownerRightsNamed |= forOwner;

            // An inherit-only entry describes what children of this directory will receive; it
            // grants nothing on the directory itself. The system drive root carries exactly such an
            // entry - Authenticated Users, Modify, inherit only - and reading it as a grant on C:\
            // is the other half of the false "C:\Program.exe is plantable" verdict above.
            if ((access.PropagationFlags & PropagationFlags.InheritOnly) != 0
                || !(forOwner || principals.Contains(sid)))
            {
                continue;
            }

            // Deny is evaluated after every Allow rather than in ACE order. Canonical ACLs put deny
            // first anyway, and a non-canonical one is exactly where an order-sensitive reading
            // would produce the confident wrong answer this check must not make.
            var rights = GenericFileRights.Expand(access.FileSystemRights) & relevant;
            var deny = access.AccessControlType == AccessControlType.Deny;
            if (forOwner && deny)
            {
                ownerDenied |= rights;
            }
            else if (forOwner)
            {
                ownerAllowed |= rights;
            }
            else if (deny)
            {
                denied |= rights;
            }
            else
            {
                allowed |= rights;
            }
        }

        var held = allowed & ~denied;
        if ((held & enabling) != 0)
        {
            return true;
        }

        // Ownership - held by one of these groups, or taken by one allowed WRITE_OWNER - gives
        // WRITE_DAC without any entry granting it, and a Deny does not take that back. An OWNER
        // RIGHTS entry does: the owner then holds what those entries grant, less anything a Deny to
        // these groups removes.
        var ownership = ownerRightsNamed
            ? ownerAllowed & ~ownerDenied & ~denied
            : FileSystemRights.ChangePermissions;
        if ((ownership & enabling) == 0)
        {
            return false;
        }
        return (held & FileSystemRights.TakeOwnership) != 0
            || (owner is not null && principals.Contains(owner));
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

    private enum TokenState
    {
        Available,
        PrivilegedUnsplit,
        Unavailable,
    }

    private static TokenState TryOpenUnprivilegedImpersonationToken(out SafeAccessTokenHandle? token)
    {
        token = null;
        if (!OpenProcessToken(
                GetCurrentProcess(),
                TokenQuery | TokenDuplicate,
                out var processToken))
        {
            return TokenState.Unavailable;
        }
        using (processToken)
        {
            SafeAccessTokenHandle? linked = null;
            try
            {
                var source = processToken;
                if (!GetTokenInformation(
                        processToken,
                        TokenElevationTypeClass,
                        out int elevationType,
                        sizeof(int),
                        out _))
                {
                    return TokenState.Unavailable;
                }
                if (elevationType == TokenElevationTypeFull)
                {
                    if (!GetTokenInformation(
                            processToken,
                            TokenLinkedTokenClass,
                            out TokenLinkedToken linkedInfo,
                            Marshal.SizeOf<TokenLinkedToken>(),
                            out _))
                    {
                        return TokenState.Unavailable;
                    }
                    linked = new SafeAccessTokenHandle(linkedInfo.Handle);
                    source = linked;
                }
                else if (elevationType == TokenElevationTypeDefault
                         && IsPrivilegedUnsplitToken(processToken))
                {
                    // SYSTEM/service and UAC-disabled administrator tokens have no honest
                    // standard-user counterpart, and evaluating their powerful token would accuse
                    // every protected directory. The caller falls back to the well-known
                    // unprivileged groups instead of fabricating a token.
                    return TokenState.PrivilegedUnsplit;
                }
                if (!DuplicateToken(source, SecurityImpersonation, out var impersonation))
                {
                    return TokenState.Unavailable;
                }
                token = impersonation;
                return TokenState.Available;
            }
            finally
            {
                linked?.Dispose();
            }
        }
    }

    private static bool IsPrivilegedUnsplitToken(SafeAccessTokenHandle token)
    {
        using var identity = new WindowsIdentity(token.DangerousGetHandle());
        if (identity.User is { } user
            && (user.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || user.IsWellKnown(WellKnownSidType.LocalServiceSid)
                || user.IsWellKnown(WellKnownSidType.NetworkServiceSid)))
        {
            return true;
        }
        return identity.Groups?.Any(group =>
            group is SecurityIdentifier sid
            && sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) == true;
    }

    private static bool TryAccessCheck(
        byte[] descriptor,
        SafeAccessTokenHandle token,
        PlantedObject planted,
        out bool granted)
    {
        granted = false;
        // What plants directly, or lets the user grant themselves what plants.
        var enabling = DesiredAccess(planted) | WriteDac;
        if (!TryMaximumAllowed(descriptor, token, out var access))
        {
            return false;
        }
        if ((access & enabling) == 0 && (access & WriteOwner) != 0)
        {
            // WRITE_OWNER lets the user make themselves the owner, who holds WRITE_DAC unless an
            // OWNER RIGHTS entry says otherwise. Windows is asked again about the descriptor as it
            // would read after that step, rather than this code guessing what ownership gives.
            var owned = AsOwnedBy(descriptor, token);
            if (owned is null || !TryMaximumAllowed(owned, token, out access))
            {
                return false;
            }
        }
        granted = (access & enabling) != 0;
        return true;
    }

    /// <summary>
    /// The descriptor as it would read after the token's user made itself the owner, which
    /// WRITE_OWNER allows without any privilege.
    /// </summary>
    private static byte[]? AsOwnedBy(byte[] descriptor, SafeAccessTokenHandle token)
    {
        using var identity = new WindowsIdentity(token.DangerousGetHandle());
        if (identity.User is not { } user)
        {
            return null;
        }
        var owned = new RawSecurityDescriptor(descriptor, 0) { Owner = user };
        var bytes = new byte[owned.BinaryLength];
        owned.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>
    /// Every right the token holds on the descriptor (<c>MAXIMUM_ALLOWED</c>), including the owner's
    /// implicit WRITE_DAC, which a question about the create right alone never reports.
    /// </summary>
    private static bool TryMaximumAllowed(byte[] descriptor, SafeAccessTokenHandle token, out uint access)
    {
        access = 0;
        var mapping = new GenericMapping
        {
            GenericRead = FileGenericRead,
            GenericWrite = FileGenericWrite,
            GenericExecute = FileGenericExecute,
            GenericAll = FileAllAccess,
        };
        var descriptorHandle = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        var privileges = IntPtr.Zero;
        try
        {
            uint privilegeBytes = InitialPrivilegeSetBytes;
            privileges = Marshal.AllocHGlobal(checked((int)privilegeBytes));
            if (!AccessCheck(
                    descriptorHandle.AddrOfPinnedObject(),
                    token,
                    MaximumAllowed,
                    ref mapping,
                    privileges,
                    ref privilegeBytes,
                    out var grantedAccess,
                    out var accessStatus))
            {
                if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer
                    || privilegeBytes > MaximumPrivilegeSetBytes)
                {
                    return false;
                }
                Marshal.FreeHGlobal(privileges);
                // Cleared first: if the new allocation throws, the finally must not free this again.
                privileges = IntPtr.Zero;
                privileges = Marshal.AllocHGlobal(checked((int)privilegeBytes));
                if (!AccessCheck(
                        descriptorHandle.AddrOfPinnedObject(),
                        token,
                        MaximumAllowed,
                        ref mapping,
                        privileges,
                        ref privilegeBytes,
                        out grantedAccess,
                        out accessStatus))
                {
                    return false;
                }
            }
            access = accessStatus ? grantedAccess : 0;
            return true;
        }
        finally
        {
            if (privileges != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(privileges);
            }
            descriptorHandle.Free();
        }
    }

    private static uint DesiredAccess(PlantedObject planted) =>
        planted == PlantedObject.Directory ? FileAddSubdirectory : FileAddFile;

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenLinkedToken
    {
        public IntPtr Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const int TokenElevationTypeClass = 18;
    private const int TokenLinkedTokenClass = 19;
    private const int TokenElevationTypeDefault = 1;
    private const int TokenElevationTypeFull = 2;
    private const int SecurityImpersonation = 2;
    private const uint MaximumAllowed = 0x02000000;
    private const int SystemMandatoryLabelAceType = 0x11;
    private const int LabelSidBytes = 12;              // S-1-16-<level>: one sub-authority
    private const uint MediumIntegrityLevel = 0x2000;  // a standard user's token
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;
    private const uint FileAddFile = 0x00000002;
    private const uint FileAddSubdirectory = 0x00000004;
    private const uint FileGenericRead = 0x00120089;
    private const uint FileGenericWrite = 0x00120116;
    private const uint FileGenericExecute = 0x001200A0;
    private const uint FileAllAccess = 0x001F01FF;
    private const uint InitialPrivilegeSetBytes = 4096;
    private const uint MaximumPrivilegeSetBytes = 1024 * 1024;
    private const int ErrorInsufficientBuffer = 122;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(
        SafeAccessTokenHandle existingToken,
        int impersonationLevel,
        out SafeAccessTokenHandle duplicateToken);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        out int tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        out TokenLinkedToken tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(
        IntPtr securityDescriptor,
        SafeAccessTokenHandle clientToken,
        uint desiredAccess,
        ref GenericMapping genericMapping,
        IntPtr privilegeSet,
        ref uint privilegeSetLength,
        out uint grantedAccess,
        [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);
}
