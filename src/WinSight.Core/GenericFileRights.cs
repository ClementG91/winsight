using System.Security.AccessControl;

namespace WinSight.Core;

/// <summary>
/// Expands the four generic access bits an ACE may carry into the specific file rights they stand
/// for.
/// </summary>
/// <remarks>
/// <b>The hole this closes.</b> An access mask in a DACL may express its grant with the generic
/// bits - <c>GENERIC_ALL</c>, <c>GENERIC_WRITE</c>, <c>GENERIC_READ</c>, <c>GENERIC_EXECUTE</c> -
/// which the object's own generic mapping resolves at access-check time. .NET does not do that
/// resolution: <see cref="FileSystemAccessRule.FileSystemRights"/> returns the mask as stored, so an
/// ACE granting <c>GENERIC_ALL</c> comes back as <c>0x10000000</c> and shares no bit with
/// <see cref="FileSystemRights.WriteData"/>, <see cref="FileSystemRights.Delete"/> or any other
/// specific right.
///
/// Two checks in this codebase test specific bits against a mask read straight from Windows, and
/// both failed open on such an ACE:
///
/// <list type="bullet">
/// <item>The privileged service's path-trust check decoded a component granting Users
/// <c>GENERIC_ALL</c> as granting nothing dangerous, and trusted a path an unprivileged account
/// fully controls - the exact condition that check exists to refuse.</item>
/// <item>The hijack scan's elevated writability evaluation read a directory granting Users
/// <c>GENERIC_WRITE</c> as not plantable, and reported a real DLL side-loading point as safe.</item>
/// </list>
///
/// <b>Why this is reachable and not theoretical.</b> Generic bits are what an ACL gets when it is
/// written by hand rather than by Explorer: <c>icacls /grant Users:(F)</c>, SDDL strings using
/// <c>GA</c>/<c>GW</c>, and installer scripts that call <c>SetNamedSecurityInfo</c> with the generic
/// mapping all produce them. An attacker who can set an ACL at all can choose the spelling the
/// checker does not read.
///
/// <b>Why expand rather than test the generic bits directly.</b> Callers reason in specific rights,
/// and the mapping from generic to specific is the operating system's, not the caller's. Folding it
/// once here means a checker written against <c>WriteData</c> keeps working whichever spelling an
/// ACE used, and a future checker gets the correct behaviour without knowing this problem exists.
/// The values are the file generic mapping from <c>winnt.h</c>.
/// </remarks>
public static class GenericFileRights
{
    private const int GenericAll = unchecked((int)0x10000000);
    private const int GenericExecute = 0x20000000;
    private const int GenericWrite = 0x40000000;
    private const int GenericRead = unchecked((int)0x80000000);

    /// <summary>FILE_GENERIC_READ.</summary>
    private const FileSystemRights FileGenericRead =
        FileSystemRights.ReadData | FileSystemRights.ReadExtendedAttributes
        | FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions
        | FileSystemRights.Synchronize;

    /// <summary>FILE_GENERIC_WRITE.</summary>
    private const FileSystemRights FileGenericWrite =
        FileSystemRights.WriteData | FileSystemRights.AppendData
        | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes
        | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize;

    /// <summary>FILE_GENERIC_EXECUTE.</summary>
    private const FileSystemRights FileGenericExecute =
        FileSystemRights.ExecuteFile | FileSystemRights.ReadAttributes
        | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize;

    /// <summary>
    /// FILE_ALL_ACCESS: every specific right, including the ones that let a principal replace,
    /// delete or re-permission the object.
    /// </summary>
    private const FileSystemRights FileAllAccess =
        FileSystemRights.FullControl;

    /// <summary>
    /// <paramref name="rights"/> with any generic bits replaced by the specific rights they grant.
    /// A mask carrying no generic bit is returned unchanged.
    /// </summary>
    /// <remarks>
    /// The generic bits themselves are cleared, because a caller testing specific bits has no use
    /// for them and leaving them set invites a mask comparison that accidentally succeeds.
    /// </remarks>
    public static FileSystemRights Expand(FileSystemRights rights)
    {
        var raw = (int)rights;
        if ((raw & (GenericAll | GenericExecute | GenericWrite | GenericRead)) == 0)
        {
            return rights;
        }

        var expanded = rights;
        if ((raw & GenericAll) != 0)
        {
            expanded |= FileAllAccess;
        }
        if ((raw & GenericWrite) != 0)
        {
            expanded |= FileGenericWrite;
        }
        if ((raw & GenericRead) != 0)
        {
            expanded |= FileGenericRead;
        }
        if ((raw & GenericExecute) != 0)
        {
            expanded |= FileGenericExecute;
        }
        return (FileSystemRights)((int)expanded
            & ~(GenericAll | GenericExecute | GenericWrite | GenericRead));
    }
}
