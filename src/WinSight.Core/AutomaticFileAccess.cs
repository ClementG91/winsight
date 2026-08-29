namespace WinSight.Core;

/// <summary>
/// Decides whether an automatically discovered path can be touched without opening a network
/// channel chosen by the machine being scanned.
/// </summary>
/// <remarks>
/// Registry values, service command lines and environment variables are attacker-controlled
/// evidence. Calling <c>File.Exists</c> on a UNC path is not a harmless predicate: Windows reaches
/// the server and can authenticate the current account or machine. WinSight promises no automatic
/// network traffic, so filesystem inspection is limited to relative paths and roots Windows
/// positively identifies as local storage. The path is still reported; only the implicit I/O is
/// refused.
/// </remarks>
public static class AutomaticFileAccess
{
    public static bool IsLocal(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        if (path.StartsWith(@"\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || path.StartsWith(@"\??\", StringComparison.Ordinal)
            || path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        try
        {
            if (!Path.IsPathRooted(path))
            {
                return true;
            }
            var root = Path.GetPathRoot(path);
            if (string.IsNullOrWhiteSpace(root) || root is "\\" or "/")
            {
                return false;
            }
            return new DriveInfo(root).DriveType is
                DriveType.Fixed or DriveType.Removable or DriveType.CDRom or DriveType.Ram;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException
                                     or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
