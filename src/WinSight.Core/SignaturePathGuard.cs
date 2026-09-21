using System.IO;

namespace WinSight.Core;

/// <summary>
/// Validates the path argument the Explorer verb and the <c>sign</c> CLI hand in before it is opened.
/// The argument arrives from outside WinSight (a right-click target, a command line), so it is treated
/// as untrusted: only an ordinary, fully qualified, existing local file qualifies. A UNC path (which
/// would authenticate to a share) or a Win32/NT device path is refused, the same rule the dashboard's
/// finding actions already apply.
/// </summary>
public static class SignaturePathGuard
{
    /// <summary>The validated full path, or null when the argument is not an ordinary local file.</summary>
    public static string? LocalFileArgument(string? raw) => LocalFileArgument(raw, AutomaticFileAccess.IsLocal);

    internal static string? LocalFileArgument(string? raw, Func<string, bool> isLocal)
    {
        if (string.IsNullOrWhiteSpace(raw) || !IsOrdinaryLocalPath(raw))
        {
            return null;
        }
        try
        {
            if (!isLocal(raw))
            {
                return null;
            }
            var full = Path.GetFullPath(raw);
            return AutomaticFileAccess.FileExists(full) ? full : null;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or NotSupportedException)
        {
            return null;
        }
    }

    private static bool IsOrdinaryLocalPath(string path) =>
        path.Length >= 3
        && char.IsAsciiLetter(path[0])
        && path[1] == ':'
        && (path[2] == Path.DirectorySeparatorChar || path[2] == Path.AltDirectorySeparatorChar)
        && Path.IsPathFullyQualified(path);
}
