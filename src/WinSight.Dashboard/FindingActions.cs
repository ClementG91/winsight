using System.IO;
using WinSight.Reporting;

namespace WinSight.Dashboard;

/// <summary>Validates untrusted report metadata before exposing a filesystem action.</summary>
public static class FindingActions
{
    private static readonly string[] PathFieldNames = ["image", "path"];

    public static string? ExistingAbsolutePath(ReportItem item)
    {
        foreach (var key in PathFieldNames)
        {
            if (!item.Fields.TryGetValue(key, out var candidate) || string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }
            try
            {
                // Report fields may originate from programs or registry data. Never
                // let a click initiate authentication to a UNC share or address a
                // Win32/NT device namespace; only ordinary local drive paths qualify.
                if (!IsOrdinaryLocalPath(candidate))
                {
                    continue;
                }
                var fullPath = Path.GetFullPath(candidate);
                if (File.Exists(fullPath) || Directory.Exists(fullPath))
                {
                    return fullPath;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
            {
                // Invalid or inaccessible report metadata never becomes a process argument.
            }
        }
        return null;
    }

    private static bool IsOrdinaryLocalPath(string path) =>
        path.Length >= 3
        && char.IsAsciiLetter(path[0])
        && path[1] == ':'
        && (path[2] == Path.DirectorySeparatorChar || path[2] == Path.AltDirectorySeparatorChar)
        && Path.IsPathFullyQualified(path);
}
