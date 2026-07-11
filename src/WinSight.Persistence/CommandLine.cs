using System.Text;

namespace WinSight.Persistence;

/// <summary>
/// Best-effort extraction of the executable path from an autostart command string.
/// Registry autostart values are raw command lines: quoted or not, with arguments,
/// and often carrying environment variables (e.g. %SystemRoot%). This resolves the
/// leading executable so its signature can be checked.
/// </summary>
public static class CommandLine
{
    /// <summary>
    /// Returns the resolved, existing executable path for a raw command, or null when
    /// it cannot be resolved to a real file. Handles surrounding quotes, trailing
    /// arguments, and environment-variable expansion.
    /// </summary>
    public static string? ExtractExecutable(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var exe = expanded.StartsWith('"') ? FirstQuoted(expanded) : FirstToken(expanded);
        if (string.IsNullOrEmpty(exe))
        {
            return null;
        }

        if (File.Exists(exe))
        {
            return Path.GetFullPath(exe);
        }

        // Bare module name (LSA/print/driver DLLs, some system commands) — resolve
        // against System32, trying a .dll suffix when there's no extension.
        if (!exe.Contains('\\') && !exe.Contains('/'))
        {
            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            foreach (var candidate in new[] { Path.Combine(system32, exe), Path.Combine(system32, exe + ".dll") })
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        return null;
    }

    private static string FirstQuoted(string s)
    {
        var end = s.IndexOf('"', 1);
        return end > 0 ? s[1..end] : string.Empty;
    }

    // Unquoted commands may contain a space in the path (e.g. C:\Program Files\...).
    // Grow the candidate token by token and return the longest prefix that is a file.
    private static string FirstToken(string s)
    {
        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var candidate = new StringBuilder();
        for (var i = 0; i < parts.Length; i++)
        {
            if (i > 0)
            {
                candidate.Append(' ');
            }
            candidate.Append(parts[i]);
            if (File.Exists(candidate.ToString()))
            {
                return candidate.ToString();
            }
        }
        // Fall back to the first whitespace-delimited token.
        return parts.Length > 0 ? parts[0] : string.Empty;
    }
}
