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

        // Driver/service ImagePaths use NT-style forms the Win32 file APIs can't open
        // as-is (\SystemRoot\..., \??\C:\..., or a bare "system32\drivers\x.sys"
        // relative to %SystemRoot%). Without this, every Windows driver resolves to
        // "no image" and gets flagged suspicious — 150+ false positives on a clean box.
        foreach (var candidate in NtPathCandidates(exe))
        {
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        // Bare module name (LSA/print/driver DLLs, system commands, the default
        // Winlogon shell) — resolve against System32 AND the Windows dir (explorer.exe
        // lives in %windir%, not System32), trying a .dll suffix when there's no
        // extension. Without %windir% the legitimate default shell reads as "no image".
        if (!exe.Contains('\\') && !exe.Contains('/'))
        {
            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            foreach (var candidate in new[]
                     {
                         Path.Combine(system32, exe), Path.Combine(system32, exe + ".dll"),
                         Path.Combine(windir, exe), Path.Combine(windir, exe + ".exe"),
                     })
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Yields the plausible on-disk paths for a raw image token, normalising the
    /// NT/driver path forms that Win32 can't open directly: the literal token first,
    /// then <c>\SystemRoot\</c> and <c>\??\</c> prefixes stripped/mapped, and a
    /// System-root-relative fallback for the common bare "system32\drivers\x.sys".
    /// </summary>
    public static IEnumerable<string> NtPathCandidates(string exe)
    {
        yield return exe;

        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // \SystemRoot\system32\... -> <windir>\system32\...
        if (exe.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            yield return Path.Combine(windir, exe[@"\SystemRoot\".Length..]);
        }
        // %SystemRoot%-style already expanded elsewhere; handle a leading "SystemRoot\".
        else if (exe.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            yield return Path.Combine(windir, exe[@"SystemRoot\".Length..]);
        }
        // \??\C:\path -> C:\path (Win32 device-path escape)
        else if (exe.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            yield return exe[@"\??\".Length..];
        }
        // Relative "system32\drivers\x.sys" (no drive, no leading slash) -> under windir.
        else if (!Path.IsPathRooted(exe) &&
                 exe.StartsWith("system32", StringComparison.OrdinalIgnoreCase))
        {
            yield return Path.Combine(windir, exe);
        }
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
