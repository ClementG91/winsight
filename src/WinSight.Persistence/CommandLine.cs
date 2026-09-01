using System.Text;

using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>The outcome of mapping an autostart command to an on-disk image.</summary>
public enum ImageResolutionStatus
{
    Present,
    FileMissing,
    AccessDenied,
    Error,
    Unresolved,
}

/// <summary>
/// Keeps the existing image separate from the normalized path Windows would load.
/// This distinction matters for orphaned service/driver registrations: an absent
/// file is not an unsigned file and its signature was never checked.
/// </summary>
public readonly record struct ExecutableResolution(
    string? ImagePath,
    string? ExpectedPath,
    ImageResolutionStatus Status);

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
        => ResolveExecutable(command).ImagePath;

    /// <summary>
    /// Resolves a command while preserving a normalized expected path when the file
    /// is absent or inaccessible. Callers can therefore report the real condition
    /// instead of collapsing it into an ambiguous missing-signature verdict.
    /// </summary>
    public static ExecutableResolution ResolveExecutable(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return new(null, null, ImageResolutionStatus.Unresolved);
        }

        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var exe = expanded.StartsWith('"') ? FirstQuoted(expanded) : FirstToken(expanded);
        if (string.IsNullOrEmpty(exe))
        {
            return new(null, null, ImageResolutionStatus.Unresolved);
        }

        string? expected = null;
        string? inaccessible = null;

        // Driver/service ImagePaths use NT-style forms the Win32 file APIs can't open
        // as-is (\SystemRoot\..., \??\C:\..., or a bare "system32\drivers\x.sys"
        // relative to %SystemRoot%). Without this, every Windows driver resolves to
        // "no image" and gets flagged suspicious, 150+ false positives on a clean box.
        foreach (var candidate in NtPathCandidates(exe))
        {
            var probe = Probe(candidate);
            if (probe.Status == ImageResolutionStatus.Present)
            {
                return probe;
            }
            if (probe.ExpectedPath is { } probePath && Path.IsPathFullyQualified(probePath))
            {
                expected = probePath;
                if (probe.Status == ImageResolutionStatus.AccessDenied)
                {
                    inaccessible = probePath;
                }
            }
        }

        // Bare module name (LSA/print/driver DLLs, system commands, the default
        // Winlogon shell), resolve against System32 AND the Windows dir (explorer.exe
        // lives in %windir%, not System32), trying a .dll suffix when there's no
        // extension. Without %windir% the legitimate default shell reads as "no image".
        if (!exe.Contains('\\') && !exe.Contains('/'))
        {
            foreach (var candidate in BareModuleCandidates(exe))
            {
                var probe = Probe(candidate);
                if (probe.Status == ImageResolutionStatus.Present)
                {
                    return probe;
                }
                if (probe.Status == ImageResolutionStatus.AccessDenied)
                {
                    inaccessible = probe.ExpectedPath;
                }
            }
            // A bare module name can legitimately resolve through several Windows
            // loader rules. Do not claim one guessed location is definitely absent.
            return inaccessible is not null
                ? new(null, inaccessible, ImageResolutionStatus.AccessDenied)
                : new(null, null, ImageResolutionStatus.Unresolved);
        }

        return inaccessible is not null
            ? new(null, inaccessible, ImageResolutionStatus.AccessDenied)
            : expected is not null
                ? new(null, expected, ImageResolutionStatus.FileMissing)
                : new(null, null, ImageResolutionStatus.Unresolved);
    }

    /// <summary>
    /// The on-disk locations Windows would actually try for a bare module name, in probe order.
    /// </summary>
    /// <remarks>
    /// <b>Why the <c>.exe</c> suffix and the search path matter.</b> <c>CreateProcess</c> with a
    /// null application name appends <c>.exe</c> to an extension-less token and then searches
    /// System32, the Windows directory and <c>%PATH%</c>. Before this existed, the probe list held
    /// <c>System32\&lt;name&gt;</c>, <c>System32\&lt;name&gt;.dll</c>, <c>%windir%\&lt;name&gt;</c>
    /// and <c>%windir%\&lt;name&gt;.exe</c> — which resolves <c>explorer</c> but not
    /// <c>cmd</c>, <c>wscript</c>, <c>regsvr32</c> or <c>powershell</c>, because those live in
    /// <c>System32</c> (or, for PowerShell, in <c>System32\WindowsPowerShell\v1.0</c>, reachable
    /// only through <c>%PATH%</c>). A Run value of <c>powershell -enc &lt;base64&gt;</c> therefore
    /// resolved to nothing at all and was reported as a verification error rather than as a signed
    /// interpreter carrying an encoded payload — while <c>powershell.exe -enc</c>, four characters
    /// longer, was caught. Dropping the extension was a complete bypass of the command-line triage.
    ///
    /// <b>The existing candidates keep their order.</b> The new ones are appended, so every name
    /// that resolved before resolves to the same file: LSA and print-monitor module names still
    /// reach their <c>.dll</c> before any <c>.exe</c> is considered.
    ///
    /// <b>%PATH% is read once.</b> A report holds thousands of entries; re-splitting the variable
    /// per entry would be pure waste, and the search path does not change during a scan.
    /// </remarks>
    internal static IEnumerable<string> BareModuleCandidates(string exe)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        yield return Path.Combine(system32, exe);
        yield return Path.Combine(system32, exe + ".dll");
        yield return Path.Combine(windir, exe);
        yield return Path.Combine(windir, exe + ".exe");

        // CreateProcess appends .exe (only .exe — PATHEXT is a shell convention, not a loader one)
        // when the token carries no extension, and searches System32 before %PATH%.
        var hasExtension = Path.GetExtension(exe).Length > 0;
        if (!hasExtension)
        {
            yield return Path.Combine(system32, exe + ".exe");
        }

        foreach (var directory in SearchPathDirectories.Value)
        {
            yield return Path.Combine(directory, exe);
            if (!hasExtension)
            {
                yield return Path.Combine(directory, exe + ".exe");
            }
        }
    }

    private static readonly Lazy<string[]> SearchPathDirectories = new(LoadSearchPathDirectories);

    private static string[] LoadSearchPathDirectories()
    {
        string? path;
        try
        {
            path = Environment.GetEnvironmentVariable("PATH");
        }
        catch (System.Security.SecurityException)
        {
            return [];
        }
        if (string.IsNullOrWhiteSpace(path))
        {
            return [];
        }

        // Bounded: a pathologically long %PATH% must not turn one unresolved token into thousands
        // of filesystem probes on every one of a report's entries.
        const int MaxSearchDirectories = 64;
        var directories = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in path.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var directory = entry.Trim('"');
            if (directory.Length == 0 || !seen.Add(directory))
            {
                continue;
            }
            directories.Add(directory);
            if (directories.Count == MaxSearchDirectories)
            {
                break;
            }
        }
        return [.. directories];
    }

    private static ExecutableResolution Probe(string candidate)
    {
        string full;
        try
        {
            full = Path.GetFullPath(candidate);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new(null, null, ImageResolutionStatus.Unresolved);
        }

        if (!AutomaticFileAccess.IsLocal(full))
        {
            return new(null, full, ImageResolutionStatus.Unresolved);
        }

        try
        {
            var attributes = File.GetAttributes(full);
            return (attributes & FileAttributes.Directory) == 0
                ? new(full, full, ImageResolutionStatus.Present)
                : new(null, full, ImageResolutionStatus.Unresolved);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new(null, full, ImageResolutionStatus.AccessDenied);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or DriveNotFoundException)
        {
            return new(null, full, ImageResolutionStatus.FileMissing);
        }
        catch (IOException)
        {
            // Sharing violations and transient filesystem failures mean the target
            // could not be inspected reliably; do not mislabel this as access denial.
            return new(null, full, ImageResolutionStatus.Error);
        }
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
            if (AutomaticFileAccess.IsLocal(candidate.ToString())
                && File.Exists(candidate.ToString()))
            {
                return candidate.ToString();
            }
        }

        // Preserve an unquoted path containing spaces even when its target is gone.
        // Service ImagePath values frequently omit quotes; the executable extension
        // is a safer boundary than the first whitespace for reporting an orphan.
        int? executableEnd = null;
        foreach (var extension in new[] { ".exe", ".com", ".dll", ".sys", ".scr" })
        {
            var searchFrom = 0;
            while (s.IndexOf(extension, searchFrom, StringComparison.OrdinalIgnoreCase) is var end && end >= 0)
            {
                var after = end + extension.Length;
                if (after == s.Length || char.IsWhiteSpace(s[after]))
                {
                    executableEnd = executableEnd is null ? after : Math.Min(executableEnd.Value, after);
                    break;
                }
                searchFrom = after;
            }
        }
        if (executableEnd is { } boundary)
        {
            return s[..boundary];
        }
        // Fall back to the first whitespace-delimited token.
        return parts.Length > 0 ? parts[0] : string.Empty;
    }
}
