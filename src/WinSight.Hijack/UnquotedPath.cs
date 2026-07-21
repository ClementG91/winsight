namespace WinSight.Hijack;

/// <summary>
/// Decides whether a service's registered command line can be hijacked because it is not quoted,
/// and names the files an attacker would plant to do it.
/// </summary>
/// <remarks>
/// <b>The vector.</b> Windows registers a service as a command line, not a path. When that command
/// line is unquoted and contains a space, <c>CreateProcess</c> tries each prefix in turn:
/// <c>C:\Program Files\My App\svc.exe -k net</c> is first attempted as <c>C:\Program.exe</c>, then
/// <c>C:\Program Files\My.exe</c>, and only then the intended binary. Anyone able to write one of
/// those earlier candidates gets their code run by whatever account the service uses — usually
/// SYSTEM, at boot, before the operator logs in.
///
/// <b>Why the candidates are computed rather than just flagged.</b> "This service path is unquoted"
/// is a lint result; "anyone who can write <c>C:\Program.exe</c> owns this SYSTEM service" is a
/// finding an operator can act on, and the second requires knowing exactly which paths are tried.
/// Getting that list subtly wrong — off by one segment, or including the real binary — would send
/// someone to inspect the wrong file, so it is a pure function with its own tests.
///
/// Nothing here touches the disk: whether a candidate is actually writable is a separate question,
/// answered at the edge, so this rule stays testable against paths that do not exist.
/// </remarks>
public static class UnquotedPath
{
    /// <summary>
    /// The paths <c>CreateProcess</c> would try before reaching the intended executable, in the
    /// order it tries them. Empty when the command line cannot be hijacked this way.
    /// </summary>
    /// <param name="commandLine">The registered command line, e.g. a service's <c>ImagePath</c>.</param>
    public static IReadOnlyList<string> HijackCandidates(string? commandLine)
    {
        var line = commandLine?.Trim();
        if (string.IsNullOrEmpty(line))
        {
            return [];
        }

        // A quoted image is exactly what makes this safe — CreateProcess takes the quoted span as
        // the executable and never guesses. This is the common, correct case.
        if (line.StartsWith('"'))
        {
            return [];
        }

        // A driver's ImagePath is an NT path (\SystemRoot\..., \??\...), loaded by the kernel rather
        // than CreateProcess, so the prefix rule does not apply to it at all.
        if (line.StartsWith('\\'))
        {
            return [];
        }

        // Everything from the first space onward may be arguments — that ambiguity IS the bug — so
        // the executable is taken to end at the last path segment that looks like a program.
        var executable = ExecutableSpan(line);
        if (executable is null)
        {
            return [];
        }

        var candidates = new List<string>();
        var separator = executable.IndexOf(' ', StringComparison.Ordinal);
        while (separator >= 0)
        {
            var prefix = executable[..separator];
            // Only a prefix that is still a rooted path is a real candidate; a bare fragment is not
            // something CreateProcess would resolve to a file on disk here.
            if (Path.IsPathRooted(prefix) && prefix.Trim().Length > 0)
            {
                candidates.Add(prefix + ".exe");
            }
            separator = executable.IndexOf(' ', separator + 1);
        }
        return candidates;
    }

    /// <summary>True when at least one earlier path would be tried before the intended binary.</summary>
    public static bool IsHijackable(string? commandLine) => HijackCandidates(commandLine).Count > 0;

    /// <summary>
    /// The part of an unquoted command line that names the executable.
    /// </summary>
    /// <remarks>
    /// Windows itself cannot know where the executable ends — that is the whole ambiguity — so this
    /// takes the longest prefix ending in <c>.exe</c>. When there is no <c>.exe</c> at all the
    /// command line is not something this rule can reason about, and it says so with null rather
    /// than guessing: a wrong candidate list sends an operator to inspect an innocent file.
    /// </remarks>
    private static string? ExecutableSpan(string line)
    {
        const string extension = ".exe";
        var at = line.LastIndexOf(extension, StringComparison.OrdinalIgnoreCase);
        if (at < 0)
        {
            return null;
        }
        var end = at + extension.Length;
        // ".exe" must end a segment; "...\foo.exefoo" is not an executable name.
        if (end < line.Length && line[end] is not (' ' or '"'))
        {
            return null;
        }
        return line[..end];
    }
}
