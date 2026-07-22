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
    /// Extensions a registered image can end with. The earliest match in the string wins, whichever
    /// extension it is.
    /// </summary>
    /// <remarks>
    /// <c>.com</c> is deliberately absent. It is a legitimate executable extension, but it is also
    /// the end of almost every domain name, and service arguments are full of those: reading the
    /// <c>.com</c> in <c>C:\App\run --host example.com</c> as the image would name <c>C:\App\run.exe</c>
    /// — the real executable — as something to be planted. A false accusation is worse than the miss
    /// it would have prevented, and a <c>.com</c> service image is close to unheard of.
    /// </remarks>
    private static readonly string[] ExecutableExtensions =
        [".exe", ".bat", ".cmd", ".scr", ".pif"];

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

        if (IsKernelOrDevicePath(line))
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
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var separator = executable.IndexOf(' ', StringComparison.Ordinal);
        while (separator >= 0)
        {
            // Windows drops trailing spaces from a path component, so `C:\Program  Files\...` with
            // two spaces yields the same candidate twice rather than the impossible `C:\Program .exe`.
            var prefix = executable[..separator].TrimEnd();
            if (IsPlantablePrefix(prefix))
            {
                var candidate = prefix + ".exe";
                if (seen.Add(candidate))
                {
                    candidates.Add(candidate);
                }
            }
            separator = executable.IndexOf(' ', separator + 1);
        }
        return candidates;
    }

    /// <summary>
    /// Paths this rule does not model, as opposed to paths it finds nothing in.
    /// </summary>
    /// <remarks>
    /// A driver's ImagePath is an NT path (<c>\SystemRoot\…</c>, <c>\??\…</c>) loaded by the kernel,
    /// not by <c>CreateProcess</c>, so no prefix is ever tried. The <c>\\?\</c> and <c>\\.\</c>
    /// namespaces go straight to the object manager with normalization disabled.
    ///
    /// <b>A UNC path is deliberately not in this set.</b> It used to be, because the check was
    /// written as "starts with a backslash" while its rationale only covered kernel paths — so
    /// <c>\\server\share\My App\svc.exe</c> reported nothing at all, even though
    /// <c>CreateProcess</c> prefix-searches it exactly like a drive path and
    /// <c>\\server\share\My.exe</c> is a real place to plant.
    /// </remarks>
    private static bool IsKernelOrDevicePath(string line) =>
        line.StartsWith(@"\\?\", StringComparison.Ordinal)
        || line.StartsWith(@"\\.\", StringComparison.Ordinal)
        || (line.StartsWith('\\') && !line.StartsWith(@"\\", StringComparison.Ordinal));

    /// <summary>
    /// Whether a prefix names a file someone could actually create.
    /// </summary>
    /// <remarks>
    /// Being rooted is not enough: a root is not a file. <c>C:\</c>, <c>\\server</c> and
    /// <c>\\server\share</c> are all rooted, and emitting them as candidates would send an operator
    /// to inspect a path that cannot exist — the specific failure this whole type is written to
    /// avoid. Requiring the prefix to reach below its own root covers drive and UNC roots with one
    /// rule instead of two spellings that could drift apart.
    /// </remarks>
    private static bool IsPlantablePrefix(string prefix)
    {
        if (prefix.Length == 0 || !Path.IsPathRooted(prefix))
        {
            return false;
        }
        var root = Path.GetPathRoot(prefix);
        return !string.IsNullOrEmpty(root) && prefix.Length > root.Length;
    }

    /// <summary>True when at least one earlier path would be tried before the intended binary.</summary>
    public static bool IsHijackable(string? commandLine) => HijackCandidates(commandLine).Count > 0;

    /// <summary>
    /// The part of an unquoted command line that names the executable.
    /// </summary>
    /// <remarks>
    /// Windows itself cannot know where the executable ends — that is the whole ambiguity — so this
    /// takes the <b>first</b> <c>.exe</c> that ends a token, which is also the order
    /// <c>CreateProcess</c> resolves in: it tries the shortest interpretations first.
    ///
    /// Taking the <i>last</i> one instead is wrong and was the first version of this: a service
    /// registered as <c>C:\Program Files\App\svc.exe -c C:\other.exe</c> matched the <c>.exe</c>
    /// inside the argument, so the whole command line became "the executable" and the candidate
    /// list contained <c>C:\Program Files\App\svc.exe.exe</c> and
    /// <c>C:\Program Files\App\svc.exe -c.exe</c> — paths that cannot exist, sending an operator to
    /// inspect nothing. Exactly the failure this method exists to prevent.
    ///
    /// When there is no <c>.exe</c> ending a token at all, the command line is not something this
    /// rule can reason about, and it says so with null rather than guessing.
    ///
    /// Internal rather than private because <see cref="HijackScanner.ExecutableDirectory"/> reads the
    /// same string for a different question and must reach the same answer. It had its own copy of
    /// this parse without the end-of-token rule, so the two disagreed on exactly the inputs this rule
    /// was hardened for — one of them would have named a directory that is not the service's.
    ///
    /// <b>Not only <c>.exe</c>.</b> The candidates are always <c>.exe</c>, because that is the
    /// extension <c>CreateProcess</c> appends to a prefix it is guessing at — but the <i>registered</i>
    /// image does not have to be one. A command line ending in <c>.bat</c>, <c>.cmd</c>, <c>.com</c>,
    /// <c>.scr</c> or <c>.pif</c> is prefix-searched identically, and reading none of them meant those
    /// command lines reported nothing at all.
    /// </remarks>
    internal static string? ExecutableSpan(string line)
    {
        var earliestEnd = -1;
        var earliest = int.MaxValue;
        foreach (var extension in ExecutableExtensions)
        {
            var at = line.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            while (at >= 0)
            {
                var end = at + extension.Length;
                // The extension must end a token: "...\foo.exefoo" is not an executable name, while
                // a directory called "my.exe" followed by a space genuinely is what Windows tries
                // first.
                if (end == line.Length || line[end] is ' ' or '"')
                {
                    if (at < earliest)
                    {
                        earliest = at;
                        earliestEnd = end;
                    }
                    break;
                }
                at = line.IndexOf(extension, at + 1, StringComparison.OrdinalIgnoreCase);
            }
        }
        return earliestEnd < 0 ? null : line[..earliestEnd];
    }
}
