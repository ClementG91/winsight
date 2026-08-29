namespace WinSight.Application;

/// <summary>
/// The command line's exit codes and option vocabulary, in one place both the CLI and its
/// documentation read.
/// </summary>
/// <remarks>
/// <b>The two failures this fixes.</b> Exit code 1 meant both "something notable was found" and
/// "the scan could not run" - a live ETW pump that ended unexpectedly returned 1 exactly as a scan
/// that found a rogue Run key does. Anything invoking WinSight from a scheduled task, which the
/// README recommends, could not tell a finding from a broken observation. And no option was ever
/// validated: <c>--jsonn</c> silently produced human output, which in an automated pipeline is an
/// empty parse rather than an error.
///
/// <b>The split.</b> Findings stay in 0/1, so every existing caller keeps working. Failures move to
/// 10 and above, which no previous version returned, so a caller that only checks <c>!= 0</c> is
/// unaffected while one that wants the distinction can have it.
/// </remarks>
public static class CliContract
{
    /// <summary>Nothing notable was found.</summary>
    public const int Clean = 0;

    /// <summary>Something notable was found. The scan itself succeeded.</summary>
    public const int Notable = 1;

    /// <summary>The command line could not be understood: unknown verb, bad argument, bad option.</summary>
    public const int UsageError = 2;

    /// <summary>An observation could not be made - a live ETW session failed to run.</summary>
    public const int ObservationFailed = 10;

    /// <summary>The privileged firewall service could not be reached.</summary>
    public const int ServiceUnavailable = 11;

    /// <summary>The scan failed for a reason WinSight did not anticipate.</summary>
    public const int UnexpectedFailure = 12;

    /// <summary>Options every command accepts.</summary>
    private static readonly HashSet<string> GlobalOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--json", "--flagged", "--watch", "--help", "-h", "--version", "--no-network",
    };

    /// <summary>
    /// The first argument that is not a known option, or null when they are all recognised.
    /// </summary>
    /// <remarks>
    /// Only leading-dash tokens are checked. A bare word is a verb or a verb's argument, and those
    /// are validated by the dispatcher which knows the catalogue; rejecting them here would need a
    /// second, hand-maintained copy of that list - the drift this project already removed once.
    /// </remarks>
    public static string? FirstUnknownOption(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        foreach (var argument in args)
        {
            if (argument.StartsWith('-') && !GlobalOptions.Contains(argument))
            {
                return argument;
            }
        }
        return null;
    }

    /// <summary>
    /// The verbs that honour <c>--watch</c>. Every other verb is a one-shot scan.
    /// </summary>
    private static readonly HashSet<string> WatchableVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "av", "avmonitor", "attribution", "dns",
    };

    /// <summary>
    /// An option the named verb does not honour, or null when every option applies.
    /// </summary>
    /// <remarks>
    /// <b>The failure this closes.</b> <c>--watch</c> was accepted globally and honoured by four
    /// verbs. <c>winsight persistence --watch</c> therefore ran a one-shot persistence scan, printed
    /// it, and exited - the operator asked to be told when something changed and was handed a
    /// snapshot instead, with nothing saying so. Somebody leaving that in a scheduled task believes
    /// they have a live watch and has a report from the moment it ran.
    ///
    /// That is exactly the failure this class already documents fixing for a second verb and for a
    /// misspelled option: an argument that changes what the operator asked for must not be silently
    /// dropped. It was fixed for the two cases where the argument was wrong, and missed for the one
    /// where the argument is right and the verb cannot do it.
    ///
    /// The message names the verbs that do support it, because "unsupported" without "here is where
    /// it works" sends somebody back to the help text to find out.
    /// </remarks>
    public static string? FirstUnsupportedOption(IReadOnlyList<string> args, string verb)
    {
        ArgumentNullException.ThrowIfNull(args);

        return args.Any(argument => argument.Equals("--watch", StringComparison.OrdinalIgnoreCase))
            && !WatchableVerbs.Contains(verb)
                ? "--watch"
                : null;
    }

    /// <summary>The verbs <c>--watch</c> works with, for a usage message that helps.</summary>
    public static string WatchableVerbList =>
        string.Join(", ", WatchableVerbs.Where(verb => verb != "avmonitor").Order(StringComparer.Ordinal));

    /// <summary>
    /// The verbs after the first, which earlier versions silently ignored:
    /// <c>winsight persistence extensions</c> ran a persistence scan and said nothing about the
    /// second word, so an operator got a report for a tool they did not ask about.
    /// </summary>
    public static IReadOnlyList<string> ExtraVerbs(IReadOnlyList<string> args, string commandVerb)
    {
        ArgumentNullException.ThrowIfNull(args);
        var verbs = args.Where(argument => !argument.StartsWith('-')).ToList();
        var index = verbs.FindIndex(verb =>
            verb.Equals(commandVerb, StringComparison.OrdinalIgnoreCase));
        return index < 0 ? [] : verbs.Skip(index + 1).ToList();
    }

    /// <summary>The exit-code table, rendered for <c>--help</c> and the documentation.</summary>
    public static string ExitCodeTable =>
        $"""
        Exit codes
          {Clean}   nothing notable found
          {Notable}   something notable was found (the scan succeeded)
          {UsageError}   usage error: unknown command, argument or option
          {ObservationFailed}  an observation could not be made (live ETW unavailable)
          {ServiceUnavailable}  the privileged firewall service could not be reached
          {UnexpectedFailure}  the scan failed unexpectedly

        Findings are 0 and 1; failures are 10 and above, so `if ($LASTEXITCODE -ge 10)`
        distinguishes "could not look" from "looked and found something".
        """;
}
