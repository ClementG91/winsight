namespace WinSight.Persistence;

/// <summary>
/// The canonical identity of a persistence entry: the tuple that decides whether two
/// observations are "the same persistence". It is (surface, name, target executable, arguments).
/// </summary>
/// <remarks>
/// <b>The arguments used to be excluded, and that was the hole.</b> The reasoning was that they are
/// noise and that a stable entry must hash identically between scans. The first half is wrong for
/// exactly the entries that matter: an interpreter's arguments <i>are</i> the payload, so rewriting
/// <c>rundll32.exe C:\…\ok.dll,Entry</c> as <c>rundll32.exe C:\…\evil.dll,Start</c> left the
/// identity untouched and Guardian raised nothing at all — on the technique the persistence scanner
/// exists to catch, and while the real-time monitor was running.
///
/// The second half is satisfied anyway. Arguments come from the stored value — a registry string, a
/// task definition — not from a live process, so an unchanged entry produces the same string every
/// scan. Nothing volatile enters here.
/// </remarks>
/// <remarks>
/// Target canonicalization is intentionally lenient, unlike the firewall's strict
/// <c>OutboundPolicyEvaluator.CanonicalPath</c>. Persistence targets are frequently relative
/// ("explorer.exe"), missing on disk, or unresolved; canonicalization must therefore never
/// throw. It only trims quotes/whitespace, normalizes separators, and lower-cases with the
/// invariant culture, so identity is stable without pretending a path is absolute when it is not.
/// </remarks>
public readonly record struct PersistenceIdentity(
    AutostartVector Vector,
    string Name,
    string Target,
    string Arguments = "")
{
    /// <summary>
    /// Derives the identity of a resolved entry. Prefers the expected target Windows would load
    /// (present even when the file is absent), then the resolved image, then the raw command, so
    /// a "file missing" entry still has a stable identity to diff against.
    /// </summary>
    public static PersistenceIdentity FromEntry(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var target = entry.ExpectedImagePath ?? entry.ImagePath ?? entry.Command;
        return new PersistenceIdentity(
            entry.Vector,
            Canonicalize(entry.Name),
            Canonicalize(target),
            CanonicalizeArguments(entry.Command));
    }

    /// <summary>
    /// Everything after the executable on a command line, canonicalised.
    /// </summary>
    /// <remarks>
    /// Only the tail is taken, because the head is already the target: including the whole command
    /// would make a value spelled <c>%windir%\explorer.exe</c> and the same value spelled with the
    /// variable expanded look like two different entries. The tail is the part that carries the
    /// payload and the part an attacker rewrites in place.
    /// </remarks>
    internal static string CanonicalizeArguments(string? command)
    {
        var trimmed = command?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return string.Empty;
        }
        int tail;
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            tail = end < 0 ? trimmed.Length : end + 1;
        }
        else
        {
            var space = trimmed.IndexOf(' ');
            tail = space < 0 ? trimmed.Length : space;
        }
        var arguments = trimmed[tail..].Trim();
        if (arguments.Length == 0)
        {
            return string.Empty;
        }
        // Case-folded and whitespace-collapsed, but separators are left exactly as written: unlike
        // a path, a forward slash in arguments is a switch introducer, and rewriting "/select,x" to
        // "\select,x" would corrupt the very string this is meant to compare.
        return string.Join(
            ' ',
            arguments.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .ToLowerInvariant();
    }

    /// <summary>
    /// Lenient canonical form: quote/whitespace-trimmed, separators normalized to backslash,
    /// lower-cased (invariant). Never throws and never requires an absolute path, so an
    /// unresolved or relative value keeps a stable identity across scans.
    /// </summary>
    internal static string Canonicalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        return value.Trim().Trim('"').Trim().Replace('/', '\\').ToLowerInvariant();
    }
}
