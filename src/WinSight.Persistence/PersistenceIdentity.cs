namespace WinSight.Persistence;

/// <summary>
/// The canonical identity of a persistence entry: the tuple that decides whether two
/// observations are "the same persistence". It is (surface, name, target executable),
/// deliberately NOT the raw command — a command's arguments are noise, and the same entry
/// re-read moments later must hash identically or a diff would report it as new every scan.
/// </summary>
/// <remarks>
/// Target canonicalization is intentionally lenient, unlike the firewall's strict
/// <c>OutboundPolicyEvaluator.CanonicalPath</c>. Persistence targets are frequently relative
/// ("explorer.exe"), missing on disk, or unresolved; canonicalization must therefore never
/// throw. It only trims quotes/whitespace, normalizes separators, and lower-cases with the
/// invariant culture, so identity is stable without pretending a path is absolute when it is not.
/// </remarks>
public readonly record struct PersistenceIdentity(AutostartVector Vector, string Name, string Target)
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
            Canonicalize(target));
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
