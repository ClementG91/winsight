namespace WinSight.Persistence;

/// <summary>
/// Which parts of each autostart source a Guardian baseline has seen in full. It travels with the
/// baseline so that reading a source for the first time - typically the first elevated launch after
/// an unelevated one - baselines what was already there instead of announcing it (WS-70).
/// </summary>
/// <remarks>
/// <b>The model.</b> Per source, either complete, or complete except a set of location scopes that
/// could not be read. A source absent from the map was never seen in full: it failed, was not
/// scanned, or cannot confirm absence at all. That is the same notion of "seen in full" that
/// <see cref="PersistenceScanResult"/> uses to confirm a removal, so a location is covered here
/// exactly when some scan could have proved the absence of an entry there.
///
/// <b>Sticky by design.</b> <see cref="Merge"/> is a union: a location once seen in full stays
/// covered, because the baseline still holds what that full view found. Shrinking coverage when a
/// later, unelevated run could not read a source would make the next elevated run absorb whatever
/// was planted in between - the one arrival worth reporting.
/// </remarks>
public sealed class PersistenceCoverageMap
{
    private readonly Dictionary<string, IReadOnlyList<string>> _uncovered;

    /// <param name="uncoveredScopesBySource">
    /// For each source seen in full, the scopes it could not read; an empty list means complete.
    /// </param>
    public PersistenceCoverageMap(IReadOnlyDictionary<string, IReadOnlyList<string>> uncoveredScopesBySource)
    {
        ArgumentNullException.ThrowIfNull(uncoveredScopesBySource);
        _uncovered = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (source, scopes) in uncoveredScopesBySource)
        {
            _uncovered[source] = scopes.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    /// <summary>Nothing seen in full yet.</summary>
    public static PersistenceCoverageMap Empty { get; } =
        new(new Dictionary<string, IReadOnlyList<string>>());

    /// <summary>The sources this map knows, with the scopes each could not read (empty: complete).</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Sources => _uncovered;

    /// <summary>What one scan saw in full: its complete sources, and its attributed partial ones.</summary>
    public static PersistenceCoverageMap FromScan(PersistenceScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        var map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (source, scopes) in scan.PartialSources ?? new Dictionary<string, IReadOnlyCollection<string>>())
        {
            map[source] = scopes.ToArray();
        }
        foreach (var source in scan.CompleteSources ?? new HashSet<string>())
        {
            map[source] = [];
        }
        return new PersistenceCoverageMap(map);
    }

    /// <summary>Whether this location of this source has been seen in full.</summary>
    public bool Covers(string source, string location) =>
        _uncovered.TryGetValue(source, out var scopes) && !scopes.Any(scope => ScopeCovers(scope, location));

    /// <summary>
    /// The scopes of <paramref name="source"/> never read in full, empty when the source is complete,
    /// or null when the source was never seen in full at all.
    /// </summary>
    public IReadOnlyList<string>? UncoveredScopes(string source) =>
        _uncovered.TryGetValue(source, out var scopes) ? scopes : null;

    /// <summary>The union of what the two maps have seen in full.</summary>
    public PersistenceCoverageMap Merge(PersistenceCoverageMap other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var merged = new Dictionary<string, IReadOnlyList<string>>(_uncovered, StringComparer.Ordinal);
        foreach (var (source, theirs) in other._uncovered)
        {
            if (!merged.TryGetValue(source, out var ours))
            {
                merged[source] = theirs;
                continue;
            }
            // A location stays uncovered only if neither view read it: it lies under an unread
            // scope of each. Of two nested scopes, the deeper one is what both missed.
            var both = new List<string>();
            foreach (var mine in ours)
            {
                foreach (var their in theirs)
                {
                    if (ScopeCovers(mine, their))
                    {
                        both.Add(their);
                    }
                    else if (ScopeCovers(their, mine))
                    {
                        both.Add(mine);
                    }
                }
            }
            merged[source] = both;
        }
        return new PersistenceCoverageMap(merged);
    }

    /// <summary>Whether <paramref name="location"/> lies at or under <paramref name="scope"/>.</summary>
    /// <remarks>
    /// A scope covers its own key path and what is below it, not a sibling that merely starts with
    /// the same characters: <c>HKU\S-1-5-21-1-100</c> does not cover <c>HKU\S-1-5-21-1-1001</c>. The
    /// location may carry a display suffix after a space (<c>… [Registry64]</c>).
    /// </remarks>
    internal static bool ScopeCovers(string scope, string location)
    {
        var trimmed = scope.TrimEnd('\\');
        return location.StartsWith(trimmed, StringComparison.OrdinalIgnoreCase)
            && (location.Length == trimmed.Length || location[trimmed.Length] is '\\' or ' ');
    }
}
