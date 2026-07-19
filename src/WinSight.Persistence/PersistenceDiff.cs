namespace WinSight.Persistence;

/// <summary>The outcome of comparing a fresh persistence scan against a known baseline.</summary>
/// <param name="Added">Entries whose identity was not in the baseline (each identity once).</param>
/// <param name="Removed">Baseline identities absent from the fresh scan.</param>
public sealed record PersistenceDiffResult(
    IReadOnlyList<AutostartEntry> Added,
    IReadOnlyList<PersistenceIdentity> Removed);

/// <summary>
/// Pure comparison of a fresh persistence scan against a baseline set of identities. It holds no
/// state, does no I/O, and never touches a clock — the monitor's correctness lives here, where a
/// unit test can reach it.
/// </summary>
public static class PersistenceDiffEngine
{
    public static PersistenceDiffResult Diff(
        IReadOnlySet<PersistenceIdentity> baseline,
        IReadOnlyList<AutostartEntry> fresh)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(fresh);

        var freshIdentities = new HashSet<PersistenceIdentity>();
        var added = new List<AutostartEntry>();
        foreach (var entry in fresh)
        {
            var id = PersistenceIdentity.FromEntry(entry);
            // A single scan can legitimately carry the same identity twice (e.g. HKLM and HKCU
            // resolving to the same target); count it once and keep the first occurrence.
            if (!freshIdentities.Add(id))
            {
                continue;
            }
            if (!baseline.Contains(id))
            {
                added.Add(entry);
            }
        }

        var removed = new List<PersistenceIdentity>();
        foreach (var id in baseline)
        {
            if (!freshIdentities.Contains(id))
            {
                removed.Add(id);
            }
        }

        return new PersistenceDiffResult(added, removed);
    }
}
