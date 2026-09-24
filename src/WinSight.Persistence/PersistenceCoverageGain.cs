namespace WinSight.Persistence;

/// <summary>
/// Entries seen for the first time because their location was read in full for the first time - an
/// elevated launch after unelevated ones, typically - and which were added to the baseline without
/// an alert (WS-70).
/// </summary>
/// <remarks>
/// <b>Uncertain, not clean (RA-03).</b> Almost all of them are what they look like: items that were
/// always there and that the earlier view was not allowed to read. But an entry written while its
/// location was unreadable looks exactly like one written years ago, and absorbing both without a
/// word hid that gap completely. This says when WinSight's view widened, what it found at that
/// moment, and that it cannot date those items. It does not say they are hostile.
/// </remarks>
/// <param name="ObservedUtc">The scan that widened the view.</param>
/// <param name="Entries">What it found where it could not read before, at most <see cref="MaxListed"/>.</param>
/// <param name="Unlisted">Entries absorbed beyond <see cref="MaxListed"/>, counted but not kept.</param>
public sealed record PersistenceCoverageGain(
    DateTimeOffset ObservedUtc,
    IReadOnlyList<AutostartEntry> Entries,
    int Unlisted = 0)
{
    /// <summary>A first elevated scan of a busy machine is thousands of items; the notice is not.</summary>
    public const int MaxListed = 4096;

    /// <summary>Every entry the gain absorbed, listed or not.</summary>
    public int Count => Entries.Count + Unlisted;

    /// <summary>The surfaces the entries came from, each once, in the order first seen.</summary>
    public IReadOnlyList<string> Sources =>
        Entries.Select(entry => entry.Source).Where(source => source.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
}
