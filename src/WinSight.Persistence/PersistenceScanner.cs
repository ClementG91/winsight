using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// KnockKnock-class scanner: sweeps every registered autostart surface, resolves each
/// item's on-disk executable, and attaches its Authenticode verdict. Read-only — it
/// reveals what persists; it never removes anything.
/// </summary>
public sealed class PersistenceScanner
{
    private readonly IReadOnlyList<IAutostartEnumerator> _enumerators;
    private readonly SignatureVerifier _verifier;

    public PersistenceScanner(
        IReadOnlyList<IAutostartEnumerator>? enumerators = null,
        SignatureVerifier? verifier = null)
    {
        _enumerators = enumerators ?? DefaultEnumerators();
        _verifier = verifier ?? new SignatureVerifier();
    }

    /// <summary>The autostart surfaces covered by a default scan (Phase 1).</summary>
    public static IReadOnlyList<IAutostartEnumerator> DefaultEnumerators() =>
        new IAutostartEnumerator[] { new RunKeyEnumerator(), new ServiceEnumerator() };

    /// <summary>
    /// Enumerates every autostart item across all surfaces, newest-surface-first in
    /// registration order. Enumerator failures are isolated per surface.
    /// </summary>
    public IReadOnlyList<AutostartEntry> Scan()
    {
        var results = new List<AutostartEntry>();
        foreach (var enumerator in _enumerators)
        {
            foreach (var raw in enumerator.Enumerate())
            {
                var image = CommandLine.ExtractExecutable(raw.Command);
                var verdict = image is null ? SignatureVerdict.Missing : _verifier.Verify(image);
                results.Add(new AutostartEntry(
                    raw.Vector, raw.Name, raw.Location, raw.Command, image, verdict));
            }
        }
        return results;
    }
}
