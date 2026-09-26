namespace WinSight.Persistence;

/// <summary>
/// Persists the Guardian baseline (the set of known autostart identities) across runs, so the next
/// launch can tell what persistence appeared while WinSight was not running. It stores identities
/// only — the same autostart names and target paths the on-demand scan already shows, on the user's
/// own machine, no secrets — and it is local-only (no telemetry).
/// </summary>
public interface IPersistenceBaselineStore
{
    /// <summary>
    /// Loads the last-saved baseline, or null when there is none or it could not be read. A null
    /// result means "treat this as a first run and seed silently", never a crash.
    /// </summary>
    IReadOnlySet<PersistenceIdentity>? Load();

    /// <summary>
    /// Saves the current baseline, replacing any previous one. Implementations report failures; the
    /// monitor owns the retry/error boundary so persistence loss is observable.
    /// </summary>
    void Save(IReadOnlyCollection<PersistenceIdentity> baseline);

    /// <summary>
    /// Loads the baseline with the coverage it was saved under (WS-70). Coverage is null for a
    /// baseline saved without it, which keeps the pre-coverage behaviour for that one read.
    /// </summary>
    PersistedBaseline? LoadWithCoverage() => Load() is { } identities ? new PersistedBaseline(identities, null) : null;

    /// <summary>Saves the baseline together with the coverage it reflects.</summary>
    void Save(IReadOnlyCollection<PersistenceIdentity> baseline, PersistenceCoverageMap? coverage) => Save(baseline);
}

/// <summary>A persisted baseline and, when it was saved with one, its coverage.</summary>
public sealed record PersistedBaseline(
    IReadOnlySet<PersistenceIdentity> Identities,
    PersistenceCoverageMap? Coverage);
