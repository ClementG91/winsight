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

    /// <summary>Saves the current baseline, replacing any previous one. Best-effort; failures are swallowed.</summary>
    void Save(IReadOnlyCollection<PersistenceIdentity> baseline);
}
