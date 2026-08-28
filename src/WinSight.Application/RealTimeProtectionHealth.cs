namespace WinSight.Application;

/// <summary>How much of a real-time protection is actually running.</summary>
public enum ProtectionState
{
    /// <summary>Deliberately not running. An operator choice, not a failure.</summary>
    Off,

    /// <summary>Running, and watching everything it was asked to.</summary>
    Active,

    /// <summary>Running, but blind in part of what it was asked to watch.</summary>
    Partial,

    /// <summary>Asked to run and watching nothing at all.</summary>
    Failed,
}

/// <summary>One real-time monitor's state, ready to render.</summary>
/// <param name="Name">Stable identifier of the monitor, e.g. <c>Guardian</c>.</param>
/// <param name="State">What it is actually doing.</param>
/// <param name="Armed">Locations it is watching.</param>
/// <param name="Requested">Locations it was asked to watch.</param>
/// <param name="LostObservations">True when it is known to have dropped events.</param>
public readonly record struct MonitorHealth(
    string Name,
    ProtectionState State,
    int Armed,
    int Requested,
    bool LostObservations = false)
{
    /// <summary>
    /// The state implied by a monitor that is meant to be running and watches
    /// <paramref name="armed"/> of <paramref name="requested"/> locations.
    /// </summary>
    /// <remarks>
    /// Zero armed out of a non-zero request is a failure, not a partial: the monitor is on and sees
    /// nothing, which is the exact case that used to render identically to a healthy one. A monitor
    /// asked to watch nothing is Active rather than Failed - there is nothing it is failing to do.
    /// </remarks>
    public static MonitorHealth For(
        string name, bool enabled, int armed, int requested, bool lostObservations = false)
    {
        if (!enabled)
        {
            return new MonitorHealth(name, ProtectionState.Off, 0, requested);
        }
        var state = requested > 0 && armed == 0
            ? ProtectionState.Failed
            : armed < requested || lostObservations
                ? ProtectionState.Partial
                : ProtectionState.Active;
        return new MonitorHealth(name, state, armed, requested, lostObservations);
    }
}

/// <summary>
/// The combined state of the dashboard's real-time protections, so the UI can show what is actually
/// running rather than what was switched on.
/// </summary>
/// <remarks>
/// <b>The inconsistency this exists to remove.</b> Everywhere else, this codebase refuses to turn "I
/// could not read" into "nothing found" - <c>PersistenceCoverage</c>, <c>AcquisitionSnapshot</c>,
/// <c>AttributionHealth</c>, the firewall's separation of desired mode from effective state. That
/// discipline stopped exactly where the operator looks. Guardian, the camera/mic watch and the
/// ransomware monitor all started inside a fire-and-forget task whose failures were swallowed
/// deliberately; the checkbox stayed ticked, the badge stayed green, and a protection that never
/// started looked identical to one that was working. The counts to tell them apart already existed
/// and nothing read them.
/// </remarks>
public sealed record RealTimeProtectionHealth(IReadOnlyList<MonitorHealth> Monitors)
{
    public static readonly RealTimeProtectionHealth Unknown = new([]);

    /// <summary>The weakest state among the monitors that are meant to be running.</summary>
    /// <remarks>
    /// Weakest rather than average, because a summary that averages away a dead monitor is the
    /// failure this replaces. Monitors that are off do not drag the summary down: an operator who
    /// turned something off already knows.
    /// </remarks>
    public ProtectionState Overall
    {
        get
        {
            var running = Monitors.Where(monitor => monitor.State != ProtectionState.Off).ToList();
            if (running.Count == 0)
            {
                return ProtectionState.Off;
            }
            if (running.Any(monitor => monitor.State == ProtectionState.Failed))
            {
                return ProtectionState.Failed;
            }
            return running.Any(monitor => monitor.State == ProtectionState.Partial)
                ? ProtectionState.Partial
                : ProtectionState.Active;
        }
    }

    /// <summary>Monitors that are running and watching everything they were asked to.</summary>
    public int HealthyCount => Monitors.Count(monitor => monitor.State == ProtectionState.Active);

    /// <summary>Monitors that are meant to be running.</summary>
    public int RunningCount => Monitors.Count(monitor => monitor.State != ProtectionState.Off);

    /// <summary>
    /// One line per monitor, naming its state and what it covers. Culture-independent detail the UI
    /// pairs with a localised heading.
    /// </summary>
    public IReadOnlyList<string> Lines() =>
        [.. Monitors.Select(monitor => monitor.State switch
        {
            ProtectionState.Off => $"{monitor.Name}: off",
            ProtectionState.Failed => $"{monitor.Name}: FAILED - watching none of {monitor.Requested}",
            ProtectionState.Partial when monitor.LostObservations =>
                $"{monitor.Name}: partial - {monitor.Armed}/{monitor.Requested}, events were dropped",
            ProtectionState.Partial => $"{monitor.Name}: partial - {monitor.Armed}/{monitor.Requested}",
            _ => $"{monitor.Name}: active - {monitor.Armed}/{monitor.Requested}",
        })];
}
