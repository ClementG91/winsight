namespace WinSight.FirewallService;

/// <summary>
/// Records that the service stopped because its endpoint was lost, so the process can exit with a
/// failure code and the SCM applies the restart actions the installer configured.
/// </summary>
/// <remarks>
/// <b>Why the exit code decides whether recovery happens at all.</b> On endpoint loss the worker
/// calls <c>StopApplication</c>, the host returns normally and the process exited 0. The Service
/// Control Manager reads that as a clean, intentional stop, and
/// <c>SERVICE_FAILURE_ACTIONS</c> - configured with restarts at 5 s, 30 s and then every 60 s - is
/// only consulted when a service terminates with an error. So the recovery path never ran: the SCM
/// saw nothing to recover from, and the hard-exit watchdog is a background thread that a normal
/// process exit removes before its eight seconds elapse.
///
/// The concrete consequence is the pipe-squatting case. A caller that owns the pipe name before the
/// service starts makes <c>FIRST_PIPE_INSTANCE</c> creation fail after
/// <c>EnforcementStartupService</c> has already applied the filters, so the squatter gets "filters
/// applied, then immediately removed" - in a loop, without privilege, and with nothing restarting
/// the service in between.
/// </remarks>
internal sealed class FirewallServiceExitSignal
{
    private int _endpointLost;

    /// <summary>True once the endpoint was lost outside a requested shutdown.</summary>
    internal bool EndpointLost => Volatile.Read(ref _endpointLost) != 0;

    /// <summary>The process exit code: a failure the SCM will act on, or success.</summary>
    /// <remarks>
    /// 1 rather than a distinctive value on purpose: the SCM only distinguishes zero from non-zero
    /// when deciding whether to run a failure action, and a service exit code is reported to the
    /// operator through <c>sc query</c> where a Win32-shaped value would be misread as one.
    /// </remarks>
    internal int ExitCode => EndpointLost ? 1 : 0;

    internal void ReportEndpointLost() => Volatile.Write(ref _endpointLost, 1);
}
