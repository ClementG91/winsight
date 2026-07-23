using WinSight.Firewall;

namespace WinSight.Application;

/// <summary>What the authenticated firewall pipe grants the current caller.</summary>
public enum IpcSelfTestOutcome
{
    /// <summary>The service could not be read at all: not installed, not running, or the caller's
    /// identity is not permitted even to read (the fail-closed <c>None</c> capability).</summary>
    ServiceUnavailable,

    /// <summary>The caller can read status but is refused a policy mutation - the expected result for
    /// a standard user or an unelevated administrator.</summary>
    CanReadOnly,

    /// <summary>The caller can read status and mutate policy - the expected result for an elevated
    /// administrator or SYSTEM.</summary>
    CanMutate,

    /// <summary>The caller can read, but enforcement is active, so the mutation leg was deliberately
    /// not sent: a diagnostic must never reconcile WFP on a live-armed machine.</summary>
    ReadableMutateSkipped,
}

/// <summary>The observed outcome of one IPC self-test run.</summary>
public sealed record IpcSelfTestResult(
    IpcSelfTestOutcome Outcome,
    bool ServiceAvailable,
    OutboundFirewallMode Mode,
    FirewallEnforcementState EffectiveState,
    FirewallMutationResult? MutationProbe);

/// <summary>
/// Reports what capability the authenticated firewall pipe grants the current caller, without
/// changing machine state. It reads status, then - unless the machine is armed - sends one mutation
/// that removes the policy for a path that is never a real policed executable, so an authorized
/// caller removes nothing and an unauthorized caller is refused before the request is dispatched.
///
/// The point is the multi-user boundary: run under a standard user or an unelevated administrator it
/// must report <see cref="IpcSelfTestOutcome.CanReadOnly"/>; run elevated it may report
/// <see cref="IpcSelfTestOutcome.CanMutate"/>. It is the read-only, side-effect-free way to exercise
/// that boundary end to end over the real pipe.
/// </summary>
public static class FirewallIpcSelfTest
{
    /// <summary>
    /// A syntactically valid path that cannot be a real policed executable, so removing its (absent)
    /// policy is a no-op for an authorized caller. Chosen under the machine-data root the service
    /// itself owns rather than a user path, so it can never collide with a real user application.
    /// </summary>
    public const string ProbePath = @"C:\ProgramData\WinSight\__ipc-selftest-probe__.exe";

    public static async Task<IpcSelfTestResult> RunAsync(
        FirewallServiceGateway gateway,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(gateway);

        var view = await gateway.GetViewAsync(cancellationToken).ConfigureAwait(false);
        if (!view.ServiceAvailable)
        {
            return new IpcSelfTestResult(
                IpcSelfTestOutcome.ServiceUnavailable, false, view.Mode, view.EffectiveState, null);
        }

        // A no-op RemovePolicy still reconciles WFP when the machine is armed. A diagnostic must not
        // do that, so read-only is the whole answer here.
        if (view.EffectiveState == FirewallEnforcementState.Active)
        {
            return new IpcSelfTestResult(
                IpcSelfTestOutcome.ReadableMutateSkipped, true, view.Mode, view.EffectiveState, null);
        }

        var mutation = await gateway.RemovePolicyAsync(ProbePath, cancellationToken).ConfigureAwait(false);
        var outcome = mutation switch
        {
            // Refused before dispatch: the caller can read but not mutate.
            FirewallMutationResult.Unauthorized => IpcSelfTestOutcome.CanReadOnly,
            // The read worked a moment ago but the mutate leg could not reach the service; stay
            // conservative rather than claim a mutate capability that was never demonstrated.
            FirewallMutationResult.ServiceUnavailable => IpcSelfTestOutcome.CanReadOnly,
            // Anything else means the request passed the authorization gate, which only a
            // mutate-capable caller can do.
            _ => IpcSelfTestOutcome.CanMutate,
        };
        return new IpcSelfTestResult(outcome, true, view.Mode, view.EffectiveState, mutation);
    }
}
