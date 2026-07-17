using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WinSight.Firewall;

/// <summary>
/// Builds the restrictive named-pipe ACL and the caller-authorisation decision for the
/// privileged firewall service. Framing is not authentication: the pipe must only be
/// reachable by trusted local principals, and the connected identity is checked again
/// before any command runs.
/// </summary>
public static class FirewallServiceSecurity
{
    /// <summary>The default local pipe name for the WinSight outbound-firewall service.</summary>
    public const string DefaultPipeName = @"WinSight\firewall";

    /// <summary>
    /// A hardened <see cref="PipeSecurity"/> explicitly owned by SYSTEM: full control for SYSTEM and the local
    /// Administrators group, read/write for interactive local users so the unprivileged
    /// dashboard can connect, and an explicit deny for network logons so the pipe is
    /// never reachable remotely. Anonymous and everyone-style access is never granted.
    /// </summary>
    public static PipeSecurity CreateHardenedSecurity()
    {
        var security = new PipeSecurity();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        security.SetOwner(system);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            interactive,
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
            AccessControlType.Allow));

        // Deny takes precedence over any allow: a remote (network) logon can never use
        // the pipe even if it is otherwise a member of an allowed group.
        security.AddAccessRule(new PipeAccessRule(network, PipeAccessRights.FullControl, AccessControlType.Deny));

        return security;
    }

    /// <summary>
    /// True only for a real, authenticated, non-anonymous, non-guest Windows identity.
    /// Fails closed: a null or unauthenticated identity is never authorised.
    /// </summary>
    public static bool IsAuthorisedCaller(WindowsIdentity? identity)
        => GetCallerCapability(identity) != FirewallCallerCapability.None;

    public static FirewallCallerCapability GetCallerCapability(WindowsIdentity? identity)
    {
        if (identity is null || !identity.IsAuthenticated || identity.IsAnonymous || identity.IsGuest)
        {
            return FirewallCallerCapability.None;
        }
        if (identity.User is null || identity.Groups?.Contains(
                new SecurityIdentifier(WellKnownSidType.NetworkSid, null)) == true)
        {
            return FirewallCallerCapability.None;
        }
        if (identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            return FirewallCallerCapability.MutateMachinePolicy;
        }
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
            ? FirewallCallerCapability.MutateMachinePolicy
            : FirewallCallerCapability.ReadStatus;
    }
}

public enum FirewallCallerCapability
{
    None,
    ReadStatus,
    MutateMachinePolicy,
}
