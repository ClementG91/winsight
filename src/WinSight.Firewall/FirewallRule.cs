namespace WinSight.Firewall;

/// <summary>Traffic direction a firewall rule applies to.</summary>
public enum FirewallDirection
{
    Inbound,
    Outbound,
    Unknown,
}

/// <summary>What a firewall rule does to matching traffic.</summary>
public enum FirewallAction
{
    Allow,
    Block,
    Unknown,
}

/// <summary>A Windows Defender Firewall rule (read-only view).</summary>
/// <param name="DisplayName">The rule's display name.</param>
/// <param name="Direction">Inbound or outbound.</param>
/// <param name="Action">Allow or block.</param>
/// <param name="Enabled">Whether the rule is currently active.</param>
/// <param name="Program">The bound executable, when the rule targets one.</param>
/// <param name="Ports">A "protocol:ports" summary, when the rule specifies one.</param>
public sealed record FirewallRule(
    string DisplayName,
    FirewallDirection Direction,
    FirewallAction Action,
    bool Enabled,
    string? Program,
    string? Ports);

/// <summary>Maps the MSFT_NetFirewallRule numeric enums to WinSight's.</summary>
public static class FirewallEnum
{
    public static FirewallDirection Direction(int value) => value switch
    {
        1 => FirewallDirection.Inbound,
        2 => FirewallDirection.Outbound,
        _ => FirewallDirection.Unknown,
    };

    public static FirewallAction Action(int value) => value switch
    {
        2 => FirewallAction.Allow,
        4 => FirewallAction.Block,
        _ => FirewallAction.Unknown,
    };
}
