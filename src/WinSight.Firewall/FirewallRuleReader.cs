using System.Management;

namespace WinSight.Firewall;

/// <summary>
/// LuLu-class (read-only, phase 1): reads the Windows Defender Firewall rules
/// (MSFT_NetFirewallRule in root\StandardCimv2 — the same source as
/// Get-NetFirewallRule) so a user can see what their firewall allows and blocks.
/// Managed via System.Management (no admin needed to read). Per-rule program/port
/// enrichment (via the associated application/port filters) and an enforcing,
/// prompt-on-connection firewall are later phases.
/// </summary>
public sealed class FirewallRuleReader
{
    public IReadOnlyList<FirewallRule> Read()
    {
        var rules = new List<FirewallRule>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT DisplayName, Direction, Action, Enabled FROM MSFT_NetFirewallRule"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                using (o)
                {
                    var name = o["DisplayName"] as string ?? string.Empty;
                    if (name.Length == 0)
                    {
                        continue;
                    }
                    rules.Add(new FirewallRule(
                        name,
                        FirewallEnum.Direction(ToInt(o["Direction"])),
                        FirewallEnum.Action(ToInt(o["Action"])),
                        ToInt(o["Enabled"]) == 1)); // MSFT enum: 1 = True, 2 = False
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Namespace/class unavailable — no rules surfaced.
        }
        return rules;
    }

    private static int ToInt(object? value) => value switch
    {
        ushort u => u,
        uint u => (int)u,
        int i => i,
        byte b => b,
        _ => 0,
    };
}
