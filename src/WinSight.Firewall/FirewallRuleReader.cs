using System.Management;

namespace WinSight.Firewall;

/// <summary>
/// LuLu-class (read-only, phase 1): reads the Windows Defender Firewall rules
/// (MSFT_NetFirewallRule in root\StandardCimv2, the same source as
/// Get-NetFirewallRule), enriched with each rule's bound program and ports from the
/// associated application/port filters (joined by InstanceID, best-effort). Managed
/// via System.Management (no admin needed to read). An enforcing,
/// prompt-on-connection firewall is a later phase (needs a background service/WFP).
/// </summary>
public sealed class FirewallRuleReader
{
    private const string Namespace = @"\\.\root\StandardCimv2";

    public IReadOnlyList<FirewallRule> Read()
    {
        // Program/port live on separate filter objects keyed by the same InstanceID
        // as the rule; read them once and join in memory (avoids a query per rule).
        var programs = FilterMap("MSFT_NetFirewallApplicationFilter", o => Str(o, "Program"));
        var ports = FilterMap("MSFT_NetFirewallPortFilter",
            o => JoinPort(Str(o, "Protocol"), Str(o, "LocalPort")));

        var rules = new List<FirewallRule>();
        try
        {
            var scope = new ManagementScope(Namespace);
            using var searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT InstanceID, DisplayName, Direction, Action, Enabled FROM MSFT_NetFirewallRule"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                using (o)
                {
                    var name = Str(o, "DisplayName");
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }
                    var id = Str(o, "InstanceID") ?? string.Empty;
                    rules.Add(new FirewallRule(
                        name,
                        FirewallEnum.Direction(ToInt(o["Direction"])),
                        FirewallEnum.Action(ToInt(o["Action"])),
                        ToInt(o["Enabled"]) == 1, // MSFT enum: 1 = True, 2 = False
                        programs.GetValueOrDefault(id),
                        ports.GetValueOrDefault(id)));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Namespace/class unavailable, no rules surfaced.
        }
        return rules;
    }

    private static Dictionary<string, string?> FilterMap(string className, Func<ManagementBaseObject, string?> valueOf)
    {
        var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var scope = new ManagementScope(Namespace);
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {className}"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                using (o)
                {
                    var id = Str(o, "InstanceID");
                    var value = valueOf(o);
                    if (id is not null && !string.IsNullOrEmpty(value) && value != "Any")
                    {
                        map[id] = value;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Filter class unavailable, rules just won't be enriched.
        }
        return map;
    }

    private static string? JoinPort(string? protocol, string? localPort)
    {
        if (string.IsNullOrEmpty(protocol) || protocol == "Any")
        {
            return string.IsNullOrEmpty(localPort) ? null : localPort;
        }
        return string.IsNullOrEmpty(localPort) ? protocol : $"{protocol}:{localPort}";
    }

    // Reads a property as a string, tolerating an absent property.
    private static string? Str(ManagementBaseObject o, string name)
    {
        try
        {
            return o[name]?.ToString();
        }
        catch (ManagementException)
        {
            return null;
        }
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
