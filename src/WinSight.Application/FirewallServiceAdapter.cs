using WinSight.Firewall;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// Projects the outbound-firewall service view into the shared report shape the
/// dashboard renders, and builds a gateway over the real pipe client. Read-only: it
/// never mutates policy. Executable paths are preserved verbatim as forensic evidence;
/// only the WinSight-owned status and action labels are localized downstream.
/// </summary>
public static class FirewallServiceAdapter
{
    /// <summary>The report tool name, matching the dashboard navigation entry.</summary>
    public const string ReportTool = "outbound-firewall";

    /// <summary>A gateway over the real, authenticated firewall service pipe.</summary>
    public static FirewallServiceGateway CreateGateway() => new(new FirewallServiceClient());

    /// <summary>Maps a service view into a report: one status line plus one line per policy.</summary>
    public static ToolReport BuildReport(FirewallServiceView view)
    {
        ArgumentNullException.ThrowIfNull(view);
        var builder = new ToolReport.Builder(ReportTool);

        builder.Add(
            Severity.Info,
            "service",
            view.ServiceAvailable ? view.Mode.ToString() : "not installed",
            new Dictionary<string, string?>
            {
                ["kind"] = "status",
                ["available"] = view.ServiceAvailable.ToString(),
                ["mode"] = view.Mode.ToString(),
                ["enforcement"] = view.EnforcementEnabled.ToString(),
            });

        foreach (var policy in view.Policies.OrderBy(p => p.ExecutablePath, StringComparer.OrdinalIgnoreCase))
        {
            builder.Add(
                Severity.Info,
                policy.ExecutablePath,
                policy.Action.ToString(),
                new Dictionary<string, string?>
                {
                    ["kind"] = "policy",
                    ["path"] = policy.ExecutablePath,
                    ["action"] = policy.Action.ToString(),
                });
        }

        var summary = view.ServiceAvailable
            ? $"{view.Mode}, {view.Policies.Count} policy(ies)"
            : "service not installed";
        return builder.Build(summary);
    }
}
