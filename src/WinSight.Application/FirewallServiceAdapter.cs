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
            view.ServiceAvailable ? view.EffectiveState.ToString() : "Unavailable",
            new Dictionary<string, string?>
            {
                ["kind"] = "status",
                ["available"] = view.ServiceAvailable.ToString(),
                ["mode"] = view.Mode.ToString(),
                ["enforcement"] = view.EnforcementEnabled.ToString(),
                ["effectiveState"] = view.EffectiveState.ToString(),
                ["unrecorded"] = view.UnrecordedApps.ToString(System.Globalization.CultureInfo.InvariantCulture),
            });

        // An app that reached the network with nobody having ruled on it is the one thing here that
        // genuinely wants a human, so it is Notable: it survives the "only what needs attention"
        // filter and makes a scripted check exit non-zero. It is listed before the settled policies.
        foreach (var app in view.Pending)
        {
            builder.Add(
                Severity.Notable,
                app.ExecutablePath,
                app.LastRemote,
                new Dictionary<string, string?>
                {
                    ["kind"] = "pending",
                    ["path"] = app.ExecutablePath,
                    ["remote"] = app.LastRemote,
                    ["firstSeen"] = app.FirstSeenUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    ["lastSeen"] = app.LastSeenUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
                    ["observations"] = app.Observations.ToString(System.Globalization.CultureInfo.InvariantCulture),
                });
        }

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
                    ["enabled"] = policy.Enabled.ToString(),
                });
        }

        // Summary is a protocol-facing invariant, not dashboard presentation. The dashboard
        // localizes status from the structured fields above; keeping this bounded avoids adding
        // an English-only sentence to an otherwise localized user surface.
        var summary = view.ServiceAvailable ? view.EffectiveState.ToString() : "Unavailable";
        return builder.Build(summary);
    }
}
