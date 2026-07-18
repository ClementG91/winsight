using System.Globalization;
using WinSight.Firewall;
using WinSight.Reporting;

namespace WinSight.Dashboard;

public sealed record FindingPresentation(string Title, string Detail);

/// <summary>
/// Turns structured report evidence into localized UI text. Paths, process names,
/// domains and other forensic values are preserved exactly; only WinSight-owned
/// semantic labels are translated.
/// </summary>
public static class DashboardFindingPresenter
{
    public static FindingPresentation Present(
        string tool,
        ReportItem item,
        LocalizationManager text) => tool switch
        {
            "persistence" => Persistence(item, text),
            "camera-mic" => CameraMic(item, text),
            "processes" => Process(item, text),
            "modules" => Module(item, text),
            "hosts" => Hosts(item, text),
            "certificates" => Certificate(item, text),
            "extensions" => Extension(item, text),
            "firewall" => Firewall(item, text),
            "outbound-firewall" => OutboundFirewall(item, text),
            "connections" => Connection(item, text),
            _ => new FindingPresentation(item.Title, item.Detail),
        };

    public static string Detail(string tool, ReportItem item, LocalizationManager text) =>
        Present(tool, item, text).Detail;

    private static FindingPresentation Persistence(ReportItem item, LocalizationManager text)
    {
        var status = Field(item, "status");
        var label = string.IsNullOrWhiteSpace(status)
            ? text["PersistenceStatusVerificationError"]
            : text.GetOrFallback($"PersistenceStatus{status}", status);
        var evidence = FirstNonEmpty(item, "image", "expectedImage", "command") ?? item.Detail;
        var suffix = HasVirusTotal(item, out var malicious, out var total)
            ? $"{label}; VT {malicious}/{total}"
            : label;
        var vector = Field(item, "vector");
        var name = Field(item, "name");
        var localizedVector = string.IsNullOrWhiteSpace(vector)
            ? string.Empty
            : text.GetOrFallback($"PersistenceVector{vector}", vector);
        var title = !string.IsNullOrWhiteSpace(localizedVector) && !string.IsNullOrWhiteSpace(name)
            ? $"{localizedVector}/{name}"
            : item.Title;
        return new FindingPresentation(title, $"{evidence}  [{suffix}]");
    }

    private static FindingPresentation CameraMic(ReportItem item, LocalizationManager text)
    {
        var kind = Field(item, "kind");
        var device = kind == "webcam" ? text["SensorWebcam"] : text["SensorMicrophone"];
        var app = Field(item, "app") ?? text["UnknownValue"];
        var title = text.Format("SensorItemTitle", device, app);
        if (BoolField(item, "active"))
        {
            return new FindingPresentation(title, text["SensorInUseNow"]);
        }

        var timestamp = FirstNonEmpty(item, "lastStop", "lastStart");
        if (DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var used))
        {
            return new FindingPresentation(title, text.Format("SensorLastUsed", used.ToLocalTime().ToString("g", text.Culture)));
        }
        return new FindingPresentation(title, text.Format("SensorLastUsed", text["UnknownValue"]));
    }

    private static FindingPresentation Process(ReportItem item, LocalizationManager text)
    {
        var name = Field(item, "name") ?? item.Title;
        var pid = Field(item, "pid") ?? "?";
        return new FindingPresentation(
            text.Format("ProcessWithPid", name, pid),
            Field(item, "path") ?? text["NoImage"]);
    }

    private static FindingPresentation Module(ReportItem item, LocalizationManager text)
    {
        var process = Field(item, "process") ?? text["UnknownValue"];
        var pid = Field(item, "pid") ?? "?";
        var module = Field(item, "module") ?? text["UnknownValue"];
        return new FindingPresentation(
            text.Format("ModuleLoadedByProcess", process, pid, module),
            Field(item, "path") ?? text["UnknownValue"]);
    }

    private static FindingPresentation Hosts(ReportItem item, LocalizationManager text)
    {
        var detail = item.Severity == Severity.Info
            ? text["StaticMapping"]
            : BoolField(item, "isSink")
                ? text["HostSecurityBlackhole"]
                : text["HostExternalRedirect"];
        return new FindingPresentation(item.Title, detail);
    }

    private static FindingPresentation Certificate(ReportItem item, LocalizationManager text)
    {
        if (item.Severity == Severity.Info)
        {
            return new FindingPresentation(
                item.Title,
                text.Format("CertificateProperties", Field(item, "signatureAlgorithm"), Field(item, "keyBits")));
        }

        var risks = new List<string>();
        if (BoolField(item, "hasPrivateKey"))
        {
            risks.Add(text["CertificatePrivateKeyRisk"]);
        }
        if (!BoolField(item, "isSelfSigned") && IsWeakSignature(Field(item, "signatureAlgorithm")))
        {
            risks.Add(text.Format("CertificateWeakSignatureRisk", Field(item, "signatureAlgorithm")));
        }
        if (BoolField(item, "isRsa") && int.TryParse(Field(item, "keyBits"), out var bits) && bits is > 0 and < 2048)
        {
            risks.Add(text.Format("CertificateSmallRsaRisk", bits));
        }
        return new FindingPresentation(item.Title, risks.Count == 0 ? item.Detail : string.Join("; ", risks));
    }

    private static FindingPresentation Extension(ReportItem item, LocalizationManager text)
    {
        var permissions = new[] { Field(item, "permissions"), Field(item, "hostPermissions") }
            .Where(value => !string.IsNullOrWhiteSpace(value));
        var detail = string.Join(" ", permissions);
        return new FindingPresentation(item.Title, detail.Length == 0 ? text["NoDeclaredPermissions"] : detail);
    }

    private static FindingPresentation Firewall(ReportItem item, LocalizationManager text)
    {
        var direction = LocalizedEnum(text, "FirewallDirection", Field(item, "direction"));
        var action = LocalizedEnum(text, "FirewallAction", Field(item, "action"));
        var name = Field(item, "name") ?? item.Title;
        var details = new[] { Field(item, "program"), Field(item, "ports") }
            .Where(value => !string.IsNullOrWhiteSpace(value));
        return new FindingPresentation(text.Format("FirewallRuleTitle", direction, action, name), string.Join("  ", details));
    }

    /// <summary>
    /// Renders one row of the outbound-firewall report.
    /// </summary>
    /// <remarks>
    /// The dispatch is explicit on kind, and an unrecognised kind falls back to the report's own
    /// values rather than to the status branch. An earlier version tested kind only for "policy"
    /// and let everything else fall through: when pending rows arrived they had no "available"
    /// field, read as unavailable, and every one of them rendered as "the service is not
    /// installed" while the service was running. A row that is not a status row must never be able
    /// to speak as one — that is not a cosmetic slip, it is the UI stating the opposite of the
    /// truth about whether the machine is protected.
    /// </remarks>
    private static FindingPresentation OutboundFirewall(ReportItem item, LocalizationManager text) =>
        Field(item, "kind") switch
        {
            "policy" => OutboundFirewallPolicy(item, text),
            "pending" => OutboundFirewallPending(item, text),
            "status" => OutboundFirewallStatus(item, text),
            _ => new FindingPresentation(item.Title, item.Detail),
        };

    private static FindingPresentation OutboundFirewallPolicy(ReportItem item, LocalizationManager text)
    {
        var action = Field(item, "action");
        var actionLabel = text.GetOrFallback($"OutboundAction{action}", action ?? item.Detail);
        // A policy the operator switched off does not filter, so showing only its action would read
        // as if it still did. Mark a disabled policy explicitly, or the row implies protection that
        // is turned off. Only an explicit "False" disables it; a missing field stays enabled.
        var detail = string.Equals(Field(item, "enabled"), "False", StringComparison.OrdinalIgnoreCase)
            ? text.Format("OutboundActionDisabled", actionLabel)
            : actionLabel;
        return new FindingPresentation(Field(item, "path") ?? item.Title, detail);
    }

    /// <summary>An app that reached the network with nobody having ruled on it: the row that wants a human.</summary>
    private static FindingPresentation OutboundFirewallPending(ReportItem item, LocalizationManager text)
    {
        var remote = Field(item, "remote") ?? text["UnknownValue"];
        var observations = Field(item, "observations") ?? "1";
        return new FindingPresentation(
            Field(item, "path") ?? item.Title,
            text.Format("OutboundFirewallPending", remote, observations));
    }

    private static FindingPresentation OutboundFirewallStatus(ReportItem item, LocalizationManager text)
    {
        if (!BoolField(item, "available"))
        {
            return new FindingPresentation(text["OutboundFirewallServiceTitle"], text["OutboundFirewallUnavailable"]);
        }

        var detail = Field(item, "effectiveState") switch
        {
            nameof(FirewallEnforcementState.Active) => text["OutboundFirewallEnforcing"],
            nameof(FirewallEnforcementState.Degraded) => text["OutboundFirewallDegraded"],
            _ => text["OutboundFirewallAuditOnly"],
        };
        return new FindingPresentation(text["OutboundFirewallServiceTitle"], detail);
    }

    private static FindingPresentation Connection(ReportItem item, LocalizationManager text)
    {
        var process = Field(item, "process") ?? text["UnknownValue"];
        var pid = Field(item, "pid") ?? "?";
        var state = Field(item, "state");
        var detail = text.Format("ConnectionProcessState", process, pid, state);
        if (HasVirusTotal(item, out var malicious, out var total))
        {
            detail += $"  [VT {malicious}/{total}]";
        }
        return new FindingPresentation(item.Title, detail);
    }

    private static string LocalizedEnum(LocalizationManager text, string prefix, string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
        return text.GetOrFallback($"{prefix}{normalized}", normalized);
    }

    private static bool HasVirusTotal(ReportItem item, out string malicious, out string total)
    {
        malicious = Field(item, "vtMalicious") ?? string.Empty;
        total = Field(item, "vtTotal") ?? string.Empty;
        return malicious.Length > 0 && total.Length > 0;
    }

    private static bool IsWeakSignature(string? algorithm) =>
        algorithm?.Contains("md5", StringComparison.OrdinalIgnoreCase) == true ||
        algorithm?.Contains("sha1", StringComparison.OrdinalIgnoreCase) == true ||
        algorithm?.Contains("md2", StringComparison.OrdinalIgnoreCase) == true;

    private static bool BoolField(ReportItem item, string name) =>
        bool.TryParse(Field(item, name), out var value) && value;

    private static string? Field(ReportItem item, string name) =>
        item.Fields.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    private static string? FirstNonEmpty(ReportItem item, params string[] names)
    {
        foreach (var name in names)
        {
            if (Field(item, name) is { } value)
            {
                return value;
            }
        }
        return null;
    }
}
