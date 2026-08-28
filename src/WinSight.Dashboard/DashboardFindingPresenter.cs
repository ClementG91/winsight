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
            "integrity" => Integrity(item, text),
            // Six tools rendered raw English into the French and Spanish dashboards because they had
            // no presenter and fell back to item.Detail - among them the strongest sentence the whole
            // product produces, about a driver that is unsigned and can see every keystroke.
            "input" => InputHook(item, text),
            "drivers" => Driver(item, text),
            "hijack" => Hijack(item, text),
            "presence" => Presence(item, text),
            "dns" => Dns(item, text),
            "alerts" => Alert(item, text),
            _ => new FindingPresentation(item.Title, item.Detail),
        };

    /// <summary>
    /// A driver on the keyboard or mouse path: what it is, and whether its signature vouches for it.
    /// </summary>
    private static FindingPresentation InputHook(ReportItem item, LocalizationManager text)
    {
        var name = Field(item, "name") ?? item.Title;
        var signature = SignatureLabel(item, text);
        var concern = Field(item, "concern");
        var detail = string.IsNullOrWhiteSpace(concern)
            ? signature
            : $"{signature}; {text.GetOrFallback($"InputConcern{concern}", concern)}";
        var image = Field(item, "image");
        return new FindingPresentation(
            name,
            string.IsNullOrWhiteSpace(image) ? detail : $"{image}  [{detail}]");
    }

    private static FindingPresentation Driver(ReportItem item, LocalizationManager text)
    {
        var name = Field(item, "name") ?? item.Title;
        var signature = SignatureLabel(item, text);
        var concern = Field(item, "concern");
        var detail = string.IsNullOrWhiteSpace(concern)
            ? signature
            : $"{signature}; {text.GetOrFallback($"DriverConcern{concern}", concern)}";
        var image = FirstNonEmpty(item, "image", "expectedImage");
        return new FindingPresentation(
            name,
            string.IsNullOrWhiteSpace(image) ? detail : $"{image}  [{detail}]");
    }

    /// <summary>
    /// A hijackable configuration, graded by whether it is exploitable on this machine rather than
    /// merely present - the distinction the whole scanner is built around, so it must survive
    /// translation.
    /// </summary>
    private static FindingPresentation Hijack(ReportItem item, LocalizationManager text)
    {
        var kind = Field(item, "kind");
        var subject = Field(item, "subject") ?? item.Title;
        var exposure = Field(item, "exposure");
        var title = string.IsNullOrWhiteSpace(kind)
            ? subject
            : $"{text.GetOrFallback($"HijackKind{kind}", kind)}/{subject}";
        var label = string.IsNullOrWhiteSpace(exposure)
            ? item.Detail
            : text.GetOrFallback($"HijackExposure{exposure}", exposure);
        var path = FirstNonEmpty(item, "actionablePath", "context");
        return new FindingPresentation(
            title,
            string.IsNullOrWhiteSpace(path) ? label : $"{path}  [{label}]");
    }

    /// <summary>
    /// Why the machine woke, and whether that means somebody was at it. Localised carefully: the
    /// cause is a code, never the device name Windows rendered.
    /// </summary>
    private static FindingPresentation Presence(ReportItem item, LocalizationManager text)
    {
        var cause = Field(item, "cause");
        var label = string.IsNullOrWhiteSpace(cause)
            ? item.Detail
            : text.GetOrFallback($"PresenceCause{cause}", cause);
        var woke = Field(item, "wokeUtc");
        var title = DateTimeOffset.TryParse(
            woke, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var when)
            ? when.ToLocalTime().ToString("g", text.Culture)
            : item.Title;
        var source = Field(item, "source");
        return new FindingPresentation(
            title,
            string.IsNullOrWhiteSpace(source) ? label : $"{label} - {source}");
    }

    private static FindingPresentation Dns(ReportItem item, LocalizationManager text)
    {
        var name = Field(item, "name") ?? item.Title;
        var type = Field(item, "type");
        var data = Field(item, "data");
        var origin = BoolField(item, "local") ? text["DnsFromCache"] : text["DnsFromNetwork"];
        var detail = string.IsNullOrWhiteSpace(data) ? origin : $"{data}  [{origin}]";
        return new FindingPresentation(
            string.IsNullOrWhiteSpace(type) ? name : $"{name} ({type})", detail);
    }

    private static FindingPresentation Alert(ReportItem item, LocalizationManager text)
    {
        var source = Field(item, "source") ?? item.Title;
        var kind = Field(item, "kind");
        var title = string.IsNullOrWhiteSpace(kind)
            ? source
            : $"{source}/{text.GetOrFallback($"AlertKind{kind}", kind)}";
        var when = Field(item, "time");
        var detail = Field(item, "detail") ?? item.Detail;
        return new FindingPresentation(
            title,
            DateTimeOffset.TryParse(
                when, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var moment)
                ? $"{moment.ToLocalTime().ToString("g", text.Culture)} - {detail}"
                : detail);
    }

    /// <summary>
    /// The signature verdict shared by the driver-shaped tools, so one translation serves both.
    /// </summary>
    private static string SignatureLabel(ReportItem item, LocalizationManager text)
    {
        var signature = Field(item, "signature");
        var label = string.IsNullOrWhiteSpace(signature)
            ? text["UnknownValue"]
            : text.GetOrFallback($"SignatureState{signature}", signature);
        var signer = Field(item, "signer");
        return string.IsNullOrWhiteSpace(signer) ? label : $"{label} - {signer}";
    }

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
        // Appended, never substituted. This presenter rebuilds the line from fields rather than
        // reusing item.Detail, so an entry flagged for its command line would otherwise render in
        // the dashboard as "Signature valid" alone — the reassuring half of the finding, and the
        // one sentence this check exists to stop anybody reading on its own.
        if (Field(item, "commandLineConcern") is { } concern)
        {
            suffix = $"{suffix}; {text.GetOrFallback($"PersistenceAbuse{concern}", concern)}";
        }
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
        if (int.TryParse(
                Field(item, "unrecorded"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var unrecorded)
            && unrecorded > 0)
        {
            detail = $"{detail} {text.Format("OutboundFirewallObservationGaps", unrecorded)}";
        }
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

    private static FindingPresentation Integrity(ReportItem item, LocalizationManager text) =>
        Field(item, "protection") switch
        {
            "Antivirus" => Antivirus(item, text),
            "Controlled Folder Access" => ControlledFolderAccess(item, text),
            _ => new FindingPresentation(item.Title, item.Detail),
        };

    private static FindingPresentation Antivirus(ReportItem item, LocalizationManager text)
    {
        var products = AntivirusProducts(item);
        var concern = Field(item, "concern");
        var detail = concern switch
        {
            "Protected" => text.Format(
                "AntivirusProtected",
                ProductNames(products.Where(product =>
                    product.Activity == "On" && product.Signature == "UpToDate"), text)),
            "SignaturesOutOfDate" => text.Format(
                "AntivirusSignaturesOutOfDate",
                ProductNames(products.Where(product => product.Activity == "On"), text)),
            "SignatureStatusUnknown" => text.Format(
                "AntivirusSignatureStatusUnknown",
                ProductNames(products.Where(product => product.Activity == "On"), text)),
            "ActivityStatusUnknown" => text.Format(
                "AntivirusActivityStatusUnknown",
                ProductNames(products.Where(product => product.Activity == "Unknown"), text)),
            "NoActiveAntiVirus" => text.Format(
                "AntivirusNoActive",
                InactiveProducts(products, text)),
            "NoAntiVirusRegistered" => text["AntivirusNoneRegistered"],
            "Unavailable" => text["AntivirusUnavailable"],
            _ => text["IntegrityEvidenceUnavailable"],
        };
        return new FindingPresentation(text["AntivirusProtectionTitle"], detail);
    }

    private static FindingPresentation ControlledFolderAccess(ReportItem item, LocalizationManager text)
    {
        var concern = Field(item, "concern");
        var detail = concern switch
        {
            "Off" => text["CfaOff"],
            "AuditOnly" => text["CfaAuditOnly"],
            "BlockDiskModificationOnly" => text["CfaBlockDiskModificationOnly"],
            "AuditDiskModificationOnly" => text["CfaAuditDiskModificationOnly"],
            "Protecting" => text["CfaProtecting"],
            "RuntimeRequirementsNotMet" => text["CfaRuntimeRequirementsNotMet"],
            "UnknownMode" => text.Format("CfaUnknownMode", Field(item, "rawStateValue") ?? text["UnknownValue"]),
            "Unavailable" => text["CfaUnavailable"],
            "DefenderNotRunning" => DefenderNotRunning(item, text),
            _ => text["IntegrityEvidenceUnavailable"],
        };
        return new FindingPresentation(text["CfaTitle"], detail);
    }

    private static string DefenderNotRunning(ReportItem item, LocalizationManager text)
    {
        var antivirusConcern = Field(item, "antivirusConcern");
        var protectedThirdParty = Field(item, "protectedThirdPartyAntivirus");
        if (antivirusConcern == "Protected" && protectedThirdParty is not null)
        {
            return text.Format("CfaDefenderNotRunningProtectedThirdParty", protectedThirdParty);
        }

        return antivirusConcern switch
        {
            "Unavailable" => text["CfaDefenderNotRunningAvUnavailable"],
            "ActivityStatusUnknown" => text.Format(
                "CfaDefenderNotRunningActivityUnknown",
                Field(item, "activityUnknownAntivirus") ?? text["UnknownValue"]),
            "SignatureStatusUnknown" => text.Format(
                "CfaDefenderNotRunningSignatureUnknown",
                Field(item, "onAntivirus") ?? text["UnknownValue"]),
            "SignaturesOutOfDate" => text.Format(
                "CfaDefenderNotRunningSignaturesOutOfDate",
                Field(item, "onAntivirus") ?? text["UnknownValue"]),
            "Protected" => text["CfaDefenderNotRunningInconsistent"],
            _ => text["CfaDefenderNotRunningNoOnAntivirus"],
        };
    }

    private static List<AntivirusProductEvidence> AntivirusProducts(ReportItem item)
    {
        if (!int.TryParse(
                Field(item, "registeredAntivirusCount"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var count))
        {
            return [];
        }

        var products = new List<AntivirusProductEvidence>(Math.Clamp(count, 0, 64));
        for (var index = 0; index < Math.Clamp(count, 0, 64); index++)
        {
            var prefix = $"antivirusProduct.{index}.";
            if (Field(item, $"{prefix}name") is not { } name)
            {
                continue;
            }
            products.Add(new AntivirusProductEvidence(
                name,
                Field(item, $"{prefix}activity") ?? "Unknown",
                Field(item, $"{prefix}signature") ?? "Unknown"));
        }
        return products;
    }

    private static string ProductNames(
        IEnumerable<AntivirusProductEvidence> products,
        LocalizationManager text)
    {
        var names = products.Select(product => product.Name).ToArray();
        return names.Length == 0 ? text["UnknownValue"] : string.Join(", ", names);
    }

    private static string InactiveProducts(
        List<AntivirusProductEvidence> products,
        LocalizationManager text)
    {
        var groups = new[]
        {
            (State: "Off", Resource: "AntivirusStateOff"),
            (State: "Snoozed", Resource: "AntivirusStateSnoozed"),
            (State: "Expired", Resource: "AntivirusStateExpired"),
        };
        var descriptions = groups.Select(group =>
        {
            var names = products
                .Where(product => product.Activity == group.State)
                .Select(product => product.Name)
                .ToArray();
            return names.Length == 0
                ? null
                : text.Format("AntivirusStateGroup", text[group.Resource], string.Join(", ", names));
        }).Where(description => description is not null);
        var result = string.Join("; ", descriptions!);
        return result.Length == 0 ? text["UnknownValue"] : result;
    }

    private sealed record AntivirusProductEvidence(string Name, string Activity, string Signature);

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
