using WinSight.Core;
using WinSight.Ransomware;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// Maps each tool's domain results into the shared <see cref="ToolReport"/> shape.
/// The tools stay pure data producers; presentation lives here, once, so the renderer
/// (text/JSON) and a future GUI consume one contract.
/// </summary>
public static partial class Adapters
{
    public static IReadOnlySet<string> SnapshotCommands { get; } = new HashSet<string>(
        ["persistence", "av", "net", "dns", "firewall", "processes", "modules", "extensions", "certs", "hosts", "input", "drivers", "integrity", "hijack", "presence"],
        StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<string> OverviewCommands { get; } =
        ["persistence", "av", "net", "dns", "extensions", "hosts", "certs", "input", "integrity", "hijack"];

    // One caching verifier shared across tools, so the same system binaries checked
    // by both persistence and connections in a single `all` run are verified once.
    // Native WinVerifyTrust first (fast, tamper-checking), catalog-aware PS fallback
    // for catalog-signed binaries, managed fallback below that, all cached. The dashboard and MCP
    // host this static verifier for their full lifetime, so cached trust is bound to file content;
    // timestamps and length alone are attacker-controlled metadata.
    private static readonly ISignatureVerifier SharedVerifier =
        new CachingSignatureVerifier(new NativeSignatureVerifier(), verifyContent: true);

    private static void AddCoverageFinding<T>(
        ToolReport.Builder builder,
        AcquisitionSnapshot<T> acquisition)
    {
        if (acquisition.IsComplete)
        {
            return;
        }

        builder.Add(
            Severity.Notable,
            "scan coverage incomplete",
            $"{acquisition.UnreadableSources} source(s) and {acquisition.UnreadableItems} item(s) could not be read",
            new Dictionary<string, string?>
            {
                ["kind"] = "acquisitionCoverage",
                ["unreadableSources"] = acquisition.UnreadableSources.ToString(),
                ["unreadableItems"] = acquisition.UnreadableItems.ToString(),
            });
    }

    private static string CoverageSuffix<T>(AcquisitionSnapshot<T> acquisition) =>
        acquisition.IsComplete ? string.Empty : ", scan incomplete";

    internal static int AddSignatureCoverageFinding(
        ToolReport.Builder builder,
        IEnumerable<SignatureVerdict> verdicts)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(verdicts);
        var unknown = verdicts.Count(verdict => verdict.State == SignatureState.Unknown);
        if (unknown == 0)
        {
            return 0;
        }

        builder.Add(
            Severity.Notable,
            "signature verification incomplete",
            $"{unknown} existing file(s) could not be given an Authenticode verdict",
            new Dictionary<string, string?>
            {
                ["kind"] = "signatureCoverage",
                ["unknownSignatures"] = unknown.ToString(),
            });
        return unknown;
    }

    /// <summary>Runs one snapshot tool by its canonical CLI name.</summary>
    public static ToolReport Run(
        string command,
        bool flaggedOnly = false,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default) =>
        RunCore(
            command,
            flaggedOnly,
            allowNetworkLookups,
            new ControlledFolderAccessReader(),
            new SecurityCenterReader(),
            cancellationToken);

    /// <summary>
    /// Shared command router with explicit integrity providers. This is an instance-free,
    /// concurrency-safe seam: tests can cancel during either provider read without replacing
    /// process-global state or bypassing the same switch used by public callers.
    /// </summary>
    internal static ToolReport RunCore(
        string command,
        bool flaggedOnly,
        bool allowNetworkLookups,
        ControlledFolderAccessReader controlledFolderAccessReader,
        SecurityCenterReader securityCenterReader,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ArgumentNullException.ThrowIfNull(controlledFolderAccessReader);
        ArgumentNullException.ThrowIfNull(securityCenterReader);
        cancellationToken.ThrowIfCancellationRequested();
        return command.ToLowerInvariant() switch
        {
            "persistence" => Persistence(flaggedOnly, allowNetworkLookups, cancellationToken),
            "av" or "avmonitor" => CameraMic(flaggedOnly),
            "net" or "netmonitor" => Connections(flaggedOnly, allowNetworkLookups, cancellationToken),
            "dns" => Dns(flaggedOnly),
            "firewall" or "fw" => Firewall(flaggedOnly),
            "processes" or "ps" => Processes(flaggedOnly, cancellationToken),
            "modules" or "dll" => Modules(flaggedOnly, cancellationToken),
            "extensions" or "ext" => Extensions(flaggedOnly, cancellationToken),
            "certificates" or "certs" => Certificates(flaggedOnly, cancellationToken),
            "hosts" => Hosts(flaggedOnly),
            "input" or "inputhooks" => InputHooks(flaggedOnly, cancellationToken),
            "integrity" or "ci" => CodeIntegrity(
                flaggedOnly,
                controlledFolderAccessReader,
                securityCenterReader,
                cancellationToken),
            "drivers" or "drv" => Drivers(flaggedOnly, cancellationToken),
            "hijack" or "hijacks" => Hijack(flaggedOnly, cancellationToken),
            "presence" => Presence(flaggedOnly),
            "alerts" => Alerts(),
            "actions" => Actions(),
            "rules" => Rules(),
            _ => throw new ArgumentOutOfRangeException(nameof(command), command, "Unknown WinSight tool."),
        };
    }

    /// <summary>
    /// Runs the balanced default overview. Process, module, driver and firewall
    /// inventories remain explicit because they are large and would make a routine
    /// overview noisy.
    /// </summary>
    public static IReadOnlyList<ToolReport> RunOverview(
        bool flaggedOnly = false,
        IProgress<ScanProgress>? progress = null,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var reports = new List<ToolReport>(OverviewCommands.Count);
        for (var index = 0; index < OverviewCommands.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = OverviewCommands[index];
            progress?.Report(new ScanProgress(index, OverviewCommands.Count, command));
            reports.Add(Run(command, flaggedOnly, allowNetworkLookups, cancellationToken));
            progress?.Report(new ScanProgress(index + 1, OverviewCommands.Count, command));
        }
        return reports;
    }

    /// <summary>The words every scan uses for a signature that holds only through a user-installed root.</summary>
    private const string UserRootTrustNote = "signature valid ONLY through a user-installed root";

    /// <summary>
    /// Appends <see cref="UserRootTrustNote"/> to a finding's detail when it applies. Said in the
    /// text, not only in a field: an item flagged with nothing but a path reads as a false alarm.
    /// </summary>
    private static string WithUserRootNote(string detail, bool trustedOnlyThroughUserRoot) =>
        trustedOnlyThroughUserRoot ? $"{detail} [{UserRootTrustNote}]" : detail;

    private static string UserRootSuffix(int count) =>
        count == 0 ? string.Empty : $", {count} trusted only through a user-installed root";

    private static string UserRootClause(SignatureVerdict signature) =>
        signature.RestsOnUserInstalledTrust ? $", {UserRootTrustNote}" : string.Empty;

    /// <summary>
    /// <c>"true"</c> when the verdict is Microsoft's own signature - an exact Microsoft signing
    /// identity on a chain the machine trusts - and null otherwise. Emitted so the
    /// <c>--nonmicrosoft</c> view filter reads a fact established from the whole verdict, rather
    /// than finding "Microsoft" somewhere in the signer text, which any self-signed certificate can
    /// carry.
    /// </summary>
    internal static string? MicrosoftSignedField(SignatureVerdict signature) =>
        CertificateSubject.IsMicrosoft(signature) ? "true" : null;
}
