using System.Globalization;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    public static ToolReport Persistence(
        bool flaggedOnly,
        bool allowNetworkLookups = true,
        CancellationToken cancellationToken = default)
    {
        var scan = new PersistenceScanner(verifier: SharedVerifier).ScanWithCoverage(cancellationToken);
        var entries = scan.Entries;

        // Opt-in VirusTotal enrichment for the flagged, resolvable items only.
        //
        // Ordered most adverse first, because the enricher looks up at most four distinct files and
        // takes them in the order given. Unordered, those four went to whichever entries the
        // enumerator reached first - so an unsigned DLL in an IFEO Debugger value could lose its
        // lookup to four orphaned registrations whose only fault is that their target is missing.
        var vt = VirusTotalEnricher.Lookup(
            entries.Where(e => e.IsSuspicious && e.ImagePath is not null)
                .OrderByDescending(e => e.Abuse != InterpreterAbuse.None)
                .ThenByDescending(e => e.IsAdverse)
                .Select(e => e.ImagePath!),
            allowNetworkLookups,
            cancellationToken);

        var b = new ToolReport.Builder("persistence");
        // --flagged means "only noteworthy items", so it now shows what was checked and found
        // adverse - not what could not be checked. An orphaned OEM registration used to sit in that
        // list beside a live IFEO hijack, which is what made the list too long to read.
        //
        // The coverage signal is not lost: the summary line names the unverified count, and a full
        // scan still shows every one of them at their own severity. Moving them out of this view is
        // what makes the view worth having; naming them in the header is what keeps the scan honest.
        foreach (var e in entries.Where(e => !flaggedOnly || e.IsAdverse)
                     .OrderByDescending(e => e.IsAdverse).ThenByDescending(e => e.IsUnverified)
                     .ThenBy(e => e.Vector))
        {
            var report = e.ImagePath is not null && vt.TryGetValue(e.ImagePath, out var v) ? v : null;
            // The whole command line must not become the detail. The MCP projector withholds
            // fields named "command"/"commandLine" and only substitutes environment variables in
            // Detail, so falling back to the raw command sent the payload - base64 and all - to the
            // model without WINSIGHT_MCP_ALLOW_SENSITIVE=1 or includeSensitive=true. That happened
            // exactly when the image could not be resolved, which is the encoded-LOLBin case the
            // gate exists for. The leading token is enough to name the entry; the arguments are the
            // payload and stay in the governed field.
            var displayedPath = e.ImagePath ?? e.ExpectedImagePath ?? CommandHead(e.Command);
            var verdict = report is not null
                ? $"VT {report.Malicious}/{report.Total}"
                : PersistenceStatusLabel(e.Status, e.Signature.Anchor, e.Signature.Revocation);
            // The command-line reason has to ride beside the signature verdict rather than replace
            // it, because the pair is the finding: "signature valid" alone reads as an all-clear on
            // exactly the entries this rule exists to catch. The raw command line stays in the
            // fields below rather than moving into the detail, so MCP's existing rule — command
            // text is withheld unless the operator opened the sensitive gate — keeps governing it.
            var abuse = InterpreterAbuseTriage.Describe(e.Abuse);
            // A valid signature that is nonetheless flagged has to say why on the same line. Without
            // this the entry reads "signature valid" beside a [!] mark, which is the most confusing
            // thing a report can do: it looks like the tool contradicting itself rather than making
            // a point about where the code is registered to load.
            var privileged = PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(e)
                ? $"third-party code loaded by {PrivilegedHostLabel(e.Vector)}"
                : null;
            var reasons = string.Join("; ", new[] { verdict, abuse, privileged }
                .Where(reason => !string.IsNullOrEmpty(reason)));
            var detail = $"{displayedPath}  [{reasons}]";
            b.Add(
                // Three levels, not two. An entry whose target could not be checked is Unverified:
                // present in the report, absent from the "worth examining" count, and not a reason
                // for a scheduled task to exit non-zero.
                e.IsAdverse ? Severity.Notable
                    : e.IsUnverified ? Severity.Unverified
                    : Severity.Info,
                $"{e.Vector}/{e.Name}",
                detail,
                new Dictionary<string, string?>
                {
                    ["vector"] = e.Vector.ToString(),
                    ["name"] = e.Name,
                    ["location"] = e.Location,
                    ["command"] = e.Command,
                    ["image"] = e.ImagePath,
                    ["expectedImage"] = e.ExpectedImagePath,
                    ["fileStatus"] = e.ImageStatus.ToString(),
                    ["signature"] = e.ImageStatus == ImageResolutionStatus.Present
                        ? e.Signature.State.ToString()
                        : null,
                    ["signatureChecked"] = (e.ImageStatus == ImageResolutionStatus.Present).ToString(),
                    ["status"] = e.Status.ToString(),
                    // Null rather than "None" when there is nothing to report: a machine consumer
                    // should be able to test for the key's presence, and the MCP projector drops
                    // null-valued fields, so a clean entry costs nothing on the wire.
                    ["commandLineConcern"] = e.Abuse == InterpreterAbuse.None ? null : e.Abuse.ToString(),
                    ["signer"] = e.Signature.Signer,
                    ["userInstalledTrust"] = e.ImageStatus == ImageResolutionStatus.Present
                        && e.Signature.RestsOnUserInstalledTrust ? "true" : null,
                    ["microsoftSigned"] = e.ImageStatus == ImageResolutionStatus.Present
                        ? MicrosoftSignedField(e.Signature)
                        : null,
                    // Null rather than "Unspecified" when nothing was established, so a consumer
                    // tests for the key's presence and the MCP projector drops it from a clean
                    // entry rather than paying for a word that means "no answer".
                    ["revocation"] = e.Signature.Revocation == RevocationStanding.Unspecified
                        ? null
                        : e.Signature.Revocation.ToString(),
                    ["vtMalicious"] = report?.Malicious.ToString(),
                    ["vtTotal"] = report?.Total.ToString(),
                    ["vtLink"] = report?.Permalink,
                });
        }
        AddSignatureCoverageFinding(
            b,
            entries.Where(entry => entry.ImageStatus == ImageResolutionStatus.Present)
                .Select(entry => entry.Signature));
        AddPersistenceCoverageFinding(b, scan.Coverage);
        return b.Build(PersistenceSummary(entries, scan.Coverage));
    }

    /// <summary>
    /// Surfaces the scan was not allowed to read, as a finding rather than only as a clause in the
    /// summary line.
    /// </summary>
    /// <remarks>
    /// <b>Why the clause was not enough.</b> Persistence was the one scanner of eleven that reported
    /// its coverage gap only through <c>Summary</c>. The CLI and the MCP server print that string,
    /// so both saw it - but the dashboard replaces <c>SummaryText</c> with its own "N results, M to
    /// examine" line, and the clause went with it. The audience that lost it is precisely the
    /// non-technical one, on the scanner where the difference between "there is nothing there" and
    /// "I could not look" is measured at 210 items on a real machine.
    ///
    /// Emitting a finding puts it in the results grid, where no presentation layer can drop it, and
    /// makes persistence behave like the ten scanners beside it.
    ///
    /// It is Unverified rather than Notable: an unelevated scan is not a finding about the machine,
    /// and making it drive the exit code would mean every scheduled task without elevation reports
    /// failure for ever.
    /// </remarks>
    internal static void AddPersistenceCoverageFinding(
        ToolReport.Builder builder, PersistenceCoverage coverage)
    {
        if (!coverage.IsPartial)
        {
            return;
        }
        var surfaces = string.Join(", ", coverage.UnreadableSurfaces.Distinct().Order(StringComparer.Ordinal));
        builder.Add(
            Severity.Unverified,
            "autostart surfaces not readable",
            coverage.UnreadableLocations > 0
                ? $"{coverage.UnreadableLocations} location(s) could not be read ({surfaces}); "
                    + "run elevated to cover them"
                : $"surface(s) could not be read ({surfaces}); run elevated to cover them",
            new Dictionary<string, string?>
            {
                ["unreadableLocations"] = coverage.UnreadableLocations.ToString(
                    CultureInfo.InvariantCulture),
                ["unreadableSurfaces"] = surfaces,
            });
    }

    /// <summary>
    /// The scan's one-line result, including what it was <b>not allowed to read</b>.
    /// </summary>
    /// <remarks>
    /// Measured on a real desktop, the same scan returned 8 546 items unelevated and 8 756
    /// elevated. The 210 missing ones were scheduled tasks — Brave, Edge, NVIDIA, OneDrive and
    /// Google updaters — and one of them was already flagged as suspicious. Nothing said so: the
    /// unelevated report read as a complete, clean scan. Naming the gap costs one clause and is the
    /// difference between "there is nothing there" and "I could not look".
    /// </remarks>
    internal static string PersistenceSummary(
        IReadOnlyList<AutostartEntry> entries, PersistenceCoverage coverage)
    {
        // Flagged counts what was checked and found adverse. Entries whose check could not complete
        // are named separately: reporting an orphaned OEM registration as "flagged" alongside a live
        // IFEO hijack is what made this number stop meaning anything.
        var adverse = entries.Count(e => e.IsAdverse);
        var unverified = entries.Count(e => e.IsUnverified);
        var line = $"{entries.Count} autostart item(s), {adverse} flagged";
        if (unverified > 0)
        {
            line += $", {unverified} unverified";
        }
        if (!coverage.IsPartial)
        {
            return line;
        }
        var surfaces = string.Join(", ", coverage.UnreadableSurfaces.Distinct().Order(StringComparer.Ordinal));
        return coverage.UnreadableLocations > 0
            ? $"{line}, {coverage.UnreadableLocations} not readable without elevation ({surfaces})"
            : $"{line}, surface(s) not readable without elevation ({surfaces})";
    }

    /// <remarks>
    /// A trusted signature is qualified by the root it rests on. Rendering "signature valid" for a
    /// chain anchored in a root any account can install reads as an all-clear on exactly the entry
    /// that deserves the opposite, so the anchor rides in the label rather than being left for a
    /// field nobody reads.
    /// </remarks>
    /// <summary>
    /// The executable token of a command line, without its arguments.
    /// </summary>
    /// <remarks>
    /// Names the entry for a human without carrying the part that is the payload. Quoted paths keep
    /// their spaces; everything after the executable is dropped, and a token long enough to be a
    /// payload in itself is truncated rather than trusted.
    /// </remarks>
    internal static string CommandHead(string? command)
    {
        var trimmed = command?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return string.Empty;
        }
        string head;
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            head = end > 0 ? trimmed[1..end] : trimmed[1..];
        }
        else
        {
            var space = trimmed.IndexOf(' ');
            head = space > 0 ? trimmed[..space] : trimmed;
        }
        const int MaxHeadLength = 160;
        return head.Length <= MaxHeadLength ? head : head[..MaxHeadLength] + "…";
    }

    /// <summary>The process an entry on a privileged surface is loaded into, in plain words.</summary>
    private static string PrivilegedHostLabel(AutostartVector vector) => vector switch
    {
        AutostartVector.AppInitDll => "every process that links user32",
        AutostartVector.AppCertDll => "every process that is created",
        AutostartVector.LsaPackage or AutostartVector.SecurityProvider => "LSASS",
        AutostartVector.CredentialProvider => "the logon UI, as SYSTEM, before sign-in",
        AutostartVector.PrintMonitor or AutostartVector.PrintProvider =>
            "the print spooler, as SYSTEM",
        AutostartVector.TimeProvider => "the time service",
        AutostartVector.BootExecute => "the session manager, before Windows starts",
        AutostartVector.NetshHelper => "netsh, typically elevated",
        AutostartVector.Winlogon => "Winlogon",
        AutostartVector.WmiSubscription => "WMI, as SYSTEM",
        AutostartVector.ProfilerInjection => "the CLR, into managed processes",
        _ => "a privileged process",
    };

    private static string PersistenceStatusLabel(
        PersistenceStatus status,
        SignatureTrustAnchor anchor = SignatureTrustAnchor.Unspecified,
        RevocationStanding revocation = RevocationStanding.Unspecified) => status switch
        {
            PersistenceStatus.FileMissing => "file missing, signature not checked",
            PersistenceStatus.SignatureValid when anchor == SignatureTrustAnchor.UserInstalledRoot =>
                UserRootTrustNote,
            PersistenceStatus.SignatureValid when revocation == RevocationStanding.Revoked =>
                "signature valid but the certificate is REVOKED",
            PersistenceStatus.SignatureValid => "signature valid",
            PersistenceStatus.Unsigned => "unsigned",
            PersistenceStatus.InvalidSignature => "invalid signature",
            PersistenceStatus.AccessDenied => "access denied, signature not checked",
            _ => "verification error",
        };
}
