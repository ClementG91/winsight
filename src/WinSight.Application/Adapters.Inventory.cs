using WinSight.Browser;
using WinSight.Certificates;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    public static ToolReport Certificates(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acquisition = new CertStoreAuditor().SnapshotWithCoverage();
        var certs = acquisition.Items;
        var b = new ToolReport.Builder("certificates");
        foreach (var c in certs.Where(c => !flaggedOnly || c.Notable)
                     .OrderByDescending(c => c.Notable)
                     .ThenBy(c => c.Subject, StringComparer.OrdinalIgnoreCase))
        {
            b.Add(
                c.Notable ? Severity.Notable : Severity.Info,
                $"{c.Store}, {c.Subject}",
                c.Notable ? string.Join("; ", c.Risks) : $"{c.SignatureAlgorithm}, {c.KeyBits}-bit",
                new Dictionary<string, string?>
                {
                    ["store"] = c.Store,
                    ["subject"] = c.Subject,
                    ["issuer"] = c.Issuer,
                    ["thumbprint"] = c.Thumbprint,
                    ["signatureAlgorithm"] = c.SignatureAlgorithm,
                    ["keyBits"] = c.KeyBits.ToString(),
                    ["isRsa"] = c.IsRsa.ToString(),
                    ["hasPrivateKey"] = c.HasPrivateKey.ToString(),
                    ["isSelfSigned"] = c.IsSelfSigned.ToString(),
                    ["notAfter"] = c.NotAfter.ToString("o"),
                    ["role"] = c.Role.ToString(),
                    // What the dashboard needs to say why, in the operator's language, without
                    // re-deriving it: the user-only fact has no other field to be read from.
                    ["userInstalled"] = c.IsUserInstalled ? "true" : null,
                    ["risks"] = c.Risks.Count > 0 ? string.Join("; ", c.Risks) : null,
                });
        }
        AddCoverageFinding(b, acquisition);
        var roots = certs.Count(c => c.Role == CertificateTrustRole.Root);
        var publishers = certs.Count(c => c.Role == CertificateTrustRole.TrustedPublisher);
        var distrusted = certs.Count(c => c.Role == CertificateTrustRole.Disallowed);
        return b.Build($"{roots} trusted root(s), {publishers} trusted publisher(s), {distrusted} distrusted, "
            + $"{certs.Count(c => c.Notable)} flagged{CoverageSuffix(acquisition)}");
    }

    public static ToolReport Extensions(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acquisition = new ExtensionScanner().SnapshotWithCoverage();
        var extensions = acquisition.Items;
        var b = new ToolReport.Builder("extensions");
        foreach (var e in extensions.Where(e => !flaggedOnly || e.Notable)
                     .OrderByDescending(e => e.Notable)
                     .ThenBy(e => e.Browser, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var perms = string.Join(", ", e.Permissions.Concat(e.HostPermissions));
            b.Add(
                e.Notable ? Severity.Notable : Severity.Info,
                $"{e.Browser}/{e.Name}",
                (e.LoadedFromFolder ? $"loaded from a folder ({e.Location}), not installed; " : "")
                    + (perms.Length > 0 ? perms : "(no declared permissions)"),
                new Dictionary<string, string?>
                {
                    ["browser"] = e.Browser,
                    ["id"] = e.Id,
                    ["name"] = e.Name,
                    ["version"] = e.Version,
                    ["permissions"] = string.Join(" ", e.Permissions),
                    ["hostPermissions"] = string.Join(" ", e.HostPermissions),
                    ["highRisk"] = e.HighRisk.ToString(),
                    ["location"] = e.Location.ToString(),
                    ["path"] = e.Path,
                });
        }
        AddCoverageFinding(b, acquisition);
        return b.Build($"{extensions.Count} extension(s), {extensions.Count(e => e.HighRisk)} high-risk, "
            + $"{extensions.Count(e => e.LoadedFromFolder)} loaded from a folder{CoverageSuffix(acquisition)}");
    }
}
