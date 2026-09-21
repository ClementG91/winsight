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
                    ["risks"] = c.Risks.Count > 0 ? string.Join("; ", c.Risks) : null,
                });
        }
        AddCoverageFinding(b, acquisition);
        return b.Build($"{certs.Count} trusted root(s), {certs.Count(c => c.Notable)} flagged{CoverageSuffix(acquisition)}");
    }

    public static ToolReport Extensions(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acquisition = new ExtensionScanner().SnapshotWithCoverage();
        var extensions = acquisition.Items;
        var b = new ToolReport.Builder("extensions");
        foreach (var e in extensions.Where(e => !flaggedOnly || e.HighRisk)
                     .OrderByDescending(e => e.HighRisk)
                     .ThenBy(e => e.Browser, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var perms = string.Join(", ", e.Permissions.Concat(e.HostPermissions));
            b.Add(
                e.HighRisk ? Severity.Notable : Severity.Info,
                $"{e.Browser}/{e.Name}",
                perms.Length > 0 ? perms : "(no declared permissions)",
                new Dictionary<string, string?>
                {
                    ["browser"] = e.Browser,
                    ["id"] = e.Id,
                    ["name"] = e.Name,
                    ["version"] = e.Version,
                    ["permissions"] = string.Join(" ", e.Permissions),
                    ["hostPermissions"] = string.Join(" ", e.HostPermissions),
                    ["highRisk"] = e.HighRisk.ToString(),
                    ["path"] = e.Path,
                });
        }
        AddCoverageFinding(b, acquisition);
        return b.Build($"{extensions.Count} extension(s), {extensions.Count(e => e.HighRisk)} high-risk{CoverageSuffix(acquisition)}");
    }
}
