using WinSight.Core;
using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// The What's Your Sign? surface: one file's Authenticode standing for the <c>sign</c> verb, and the
/// lifecycle commands that add or remove the per-user Explorer verb. Kept beside the main adapter
/// rather than inside it, because this is the file-inspection entry point, not a machine scan.
/// </summary>
public static partial class Adapters
{
    /// <summary>
    /// Builds the signature report for one file, for the <c>sign</c> CLI verb and the Explorer verb.
    /// The path is validated as an ordinary local file first, so a UNC or device argument is refused
    /// rather than opened. A trusted signature backed by a machine root is <see cref="Severity.Info"/>;
    /// anything unsigned, untrusted, or resting on a user-installed root is <see cref="Severity.Notable"/>;
    /// an undetermined verdict is <see cref="Severity.Unverified"/>, never a finding.
    /// </summary>
    public static ToolReport DescribeSignature(string? rawPath)
    {
        var builder = new ToolReport.Builder("signature");
        var report = ReportSignature(rawPath);
        if (report is null)
        {
            builder.Add(Severity.Notable, "not an ordinary local file",
                "the argument is not an existing local file path (UNC and device paths are refused)",
                new Dictionary<string, string?> { ["kind"] = "signatureTarget", ["path"] = rawPath });
            return builder.Build("signature: no local file to check");
        }

        var severity = report.State switch
        {
            SignatureState.SignedTrusted when !report.RestsOnUserInstalledTrust => Severity.Info,
            SignatureState.Unknown or SignatureState.Missing => Severity.Unverified,
            _ => Severity.Notable,
        };
        builder.Add(severity, Path.GetFileName(report.Path), SignatureDetail(report),
            new Dictionary<string, string?>
            {
                ["kind"] = "signature",
                ["path"] = report.Path,
                ["state"] = report.State.ToString(),
                ["signer"] = report.Signer,
                ["anchor"] = report.Anchor.ToString(),
                ["revocation"] = report.Revocation.ToString(),
                ["userInstalledTrust"] = report.RestsOnUserInstalledTrust ? "true" : "false",
                ["md5"] = report.Md5,
                ["sha1"] = report.Sha1,
                ["sha256"] = report.Sha256,
            });
        return builder.Build($"signature: {report.State}");
    }

    /// <summary>
    /// The typed signature report for one file, through the same shared verifier every scan uses: the
    /// dashboard's signature window renders this, and <see cref="DescribeSignature"/> maps it for the
    /// command line, so the two can never disagree about a file. Null for anything that is not an
    /// ordinary local file.
    /// </summary>
    public static FileSignatureReport? ReportSignature(string? rawPath) =>
        new FileSignatureReporter(SharedVerifier).Describe(rawPath);

    private static string SignatureDetail(FileSignatureReport report) => report.State switch
    {
        SignatureState.SignedTrusted => report.RestsOnUserInstalledTrust
            ? $"signed by {report.Signer}; trust rests on a user-installed root"
            : $"signed by {report.Signer}",
        SignatureState.SignedUntrusted => $"signed by {report.Signer}; certificate chain did not validate",
        SignatureState.Unsigned => "no embedded Authenticode signature",
        SignatureState.Missing => "the file was not found",
        _ => "the signature could not be determined",
    };

    /// <summary>
    /// Installs or removes the per-user Explorer "Check signature with WinSight" verb. A lifecycle
    /// command the installer and uninstaller call, not a scanner, so it stays out of the help catalog.
    /// </summary>
    public static int SetSignatureVerb(bool register)
    {
        var dashboard = Path.Combine(AppContext.BaseDirectory, "winsight-dashboard.exe");
        try
        {
            var registrar = new SignatureContextMenuRegistrar(dashboard);
            if (!register)
            {
                registrar.Unregister();
                Console.WriteLine("Explorer signature verb removed for the current user.");
                return CliContract.Clean;
            }
            if (!File.Exists(dashboard))
            {
                Console.Error.WriteLine("winsight-dashboard.exe was not found next to winsight.exe");
                return CliContract.UsageError;
            }
            // Idempotent: a reinstall or repair runs this again and must not rewrite a correct verb.
            if (registrar.IsRegistered())
            {
                Console.WriteLine("Explorer signature verb is already registered for the current user.");
                return CliContract.Clean;
            }
            registrar.Register();
            Console.WriteLine("Explorer signature verb registered for the current user.");
            return CliContract.Clean;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException or IOException)
        {
            Console.Error.WriteLine($"could not change the Explorer verb: {ex.GetType().Name}");
            return CliContract.UnexpectedFailure;
        }
    }
}
