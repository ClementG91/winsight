using WinSight.Drivers;
using WinSight.InputHooks;
using WinSight.Reporting;

namespace WinSight.Application;

public static partial class Adapters
{
    /// <summary>
    /// The kernel drivers sitting in this machine's keyboard and mouse paths — the Windows answer
    /// to a ReiKey-style "what can read my keystrokes" check.
    /// </summary>
    /// <remarks>
    /// Windows exposes no documented way to enumerate <c>SetWindowsHookEx</c> hooks, but a serious
    /// keylogger installs a filter driver on the input device stack, and those are plainly
    /// readable. Anything other than the class driver Windows installs itself is reported with its
    /// signature standing — including properly signed drivers, because a signed kernel keylogger is
    /// still a kernel keylogger and this list is one or two lines on a normal machine.
    /// </remarks>
    public static ToolReport InputHooks(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var acquisition = new InputFilterScanner().ScanWithCoverage(cancellationToken);
        var filters = acquisition.Items;
        var b = new ToolReport.Builder("input");
        var notable = 0;
        foreach (var filter in filters)
        {
            var concern = InputFilterTriage.Concern(filter);
            var isNotable = InputFilterTriage.IsNotable(concern);
            if (isNotable)
            {
                notable++;
            }
            if (flaggedOnly && !isNotable)
            {
                continue;
            }
            b.Add(
                isNotable ? Severity.Notable : Severity.Info,
                $"{filter.Stack}/{filter.Name}",
                $"{filter.Position} filter — {Explain(concern)}{SignerSuffix(filter)}{UserRootClause(filter.Signature)}",
                new Dictionary<string, string?>
                {
                    ["stack"] = filter.Stack.ToString(),
                    ["position"] = filter.Position.ToString(),
                    ["name"] = filter.Name,
                    ["image"] = filter.ImagePath,
                    ["registeredImage"] = filter.RegisteredImagePath,
                    ["imageSource"] = filter.ImageSource.ToString(),
                    ["signature"] = filter.Signature.State.ToString(),
                    ["signer"] = filter.Signature.Signer,
                    ["userInstalledTrust"] = filter.Signature.RestsOnUserInstalledTrust ? "true" : null,
                    ["microsoftSigned"] = MicrosoftSignedField(filter.Signature),
                    ["concern"] = concern.ToString(),
                });
        }
        AddCoverageFinding(b, acquisition);
        AddSignatureCoverageFinding(
            b, filters.Where(filter => filter.ImagePath is not null).Select(filter => filter.Signature));
        return b.Build($"{filters.Count} input filter(s), {notable} not installed by Windows{CoverageSuffix(acquisition)}");

        static string Explain(InputFilterConcern concern) => concern switch
        {
            InputFilterConcern.Expected => "the class driver Windows installs",
            InputFilterConcern.ThirdParty => "a third-party driver that can see every keystroke",
            InputFilterConcern.Untrusted => "UNSIGNED or untrusted, and can see every keystroke",
            InputFilterConcern.Unresolvable =>
                "its registered image is not a local path, so it could not be verified, and it can see every keystroke",
            InputFilterConcern.Unverified => "its signature could not be verified, and it can see every keystroke",
            InputFilterConcern.Impersonating =>
                "NAMED like the Windows class driver, but its image is not the Windows file, and it can see every keystroke",
            _ => "listed here but its driver file is missing",
        };

        static string SignerSuffix(InputFilter filter) =>
            string.IsNullOrWhiteSpace(filter.Signature.Signer) ? string.Empty : $" (signed by {filter.Signature.Signer})";
    }

    /// <summary>
    /// The kernel-mode drivers registered on this machine — the Windows answer to a
    /// KextViewr-style "what runs inside the kernel" check.
    /// </summary>
    /// <remarks>
    /// A driver has the same authority as Windows itself, which is why an unsigned or
    /// untrusted one is the loudest single finding WinSight produces and why a rootkit's
    /// residue shows up here. Several hundred are registered on a normal machine, so
    /// <c>--flagged</c> deliberately narrows to the conditions nothing explains away:
    /// a signature that did not stand up, a registration whose image is gone, and one whose
    /// image is registered where no local path reaches, so it could not be checked at all.
    /// </remarks>
    public static ToolReport Drivers(bool flaggedOnly, CancellationToken cancellationToken = default)
    {
        var acquisition = new KernelDriverScanner(SharedVerifier).ScanWithCoverage(cancellationToken);
        var drivers = acquisition.Items;
        var triaged = drivers
            .Select(driver => (Driver: driver, Concern: KernelDriverTriage.Concern(driver)))
            .ToList();
        var notable = triaged.Count(entry => KernelDriverTriage.IsNotable(entry.Concern));

        var b = new ToolReport.Builder("drivers");
        // Notable first, then earliest-loading first: a boot-start driver is running
        // before anything on the machine could have inspected it.
        foreach (var (driver, concern) in triaged
                     .Where(entry => !flaggedOnly || KernelDriverTriage.IsNotable(entry.Concern))
                     .OrderByDescending(entry => KernelDriverTriage.IsNotable(entry.Concern))
                     .ThenBy(entry => entry.Driver.Start)
                     .ThenBy(entry => entry.Driver.Name, StringComparer.OrdinalIgnoreCase))
        {
            var displayedPath = driver.ImagePath ?? driver.ExpectedImagePath ?? "<no image>";
            b.Add(
                KernelDriverTriage.IsNotable(concern) ? Severity.Notable : Severity.Info,
                $"{driver.Kind}/{driver.Name}",
                $"{displayedPath}  [{StartLabel(driver.Start)}, {Explain(concern)}{SignerSuffix(driver)}{UserRootClause(driver.Signature)}]",
                new Dictionary<string, string?>
                {
                    ["name"] = driver.Name,
                    ["kind"] = driver.Kind.ToString(),
                    ["start"] = driver.Start.ToString(),
                    ["image"] = driver.ImagePath,
                    ["expectedImage"] = driver.ExpectedImagePath,
                    ["imageSource"] = driver.ImageSource.ToString(),
                    ["signature"] = driver.Signature.State.ToString(),
                    ["signer"] = driver.Signature.Signer,
                    ["userInstalledTrust"] = driver.Signature.RestsOnUserInstalledTrust ? "true" : null,
                    ["microsoftSigned"] = MicrosoftSignedField(driver.Signature),
                    ["windowsProvided"] = driver.IsWindowsProvided.ToString(),
                    ["concern"] = concern.ToString(),
                });
        }
        AddCoverageFinding(b, acquisition);
        AddSignatureCoverageFinding(
            b, drivers.Where(driver => driver.ImagePath is not null).Select(driver => driver.Signature));
        return b.Build($"{drivers.Count} kernel driver(s) registered, {notable} unsigned, untrusted, orphaned or unresolvable{CoverageSuffix(acquisition)}");

        // Each line states what was established, not what it implies: Windows attests
        // plenty of drivers it did not write, so "signed by somebody other than Windows"
        // is the claim the evidence supports and "third-party" is not.
        static string Explain(KernelDriverConcern concern) => concern switch
        {
            KernelDriverConcern.WindowsProvided => "shipped and signed by Windows",
            KernelDriverConcern.ThirdParty => "signed by a publisher other than Windows",
            KernelDriverConcern.Untrusted => "UNSIGNED or untrusted kernel code",
            KernelDriverConcern.Unverified => "signature could not be verified",
            KernelDriverConcern.Unresolvable => "registered image is not a local path, so it could not be verified",
            _ => "registered, but its image file is gone",
        };

        static string StartLabel(DriverStart start) => start switch
        {
            DriverStart.Boot => "boot start",
            DriverStart.System => "system start",
            DriverStart.Automatic => "automatic start",
            DriverStart.Manual => "on demand",
            DriverStart.Disabled => "disabled",
            _ => "start unknown",
        };

        // The full X.500 subject is kept in the fields for machine consumers; the human
        // line only needs the name the certificate was issued to.
        static string SignerSuffix(KernelDriver driver) =>
            KernelDriverTriage.SignerCommonName(driver.Signature.Signer) is { } signer
                ? $", signed by {signer}"
                : string.Empty;
    }
}
