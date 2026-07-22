using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// A phantom import reaching the scan output, through the real <see cref="HijackScanner"/>.
/// </summary>
/// <remarks>
/// The rule tests prove the decision; this proves it is actually reached and graded. Between the two
/// sat the failure this project keeps meeting — a correct rule wired to nothing, or wired to
/// something that never calls it. Every input is injected, so the whole path runs against a machine
/// that does not exist, with no registry, no PE files and no probe writing anything anywhere.
/// </remarks>
public sealed class PhantomScanIntegrationTests
{
    private const string Image = @"C:\Program Files\App\svc.exe";

    private sealed class Services(params RegisteredService[] services) : IServiceRegistry
    {
        public IEnumerable<RegisteredService> Enumerate() => services;
    }

    private sealed class Path(params string[] directories) : IMachinePath
    {
        public IReadOnlyList<string> Directories() => directories;
    }

    private sealed class Known(params string[] names) : IKnownDllSource
    {
        public IReadOnlySet<string> Read() =>
            new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
    }

    private sealed class Probe(bool writable) : IWritabilityProbe
    {
        public List<string> Asked { get; } = [];

        public bool CanCreate(string path)
        {
            Asked.Add(path);
            return writable;
        }
    }

    private static HijackScanner Scanner(
        RegisteredService service,
        PeImportSet imports,
        IWritabilityProbe? probe = null,
        params string[] existingFiles)
    {
        var present = new HashSet<string>(existingFiles, StringComparer.OrdinalIgnoreCase) { Image };
        return new HijackScanner(
            new Services(service),
            new Path(),
            probe ?? new Probe(writable: false),
            new Known(),
            readImports: _ => imports,
            fileExists: present.Contains);
    }

    [Fact]
    public void APhantomImportOfAnAutoStartServiceBecomesAFinding()
    {
        var scanner = Scanner(
            new RegisteredService("VulnSvc", $@"""{Image}"" -k", AutoStarts: true),
            new PeImportSet(["wlbsctrl.dll"], []));

        var finding = Assert.Single(scanner.Scan(), f => f.Kind == HijackKind.PhantomImport);

        Assert.Equal("VulnSvc:wlbsctrl.dll", finding.Subject);
        Assert.Equal(Image, finding.Context);
        Assert.Equal(["wlbsctrl.dll"], finding.Candidates);
    }

    [Fact]
    public void AWritableDirectoryInTheSearchOrderGradesItExploitable()
    {
        var scanner = Scanner(
            new RegisteredService("VulnSvc", $@"""{Image}"" -k", AutoStarts: true),
            new PeImportSet(["wlbsctrl.dll"], []),
            new Probe(writable: true));

        var finding = Assert.Single(scanner.Scan(), f => f.Kind == HijackKind.PhantomImport);

        Assert.Equal(HijackExposure.Exploitable, finding.Exposure);
        Assert.NotNull(finding.ActionablePath);
    }

    [Fact]
    public void NothingWritableGradesItLatentAndNamesNoPath()
    {
        var scanner = Scanner(
            new RegisteredService("VulnSvc", $@"""{Image}"" -k", AutoStarts: true),
            new PeImportSet(["wlbsctrl.dll"], []),
            new Probe(writable: false));

        var finding = Assert.Single(scanner.Scan(), f => f.Kind == HijackKind.PhantomImport);

        Assert.Equal(HijackExposure.Latent, finding.Exposure);
        Assert.Null(finding.ActionablePath);
    }

    [Fact]
    public void AnImportThatExistsInTheApplicationDirectoryIsNotReported()
    {
        var scanner = Scanner(
            new RegisteredService("VulnSvc", $@"""{Image}"" -k", AutoStarts: true),
            new PeImportSet(["helper.dll"], []),
            probe: null,
            @"C:\Program Files\App\helper.dll");

        Assert.DoesNotContain(scanner.Scan(), f => f.Kind == HijackKind.PhantomImport);
    }

    /// <summary>
    /// A service Windows never starts by itself is not a boot-time escalation path, and reading
    /// every registered image would multiply the I/O of a routine scan for no added signal.
    /// </summary>
    [Fact]
    public void AManualStartServiceIsNotInspected()
    {
        var scanner = Scanner(
            new RegisteredService("ManualSvc", $@"""{Image}"" -k", AutoStarts: false),
            new PeImportSet(["wlbsctrl.dll"], []));

        Assert.DoesNotContain(scanner.Scan(), f => f.Kind == HijackKind.PhantomImport);
    }

    [Fact]
    public void ADriverNtPathIsNotReadAsAnImageToInspect()
    {
        var scanner = Scanner(
            new RegisteredService("Drv", @"\SystemRoot\System32\drivers\foo.sys", AutoStarts: true),
            new PeImportSet(["wlbsctrl.dll"], []));

        Assert.Empty(scanner.Scan());
    }

    /// <summary>
    /// Writability is a fact about a directory, so ~90 services sharing a search order must not
    /// each re-probe it. Left unbounded this would write thousands of files across the machine.
    /// </summary>
    [Fact]
    public void TheProbeIsNotRepeatedForEveryServiceSharingADirectory()
    {
        var probe = new Probe(writable: false);
        var services = Enumerable.Range(0, 20)
            .Select(i => new RegisteredService($"Svc{i}", $@"""{Image}"" -k", AutoStarts: true))
            .ToArray();
        var scanner = new HijackScanner(
            new Services(services),
            new Path(),
            probe,
            new Known(),
            readImports: _ => new PeImportSet(["wlbsctrl.dll"], []),
            fileExists: path => path.Equals(Image, StringComparison.OrdinalIgnoreCase));

        var findings = scanner.Scan();

        Assert.Equal(20, findings.Count(f => f.Kind == HijackKind.PhantomImport));
        // Each distinct directory is asked once for the whole scan, not once per service.
        Assert.Equal(
            probe.Asked.Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            probe.Asked.Count);
    }
}
