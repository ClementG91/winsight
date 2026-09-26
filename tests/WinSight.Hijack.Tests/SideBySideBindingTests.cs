using System.Text;

using WinSight.Core;
using WinSight.Core.Tests;
using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// RA-04: a file of the same name somewhere in WinSxS is not the file the loader would load. An
/// import resolves out of the store only through an assembly the image's manifest binds.
/// </summary>
public sealed class SideBySideBindingTests : IDisposable
{
    private const string VcKey = "1fc8b3b9a1e18e3b";
    private const string WindowsKey = "31bf3856ad364e35";

    private static readonly SideBySideAssembly Crt90 = new("Microsoft.VC90.CRT", VcKey, "amd64");
    private static readonly SideBySideAssembly CommonControls = new("Microsoft.Windows.Common-Controls", "6595b64144ccf1df", "*");
    private static readonly SideBySideAssembly VendorLibrary = new("Contoso.Runtime", "0123456789abcdef", "amd64");

    private readonly string _root = Path.Combine(Path.GetTempPath(), "winsight-sxs-binding-" + Guid.NewGuid().ToString("n"));

    public SideBySideBindingTests() => Directory.CreateDirectory(Path.Combine(_root, "WinSxS"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void Plant(string relative)
    {
        var path = Path.Combine(_root, "WinSxS", relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, []);
    }

    private const string Crt90Amd64 = $@"amd64_microsoft.vc90.crt_{VcKey}_9.0.30729.9635_none_08e2c157a83ed5da";
    private const string Crt90X86 = $@"x86_microsoft.vc90.crt_{VcKey}_9.0.30729.9635_none_508ff82ebcbafee0";
    private const string StagedFeature = $@"amd64_microsoft-windows-networkloadbalancing_{WindowsKey}_10.0.26100.1_none_0123456789abcdef";

    // The accusation this class was built to prevent still does not happen: a bound assembly's file
    // resolves the import.
    [Fact]
    public void AnAssemblyTheManifestBindsResolvesItsFile()
    {
        Plant($@"{Crt90Amd64}\msvcr90.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Resolves("msvcr90.dll", is64Bit: true, [Crt90]));
        Assert.True(store.Resolves("MSVCR90.DLL", is64Bit: true, [Crt90 with { ProcessorArchitecture = "*" }]));
        Assert.Equal(0, store.UnansweredLookups);
    }

    // The false negative: a genuine phantom import whose name a staged feature also carries.
    [Fact]
    public void ASameNamedFileInAnAssemblyTheImageDoesNotBindResolvesNothing()
    {
        Plant($@"{StagedFeature}\wlbsctrl.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Contains("wlbsctrl.dll"));
        Assert.False(store.Resolves("wlbsctrl.dll", is64Bit: true, []));
        Assert.False(store.Resolves("wlbsctrl.dll", is64Bit: true, [CommonControls]));
        Assert.False(store.Resolves("wlbsctrl.dll", is64Bit: true, [Crt90]));
        Assert.Equal(0, store.UnansweredLookups);
    }

    [Fact]
    public void AnotherArchitecturesCopyResolvesNothing()
    {
        Plant($@"{Crt90X86}\msvcr90.dll");
        var store = new SideBySideStore(_root);

        Assert.False(store.Resolves("msvcr90.dll", is64Bit: true, [Crt90]));
        Assert.True(store.Resolves("msvcr90.dll", is64Bit: false, [Crt90 with { ProcessorArchitecture = "x86" }]));
    }

    // What cannot be decided stays unknown: an unread manifest, or a bound assembly whose own
    // dependencies are not modelled.
    [Fact]
    public void WhereTheManifestLeadsCannotBeToldTheAnswerIsUnknownNotResolved()
    {
        Plant($@"{StagedFeature}\wlbsctrl.dll");
        var store = new SideBySideStore(_root);

        Assert.Null(store.Resolves("wlbsctrl.dll", is64Bit: true, bound: null));
        Assert.Null(store.Resolves("wlbsctrl.dll", is64Bit: true, [VendorLibrary]));
        Assert.Equal(2, store.UnansweredLookups);
    }

    // MFC brings the CRT of its own Visual C++ version with it.
    [Fact]
    public void AVisualCppLibraryReachesTheRuntimeOfItsOwnVersion()
    {
        Plant($@"{Crt90Amd64}\msvcr90.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Resolves("msvcr90.dll", is64Bit: true, [new SideBySideAssembly("Microsoft.VC90.MFC", VcKey, "amd64")]));
    }

    // The manifest comes from the scanned image: a made-up name under the Visual C++ key used to reach
    // every Visual C++ component, which the loader would never do.
    [Fact]
    public void ASharedPublisherKeyAloneReachesNothing()
    {
        Plant($@"{Crt90Amd64}\msvcr90.dll");
        Plant($@"amd64_microsoft.vc80.atl_{VcKey}_8.0.50727.6195_none_0123456789abcdef\atl80.dll");
        var store = new SideBySideStore(_root);

        Assert.Null(store.Resolves("msvcr90.dll", is64Bit: true, [new SideBySideAssembly("Anything", VcKey, "amd64")]));
        // MFC 9 does not bring ATL 8: not reached, and MFC's other dependencies are not modelled.
        Assert.Null(store.Resolves("atl80.dll", is64Bit: true, [new SideBySideAssembly("Microsoft.VC90.MFC", VcKey, "amd64")]));
        // The CRT alone declares no dependency, so the answer is final.
        Assert.False(store.Resolves("atl80.dll", is64Bit: true, [Crt90]));
    }

    [Fact]
    public void AssembliesKeptUnderFusionAreAttributed()
    {
        Plant($@"Fusion\amd64_microsoft.vc80.mfc_{VcKey}_none_758c8a477f89a995\8.0\8.0.50727.6195\mfc80.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Resolves("mfc80.dll", is64Bit: true, [new SideBySideAssembly("Microsoft.VC80.MFC", VcKey, "amd64")]));
        Assert.False(store.Resolves("mfc80.dll", is64Bit: true, []));
    }

    [Fact]
    public void AShortenedComponentNameStillMatchesTheFullAssemblyName()
    {
        Plant($@"amd64_microsoft-windows-s..ngineering-shell_{WindowsKey}_10.0.26100.1_none_0123456789abcdef\shelleng.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Resolves("shelleng.dll", is64Bit: true,
            [new SideBySideAssembly("Microsoft-Windows-ShellEngineering-Shell", WindowsKey, "amd64")]));
        Assert.False(store.Resolves("shelleng.dll", is64Bit: true, [CommonControls]));
        // Another Windows assembly shares the key but not the name: it may depend on this one, which
        // is not modelled, so the answer is unknown rather than a finding.
        Assert.Null(store.Resolves("shelleng.dll", is64Bit: true,
            [new SideBySideAssembly("Microsoft-Windows-Unrelated", WindowsKey, "amd64")]));
    }

    [Fact]
    public void APartialIndexNeverAnswersFalse()
    {
        Plant($@"{StagedFeature}\wlbsctrl.dll");
        Plant($@"{Crt90Amd64}\msvcr90.dll");
        var store = new SideBySideStore(_root, TimeSpan.FromMinutes(1), maxEntries: 1);

        Assert.Null(store.Resolves("wlbsctrl.dll", is64Bit: true, []));
    }

    [Fact]
    public void AStoreThatKnowsOnlyPresenceCallsItUnknown()
    {
        ISideBySideStore presenceOnly = new PresenceOnly();
        ISideBySideStore absent = new PresenceOnly(present: false);

        Assert.Null(presenceOnly.Resolves("anything.dll", is64Bit: true, []));
        Assert.False(absent.Resolves("anything.dll", is64Bit: true, []));
    }

    [Theory]
    [InlineData("amd64_aspnet_compiler_b03f5f7f11d50a3a_10.0.26100.1_none_75598f0af79da90a", "amd64", "aspnet_compiler")]
    [InlineData("amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9635_none_08e2c157a83ed5da", "amd64", "microsoft.vc90.crt")]
    [InlineData("amd64_c_1394.inf.resources_31bf3856ad364e35_10.0.26100.1_en-us_fd1241dd34aad749", "amd64", "c_1394.inf.resources")]
    public void ComponentFolderNamesAreReadFromTheRight(string folder, string architecture, string name)
    {
        var component = SideBySideComponent.Parse(folder, versioned: true);

        Assert.NotNull(component);
        Assert.Equal(architecture, component.Architecture);
        Assert.Equal(name, component.Name);
    }

    [Theory]
    [InlineData("Backup")]
    [InlineData("FusionDiff")]
    [InlineData("SettingsManifests")]
    [InlineData("amd64_name_notakey_1.0_none_hash")]
    public void BookkeepingFoldersAreNotComponents(string folder) =>
        Assert.Null(SideBySideComponent.Parse(folder, versioned: true));

    // Through the real scanner: the staged copy no longer hides the phantom import, and the bound
    // runtime still does not produce one.
    [Fact]
    public void TheScannerReportsAPhantomImportAStagedCopyUsedToHide()
    {
        Plant($@"{StagedFeature}\wlbsctrl.dll");
        Plant($@"{Crt90Amd64}\msvcr90.dll");
        const string image = @"C:\Program Files\Contoso\svc.exe";
        var imports = new PeImportSet(["wlbsctrl.dll", "msvcr90.dll"], []) { Is64Bit = true, BoundAssemblies = [Crt90] };
        var scanner = new HijackScanner(
            new OneService(new RegisteredService("Contoso", $@"""{image}"" -k", AutoStarts: true)),
            new NoPath(),
            new NothingWritable(),
            new NoKnownDlls(),
            readImports: _ => imports,
            fileExists: path => path.Equals(image, StringComparison.OrdinalIgnoreCase),
            sideBySideStore: new SideBySideStore(_root));

        var scan = scanner.ScanWithCoverage();

        var phantom = Assert.Single(scan.Items, finding => finding.Kind == HijackKind.PhantomImport);
        Assert.Equal("Contoso:wlbsctrl.dll", phantom.Subject);
        Assert.Equal(0, scan.UnreadableItems);
    }

    private sealed class OneService(RegisteredService service) : IServiceRegistry
    {
        public IEnumerable<RegisteredService> Enumerate() => [service];
    }

    private sealed class NoPath : IMachinePath
    {
        public IReadOnlyList<string> Directories() => [];
    }

    private sealed class NoKnownDlls : IKnownDllSource
    {
        public IReadOnlySet<string> Read() => new HashSet<string>();
    }

    private sealed class NothingWritable : IWritabilityProbe
    {
        public bool CanCreate(string path) => false;
    }

    private sealed class PresenceOnly(bool present = true) : ISideBySideStore
    {
        public int UnansweredLookups => 0;

        public bool? Contains(string dll) => present;
    }
}

/// <summary>The manifest an image embeds, read as hostile input.</summary>
public sealed class SideBySideManifestTests
{
    private const string Manifest = """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
          <assemblyIdentity type="win32" name="Contoso.Service" version="1.0.0.0" processorArchitecture="amd64"/>
          <dependency>
            <dependentAssembly>
              <assemblyIdentity type="win32" name="Microsoft.VC90.CRT" version="9.0.21022.8" processorArchitecture="amd64" publicKeyToken="1fc8b3b9a1e18e3b"/>
            </dependentAssembly>
          </dependency>
          <dependency>
            <dependentAssembly>
              <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
            </dependentAssembly>
          </dependency>
        </assembly>
        """;

    [Fact]
    public void TheDependenciesAreReadAndTheImagesOwnIdentityIsNotOne()
    {
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(Manifest)).Concat(new byte[7]).ToArray();

        var dependencies = SideBySideManifest.ReadDependencies(bytes);

        Assert.NotNull(dependencies);
        Assert.Equal(2, dependencies.Count);
        Assert.Equal(new SideBySideAssembly("Microsoft.VC90.CRT", "1fc8b3b9a1e18e3b", "amd64"), dependencies[0]);
        Assert.Equal("*", dependencies[1].ProcessorArchitecture);
    }

    [Fact]
    public void AUtf16ManifestPaddedWithNulsIsRead()
    {
        var bytes = Encoding.Unicode.GetPreamble()
            .Concat(Encoding.Unicode.GetBytes(Manifest.Replace("UTF-8", "UTF-16", StringComparison.Ordinal)))
            .Concat(new byte[6]).ToArray();

        Assert.Equal(2, SideBySideManifest.ReadDependencies(bytes)?.Count);
    }

    [Fact]
    public void AManifestWithoutDependenciesBindsNothing()
    {
        var manifest = """<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo/></assembly>""";

        Assert.Empty(SideBySideManifest.ReadDependencies(Encoding.UTF8.GetBytes(manifest))!);
    }

    // Unparseable is unknown, never "binds nothing": that answer would turn a present file into a finding.
    [Theory]
    [InlineData("<assembly><dependency><dependentAssembly>")]
    [InlineData("""<!DOCTYPE assembly [<!ENTITY x "y">]><assembly>&x;</assembly>""")]
    [InlineData("not xml at all")]
    [InlineData("")]
    public void AManifestThatDoesNotParseIsUnknown(string manifest) =>
        Assert.Null(SideBySideManifest.ReadDependencies(Encoding.UTF8.GetBytes(manifest)));

    [Fact]
    public void AnUnreasonableNumberOfDependenciesIsRefused()
    {
        var dependencies = string.Concat(Enumerable.Range(0, 65).Select(i =>
            $"""<dependency><dependentAssembly><assemblyIdentity name="A{i}" publicKeyToken="0123456789abcdef"/></dependentAssembly></dependency>"""));

        Assert.Null(SideBySideManifest.ReadDependencies(Encoding.UTF8.GetBytes($"<assembly>{dependencies}</assembly>")));
    }

    [Fact]
    public void TheImageReaderCarriesTheManifestAndTellsAbsentFromUnreadable()
    {
        var withManifest = PeResourceImage.Build([(PeResources.ManifestType, 1, Encoding.UTF8.GetBytes(Manifest))]);
        var withoutManifest = PeResourceImage.Build([(PeResources.VersionType, 1, new byte[64])]);
        var broken = PeResourceImage.Build([(PeResources.ManifestType, 1, Encoding.UTF8.GetBytes("<assembly><dependency>"))]);
        var oversized = PeResourceImage.Build([(PeResources.ManifestType, 1, new byte[SideBySideManifest.MaximumBytes + 1])]);

        Assert.Equal(2, PeImports.ManifestDependencies(withManifest)?.Count);
        Assert.Empty(PeImports.ManifestDependencies(withoutManifest)!);
        Assert.Null(PeImports.ManifestDependencies(broken));
        Assert.Null(PeImports.ManifestDependencies(oversized));
    }

    [Fact]
    public void ReadingAFileSetsTheBindingsOnlyFromAReadManifest()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-manifest-{Guid.NewGuid():N}.exe");
        try
        {
            File.WriteAllBytes(path, PeResourceImage.Build([(PeResources.ManifestType, 1, Encoding.UTF8.GetBytes(Manifest))]));

            var imports = PeImports.ReadFile(path);

            Assert.True(imports.IsReadable);
            Assert.Equal("Microsoft.VC90.CRT", imports.BoundAssemblies?[0].Name);
            // Built without reading a manifest, a set cannot claim to bind nothing.
            Assert.Null(new PeImportSet(["x.dll"], []).BoundAssemblies);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
