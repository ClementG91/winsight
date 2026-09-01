using WinSight.Hijack;
using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// Which directory "the system directory" means, and what happens to an import the search order
/// cannot answer.
/// </summary>
/// <remarks>
/// <b>Two confident accusations against ordinary software.</b> The scan searched <c>System32</c>
/// for every binary regardless of its bitness. A 32-bit process is served <c>SysWOW64</c> by the
/// file-system redirector, so every 32-bit auto-start service importing a DLL that ships only in
/// SysWOW64 - the ordinary case for the 32-bit half of anything - had that import reported as
/// phantom. The bitness was read during the PE parse, to find the data directory, and thrown away.
///
/// And "no directory in the search order holds this file" was treated as "the loader cannot find
/// it". A binary whose manifest binds a side-by-side assembly resolves those imports out of the
/// WinSxS store, which appears in no search path, so every service linked against the Visual C++
/// or MFC/ATL redistributables was reported the same way.
///
/// Both produced a finding against a SYSTEM service, which is the loudest thing this scanner can
/// say.
/// </remarks>
public sealed class DllSearchBitnessTests
{
    private static readonly string Windows =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    [Fact]
    public void A64BitImageSearchesSystem32() =>
        Assert.Equal(
            System32, DllSearchOrder.SystemDirectoryFor(true, System32, Windows));

    /// <summary>
    /// The case that produced the false positives. On a 64-bit machine a 32-bit image must search
    /// SysWOW64.
    /// </summary>
    [Fact]
    public void A32BitImageSearchesSysWow64WhenItExists()
    {
        var wow = Path.Combine(Windows, "SysWOW64");

        var resolved = DllSearchOrder.SystemDirectoryFor(false, System32, Windows);

        if (Directory.Exists(wow))
        {
            Assert.Equal(wow, resolved);
        }
        else
        {
            // A 32-bit Windows has no redirector and no SysWOW64; the system directory is already
            // the right answer, and substituting a directory that does not exist would be worse.
            Assert.Equal(System32, resolved);
        }
    }

    /// <summary>
    /// On a machine with no SysWOW64 the substitution must not happen, or the search order would
    /// contain a directory that does not exist and every import would read as phantom.
    /// </summary>
    [Fact]
    public void A32BitImageFallsBackWhenThereIsNoSysWow64()
    {
        var noWow = Path.Combine(Path.GetTempPath(), $"winsight-nowow-{Guid.NewGuid():N}");
        Directory.CreateDirectory(noWow);
        try
        {
            Assert.Equal(System32, DllSearchOrder.SystemDirectoryFor(false, System32, noWow));
        }
        finally
        {
            Directory.Delete(noWow, recursive: true);
        }
    }

    /// <summary>The bitness is carried out of the parse rather than discarded.</summary>
    [Fact]
    public void TheParserReportsTheBitnessOfARealImage()
    {
        var imports = PeImports.ReadFile(Path.Combine(System32, "kernel32.dll"));

        Assert.True(imports.IsReadable);
        Assert.NotNull(imports.Is64Bit);
        Assert.Equal(Environment.Is64BitOperatingSystem, imports.Is64Bit);
    }

    /// <summary>
    /// An import the search order cannot answer, but which the loader can still reach, must not be
    /// called phantom.
    /// </summary>
    [Fact]
    public void AnImportResolvableElsewhereIsNotPhantom()
    {
        var set = new PeImportSet(["msvcr90.dll"], []);

        var withoutStore = PhantomDllRule.Find(
            set, ["C:\\nowhere"], new HashSet<string>(), _ => false);
        var withStore = PhantomDllRule.Find(
            set, ["C:\\nowhere"], new HashSet<string>(), _ => false,
            canPlantIn: null, resolvedElsewhere: _ => true);

        Assert.Single(withoutStore);
        Assert.Empty(withStore);
    }

    /// <summary>
    /// The extra question is asked only about names the search order failed to answer, so a service
    /// with a hundred imports does not pay a hundred store lookups.
    /// </summary>
    [Fact]
    public void TheStoreIsOnlyAskedAboutUnresolvedImports()
    {
        var asked = new List<string>();
        var set = new PeImportSet(["present.dll", "absent.dll"], []);

        PhantomDllRule.Find(
            set,
            ["C:\\dir"],
            new HashSet<string>(),
            path => path.EndsWith("present.dll", StringComparison.OrdinalIgnoreCase),
            canPlantIn: null,
            resolvedElsewhere: dll => { asked.Add(dll); return false; });

        Assert.Equal(["absent.dll"], asked);
    }

    /// <summary>
    /// A machine with no side-by-side store answers "not present" definitively - nothing can
    /// resolve through a store that does not exist - rather than refusing to answer.
    /// </summary>
    [Fact]
    public void AMachineWithNoStoreAnswersDefinitively()
    {
        var empty = Path.Combine(Path.GetTempPath(), $"winsight-nosxs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(empty);
        try
        {
            var store = new SideBySideStore(empty);

            Assert.False(store.Contains("msvcr90.dll"));
            Assert.Equal(0, store.UnansweredLookups);
        }
        finally
        {
            Directory.Delete(empty, recursive: true);
        }
    }

    /// <summary>
    /// A store that is present and complete answers both ways, and a name it holds is reported as
    /// resolvable however deep in the tree it sits.
    /// </summary>
    [Fact]
    public void ACompleteIndexAnswersBothWays()
    {
        var root = Path.Combine(Path.GetTempPath(), $"winsight-sxs-{Guid.NewGuid():N}");
        var assembly = Path.Combine(root, "WinSxS", "amd64_microsoft.vc90.crt_deadbeef");
        Directory.CreateDirectory(assembly);
        File.WriteAllText(Path.Combine(assembly, "msvcr90.dll"), "stub");
        try
        {
            var store = new SideBySideStore(root);

            Assert.True(store.Contains("msvcr90.dll"));
            Assert.False(store.Contains("definitely-not-here.dll"));
            Assert.Equal(0, store.UnansweredLookups);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>The lookup ignores case, because import names are not case-consistent.</summary>
    [Fact]
    public void TheLookupIgnoresCase()
    {
        var root = Path.Combine(Path.GetTempPath(), $"winsight-sxs-{Guid.NewGuid():N}");
        var assembly = Path.Combine(root, "WinSxS", "x86_microsoft.vc90.mfc_cafebabe");
        Directory.CreateDirectory(assembly);
        File.WriteAllText(Path.Combine(assembly, "MFC90.DLL"), "stub");
        try
        {
            Assert.True(new SideBySideStore(root).Contains("mfc90.dll"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// An unanswerable question must not become a finding. The scanner turns a null into "skip and
    /// count as coverage", which is the rule this codebase applies everywhere else.
    /// </summary>
    [Fact]
    public void AnUnansweredLookupIsCountedRatherThanGuessed()
    {
        var store = new PartialStore();

        Assert.Null(store.Contains("anything.dll"));
        Assert.Equal(1, store.UnansweredLookups);
    }

    private sealed class PartialStore : ISideBySideStore
    {
        public int UnansweredLookups { get; private set; }

        public bool? Contains(string dll)
        {
            UnansweredLookups++;
            return null;
        }
    }
}
