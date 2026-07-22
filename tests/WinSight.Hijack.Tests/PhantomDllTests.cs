using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The phantom-import rule: an import no file in the search order answers.
/// </summary>
/// <remarks>
/// On a healthy machine this reports nothing — measured, zero findings across ~90 auto-starting
/// services. That is the intended shape and it is exactly why these tests exist: a detector that is
/// silent because the machine is clean and one that is silent because it is broken look identical
/// from outside. Everything below drives a machine that does not exist, so the rule can be made to
/// fire on demand.
/// </remarks>
public sealed class PhantomDllTests
{
    private static readonly IReadOnlyList<string> Order =
        [@"C:\Program Files\App", @"C:\Windows\System32", @"C:\Windows"];

    private static readonly IReadOnlySet<string> NoKnownDlls = new HashSet<string>();

    private static PeImportSet Imports(string[] load, string[]? delay = null) =>
        new(load, delay ?? []);

    /// <summary>Only the named paths exist; everything else is absent.</summary>
    private static Func<string, bool> Present(params string[] paths)
    {
        var set = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
        return set.Contains;
    }

    // ---- It fires ----------------------------------------------------------------------------

    [Fact]
    public void AnImportNoDirectoryProvidesIsPhantom()
    {
        var phantoms = PhantomDllRule.Find(
            Imports(["wlbsctrl.dll"]), Order, NoKnownDlls, Present());

        var phantom = Assert.Single(phantoms);
        Assert.Equal("wlbsctrl.dll", phantom.Dll);
        Assert.False(phantom.DelayLoaded);
    }

    [Fact]
    public void ADelayLoadedPhantomIsReportedAndMarkedAsSuch()
    {
        var phantoms = PhantomDllRule.Find(
            Imports([], ["WptsExtensions.dll"]), Order, NoKnownDlls, Present());

        var phantom = Assert.Single(phantoms);
        Assert.True(phantom.DelayLoaded);
    }

    // ---- It stays quiet when it should -------------------------------------------------------

    [Theory]
    [InlineData(@"C:\Program Files\App\helper.dll")]
    [InlineData(@"C:\Windows\System32\helper.dll")]
    [InlineData(@"C:\Windows\helper.dll")]
    public void AnImportAnyDirectoryProvidesIsNotPhantom(string present)
    {
        Assert.Empty(PhantomDllRule.Find(
            Imports(["helper.dll"]), Order, NoKnownDlls, Present(present)));
    }

    /// <summary>
    /// API sets are resolved by the loader from a schema, and no file of that name exists anywhere.
    /// </summary>
    /// <remarks>
    /// The last two cases are not hypothetical. With the prefix written as <c>ext-ms-win-</c> instead
    /// of <c>ext-ms-</c>, they were the first two findings this rule ever produced against the live
    /// machine — the print spooler and the search indexer, both accused of a phantom import, both
    /// wrong. They are pinned here because the mistake is invisible by inspection.
    /// </remarks>
    [Theory]
    [InlineData("api-ms-win-core-libraryloader-l1-2-0.dll")]
    [InlineData("api-ms-win-crt-runtime-l1-1-0.dll")]
    [InlineData("ext-ms-win-ntuser-window-l1-1-0.dll")]
    [InlineData("ext-ms-win32-subsystem-query-l1-1-0.dll")]
    [InlineData("ext-ms-onecore-appmodel-staterepository-internal-l1-1-3.dll")]
    public void AnApiSetIsNeverPhantom(string apiSet)
    {
        Assert.Empty(PhantomDllRule.Find(Imports([apiSet]), Order, NoKnownDlls, Present()));
        Assert.True(PhantomDllRule.IsLoaderResolved(apiSet));
    }

    [Fact]
    public void ARealDllIsNotMistakenForAnApiSet()
    {
        Assert.False(PhantomDllRule.IsLoaderResolved("kernel32.dll"));
        Assert.False(PhantomDllRule.IsLoaderResolved("apphelp.dll"));
        Assert.False(PhantomDllRule.IsLoaderResolved("extensions.dll"));
    }

    /// <summary>
    /// A KnownDLL is mapped from a pre-loaded section, never resolved through the search order, so
    /// planting one earlier in that order achieves nothing.
    /// </summary>
    [Theory]
    [InlineData("kernel32")]
    [InlineData("kernel32.dll")]
    public void AKnownDllIsNeverPhantomHoweverItIsRegistered(string registered)
    {
        var known = new HashSet<string>(
            [registered.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? registered[..^4] : registered],
            StringComparer.OrdinalIgnoreCase);

        Assert.Empty(PhantomDllRule.Find(Imports(["KERNEL32.DLL"]), Order, known, Present()));
    }

    // ---- Where it can be planted -------------------------------------------------------------

    [Fact]
    public void ThePlantLocationIsTheFirstWritableDirectoryInSearchOrder()
    {
        var phantom = Assert.Single(PhantomDllRule.Find(
            Imports(["wlbsctrl.dll"]), Order, NoKnownDlls, Present(),
            canPlantIn: directory => directory is @"C:\Windows" or @"C:\Windows\System32"));

        // System32 precedes Windows in the order, so it is the one an attacker would use.
        Assert.Equal(@"C:\Windows\System32", phantom.PlantableAt);
    }

    [Fact]
    public void NothingWritableMeansNoPlantLocationRatherThanAGuess()
    {
        var phantom = Assert.Single(PhantomDllRule.Find(
            Imports(["wlbsctrl.dll"]), Order, NoKnownDlls, Present(), canPlantIn: _ => false));

        Assert.Null(phantom.PlantableAt);
    }

    [Fact]
    public void WritabilityIsProbedOncePerDirectoryNotOncePerImport()
    {
        // A service declaring 130 imports must not write 130 probe files into the same folder.
        var probes = new List<string>();
        var many = Enumerable.Range(0, 40).Select(i => $"phantom{i}.dll").ToArray();

        var phantoms = PhantomDllRule.Find(
            Imports(many), Order, NoKnownDlls, Present(),
            canPlantIn: directory => { probes.Add(directory); return false; });

        Assert.Equal(40, phantoms.Count);
        Assert.Equal(Order.Count, probes.Count);
        Assert.Equal(probes.Count, probes.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void TheSameImportDeclaredTwiceIsReportedOnce()
    {
        var phantoms = PhantomDllRule.Find(
            Imports(["wlbsctrl.dll"], ["WLBSCTRL.DLL"]), Order, NoKnownDlls, Present());

        Assert.Single(phantoms);
    }
}

/// <summary>The order Windows searches, which decides which plant location actually wins.</summary>
public sealed class DllSearchOrderTests
{
    [Fact]
    public void TheApplicationDirectoryComesFirstAndThePathComesLast()
    {
        var order = DllSearchOrder.For(
            @"C:\Program Files\App", @"C:\Windows\System32", @"C:\Windows",
            [@"C:\Tools", @"C:\Utils"]);

        Assert.Equal(
            [@"C:\Program Files\App", @"C:\Windows\System32", @"C:\Windows\System", @"C:\Windows",
             @"C:\Tools", @"C:\Utils"],
            order);
    }

    [Fact]
    public void ADirectoryNamedTwiceIsSearchedOnce()
    {
        // A machine PATH routinely lists System32; a duplicate would double every probe under it.
        var order = DllSearchOrder.For(
            @"C:\Windows\System32", @"C:\Windows\System32", @"C:\Windows",
            [@"C:\Windows\System32\", @"C:\Tools"]);

        Assert.Equal([@"C:\Windows\System32", @"C:\Windows\System", @"C:\Windows", @"C:\Tools"], order);
    }
}
