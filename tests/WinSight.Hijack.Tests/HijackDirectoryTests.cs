using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The two directory checks: a service's own folder, and the machine PATH.
/// </summary>
/// <remarks>
/// Both report nothing on a healthy machine — measured on a real desktop, 18 machine PATH entries
/// and 88 auto-starting services, none writable — which is the right shape for a check like this
/// but means only a test can prove it fires at all. A silent detector and a broken one look
/// identical from the outside, and that confusion has already cost this project twice.
/// </remarks>
public sealed class HijackDirectoryTests
{
    [Fact]
    public void AWritableServiceDirectoryIsExploitable()
    {
        // A program's own directory is the first place Windows looks for every DLL it loads, so a
        // writable one answers any import the service makes — and holds the executable besides.
        var directory = ExistingDirectory();
        var triage = new HijackTriage(new Writable(directory));

        var finding = triage.AssessServiceDirectory("Thing", directory);

        Assert.Equal(HijackKind.WritableServiceDirectory, finding?.Kind);
        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
    }

    [Fact]
    public void AnUnwritableServiceDirectoryIsNotReported()
    {
        // The other eighty-seven. Listing them would bury the one that matters.
        var triage = new HijackTriage(new NothingWritable());

        Assert.Null(triage.AssessServiceDirectory("Thing", ExistingDirectory()));
    }

    [Fact]
    public void AServiceDirectoryThatDoesNotExistIsNotReported()
    {
        var triage = new HijackTriage(new Writable(@"C:\nowhere"));

        Assert.Null(triage.AssessServiceDirectory("Thing", @"C:\nowhere-at-all-12345"));
    }

    [Fact]
    public void AWritablePathEntryIsExploitable()
    {
        // A hijack point for every process that resolves anything by name rather than by path.
        var directory = ExistingDirectory();
        var triage = new HijackTriage(new Writable(directory));

        var finding = triage.AssessPathEntry(directory);

        Assert.Equal(HijackKind.WritablePathEntry, finding?.Kind);
        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        Assert.Equal(directory, finding?.ActionablePath);
    }

    [Fact]
    public void AnUnwritablePathEntryIsNotReported() =>
        Assert.Null(new HijackTriage(new NothingWritable()).AssessPathEntry(ExistingDirectory()));

    // The same vulnerability one step earlier: an entry pointing at a directory that does not exist
    // yet, in a place this user can create it. Create the directory, then fill it.
    [Fact]
    public void AnAbsentPathEntryWhoseParentIsWritableIsExploitable()
    {
        var parent = ExistingDirectory();
        var absent = Path.Combine(parent, $"missing-{Guid.NewGuid():N}");
        var triage = new HijackTriage(new Writable(parent));

        var finding = triage.AssessPathEntry(absent);

        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        Assert.Contains("does not exist", finding?.Context, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsentPathEntryWithAClosedParentIsJustStaleConfiguration()
    {
        var absent = Path.Combine(ExistingDirectory(), $"missing-{Guid.NewGuid():N}");

        Assert.Null(new HijackTriage(new NothingWritable()).AssessPathEntry(absent));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NothingToReadIsNotAFinding(string? directory) =>
        Assert.Null(new HijackTriage(new NothingWritable()).AssessPathEntry(directory!));

    /// <summary>A directory that genuinely exists, so the check reaches the writability question.</summary>
    private static string ExistingDirectory() => Path.GetTempPath().TrimEnd('\\');

    private sealed class NothingWritable : IWritabilityProbe
    {
        public bool CanCreate(string path) => false;
    }

    /// <summary>Answers yes for any file inside one of the given directories.</summary>
    private sealed class Writable(params string[] directories) : IWritabilityProbe
    {
        public bool CanCreate(string path) =>
            Path.GetDirectoryName(path) is { } parent
            && directories.Any(d => string.Equals(d.TrimEnd('\\'), parent.TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase));
    }
}
