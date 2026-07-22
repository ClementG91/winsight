using Xunit;

namespace WinSight.Application.Tests;

public sealed class AdaptersTests
{
    [Fact]
    public void SnapshotCommands_AreUniqueAndComplete()
    {
        var expected = new[]
        {
            "persistence", "av", "net", "dns", "firewall", "processes", "modules", "extensions", "certs", "hosts",
            "input", "drivers", "integrity", "hijack",
        };

        Assert.Equal(expected.Order(), Adapters.SnapshotCommands.Order());
    }

    /// <summary>
    /// Every command the suite dispatches has to be discoverable from <c>--help</c>.
    /// </summary>
    /// <remarks>
    /// The <c>hijack</c> scanner shipped wired into the dispatcher, the default overview, the MCP
    /// catalog and the dashboard — and missing from <c>--help</c>. Nothing failed, because the help
    /// text was a hand-maintained copy nothing compared against. A scanner an operator cannot find
    /// is, for them, a scanner that does not exist.
    /// </remarks>
    [Fact]
    public void EverySnapshotCommand_IsDocumentedInHelp()
    {
        var undocumented = Adapters.SnapshotCommands
            .Where(command => !CliHelp.DocumentedCommands.Contains(command))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            undocumented.Length == 0,
            $"`winsight --help` documents no way to run: {string.Join(", ", undocumented)}.");
    }

    /// <summary>
    /// Guards the parser itself: a <see cref="CliHelp.DocumentedCommands"/> that silently matched
    /// nothing would make the test above pass for every possible help text.
    /// </summary>
    [Fact]
    public void HelpParsing_RecognisesBothUsageForms()
    {
        // Grouped form, `winsight [persistence|av|net|dns|all]`.
        Assert.Contains("persistence", CliHelp.DocumentedCommands);
        // Plain form, `winsight drivers`.
        Assert.Contains("drivers", CliHelp.DocumentedCommands);
        // The overview is not a scanner and must not be mistaken for one.
        Assert.DoesNotContain("all", CliHelp.DocumentedCommands);
        // A word that appears in prose but never as a command must not register.
        Assert.DoesNotContain("kernel", CliHelp.DocumentedCommands);
    }

    [Fact]
    public void OverviewCommands_AreSupportedAndUnique()
    {
        Assert.Equal(Adapters.OverviewCommands.Count, Adapters.OverviewCommands.Distinct().Count());
        Assert.All(Adapters.OverviewCommands, command => Assert.Contains(command, Adapters.SnapshotCommands));
    }

    [Fact]
    public void RunOverview_HonoursPreCancelledTokenBeforeScanning()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => Adapters.RunOverview(cancellationToken: cts.Token));
    }

    [Theory]
    [InlineData(0, 7, 0)]
    [InlineData(3, 7, 43)]
    [InlineData(7, 7, 100)]
    [InlineData(1, 0, 0)]
    [InlineData(9, 7, 100)]
    [InlineData(-1, 7, 0)]
    public void ScanProgress_ComputesBoundedPercentage(int completed, int total, int expected)
    {
        Assert.Equal(expected, new ScanProgress(completed, total, "test").Percent);
    }

    [Fact]
    public void Run_RejectsUnknownCommandBeforeStartingAScan()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Adapters.Run("unknown"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Run_RejectsEmptyCommand(string command)
    {
        Assert.Throws<ArgumentException>(() => Adapters.Run(command));
    }
}
