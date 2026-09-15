using WinSight.InputHooks;

using Xunit;

namespace WinSight.InputHooks.Tests;

public sealed class InputFilterDiffTests
{
    private static InputFilterRef Kbd(string name, FilterPosition pos = FilterPosition.Upper) =>
        new(InputStack.Keyboard, pos, name);

    [Fact]
    public void ANewFilterIsReportedAsAdded()
    {
        var before = new[] { Kbd("kbdhid") };
        var after = new[] { Kbd("kbdhid"), Kbd("evilkbd") };

        var alert = Assert.Single(InputFilterDiff.Between(before, after));

        Assert.Equal(InputFilterChangeKind.Added, alert.Kind);
        Assert.Equal("evilkbd", alert.Filter.Name);
    }

    [Fact]
    public void ARemovedFilterIsReportedAsRemoved()
    {
        var alert = Assert.Single(InputFilterDiff.Between([Kbd("kbdhid"), Kbd("gone")], [Kbd("kbdhid")]));

        Assert.Equal(InputFilterChangeKind.Removed, alert.Kind);
        Assert.Equal("gone", alert.Filter.Name);
    }

    [Fact]
    public void PositionAndStackArePartOfTheIdentity()
    {
        // Same name, different position => the upper one is added, nothing removed.
        var before = new[] { Kbd("dup", FilterPosition.Upper) };
        var after = new[] { Kbd("dup", FilterPosition.Upper), Kbd("dup", FilterPosition.Lower) };

        var alert = Assert.Single(InputFilterDiff.Between(before, after));
        Assert.Equal(FilterPosition.Lower, alert.Filter.Position);
    }

    [Fact]
    public void NoChangeYieldsNoAlerts()
    {
        var same = new[] { Kbd("kbdhid"), new InputFilterRef(InputStack.Mouse, FilterPosition.Upper, "mouhid") };
        Assert.Empty(InputFilterDiff.Between(same, same));
    }

    [Fact]
    public void EverythingIsAddedFromAnEmptyBaseline()
    {
        var alerts = InputFilterDiff.Between([], [Kbd("a"), Kbd("b")]);
        Assert.Equal(2, alerts.Count);
        Assert.All(alerts, a => Assert.Equal(InputFilterChangeKind.Added, a.Kind));
    }
}

public sealed class InputFilterWatcherRealTests
{
    [Fact]
    public void ReadingTheCurrentFiltersDoesNotThrowAndIsRepeatable()
    {
        var first = InputFilterWatcher.ReadFromRegistry();
        var second = InputFilterWatcher.ReadFromRegistry();

        Assert.NotNull(first);
        // A read-only registry read is deterministic between two immediate calls.
        Assert.Equal(first.Count, second.Count);
    }

    [Fact]
    public void StartSeedsFromTheReaderAndDisposesCleanly()
    {
        // Inject a reader so the flow is exercised without depending on machine-specific filters.
        var watcher = new InputFilterWatcher(() => [new InputFilterRef(InputStack.Keyboard, FilterPosition.Upper, "kbdhid")]);
        try
        {
            // The keyboard/mouse class keys always exist on Windows, so a watch is established.
            Assert.True(watcher.Start());
        }
        finally
        {
            watcher.Dispose();
            watcher.Dispose(); // idempotent
        }
    }
}
