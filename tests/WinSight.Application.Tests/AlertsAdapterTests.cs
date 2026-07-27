using System.Globalization;

using WinSight.Application;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class AlertsAdapterTests
{
    [Fact]
    public void Run_KnowsTheAlertsCommand()
    {
        // The dashboard tool catalog dispatches by command string; an unknown one throws, so this
        // pins the wiring between the "alerts" tool entry and the adapter.
        var report = Adapters.Run("alerts");

        Assert.Equal("alerts", report.Tool);
    }

    [Fact]
    public void Alerts_EmptyJournal_SaysSoRatherThanLookingBroken()
    {
        // Read from a machine with no journal yet: an empty list must read as "nothing recorded",
        // never as a failure — a fresh install has no history and that is normal.
        var report = Adapters.Alerts(max: 5);

        Assert.DoesNotContain(report.Items, i => string.IsNullOrWhiteSpace(i.Title));
        Assert.False(string.IsNullOrWhiteSpace(report.Summary));
    }

    [Fact]
    public void Alerts_EveryEntryIsNotable_BecauseTheJournalOnlyHoldsThingsWorthInterrupting()
    {
        var report = Adapters.Alerts(max: 50);

        Assert.All(report.Items, item => Assert.Equal(Severity.Notable, item.Severity));
    }

    [Fact]
    public void Alerts_ItemsCarryTheStructuredFieldsTheJsonContractExposes()
    {
        var report = Adapters.Alerts(max: 50);

        Assert.All(report.Items, item =>
        {
            Assert.True(item.Fields.ContainsKey("time"));
            Assert.True(item.Fields.ContainsKey("source"));
            Assert.True(item.Fields.ContainsKey("kind"));
            Assert.True(item.Fields.ContainsKey("detail"));
        });
    }

    /// <summary>
    /// Every journalled detection reaches the report, newest first, with nothing dropped and nothing
    /// reordered. The tests above read whatever the host machine recorded, so on a clean machine they
    /// pass over an empty list and prove nothing; this one supplies the journal.
    /// </summary>
    [Fact]
    public void Alerts_ShowsEveryRecordedDetection_NewestFirst()
    {
        var path = TempJournal();
        try
        {
            var start = new DateTimeOffset(2026, 7, 22, 2, 45, 22, TimeSpan.FromHours(2));
            var written = Enumerable.Range(0, 25)
                .Select(index => new SecurityAlert(
                    start.AddMinutes(index), "Guardian", "RunKey", $@"C:\Users\Public\entry-{index}.exe"))
                .ToArray();
            foreach (var alert in written)
            {
                AlertJournal.Append(alert, path);
            }

            var report = Adapters.Alerts(path, max: 200);

            Assert.Equal(written.Length, report.Items.Count);
            Assert.Equal(
                written.Reverse().Select(alert => alert.Detail),
                report.Items.Select(item => item.Fields["detail"]));
        }
        finally
        {
            Cleanup(path);
        }
    }

    /// <summary>
    /// The join the tray notification relies on: clicking a balloon opens the Alerts view and selects
    /// the row whose <c>time</c> field equals the round-trip stamp of the alert that raised it. If the
    /// adapter ever reformatted or truncated that stamp, the click would open the app on nothing and
    /// nothing else would fail, so the equality is pinned here rather than left to the UI.
    /// </summary>
    [Fact]
    public void Alerts_TimeField_MatchesTheRoundTripStampTheNotificationClickSelectsBy()
    {
        var path = TempJournal();
        try
        {
            // DateTimeOffset.Now is what the detection handlers stamp with: local offset, and whatever
            // sub-second precision the clock gave.
            var alert = new SecurityAlert(
                DateTimeOffset.Now, "Ransomware", "CanaryTouched", @"C:\Users\me\Desktop\decoy.xlsx");
            AlertJournal.Append(alert, path);

            var item = Assert.Single(Adapters.Alerts(path, max: 200).Items);

            Assert.Equal(
                alert.TimeUtc.ToString("O", CultureInfo.InvariantCulture),
                item.Fields["time"]);
        }
        finally
        {
            Cleanup(path);
        }
    }

    private static string TempJournal() =>
        Path.Combine(Path.GetTempPath(), $"wsg-alerts-adapter-{Guid.NewGuid():N}", "alerts.log");

    private static void Cleanup(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
