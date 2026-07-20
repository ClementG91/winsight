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
}
