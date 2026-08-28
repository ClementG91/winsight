using WinSight.Application;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The distinction the dashboard could not previously draw: a protection that is running and
/// watching, one that is running and blind, and one that is off.
/// </summary>
/// <remarks>
/// Guardian, the camera/mic watch and the ransomware monitor all started inside a fire-and-forget
/// task whose failures were swallowed deliberately. The checkbox stayed ticked and the badge stayed
/// green, so a monitor that never came up rendered identically to a working one - in the one place
/// an operator actually looks. Every count needed to tell them apart already existed and nothing
/// read it.
/// </remarks>
public sealed class RealTimeProtectionHealthTests
{
    [Fact]
    public void WatchingEverythingItWasAskedToIsActive() =>
        Assert.Equal(
            ProtectionState.Active,
            MonitorHealth.For("x", enabled: true, armed: 12, requested: 12).State);

    /// <summary>
    /// Zero armed against a real request is a failure, not a partial: the monitor is on and sees
    /// nothing, which is exactly the case that used to look healthy.
    /// </summary>
    [Fact]
    public void RunningAndWatchingNothingIsAFailure() =>
        Assert.Equal(
            ProtectionState.Failed,
            MonitorHealth.For("x", enabled: true, armed: 0, requested: 12).State);

    [Fact]
    public void RunningAndWatchingSomeOfItIsPartial() =>
        Assert.Equal(
            ProtectionState.Partial,
            MonitorHealth.For("x", enabled: true, armed: 3, requested: 12).State);

    /// <summary>
    /// A watcher that armed everything and still dropped events was blind for an interval. That is a
    /// coverage gap, and the whole reason the ransomware watcher counts its overflows.
    /// </summary>
    [Fact]
    public void ArmedButHavingLostEventsIsPartial() =>
        Assert.Equal(
            ProtectionState.Partial,
            MonitorHealth.For("x", enabled: true, armed: 6, requested: 6, lostObservations: true).State);

    [Fact]
    public void NotRunningIsOffRatherThanFailed() =>
        Assert.Equal(
            ProtectionState.Off,
            MonitorHealth.For("x", enabled: false, armed: 0, requested: 12).State);

    /// <summary>A monitor asked to watch nothing is not failing to do anything.</summary>
    [Fact]
    public void NothingRequestedIsActive() =>
        Assert.Equal(
            ProtectionState.Active,
            MonitorHealth.For("x", enabled: true, armed: 0, requested: 0).State);

    /// <summary>
    /// The summary takes the weakest running monitor. Averaging would hide a dead one, which is the
    /// failure this whole type exists to remove.
    /// </summary>
    [Fact]
    public void TheSummaryIsTheWeakestRunningMonitor()
    {
        var health = new RealTimeProtectionHealth(
        [
            MonitorHealth.For("a", enabled: true, armed: 10, requested: 10),
            MonitorHealth.For("b", enabled: true, armed: 10, requested: 10),
            MonitorHealth.For("c", enabled: true, armed: 0, requested: 4),
        ]);

        Assert.Equal(ProtectionState.Failed, health.Overall);
        Assert.Equal(2, health.HealthyCount);
        Assert.Equal(3, health.RunningCount);
    }

    /// <summary>An operator who switched something off already knows; it must not read as a fault.</summary>
    [Fact]
    public void AMonitorTheOperatorTurnedOffDoesNotDragTheSummaryDown()
    {
        var health = new RealTimeProtectionHealth(
        [
            MonitorHealth.For("a", enabled: true, armed: 10, requested: 10),
            MonitorHealth.For("b", enabled: false, armed: 0, requested: 6),
        ]);

        Assert.Equal(ProtectionState.Active, health.Overall);
        Assert.Equal(1, health.RunningCount);
    }

    [Fact]
    public void NothingRunningAtAllIsOff() =>
        Assert.Equal(
            ProtectionState.Off,
            new RealTimeProtectionHealth(
                [MonitorHealth.For("a", enabled: false, armed: 0, requested: 3)]).Overall);

    [Fact]
    public void EachMonitorGetsALineNamingItsStateAndCoverage()
    {
        var lines = new RealTimeProtectionHealth(
        [
            MonitorHealth.For("Guardian", enabled: true, armed: 40, requested: 40),
            MonitorHealth.For("Ransomware", enabled: true, armed: 2, requested: 6),
            MonitorHealth.For("Camera/Mic", enabled: false, armed: 0, requested: 1),
        ]).Lines();

        Assert.Equal("Guardian: active - 40/40", lines[0]);
        Assert.Equal("Ransomware: partial - 2/6", lines[1]);
        Assert.Equal("Camera/Mic: off", lines[2]);
    }

    [Fact]
    public void ADroppedEventIsNamedInTheLine() =>
        Assert.Contains(
            "events were dropped",
            new RealTimeProtectionHealth(
            [
                MonitorHealth.For("Ransomware", enabled: true, armed: 6, requested: 6, lostObservations: true),
            ]).Lines()[0],
            StringComparison.Ordinal);
}
