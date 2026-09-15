using WinSight.Application;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class GuardianHealthTests
{
    [Fact]
    public void AFailedStartIsFailedNotOff()
    {
        Assert.Equal(ProtectionState.Failed, GuardianHost.Health(started: false, startFailed: true, (0, 0)).State);
        Assert.Equal(ProtectionState.Failed, GuardianHost.Health(started: false, startFailed: true, (20, 20)).State);
    }

    [Fact]
    public void AStartStillScanningIsNotYetClaimedAsActive()
    {
        Assert.Equal(ProtectionState.Off, GuardianHost.Health(started: false, startFailed: false, (20, 0)).State);
    }

    [Fact]
    public void AnUndeliveredArrivalOrUnrecoveredFailureMakesARunningGuardianPartial()
    {
        var degraded = new WinSight.Persistence.PersistenceMonitorDiagnostics(1, 0, 3, 0, false, true, false, null)
        {
            IsDegraded = true,
        };
        var health = GuardianHost.Health(started: true, startFailed: false, (20, 20), degraded);
        Assert.Equal(ProtectionState.Partial, health.State);
        Assert.True(health.LostObservations);

        var recovered = degraded with { IsDegraded = false };
        Assert.Equal(ProtectionState.Active, GuardianHost.Health(true, false, (20, 20), recovered).State);
    }

    [Fact]
    public void AFaultAlertIsBoundedSingleLineAndNamesTheOperation()
    {
        var fault = new WinSight.Persistence.PersistenceMonitorFault(
            WinSight.Persistence.PersistenceMonitorOperation.Notification,
            new InvalidOperationException("line one\nline two " + new string('x', 500)),
            DateTimeOffset.UtcNow);

        var alert = GuardianHost.FaultAlert(fault);

        Assert.Equal("MonitorFault", alert.Kind);
        Assert.StartsWith("Notification: InvalidOperationException: line one line two", alert.Detail);
        Assert.DoesNotContain('\n', alert.Detail);
        Assert.True(alert.Detail.Length < 400);
    }

    [Fact]
    public void TheDiagnosticsLineNamesPendingAlertsFaultsAndUnlistedArrivalsAndIsAbsentWhenHealthy()
    {
        var healthy = new WinSight.Persistence.PersistenceMonitorDiagnostics(0, 2, 1, 0, false, false, false,
            new WinSight.Persistence.PersistenceMonitorFault(WinSight.Persistence.PersistenceMonitorOperation.Scan,
                new IOException("old"), DateTimeOffset.UtcNow));
        Assert.Null(GuardianHost.DiagnosticsLine(healthy)); // recovered faults are history, not status
        Assert.False(GuardianHost.CanRetry(healthy));

        var stuck = healthy with
        {
            PendingNotifications = 2,
            AutomaticRetriesExhausted = true,
            LastFault = new WinSight.Persistence.PersistenceMonitorFault(
                WinSight.Persistence.PersistenceMonitorOperation.Notification,
                new InvalidOperationException("x"), DateTimeOffset.UtcNow),
            IsDegraded = true,
            UnlistedArrivals = 3,
        };
        var line = GuardianHost.DiagnosticsLine(stuck);
        Assert.Equal("Guardian: 2 undelivered alert(s), automatic retries stopped; last fault Notification: InvalidOperationException; 3 arrival(s) reported but not kept in the in-app list", line);
        Assert.True(GuardianHost.CanRetry(stuck));
    }

    [Theory]
    [InlineData(20, 20, ProtectionState.Active)]
    [InlineData(20, 17, ProtectionState.Partial)]
    [InlineData(20, 0, ProtectionState.Failed)]
    public void AStartedMonitorReflectsWhatItArmed(int requested, int armed, ProtectionState expected)
    {
        Assert.Equal(expected, GuardianHost.Health(started: true, startFailed: false, (requested, armed)).State);
    }
}
