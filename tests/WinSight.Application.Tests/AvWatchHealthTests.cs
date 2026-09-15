using WinSight.AvMonitor;
using WinSight.Core;
using Xunit;

namespace WinSight.Application.Tests;

public sealed class AvWatchHealthTests
{
    [Fact]
    public void ReaderFaultIsFailedInsteadOfActive()
    {
        using var host = new AvWatchHost(new CameraMicMonitor(new FaultingReader()));
        host.Start();
        Assert.True(SpinWait.SpinUntil(() => host.Status.Failure is not null, TimeSpan.FromSeconds(5)));
        Assert.False(host.Status.IsRunning);
        Assert.IsType<InvalidOperationException>(host.Status.Failure);
        Assert.Equal(ProtectionState.Failed, host.Health(enabled: true).State);
    }

    [Fact]
    public void CurrentCoverageIsReflectedAndRecoversAfterReadFailures()
    {
        var reader = new MutableReader();
        using var host = new AvWatchHost(new CameraMicMonitor(reader, TimeSpan.FromMilliseconds(10)));
        host.Start();
        WaitFor(ProtectionState.Active);
        reader.Snapshot = new AcquisitionSnapshot<DeviceUsage>([], unreadableSources: 1);
        WaitFor(ProtectionState.Partial);
        Assert.Equal(3, host.Health(true).Armed);
        reader.Snapshot = new AcquisitionSnapshot<DeviceUsage>([], unreadableItems: 1);
        Assert.True(SpinWait.SpinUntil(() => host.Health(true).LostObservations, TimeSpan.FromSeconds(5)));
        reader.Snapshot = null; // transient access failure
        WaitFor(ProtectionState.Failed);
        Assert.True(host.Status.IsRunning);
        Assert.Null(host.Status.Failure);
        reader.Snapshot = new AcquisitionSnapshot<DeviceUsage>([]);
        WaitFor(ProtectionState.Active);
        host.Dispose();
        Assert.False(host.Status.IsRunning);
        Assert.Equal(ProtectionState.Failed, host.Health(true).State);
        Assert.Equal(ProtectionState.Off, host.Health(false).State);

        void WaitFor(ProtectionState state) => Assert.True(SpinWait.SpinUntil(
            () => host.Health(true).State == state, TimeSpan.FromSeconds(5)), $"Expected {state}");
    }

    private sealed class FaultingReader : ICapabilityAccessReader
    {
        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() => throw new InvalidOperationException("reader fault");
    }

    private sealed class MutableReader : ICapabilityAccessReader
    {
        private AcquisitionSnapshot<DeviceUsage>? _snapshot = new([]);
        internal AcquisitionSnapshot<DeviceUsage>? Snapshot
        {
            set => Volatile.Write(ref _snapshot, value);
        }
        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() =>
            Volatile.Read(ref _snapshot) ?? throw new UnauthorizedAccessException();
    }
}
