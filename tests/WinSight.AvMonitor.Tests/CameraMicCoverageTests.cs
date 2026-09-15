using WinSight.Core;
using Xunit;

namespace WinSight.AvMonitor.Tests;

public sealed class CameraMicCoverageTests
{
    private static readonly DeviceUsage InUse = new(DeviceKind.Microphone, "recorder", false,
        DateTime.UtcNow, null, true);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GapsDoNotSynthesizeDeactivationOrLoseTheLastBaseline(bool throwDuringGap)
    {
        var reader = new ScriptedReader(
            new AcquisitionSnapshot<DeviceUsage>([InUse]),
            throwDuringGap ? null : new AcquisitionSnapshot<DeviceUsage>([], unreadableItems: 1),
            new AcquisitionSnapshot<DeviceUsage>([InUse]),
            new AcquisitionSnapshot<DeviceUsage>([]));
        var events = Watch(reader);
        var stopped = Assert.Single(events);
        Assert.Equal(AvEventKind.Deactivated, stopped.Kind);
        Assert.Equal(1, reader.Gaps);
    }

    [Fact]
    public void IncompleteStartupDoesNotPretendToEstablishAnEmptyBaseline()
    {
        var reader = new ScriptedReader(null,
            new AcquisitionSnapshot<DeviceUsage>([InUse]),
            new AcquisitionSnapshot<DeviceUsage>([InUse]));
        Assert.Empty(Watch(reader));
        Assert.Equal(1, reader.Gaps);
    }

    [Fact]
    public void PersistentPartialCoverageStillReportsNewVisibleActivationsWithoutFalseStops()
    {
        var second = InUse with { App = "second-recorder" };
        var reader = new ScriptedReader(
            new AcquisitionSnapshot<DeviceUsage>([InUse], unreadableSources: 1),
            new AcquisitionSnapshot<DeviceUsage>([second], unreadableSources: 1),
            new AcquisitionSnapshot<DeviceUsage>([second], unreadableSources: 1),
            new AcquisitionSnapshot<DeviceUsage>([InUse, second]));
        var activation = Assert.Single(Watch(reader));
        Assert.Equal(AvEventKind.Activated, activation.Kind);
        Assert.Equal("second-recorder", activation.Usage.App);
    }

    [Fact]
    public void ARestartIsReportedWhileAnotherSourceStaysUnreadable()
    {
        // A count-only reader: the stop cannot be attributed to a store, so it is not announced while
        // coverage is partial, but carrying the old active record must not swallow the next start.
        var started = DateTime.UtcNow.AddMinutes(-2);
        var first = InUse with { LastStart = started };
        var stopped = first with { LastStop = started.AddMinutes(1), Active = false };
        var again = first with { LastStart = started.AddMinutes(2) };
        var reader = new ScriptedReader(
            new AcquisitionSnapshot<DeviceUsage>([first], unreadableSources: 1),
            new AcquisitionSnapshot<DeviceUsage>([stopped], unreadableSources: 1),
            new AcquisitionSnapshot<DeviceUsage>([again], unreadableSources: 1));

        var events = Watch(reader);

        Assert.Equal([AvEventKind.Activated], events.Select(e => e.Kind));
    }

    [Fact]
    public void ARestartBetweenTwoPollsIsStillAnActivation()
    {
        var started = DateTime.UtcNow.AddMinutes(-2);
        var reader = new ScriptedReader(
            new AcquisitionSnapshot<DeviceUsage>([InUse with { LastStart = started }]),
            new AcquisitionSnapshot<DeviceUsage>([InUse with { LastStart = started.AddSeconds(30) }]));

        Assert.Equal(AvEventKind.Activated, Assert.Single(Watch(reader)).Kind);
    }

    [Fact]
    public void WithoutProvenanceAPartialStopIsNotAnnounced()
    {
        // The counter-review probe: active in a complete read, then stopped while another source
        // is unreadable. Nothing establishes that no store still records the capture.
        var active = InUse with { LastStart = new DateTime(2026, 9, 14, 1, 0, 0, DateTimeKind.Utc) };
        var reader = new ScriptedReader(
            new AcquisitionSnapshot<DeviceUsage>([active]),
            new AcquisitionSnapshot<DeviceUsage>([active with { Active = false, LastStop = active.LastStart!.Value.AddMinutes(1) }],
                unreadableSources: 1));

        Assert.Empty(Watch(reader));
    }

    private static readonly DateTime T1 = new(2026, 9, 14, 1, 0, 0, DateTimeKind.Utc);

    private static DeviceUsage Cam(CapabilityStore store, bool active, DateTime? start = null) =>
        new(DeviceKind.Webcam, "same-app", true, start ?? T1, active ? null : (start ?? T1).AddMinutes(1), active)
        {
            Store = store,
        };

    private static CapabilityAccessSnapshot Read(IReadOnlyList<DeviceUsage> items, params CapabilityGap[] gaps) =>
        new(items, gaps);

    private static readonly CapabilityGap UserWebcam = new(DeviceKind.Webcam, CapabilityStore.CurrentUser);
    private static readonly CapabilityGap MachineWebcam = new(DeviceKind.Webcam, CapabilityStore.LocalMachine);

    [Fact]
    public void ActiveInOneStoreAndStoppedInTheOtherSurvivesLosingAndRegainingTheActiveStore()
    {
        var events = WatchProvenance(
            Read([Cam(CapabilityStore.CurrentUser, true), Cam(CapabilityStore.LocalMachine, false)]),
            Read([Cam(CapabilityStore.LocalMachine, false)], UserWebcam),      // active store lost
            Read([Cam(CapabilityStore.CurrentUser, true), Cam(CapabilityStore.LocalMachine, false)]), // regained
            Read([Cam(CapabilityStore.LocalMachine, false)], UserWebcam),      // lost again
            Read([Cam(CapabilityStore.CurrentUser, false), Cam(CapabilityStore.LocalMachine, false)])); // real stop

        Assert.Equal([AvEventKind.Deactivated], events.Select(e => e.Kind));
    }

    [Fact]
    public void LosingTheStoppedStoreNeverSynthesizesAStopOrAStart()
    {
        var events = WatchProvenance(
            Read([Cam(CapabilityStore.CurrentUser, true), Cam(CapabilityStore.LocalMachine, false)]),
            Read([Cam(CapabilityStore.CurrentUser, true)], MachineWebcam),
            Read([Cam(CapabilityStore.CurrentUser, true), Cam(CapabilityStore.LocalMachine, false)]));

        Assert.Empty(events);
    }

    [Fact]
    public void ARestartInTheReadableStoreIsReportedWhileTheOtherActiveStoreIsHidden()
    {
        var restart = T1.AddMinutes(10);
        var events = WatchProvenance(
            Read([Cam(CapabilityStore.LocalMachine, true), Cam(CapabilityStore.CurrentUser, false)]),
            Read([Cam(CapabilityStore.CurrentUser, false)], MachineWebcam),
            Read([Cam(CapabilityStore.CurrentUser, true, restart)], MachineWebcam),
            Read([Cam(CapabilityStore.CurrentUser, true, restart), Cam(CapabilityStore.LocalMachine, true)]));

        var activation = Assert.Single(events);
        Assert.Equal(AvEventKind.Activated, activation.Kind);
        Assert.Equal(restart, activation.Usage.LastStart);
    }

    [Fact]
    public void AStopObservedWithEvidenceIsReportedDespiteAnUnrelatedGap()
    {
        var unrelated = new CapabilityGap(DeviceKind.Microphone, CapabilityStore.LocalMachine);
        var appKeyElsewhere = new CapabilityGap(DeviceKind.Webcam, CapabilityStore.LocalMachine, "other-app", Packaged: true);
        var events = WatchProvenance(
            Read([Cam(CapabilityStore.CurrentUser, true)]),
            Read([Cam(CapabilityStore.CurrentUser, false)], unrelated, appKeyElsewhere),
            Read([Cam(CapabilityStore.CurrentUser, true, T1.AddMinutes(5))], unrelated));

        Assert.Equal([AvEventKind.Deactivated, AvEventKind.Activated], events.Select(e => e.Kind));
    }

    [Fact]
    public void AnUnreadableAppKeyHidesOnlyThatApp()
    {
        var other = Cam(CapabilityStore.CurrentUser, true) with { App = "other-app" };
        var appGap = new CapabilityGap(DeviceKind.Webcam, CapabilityStore.CurrentUser, "SAME-APP", Packaged: true);
        var events = WatchProvenance(
            Read([Cam(CapabilityStore.CurrentUser, true), other]),
            Read([], appGap));

        var stopped = Assert.Single(events);
        Assert.Equal((AvEventKind.Deactivated, "other-app"), (stopped.Kind, stopped.Usage.App));
    }

    private static List<DeviceEvent> WatchProvenance(params CapabilityAccessSnapshot[] reads)
    {
        using var stop = new CancellationTokenSource();
        var reader = new ProvenanceReader(reads, stop);
        var events = new List<DeviceEvent>();
        new CameraMicMonitor(reader, TimeSpan.Zero).Watch(events.Add, stop.Token);
        return events;
    }

    private sealed class ProvenanceReader(CapabilityAccessSnapshot[] reads, CancellationTokenSource stop) : ICapabilityAccessReader
    {
        private int _next;
        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() => ReadWithProvenance().ToCoverage();
        public CapabilityAccessSnapshot ReadWithProvenance()
        {
            var read = reads[_next++];
            if (_next == reads.Length)
            {
                stop.Cancel();
            }
            return read;
        }
    }

    private static List<DeviceEvent> Watch(ScriptedReader reader)
    {
        using var stop = new CancellationTokenSource();
        var events = new List<DeviceEvent>();
        new CameraMicMonitor(reader, TimeSpan.Zero).Watch(events.Add, stop.Token, snapshot =>
        {
            if (!snapshot.IsComplete)
            {
                reader.Gaps++;
            }
            if (reader.Finished)
            {
                stop.Cancel();
            }
        });
        return events;
    }

    private sealed class ScriptedReader(params AcquisitionSnapshot<DeviceUsage>?[] snapshots) : ICapabilityAccessReader
    {
        private int _next;
        internal bool Finished => _next == snapshots.Length;
        internal int Gaps { get; set; }
        public AcquisitionSnapshot<DeviceUsage> ReadWithCoverage() =>
            snapshots[_next++] ?? throw new UnauthorizedAccessException();
    }
}
