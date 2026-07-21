using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The seam between the session that observes writes and the index that remembers them. Driven by
/// a scripted watcher, so the join — and the health reporting that says whether an empty answer
/// means "nothing wrote this" or "nobody was watching" — is exercised without Administrator.
/// </summary>
public sealed class AttributionHostTests
{
    private static readonly DateTimeOffset Noon = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);
    private const string RunKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void AnObservedWriteBecomesAnAnswer()
    {
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 4242, @"C:\tmp\dropper.exe", RunKey)]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        var attributed = host.Attribute($"{RunKey} [Updater]", Noon.AddSeconds(1));
        Assert.Equal(@"C:\tmp\dropper.exe", attributed?.ExecutablePath);
    }

    [Fact]
    public void HealthDistinguishesBlindFromIdle()
    {
        // The distinction the whole type exists for: "running and saw twelve it could not pin"
        // is a completely different message to an operator than "not watching at all".
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 1, @"C:\a.exe", RunKey)],
            misses:
            [
                new UnattributedWrite(Noon, 2, RunKey, UnattributedReason.UnknownProcess),
                new UnattributedWrite(Noon, 3, null, UnattributedReason.UnresolvedTarget),
                new UnattributedWrite(Noon, 4, null, UnattributedReason.UnresolvedTarget),
            ]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        var health = host.Health;
        Assert.Equal(1, health.Attributed);
        Assert.Equal(1, health.UnknownProcess);
        Assert.Equal(2, health.UnresolvedTarget);
        Assert.False(health.Refused);
    }

    [Fact]
    public void NotBeingElevatedIsRecordedAsARefusalNotAsSilence()
    {
        // Without this, "attribution is unavailable" and "nothing wrote to that key" are the same
        // empty answer, and an operator cannot tell a quiet machine from a monitor that never ran.
        var watcher = new ScriptedWatcher(refuse: true);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));
        SpinWait.SpinUntil(() => host.Health.Refused, TimeSpan.FromSeconds(5));

        Assert.True(host.Health.Refused);
        Assert.False(host.Health.Running);
        Assert.Null(host.Attribute(RunKey, Noon));
    }

    [Fact]
    public void AnUnwatchedTargetHasNoAnswer()
    {
        var watcher = new ScriptedWatcher(
            writes: [new WriteObservation(Noon, 1, @"C:\a.exe", @"HKLM\SOFTWARE\Something")]);
        using var host = new AttributionHost(watcher);

        host.Start();
        watcher.Delivered.Wait(TimeSpan.FromSeconds(5));

        Assert.Null(host.Attribute(RunKey, Noon.AddSeconds(1)));
    }

    [Fact]
    public void StartIsIdempotent()
    {
        var watcher = new ScriptedWatcher();
        using var host = new AttributionHost(watcher);

        host.Start();
        host.Start();

        Assert.True(watcher.Starts <= 1, $"Watch was started {watcher.Starts} times.");
    }

    [Fact]
    public void DisposeStopsTheWatchPromptly()
    {
        var watcher = new ScriptedWatcher(blockUntilCancelled: true);
        var host = new AttributionHost(watcher);
        host.Start();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        host.Dispose();
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"Dispose took {stopwatch.Elapsed}.");
    }

    [Fact]
    public void StartAfterDisposeDoesNothing()
    {
        var watcher = new ScriptedWatcher();
        var host = new AttributionHost(watcher);
        host.Dispose();

        host.Start();

        Assert.Equal(0, watcher.Starts);
    }

    private sealed class ScriptedWatcher(
        IReadOnlyList<WriteObservation>? writes = null,
        IReadOnlyList<UnattributedWrite>? misses = null,
        bool refuse = false,
        bool blockUntilCancelled = false) : IWriteWatcher
    {
        private int _starts;

        public int Starts => Volatile.Read(ref _starts);

        public ManualResetEventSlim Delivered { get; } = new();

        public void Watch(
            Action<WriteObservation> onWrite,
            Action<UnattributedWrite>? onUnattributed,
            CancellationToken token)
        {
            Interlocked.Increment(ref _starts);
            if (refuse)
            {
                Delivered.Set();
                throw new UnauthorizedAccessException("elevation required");
            }

            foreach (var write in writes ?? [])
            {
                onWrite(write);
            }
            foreach (var miss in misses ?? [])
            {
                onUnattributed?.Invoke(miss);
            }
            Delivered.Set();

            if (blockUntilCancelled)
            {
                token.WaitHandle.WaitOne();
            }
        }
    }
}
