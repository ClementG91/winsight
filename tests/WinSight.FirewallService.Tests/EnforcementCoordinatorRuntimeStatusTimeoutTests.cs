using System.Diagnostics;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class EnforcementCoordinatorRuntimeStatusTimeoutTests : IDisposable
{
    private static readonly TimeSpan VerificationDeadline = TimeSpan.FromMilliseconds(100);
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-runtime-status-timeout-{Guid.NewGuid():N}");

    [Fact]
    public async Task GetRuntimeStatusAsync_IgnoringCancellationVerifierTimesOutDegradedAndReleasesTransition()
    {
        var (coordinator, reconciler) = await CreateActiveCoordinatorAsync();
        await using var ownedCoordinator = coordinator;
        try
        {
            var elapsed = Stopwatch.StartNew();
            var statusTask = coordinator.GetRuntimeStatusAsync();
            await reconciler.RuntimeVerificationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

            var status = await statusTask.WaitAsync(
                VerificationDeadline + TimeSpan.FromMilliseconds(900));
            elapsed.Stop();

            Assert.True(elapsed.Elapsed < VerificationDeadline + TimeSpan.FromMilliseconds(900),
                $"Runtime status exceeded its bounded verification window: {elapsed.Elapsed}.");
            Assert.Equal(OutboundFirewallMode.Enforcement, status.Mode);
            Assert.Equal(FirewallEnforcementState.Degraded, status.EffectiveState);
            Assert.False(status.EnforcementEnabled);
            Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);

            // The timed-out read must not replay a transition or mutate the owned namespace.
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);
            Assert.Equal(2, reconciler.VerifyCalls);
            Assert.True(reconciler.RuntimeVerificationCancellationToken.IsCancellationRequested);

            // A queued operation proves the transition semaphore was released by the timeout.
            Assert.Equal(OutboundFirewallMode.Enforcement,
                await coordinator.GetModeAsync().WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);

            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.LateVerificationCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);
        }
        finally
        {
            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.LateVerificationCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task GetRuntimeStatusAsync_CallerCancellationIsRethrownAndFailsClosedWithoutReplay()
    {
        var (coordinator, reconciler) = await CreateActiveCoordinatorAsync();
        await using var ownedCoordinator = coordinator;
        try
        {
            using var cancellation = new CancellationTokenSource();
            var statusTask = coordinator.GetRuntimeStatusAsync(cancellation.Token);
            await reconciler.RuntimeVerificationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();

            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => statusTask);

            Assert.Equal(cancellation.Token, error.CancellationToken);
            Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);
            Assert.True(reconciler.RuntimeVerificationCancellationToken.IsCancellationRequested);

            // Cancellation cannot strand the read lock or trigger a compensating WFP replay.
            Assert.Equal(OutboundFirewallMode.Enforcement,
                await coordinator.GetModeAsync().WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);

            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.LateVerificationCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, reconciler.ReconcileCalls);
            Assert.Equal(0, reconciler.CleanupCalls);
        }
        finally
        {
            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.LateVerificationCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task DisposeAsync_OutstandingRuntimeVerificationReturnsPromptlyAndDefersSingleDisposal()
    {
        var (coordinator, reconciler) = await CreateActiveDisposableCoordinatorAsync();
        try
        {
            var statusTask = coordinator.GetRuntimeStatusAsync();
            await reconciler.RuntimeVerificationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

            var firstDispose = coordinator.DisposeAsync().AsTask();
            var concurrentDispose = coordinator.DisposeAsync().AsTask();
            var status = await statusTask.WaitAsync(
                VerificationDeadline + TimeSpan.FromMilliseconds(900));
            await Task.WhenAll(firstDispose, concurrentDispose).WaitAsync(TimeSpan.FromSeconds(1));

            Assert.Equal(FirewallEnforcementState.Degraded, status.EffectiveState);
            Assert.False(reconciler.ReleaseVerification.Task.IsCompleted);
            Assert.False(reconciler.AllRuntimeVerificationsCompleted.Task.IsCompleted);
            Assert.False(reconciler.Disposed.Task.IsCompleted);
            Assert.Equal(0, reconciler.DisposeCalls);
            Assert.False(reconciler.DisposedWhileVerificationInUse);

            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.AllRuntimeVerificationsCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await reconciler.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(1, reconciler.DisposeCalls);
            Assert.False(reconciler.DisposedWhileVerificationInUse);

            await coordinator.DisposeAsync();
            Assert.Equal(1, reconciler.DisposeCalls);
        }
        finally
        {
            reconciler.ReleaseVerification.TrySetResult();
            if (reconciler.RuntimeVerificationStarted.Task.IsCompleted)
            {
                await reconciler.AllRuntimeVerificationsCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
            await coordinator.DisposeAsync();
            await reconciler.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task GetRuntimeStatusAsync_RepeatedRecoveryDoesNotStartAnotherDetachedVerification()
    {
        var (coordinator, reconciler) = await CreateActiveDisposableCoordinatorAsync();
        try
        {
            var initialStatus = coordinator.GetRuntimeStatusAsync();
            await reconciler.RuntimeVerificationStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(FirewallEnforcementState.Degraded,
                (await initialStatus.WaitAsync(
                    VerificationDeadline + TimeSpan.FromMilliseconds(900))).EffectiveState);

            for (var attempt = 0; attempt < 3; attempt++)
            {
                await coordinator.ApplyBlocksAsync();
                Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);

                var recoveredStatus = await coordinator.GetRuntimeStatusAsync()
                    .WaitAsync(TimeSpan.FromSeconds(1));

                Assert.Equal(FirewallEnforcementState.Degraded, recoveredStatus.EffectiveState);
                Assert.False(recoveredStatus.EnforcementEnabled);
                Assert.Equal(1, reconciler.RuntimeVerificationCalls);
                Assert.Equal(1, reconciler.MaximumConcurrentRuntimeVerifications);
                Assert.False(reconciler.AllRuntimeVerificationsCompleted.Task.IsCompleted);
            }

            Assert.Equal(4, reconciler.ReconcileCalls);
            Assert.Equal(4, reconciler.TransitionVerificationCalls);
            Assert.Equal(0, reconciler.CleanupCalls);
        }
        finally
        {
            reconciler.ReleaseVerification.TrySetResult();
            await reconciler.AllRuntimeVerificationsCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await coordinator.DisposeAsync();
            await reconciler.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }

        Assert.Equal(1, reconciler.RuntimeVerificationCalls);
        Assert.Equal(1, reconciler.DisposeCalls);
        Assert.False(reconciler.DisposedWhileVerificationInUse);
    }

    [Fact]
    public async Task DisposeAsync_BlockingFailureIsSharedByConcurrentAndLateCallers()
    {
        var store = new FirewallPolicyStore(
            Path.Combine(_directory, $"failing-disposal-{Guid.NewGuid():N}.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly, []));
        var reconciler = new BlockingFailingAsyncDisposableReconciler();
        var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController(), VerificationDeadline);

        // AuditOnly startup initializes the lazy reconciler through its cleanup path.
        await coordinator.ApplyBlocksAsync();
        Assert.Equal(1, reconciler.CleanupCalls);

        Task? firstDispose = null;
        Task? concurrentDispose = null;
        try
        {
            firstDispose = coordinator.DisposeAsync().AsTask();
            await reconciler.DisposeEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(firstDispose.IsCompleted);

            concurrentDispose = coordinator.DisposeAsync().AsTask();
            Assert.False(concurrentDispose.IsCompleted);
            Assert.Equal(1, reconciler.DisposeCalls);

            reconciler.ReleaseDispose.TrySetResult();
            var firstFailure = await Assert.ThrowsAsync<IOException>(() => firstDispose);
            var concurrentFailure = await Assert.ThrowsAsync<IOException>(() => concurrentDispose);

            Assert.Same(reconciler.Failure, firstFailure);
            Assert.Same(firstFailure, concurrentFailure);
            Assert.Equal(1, reconciler.DisposeCalls);

            var lateFailure = await Assert.ThrowsAsync<IOException>(
                () => coordinator.DisposeAsync().AsTask());
            Assert.Same(firstFailure, lateFailure);
            Assert.Equal(1, reconciler.DisposeCalls);
        }
        finally
        {
            reconciler.ReleaseDispose.TrySetResult();
            if (firstDispose is not null)
                _ = await Record.ExceptionAsync(() => firstDispose);
            if (concurrentDispose is not null)
                _ = await Record.ExceptionAsync(() => concurrentDispose);
            if (reconciler.DisposeEntered.Task.IsCompleted)
                await reconciler.DisposeExited.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task GetRuntimeStatusAsync_VerifierIOExceptionPropagatesSameFailureAndFailsClosed()
    {
        var (coordinator, reconciler) = await CreateActiveFaultingCoordinatorAsync();
        await using var ownedCoordinator = coordinator;

        var failure = await Assert.ThrowsAsync<IOException>(() => coordinator.GetRuntimeStatusAsync());

        Assert.Same(reconciler.Failure, failure);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
        Assert.Equal(1, reconciler.ReconcileCalls);
        Assert.Equal(1, reconciler.TransitionVerificationCalls);
        Assert.Equal(1, reconciler.RuntimeVerificationCalls);
        Assert.Equal(0, reconciler.CleanupCalls);

        Assert.Equal(OutboundFirewallMode.Enforcement,
            await coordinator.GetModeAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(1, reconciler.ReconcileCalls);
        Assert.Equal(0, reconciler.CleanupCalls);
    }

    [Fact]
    public async Task GetRuntimeStatusAsync_CancellationAtFaultBoundaryAlwaysFailsClosedWithoutReplay()
    {
        using var cancellation = new CancellationTokenSource();
        var (coordinator, reconciler) = await CreateActiveFaultingCoordinatorAsync(cancellation.Cancel);
        await using var ownedCoordinator = coordinator;

        var failure = await Record.ExceptionAsync(
            () => coordinator.GetRuntimeStatusAsync(cancellation.Token));

        Assert.NotNull(failure);
        Assert.True(failure is OperationCanceledException || ReferenceEquals(reconciler.Failure, failure),
            $"Unexpected verification outcome: {failure.GetType().FullName}.");
        if (failure is IOException)
            Assert.Same(reconciler.Failure, failure);
        Assert.True(cancellation.IsCancellationRequested);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
        Assert.Equal(1, reconciler.ReconcileCalls);
        Assert.Equal(1, reconciler.TransitionVerificationCalls);
        Assert.Equal(1, reconciler.RuntimeVerificationCalls);
        Assert.Equal(0, reconciler.CleanupCalls);

        Assert.Equal(OutboundFirewallMode.Enforcement,
            await coordinator.GetModeAsync().WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(1, reconciler.ReconcileCalls);
        Assert.Equal(0, reconciler.CleanupCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(60_001)]
    public void Constructor_InvalidStatusVerificationTimeout_IsRejected(int milliseconds)
    {
        var store = new FirewallPolicyStore(
            Path.Combine(_directory, $"invalid-timeout-{milliseconds}.json"), allowEnforcement: true);

        Assert.Throws<ArgumentOutOfRangeException>(() => new EnforcementCoordinator(
            store,
            new IgnoringCancellationRuntimeVerifier(),
            new RecordingStartModeController(),
            TimeSpan.FromMilliseconds(milliseconds)));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private async Task<(EnforcementCoordinator Coordinator, IgnoringCancellationRuntimeVerifier Reconciler)>
        CreateActiveCoordinatorAsync()
    {
        var store = new FirewallPolicyStore(
            Path.Combine(_directory, $"policies-{Guid.NewGuid():N}.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var reconciler = new IgnoringCancellationRuntimeVerifier();
        var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController(), VerificationDeadline);
        await coordinator.EnableEnforcementAsync();
        return (coordinator, reconciler);
    }

    private async Task<(EnforcementCoordinator Coordinator, DisposableBlockingRuntimeVerifier Reconciler)>
        CreateActiveDisposableCoordinatorAsync()
    {
        var store = new FirewallPolicyStore(
            Path.Combine(_directory, $"disposable-policies-{Guid.NewGuid():N}.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var reconciler = new DisposableBlockingRuntimeVerifier();
        var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController(), VerificationDeadline);
        await coordinator.EnableEnforcementAsync();
        return (coordinator, reconciler);
    }

    private async Task<(EnforcementCoordinator Coordinator, FaultingRuntimeVerifier Reconciler)>
        CreateActiveFaultingCoordinatorAsync(Action? onRuntimeVerification = null)
    {
        var store = new FirewallPolicyStore(
            Path.Combine(_directory, $"faulting-policies-{Guid.NewGuid():N}.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\blocked.exe", OutboundAction.Block)]));
        var reconciler = new FaultingRuntimeVerifier(onRuntimeVerification);
        var coordinator = new EnforcementCoordinator(
            store, reconciler, new RecordingStartModeController(), VerificationDeadline);
        await coordinator.EnableEnforcementAsync();
        return (coordinator, reconciler);
    }

    /// <summary>
    /// Models an uninterruptible native enumeration: after the enable verification succeeds,
    /// runtime verification deliberately ignores the supplied cancellation token until the test
    /// releases it. No reconciliation or cleanup occurs in the verifier itself.
    /// </summary>
    private sealed class IgnoringCancellationRuntimeVerifier : IWinSightWfpReconciler
    {
        private int _verifyCalls;

        public TaskCompletionSource RuntimeVerificationStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseVerification { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource LateVerificationCompleted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken RuntimeVerificationCancellationToken { get; private set; }
        public int ReconcileCalls { get; private set; }
        public int CleanupCalls { get; private set; }
        public int VerifyCalls => Volatile.Read(ref _verifyCalls);
        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReconcileCalls++;
            return Task.CompletedTask;
        }

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _verifyCalls) == 1) return Task.FromResult(true);
            RuntimeVerificationCancellationToken = cancellationToken;
            RuntimeVerificationStarted.TrySetResult();
            return CompleteAfterExplicitReleaseAsync();
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupCalls++;
            return Task.CompletedTask;
        }

        private async Task<bool> CompleteAfterExplicitReleaseAsync()
        {
            await ReleaseVerification.Task;
            LateVerificationCompleted.TrySetResult();
            return true;
        }
    }

    private sealed class DisposableBlockingRuntimeVerifier : IWinSightWfpReconciler, IAsyncDisposable
    {
        private readonly object _verificationLock = new();
        private int _transitionVerificationsDue;
        private int _activeRuntimeVerifications;
        private int _maximumConcurrentRuntimeVerifications;
        private int _runtimeVerificationCalls;
        private int _disposeCalls;
        private int _disposedWhileVerificationInUse;

        public TaskCompletionSource RuntimeVerificationStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseVerification { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AllRuntimeVerificationsCompleted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Disposed { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ReconcileCalls { get; private set; }
        public int TransitionVerificationCalls { get; private set; }
        public int CleanupCalls { get; private set; }
        public int RuntimeVerificationCalls => Volatile.Read(ref _runtimeVerificationCalls);
        public int MaximumConcurrentRuntimeVerifications =>
            Volatile.Read(ref _maximumConcurrentRuntimeVerifications);
        public int DisposeCalls => Volatile.Read(ref _disposeCalls);
        public bool DisposedWhileVerificationInUse =>
            Volatile.Read(ref _disposedWhileVerificationInUse) != 0;
        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_verificationLock)
            {
                ReconcileCalls++;
                _transitionVerificationsDue++;
            }
            return Task.CompletedTask;
        }

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            lock (_verificationLock)
            {
                if (_transitionVerificationsDue > 0)
                {
                    _transitionVerificationsDue--;
                    TransitionVerificationCalls++;
                    return Task.FromResult(true);
                }
            }

            Interlocked.Increment(ref _runtimeVerificationCalls);
            var active = Interlocked.Increment(ref _activeRuntimeVerifications);
            UpdateMaximumConcurrentRuntimeVerifications(active);
            RuntimeVerificationStarted.TrySetResult();
            return CompleteRuntimeVerificationAfterReleaseAsync();
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupCalls++;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            if (Volatile.Read(ref _activeRuntimeVerifications) != 0)
                Interlocked.Exchange(ref _disposedWhileVerificationInUse, 1);
            Interlocked.Increment(ref _disposeCalls);
            Disposed.TrySetResult();
            return ValueTask.CompletedTask;
        }

        private async Task<bool> CompleteRuntimeVerificationAfterReleaseAsync()
        {
            try
            {
                await ReleaseVerification.Task;
                return true;
            }
            finally
            {
                if (Interlocked.Decrement(ref _activeRuntimeVerifications) == 0)
                    AllRuntimeVerificationsCompleted.TrySetResult();
            }
        }

        private void UpdateMaximumConcurrentRuntimeVerifications(int active)
        {
            var observed = Volatile.Read(ref _maximumConcurrentRuntimeVerifications);
            while (active > observed)
            {
                var previous = Interlocked.CompareExchange(
                    ref _maximumConcurrentRuntimeVerifications, active, observed);
                if (previous == observed) return;
                observed = previous;
            }
        }
    }

    private sealed class BlockingFailingAsyncDisposableReconciler : IWinSightWfpReconciler, IAsyncDisposable
    {
        private int _disposeCalls;

        public TaskCompletionSource DisposeEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDispose { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource DisposeExited { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IOException Failure { get; } = new("synthetic reconciler disposal failure");
        public int CleanupCalls { get; private set; }
        public int DisposeCalls => Volatile.Read(ref _disposeCalls);
        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupCalls++;
            return Task.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref _disposeCalls);
            DisposeEntered.TrySetResult();
            await ReleaseDispose.Task;
            DisposeExited.TrySetResult();
            throw Failure;
        }
    }

    private sealed class FaultingRuntimeVerifier(Action? onRuntimeVerification) : IWinSightWfpReconciler
    {
        private int _transitionVerificationsDue;

        public IOException Failure { get; } = new("synthetic runtime verification failure");
        public int ReconcileCalls { get; private set; }
        public int TransitionVerificationCalls { get; private set; }
        public int RuntimeVerificationCalls { get; private set; }
        public int CleanupCalls { get; private set; }
        public bool IsSupported => true;

        public Task ReconcileExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReconcileCalls++;
            _transitionVerificationsDue++;
            return Task.CompletedTask;
        }

        public Task<bool> VerifyExactAsync(
            IReadOnlyList<AppFirewallPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            if (_transitionVerificationsDue > 0)
            {
                _transitionVerificationsDue--;
                TransitionVerificationCalls++;
                return Task.FromResult(true);
            }

            RuntimeVerificationCalls++;
            onRuntimeVerification?.Invoke();
            return Task.FromException<bool>(Failure);
        }

        public Task CleanupAllAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupCalls++;
            return Task.CompletedTask;
        }
    }
}
