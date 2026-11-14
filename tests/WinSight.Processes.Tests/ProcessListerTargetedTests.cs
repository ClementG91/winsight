using WinSight.Core;

using Xunit;

namespace WinSight.Processes.Tests;

public sealed class ProcessListerTargetedTests
{
    [Fact]
    public void TargetedSnapshotContainsOnlyTheCurrentProcessAndUsesTheInjectedVerifier()
    {
        var verifier = new RecordingVerifier();

        var snapshot = new ProcessLister(verifier).SnapshotForWithCoverage(Environment.ProcessId);

        var process = Assert.Single(snapshot.Items);
        Assert.Equal(Environment.ProcessId, process.Pid);
        Assert.True(snapshot.IsComplete);
        Assert.False(string.IsNullOrWhiteSpace(process.Name));
        Assert.NotNull(process.StartTimestampUtcTicks);
        Assert.Equal(1, verifier.BatchCalls);
        Assert.All(verifier.Paths, path => Assert.Equal(process.Path, path));
        Assert.Equal(process.Path is null ? SignatureState.Unknown : SignatureState.Unsigned, process.Signature.State);
    }

    [Fact]
    public void PrecancelledTargetedSnapshotPreservesTheTokenBeforeVerification()
    {
        var verifier = new RecordingVerifier();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var failure = Assert.Throws<OperationCanceledException>(() =>
            new ProcessLister(verifier).SnapshotForWithCoverage(Environment.ProcessId, cancellation.Token));

        Assert.Equal(cancellation.Token, failure.CancellationToken);
        Assert.Equal(0, verifier.BatchCalls);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void NegativeTargetedPidsAreRejectedBeforeVerification(int pid)
    {
        var verifier = new RecordingVerifier();

        var failure = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ProcessLister(verifier).SnapshotForWithCoverage(pid));

        Assert.Equal("pid", failure.ParamName);
        Assert.Equal(0, verifier.BatchCalls);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void CancellationPrecedesNegativePidValidation(int pid)
    {
        var verifier = new RecordingVerifier();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var failure = Assert.Throws<OperationCanceledException>(() =>
            new ProcessLister(verifier).SnapshotForWithCoverage(pid, cancellation.Token));

        Assert.Equal(cancellation.Token, failure.CancellationToken);
        Assert.Equal(0, verifier.BatchCalls);
    }

    private sealed class RecordingVerifier : ISignatureVerifier
    {
        internal int BatchCalls { get; private set; }
        internal IReadOnlyCollection<string> Paths { get; private set; } = [];

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) => SignatureVerdict.Unsigned;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BatchCalls++;
            Paths = paths.ToArray();
            return paths.ToDictionary(path => path, _ => SignatureVerdict.Unsigned, StringComparer.OrdinalIgnoreCase);
        }
    }
}
