using WinSight.Core;
using Xunit;

namespace WinSight.Processes.Tests;

/// <summary>
/// Integration coverage: on a real Windows host there is always at least the test
/// runner itself running, so a snapshot must never be empty and every entry must be
/// well-formed. Signature plumbing is injected so WMI/process coverage stays fast;
/// the real Authenticode chain has dedicated integration tests in Core/Persistence.
/// </summary>
public sealed class ProcessListerIntegrationTests
{
    [Fact]
    public void Snapshot_ReturnsRunningProcesses_WithValidShape()
    {
        var processes = new ProcessLister(new StubVerifier()).Snapshot();

        Assert.NotEmpty(processes);
        Assert.All(processes, p =>
        {
            Assert.True(p.Pid >= 0);
            Assert.False(string.IsNullOrWhiteSpace(p.Name));
            // A resolvable image gets a real verdict; a protected/system image stays Missing.
            if (p.Path is null)
            {
                Assert.Equal(SignatureState.Missing, p.Signature.State);
            }
        });

        // The current test process must be in the snapshot with a resolvable, signed-or-known image.
        var self = System.Environment.ProcessId;
        Assert.Contains(processes, p => p.Pid == self);
    }

    [Fact]
    public void Snapshot_SharesInjectedVerifier()
    {
        // A stub verifier proves the lister honours DI (no accidental hard-wiring to native).
        var stub = new StubVerifier();
        var processes = new ProcessLister(stub).Snapshot();

        Assert.NotEmpty(processes);
        Assert.True(stub.Called);
    }

    private sealed class StubVerifier : ISignatureVerifier
    {
        public bool Called { get; private set; }

        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) => SignatureVerdict.Unsigned;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            Called = true;
            var map = new Dictionary<string, SignatureVerdict>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var p in paths)
            {
                map[p] = SignatureVerdict.Unsigned;
            }
            return map;
        }
    }
}
