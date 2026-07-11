using WinSight.Core;
using Xunit;

namespace WinSight.Modules.Tests;

/// <summary>
/// Integration coverage: the test host itself always has DLLs loaded (coreclr, the
/// test framework, etc.), so a snapshot must include this process with a well-formed
/// module list. Uses a stub verifier for speed/determinism, plus one real-verifier
/// smoke run to exercise the native Authenticode path on Windows.
/// </summary>
public sealed class ModuleListerIntegrationTests
{
    [Fact]
    public void Snapshot_IncludesCurrentProcessModules_WithValidShape()
    {
        var stub = new StubVerifier();
        var modules = new ModuleLister(stub).Snapshot();

        Assert.NotEmpty(modules);
        Assert.True(stub.Called);

        var self = System.Environment.ProcessId;
        var mine = modules.Where(m => m.Pid == self).ToList();
        Assert.NotEmpty(mine);
        Assert.All(mine, m =>
        {
            Assert.True(m.Pid > 0);
            Assert.False(string.IsNullOrWhiteSpace(m.ProcessName));
            Assert.False(string.IsNullOrWhiteSpace(m.ModuleName));
        });
    }

    [Fact]
    public void Snapshot_RealVerifier_RunsAndReturnsModules()
    {
        // Exercises the true native signature path over real loaded DLLs.
        var modules = new ModuleLister().Snapshot();
        Assert.NotEmpty(modules);
    }

    private sealed class StubVerifier : ISignatureVerifier
    {
        public bool Called { get; private set; }

        public SignatureVerdict Verify(string path) => SignatureVerdict.Unsigned;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths)
        {
            Called = true;
            var map = new Dictionary<string, SignatureVerdict>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var p in paths)
            {
                map[p] = SignatureVerdict.SignedTrusted;
            }
            return map;
        }
    }
}
