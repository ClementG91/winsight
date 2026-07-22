using WinSight.Core;
using WinSight.Modules;

using Xunit;

namespace WinSight.Modules.Tests;

/// <summary>
/// Reading the modules of one process without walking every process on the machine.
/// </summary>
/// <remarks>
/// The per-process drill-down needs one process's modules. The only entry point was a full sweep —
/// measured at 57 seconds and 14 253 modules across 222 processes on a real desktop — which is a
/// perfectly good answer to a different question and an unusable one here: a view opened on a single
/// pid cannot cost a minute. This is that entry point, and these tests hold it to returning exactly
/// the process asked for.
/// </remarks>
public sealed class SingleProcessSnapshotTests
{
    private sealed class StubVerifier : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            SignatureVerdict.Unknown;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            paths.ToDictionary(path => path, _ => SignatureVerdict.Unknown, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReadsTheModulesOfTheRequestedProcess()
    {
        // The test host is a running process with modules loaded, so it is the one process that is
        // guaranteed to be there whatever else the machine is doing.
        var modules = new ModuleLister(new StubVerifier()).SnapshotFor(Environment.ProcessId);

        Assert.NotEmpty(modules);
        Assert.All(modules, module => Assert.Equal(Environment.ProcessId, module.Pid));
    }

    [Fact]
    public void ReturnsNothingForAProcessThatIsNotRunning()
    {
        // A drill-down is often opened on a pid that has just exited — that is precisely the
        // interesting case — so it must answer "nothing", not throw.
        var modules = new ModuleLister(new StubVerifier()).SnapshotFor(pid: -1);

        Assert.Empty(modules);
    }

    [Fact]
    public void NeverReportsModulesBelongingToAnotherProcess()
    {
        var modules = new ModuleLister(new StubVerifier()).SnapshotFor(Environment.ProcessId);

        Assert.DoesNotContain(modules, module => module.Pid != Environment.ProcessId);
    }

    [Fact]
    public void HonoursCancellationBeforeDoingAnyWork()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.Throws<OperationCanceledException>(
            () => new ModuleLister(new StubVerifier()).SnapshotFor(Environment.ProcessId, cancelled.Token));
    }

    [Fact]
    public void EveryReportedModuleCarriesTheHostProcessName()
    {
        // The drill-down renders the host name beside the module; an empty one would read as a
        // module loaded into nothing.
        var modules = new ModuleLister(new StubVerifier()).SnapshotFor(Environment.ProcessId);

        Assert.All(modules, module => Assert.False(string.IsNullOrWhiteSpace(module.ProcessName)));
    }
}
