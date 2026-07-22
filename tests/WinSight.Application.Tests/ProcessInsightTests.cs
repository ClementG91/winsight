using WinSight.Application;
using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The per-process pivot: everything WinSight already knows about one process, in one place.
/// </summary>
/// <remarks>
/// The parity plan called this "UI work, not detection work". Half of that is right — the data is
/// already gathered by the processes, modules and connections scanners. The other half is not: the
/// join itself makes decisions (what counts as this process's parent, what is worth surfacing out of
/// two thousand loaded modules, what to do when the snapshots disagree) and every one of those can be
/// wrong in a way that misnames something. So the pivot is a pure function over three snapshots,
/// tested here, and the view that renders it stays a thin edge.
/// </remarks>
public sealed class ProcessInsightTests
{
    private static readonly SignatureVerdict Trusted = new(SignatureState.SignedTrusted, "CN=Contoso");
    private static readonly SignatureVerdict Unsigned = SignatureVerdict.Unsigned;

    private static ProcessInfo Process(
        int pid, string name = "app.exe", int parentPid = 100, SignatureVerdict? signature = null) =>
        new(pid, name, $@"C:\Program Files\App\{name}", parentPid, $"{name} --run", signature ?? Trusted);

    private static LoadedModule Module(
        int pid, string name, SignatureVerdict? signature = null, string? path = null) =>
        new(pid, "app.exe", name, path ?? $@"C:\Windows\System32\{name}", signature ?? Trusted);

    private static Connection Conn(
        int pid, string remote = "93.184.216.34:443", string state = "ESTABLISHED") =>
        new("TCP", "10.0.0.5:51000", remote, state, pid, "app.exe", @"C:\Program Files\App\app.exe", Trusted);

    // ---- Identity: a missing process is not an empty one -------------------------------------

    /// <summary>
    /// A pid nobody reported yields null, never a hollow insight.
    /// </summary>
    /// <remarks>
    /// An empty record would render as a process that exists and has no modules and no connections —
    /// a confident description of something that is not running. "I have never heard of this pid" and
    /// "this pid is idle" are different answers and the caller must be able to tell them apart.
    /// </remarks>
    [Fact]
    public void AnUnknownPidYieldsNothingRatherThanAnEmptyInsight()
        => Assert.Null(ProcessInsightBuilder.Build(4242, [], [], []));

    [Fact]
    public void TheProcessItselfIsCarriedThrough()
    {
        var target = Process(4242, "svc.exe");

        var insight = ProcessInsightBuilder.Build(4242, [target], [], []);

        Assert.NotNull(insight);
        Assert.Equal(target, insight.Process);
    }

    // ---- Pivot: only this process's rows ------------------------------------------------------

    [Fact]
    public void OnlyTheModulesAndConnectionsOfThisProcessAreIncluded()
    {
        var insight = ProcessInsightBuilder.Build(
            4242,
            [Process(4242), Process(99)],
            [Module(4242, "mine.dll"), Module(99, "theirs.dll")],
            [Conn(4242), Conn(99, "1.1.1.1:53")]);

        Assert.NotNull(insight);
        Assert.Equal(["mine.dll"], insight.Modules.Select(m => m.ModuleName));
        Assert.Single(insight.Connections);
        Assert.All(insight.Connections, c => Assert.Equal(4242, c.Pid));
    }

    // ---- Lineage ------------------------------------------------------------------------------

    [Fact]
    public void TheParentIsResolvedFromTheSnapshot()
    {
        var parent = Process(100, "explorer.exe", parentPid: 4);

        var insight = ProcessInsightBuilder.Build(4242, [Process(4242, parentPid: 100), parent], [], []);

        Assert.Equal(parent, insight!.Parent);
    }

    /// <summary>
    /// A parent that has already exited is absent, not invented.
    /// </summary>
    /// <remarks>
    /// This is the normal case for anything launched by an installer or a script that has since
    /// finished, and it is exactly the case worth investigating — so it must read as "parent 100, no
    /// longer running" rather than silently as no parent at all.
    /// </remarks>
    [Fact]
    public void AParentThatIsNoLongerRunningIsNullButItsPidIsStillKnown()
    {
        var insight = ProcessInsightBuilder.Build(4242, [Process(4242, parentPid: 100)], [], []);

        Assert.Null(insight!.Parent);
        Assert.Equal(100, insight.Process.ParentPid);
    }

    [Fact]
    public void ChildrenAreEveryProcessNamingThisOneAsParent()
    {
        var insight = ProcessInsightBuilder.Build(
            4242,
            [Process(4242), Process(5001, "child1.exe", parentPid: 4242),
             Process(5002, "child2.exe", parentPid: 4242), Process(6000, "other.exe", parentPid: 1)],
            [],
            []);

        Assert.Equal([5001, 5002], insight!.Children.Select(c => c.Pid));
    }

    /// <summary>
    /// A process that names itself as its own parent is neither its own parent nor its own child.
    /// </summary>
    /// <remarks>
    /// Not hypothetical: the System Idle Process reports pid 0 with parent 0, and WinSight's own
    /// reader falls back to 0 for a row whose id it cannot read. A tree view that accepts this
    /// recurses forever, and a lineage line that accepts it says a process launched itself.
    /// </remarks>
    [Fact]
    public void AProcessIsNeverItsOwnParentOrChild()
    {
        var insight = ProcessInsightBuilder.Build(0, [Process(0, "Idle", parentPid: 0)], [], []);

        Assert.NotNull(insight);
        Assert.Null(insight.Parent);
        Assert.Empty(insight.Children);
    }

    // ---- Triage: what is worth looking at -----------------------------------------------------

    /// <summary>
    /// Unsigned modules come first, because they are the reason to open this view.
    /// </summary>
    /// <remarks>
    /// A busy process loads hundreds of modules and all but a handful are Microsoft-signed. Listing
    /// them in load order buries the one that matters; this is the same reasoning as grading hijack
    /// findings by exploitability rather than listing every unquoted path.
    /// </remarks>
    [Fact]
    public void UnsignedModulesAreListedBeforeSignedOnes()
    {
        var insight = ProcessInsightBuilder.Build(
            4242,
            [Process(4242)],
            [Module(4242, "a-signed.dll"), Module(4242, "z-evil.dll", Unsigned),
             Module(4242, "b-signed.dll")],
            []);

        Assert.Equal("z-evil.dll", insight!.Modules[0].ModuleName);
        Assert.Equal(1, insight.UnsignedModuleCount);
        Assert.Equal(3, insight.Modules.Count);
    }

    [Fact]
    public void ModulesWithTheSameStandingKeepADeterministicOrder()
    {
        // Two runs of the same snapshot must render identically, or a diff between them is noise.
        var modules = new[] { Module(4242, "z.dll"), Module(4242, "a.dll"), Module(4242, "m.dll") };

        var insight = ProcessInsightBuilder.Build(4242, [Process(4242)], modules, []);

        Assert.Equal(["a.dll", "m.dll", "z.dll"], insight!.Modules.Select(m => m.ModuleName));
    }

    [Fact]
    public void ExternalEstablishedConnectionsAreCountedSeparately()
    {
        var insight = ProcessInsightBuilder.Build(
            4242,
            [Process(4242)],
            [],
            [Conn(4242, "93.184.216.34:443"), Conn(4242, "127.0.0.1:8080"),
             Conn(4242, "93.184.216.35:443", "TIME_WAIT")]);

        Assert.Equal(3, insight!.Connections.Count);
        Assert.Equal(1, insight.EstablishedExternalCount);
    }

    // ---- The one-line answer ------------------------------------------------------------------

    /// <summary>
    /// The summary is what an operator reads first, so it must never be reassuring by omission.
    /// </summary>
    [Fact]
    public void AProcessWithNothingNotableSaysSoPlainly()
    {
        var insight = ProcessInsightBuilder.Build(
            4242, [Process(4242)], [Module(4242, "ok.dll")], []);

        Assert.False(insight!.IsNotable);
    }

    [Theory]
    // Its own image is unsigned.
    [InlineData(true, false, false)]
    // It has an unsigned module loaded into it.
    [InlineData(false, true, false)]
    // It is talking to the outside world.
    [InlineData(false, false, true)]
    public void AnythingWorthALookMakesTheProcessNotable(
        bool unsignedImage, bool unsignedModule, bool externalConnection)
    {
        var insight = ProcessInsightBuilder.Build(
            4242,
            [Process(4242, signature: unsignedImage ? Unsigned : Trusted)],
            unsignedModule ? [Module(4242, "evil.dll", Unsigned)] : [],
            externalConnection ? [Conn(4242)] : []);

        Assert.True(insight!.IsNotable);
    }

    // ---- Robustness: the snapshots are taken at different moments ------------------------------

    /// <summary>
    /// The three snapshots are not atomic, so they disagree; the pivot must survive that.
    /// </summary>
    /// <remarks>
    /// Processes, modules and connections are gathered by three separate scans seconds apart. A
    /// module or connection can therefore name a pid that has since exited, or that had not started
    /// when the process list was taken. Neither is an error and neither may throw — the view is built
    /// on whatever is consistent.
    /// </remarks>
    [Fact]
    public void ModulesAndConnectionsForAProcessMissingFromTheListDoNotProduceAnInsight()
    {
        var insight = ProcessInsightBuilder.Build(
            4242, [], [Module(4242, "orphan.dll")], [Conn(4242)]);

        Assert.Null(insight);
    }

    [Fact]
    public void DuplicateProcessRowsForOnePidResolveToOneInsight()
    {
        // Two scans, or a pid reported twice, must not produce two answers or throw.
        var insight = ProcessInsightBuilder.Build(
            4242, [Process(4242, "first.exe"), Process(4242, "second.exe")], [], []);

        Assert.NotNull(insight);
        Assert.Equal(4242, insight.Process.Pid);
    }

    [Fact]
    public void NullSnapshotsAreRejectedRatherThanSilentlyTreatedAsEmpty()
    {
        // An empty list means "nothing found"; a null means the caller has a bug. Collapsing them
        // would report a process with no modules when the module scan never ran.
        Assert.Throws<ArgumentNullException>(() => ProcessInsightBuilder.Build(1, null!, [], []));
        Assert.Throws<ArgumentNullException>(() => ProcessInsightBuilder.Build(1, [], null!, []));
        Assert.Throws<ArgumentNullException>(() => ProcessInsightBuilder.Build(1, [], [], null!));
    }
}
