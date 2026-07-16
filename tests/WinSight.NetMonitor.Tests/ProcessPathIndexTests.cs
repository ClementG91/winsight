using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

public sealed class ProcessCommandLineTests
{
    // What Windows produces for most launches, and what the kernel reported on a live machine.
    [Fact]
    public void ExtractExecutablePath_ReadsAQuotedPath() =>
        Assert.Equal(
            @"C:\jamaisvu\appinconnue.exe",
            ProcessCommandLine.ExtractExecutablePath(
                @"""C:\jamaisvu\appinconnue.exe"" -s -o NUL --max-time 4 https://example.com",
                "appinconnue.exe"));

    // The classic ambiguity: splitting on the first space yields "C:\Program". The image name says
    // where the executable ends, whatever the spaces before it.
    [Fact]
    public void ExtractExecutablePath_ReadsAnUnquotedPathWithSpaces() =>
        Assert.Equal(
            @"C:\Program Files\My App\app.exe",
            ProcessCommandLine.ExtractExecutablePath(
                @"C:\Program Files\My App\app.exe --flag", "app.exe"));

    [Fact]
    public void ExtractExecutablePath_ReadsAnUnquotedPathWithoutSpaces() =>
        Assert.Equal(
            @"C:\tools\curl.exe",
            ProcessCommandLine.ExtractExecutablePath(@"C:\tools\curl.exe -s https://example.com", "curl.exe"));

    [Fact]
    public void ExtractExecutablePath_ReadsAPathWithNoArguments() =>
        Assert.Equal(
            @"C:\tools\curl.exe",
            ProcessCommandLine.ExtractExecutablePath(@"C:\tools\curl.exe", "curl.exe"));

    [Fact]
    public void ExtractExecutablePath_MatchesTheImageNameWhateverItsCase() =>
        Assert.Equal(
            @"C:\Program Files\My App\App.exe",
            ProcessCommandLine.ExtractExecutablePath(@"C:\Program Files\My App\App.exe --flag", "app.EXE"));

    [Fact]
    public void ExtractExecutablePath_CanonicalizesWhatItReads() =>
        Assert.Equal(
            @"C:\tools\curl.exe",
            ProcessCommandLine.ExtractExecutablePath(@"""C:\tools\sub\..\curl.exe""", "curl.exe"));

    // A guessed identity is worse than none: every policy is keyed on the executable, so a wrong
    // path would let the operator rule on the wrong program.
    [Theory]
    [InlineData(null, "app.exe")]
    [InlineData("", "app.exe")]
    [InlineData("   ", "app.exe")]
    [InlineData("app.exe --flag", "app.exe")]            // relative: no identity
    [InlineData(@"""", "app.exe")]                       // unterminated quote
    [InlineData(@"""""", "app.exe")]                     // empty quoted
    public void ExtractExecutablePath_RefusesWhatItCannotRead(string? commandLine, string imageFileName) =>
        Assert.Null(ProcessCommandLine.ExtractExecutablePath(commandLine, imageFileName));

    // A quoted path is unambiguous on its own; the image name is only needed to disambiguate.
    [Fact]
    public void ExtractExecutablePath_WithoutAnImageNameStillReadsAQuotedPath() =>
        Assert.Equal(
            @"C:\Program Files\My App\app.exe",
            ProcessCommandLine.ExtractExecutablePath(@"""C:\Program Files\My App\app.exe"" --flag", null));
}

public sealed class ProcessPathIndexTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 16, 23, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Resolve_ReturnsThePathCapturedAtStart()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\a.exe");

        Assert.Equal(@"C:\apps\a.exe", index.Resolve(100));
        Assert.Null(index.Resolve(101));
    }

    // A connection can be delivered just after the process ended — that is the whole reason this
    // index exists — so a dead process must stay resolvable for a while.
    [Fact]
    public void Resolve_StillAnswersForAProcessThatJustDied()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\a.exe");

        index.Stopped(100, T0);

        Assert.Equal(@"C:\apps\a.exe", index.Resolve(100));
    }

    [Fact]
    public void Prune_ForgetsAProcessDeadLongerThanTheRetention()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\a.exe");
        index.Stopped(100, T0);

        index.Prune(T0 + ProcessPathIndex.DeadRetention + TimeSpan.FromSeconds(1));

        Assert.Null(index.Resolve(100));
    }

    [Fact]
    public void Prune_KeepsAProcessDeadWithinTheRetention_AndEveryLiveOne()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\dead.exe");
        index.Started(200, @"C:\apps\live.exe");
        index.Stopped(100, T0);

        index.Prune(T0 + TimeSpan.FromSeconds(5));

        Assert.Equal(@"C:\apps\dead.exe", index.Resolve(100));
        Assert.Equal(@"C:\apps\live.exe", index.Resolve(200));
    }

    // Windows reuses process ids. The kernel's ordered stream re-announces the id before any
    // connection can be attributed to its new owner, so a start must replace, never merge.
    [Fact]
    public void Started_ReplacesTheEntryWhenAProcessIdIsReused()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\first.exe");
        index.Stopped(100, T0);

        index.Started(100, @"C:\apps\second.exe");

        Assert.Equal(@"C:\apps\second.exe", index.Resolve(100));
    }

    // A reused id must not stay marked dead, or its path would be pruned out from under a live
    // process and its connections would go unattributed.
    [Fact]
    public void Started_AfterReuse_IsNotPrunedAsThoughItWereStillDead()
    {
        var index = new ProcessPathIndex();
        index.Started(100, @"C:\apps\first.exe");
        index.Stopped(100, T0);
        index.Started(100, @"C:\apps\second.exe");

        index.Prune(T0 + ProcessPathIndex.DeadRetention + TimeSpan.FromSeconds(1));

        Assert.Equal(@"C:\apps\second.exe", index.Resolve(100));
    }

    // Process starts arrive from a kernel trace: unbounded growth is a primitive anything could
    // drive by spawning.
    [Fact]
    public void Started_IsBounded()
    {
        var index = new ProcessPathIndex();

        for (var i = 0; i < ProcessPathIndex.MaxTracked + 500; i++)
        {
            index.Started(i, $@"C:\apps\a{i}.exe");
        }

        Assert.True(index.Count <= ProcessPathIndex.MaxTracked);
    }

    // At the ceiling the dead are dropped first: a live process's path is what connections need.
    [Fact]
    public void Started_AtTheCeiling_KeepsLiveProcessesAndDropsTheLongestDead()
    {
        var index = new ProcessPathIndex();
        index.Started(1, @"C:\apps\live.exe");
        for (var i = 2; i < ProcessPathIndex.MaxTracked; i++)
        {
            index.Started(i, $@"C:\apps\dead{i}.exe");
            index.Stopped(i, T0.AddSeconds(i));
        }

        for (var i = 0; i < 50; i++)
        {
            index.Started(100_000 + i, $@"C:\apps\new{i}.exe");
        }

        Assert.Equal(@"C:\apps\live.exe", index.Resolve(1));
        Assert.Equal(@"C:\apps\new49.exe", index.Resolve(100_049));
    }

    [Fact]
    public void Started_RejectsAnIdentityNoPolicyCouldBeKeyedOn()
    {
        var index = new ProcessPathIndex();

        Assert.ThrowsAny<ArgumentException>(() => index.Started(1, "  "));
    }

    // Process events and connections arrive on the trace thread while the observer reads.
    [Fact]
    public async Task Index_IsSafeFromSeveralThreads()
    {
        var index = new ProcessPathIndex();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(worker => Task.Run(() =>
        {
            for (var i = 0; i < 200; i++)
            {
                index.Started(i % 50, $@"C:\apps\a{i % 50}.exe");
                index.Resolve(i % 50);
                if (i % 10 == 0)
                {
                    index.Stopped(i % 50, T0);
                    index.Prune(T0);
                }
            }
        })));

        Assert.True(index.Count <= 50);
    }
}
