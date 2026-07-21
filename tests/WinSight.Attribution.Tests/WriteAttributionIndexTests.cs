using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The correlation rules. Every time here is explicit, so "how far back may a detection reach" and
/// "which write wins" are pinned without a live trace or elevation.
/// </summary>
public sealed class WriteAttributionIndexTests
{
    private static readonly DateTimeOffset Noon = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);
    private const string RunKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    private static WriteObservation Write(
        DateTimeOffset whenUtc,
        string target,
        int processId = 4242,
        string executablePath = @"C:\tmp\dropper.exe") =>
        new(whenUtc, processId, executablePath, target);

    [Fact]
    public void Attribute_NamesTheProcessThatWroteTheTarget()
    {
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey));

        var attributed = index.Attribute(RunKey, Noon.AddSeconds(1));

        Assert.NotNull(attributed);
        Assert.Equal(4242, attributed.ProcessId);
        Assert.Equal(@"C:\tmp\dropper.exe", attributed.ExecutablePath);
    }

    [Fact]
    public void Attribute_MatchesAFindingThatNamesTheValueOrViewAlongsideTheKey()
    {
        // A kernel session reports the key that changed — verified against live hardware. A finding
        // names that key plus the value inside it, or the registry view it was read through.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey));

        Assert.NotNull(index.Attribute($"{RunKey} [Updater]", Noon.AddSeconds(1)));
        Assert.NotNull(index.Attribute($"{RunKey} [64-bit]", Noon.AddSeconds(1)));
    }

    [Fact]
    public void Attribute_DoesNotBlameAParentKeyWriteForAChildKey()
    {
        // Caught on the first live run: a browser writing somewhere under HKCU\Software was named
        // as the author of a key it had never touched. A backslash means the detection is about a
        // deeper key, and a write to a parent does not explain a change in a child.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, @"HKCU\Software"));

        Assert.Null(index.Attribute(@"HKCU\Software\SomeoneElsesApp\Run [64-bit]", Noon.AddSeconds(1)));
        Assert.Null(index.Attribute(@"HKCU\Software\SomeoneElsesApp", Noon.AddSeconds(1)));
    }

    [Fact]
    public void Attribute_DoesNotMatchADifferentKeyThatMerelyStartsWithTheSameText()
    {
        // Without a boundary check, a write to ...\Run would be blamed for ...\RunOnce.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey));

        Assert.Null(index.Attribute(RunKey + "Once", Noon.AddSeconds(1)));
    }

    [Fact]
    public void Attribute_PrefersTheMostRecentWriteToTheSameTarget()
    {
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey, processId: 1, executablePath: @"C:\first.exe"));
        index.Record(Write(Noon.AddSeconds(5), RunKey, processId: 2, executablePath: @"C:\second.exe"));

        var attributed = index.Attribute(RunKey, Noon.AddSeconds(6));

        Assert.Equal(2, attributed?.ProcessId);
    }

    [Fact]
    public void Attribute_IgnoresWritesToOtherTargets()
    {
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, @"HKLM\SOFTWARE\Something\Else"));

        Assert.Null(index.Attribute(RunKey, Noon.AddSeconds(1)));
    }

    [Fact]
    public void Attribute_RefusesAWriteOlderThanTheRetentionWindow()
    {
        // Something written ten minutes before a detection did not cause it; naming it would put a
        // confident wrong answer next to a security finding.
        var index = new WriteAttributionIndex(retention: TimeSpan.FromSeconds(60));
        index.Record(Write(Noon, RunKey));

        Assert.Null(index.Attribute(RunKey, Noon.AddMinutes(10)));
    }

    [Fact]
    public void Attribute_AllowsAWriteTimestampedSlightlyAfterTheDetection()
    {
        // ETW timestamps and the detector's clock are different sources, so a strict ordering
        // comparison would drop correct attributions at the boundary.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon.AddSeconds(1), RunKey));

        Assert.NotNull(index.Attribute(RunKey, Noon));
    }

    [Fact]
    public void Attribute_RefusesAWriteFromWellAfterTheDetection()
    {
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon.AddMinutes(1), RunKey));

        Assert.Null(index.Attribute(RunKey, Noon));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Attribute_WithoutATargetSaysNothing(string? target)
    {
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey));

        Assert.Null(index.Attribute(target, Noon));
    }

    [Fact]
    public void Attribute_OnAnEmptyIndexIsANormalAnswerNotAFailure()
    {
        // The writer may have acted before monitoring started. Unattributed is expected.
        Assert.Null(new WriteAttributionIndex().Attribute(RunKey, Noon));
    }

    [Fact]
    public void Record_IgnoresAnObservationThatCannotAttributeAnything()
    {
        var index = new WriteAttributionIndex();

        index.Record(Write(Noon, target: "   "));
        index.Record(Write(Noon, RunKey, executablePath: "   "));

        Assert.Equal(0, index.Count);
    }

    [Fact]
    public void Record_StaysBoundedUnderAWriteLoop()
    {
        var index = new WriteAttributionIndex();

        for (var i = 0; i < WriteAttributionIndex.MaxObservations + 500; i++)
        {
            index.Record(Write(Noon.AddMilliseconds(i), $@"C:\tmp\file{i}.txt"));
        }

        Assert.Equal(WriteAttributionIndex.MaxObservations, index.Count);
    }

    [Fact]
    public void Record_UnderPressureDropsTheOldestAndKeepsTheNewest()
    {
        // The newest observations are the ones a detection is about to ask about.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, RunKey, processId: 7));
        for (var i = 0; i < WriteAttributionIndex.MaxObservations; i++)
        {
            index.Record(Write(Noon.AddMilliseconds(i + 1), $@"C:\tmp\file{i}.txt"));
        }

        Assert.Null(index.Attribute(RunKey, Noon.AddSeconds(5)));
        Assert.NotNull(index.Attribute(@"C:\tmp\file4095.txt", Noon.AddSeconds(5)));
    }

    [Fact]
    public void Prune_ForgetsWhatIsPastTheWindowAndKeepsTheRest()
    {
        var index = new WriteAttributionIndex(retention: TimeSpan.FromSeconds(60));
        index.Record(Write(Noon, @"C:\tmp\old.txt"));
        index.Record(Write(Noon.AddSeconds(90), @"C:\tmp\recent.txt"));

        index.Prune(Noon.AddSeconds(120));

        Assert.Equal(1, index.Count);
        Assert.NotNull(index.Attribute(@"C:\tmp\recent.txt", Noon.AddSeconds(120)));
    }

    [Fact]
    public void TargetsAreMatchedRegardlessOfCase()
    {
        // Windows paths and registry keys are case-insensitive, and providers are not consistent.
        var index = new WriteAttributionIndex();
        index.Record(Write(Noon, @"C:\Users\me\Documents\Report.docx"));

        Assert.NotNull(index.Attribute(@"c:\users\me\documents\report.docx", Noon.AddSeconds(1)));
    }
}
