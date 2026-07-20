using WinSight.Application;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class AlertJournalTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 20, 20, 3, 1, TimeSpan.Zero);

    private static string TempJournal() =>
        Path.Combine(Path.GetTempPath(), $"wsg-alerts-{Guid.NewGuid():N}", "alerts.log");

    private static void Cleanup(string path)
    {
        var dir = Path.GetDirectoryName(path);
        if (dir is not null && Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void FormatThenParse_RoundTripsEveryField()
    {
        var alert = new SecurityAlert(T0, "Ransomware", "CanaryTouched", @"C:\Users\me\Desktop\decoy.xlsx");

        var parsed = AlertJournal.Parse(AlertJournal.Format(alert));

        Assert.NotNull(parsed);
        Assert.Equal(alert.TimeUtc, parsed!.TimeUtc);
        Assert.Equal(alert.Source, parsed.Source);
        Assert.Equal(alert.Kind, parsed.Kind);
        Assert.Equal(alert.Detail, parsed.Detail);
    }

    [Fact]
    public void Format_FieldsContainingTabsOrNewlines_StayOnOneParseableLine()
    {
        // A path or name is attacker-influenced; a stray tab or newline must not corrupt the journal
        // or split one alert into two unparseable halves.
        var alert = new SecurityAlert(T0, "Ransomware", "Rename", "evil\tname\nwith\r\nbreaks.locked");

        var line = AlertJournal.Format(alert);

        Assert.DoesNotContain('\n', line);
        Assert.DoesNotContain('\r', line);
        var parsed = AlertJournal.Parse(line);
        Assert.NotNull(parsed);
        Assert.Equal("Rename", parsed!.Kind);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a journal line")]
    [InlineData("only\ttwo")]
    [InlineData("bad-timestamp\tSource\tKind\tDetail")]
    public void Parse_MalformedLine_IsNullNotAnException(string? line) =>
        Assert.Null(AlertJournal.Parse(line));

    [Fact]
    public void Append_ThenRead_ReturnsNewestFirst()
    {
        var path = TempJournal();
        try
        {
            AlertJournal.Append(new SecurityAlert(T0, "Guardian", "RunKey", "older"), path);
            AlertJournal.Append(new SecurityAlert(T0.AddMinutes(1), "Ransomware", "CanaryTouched", "newer"), path);

            var read = AlertJournal.Read(path, 10);

            Assert.Equal(2, read.Count);
            Assert.Equal("newer", read[0].Detail); // newest first: what you want to see on arrival
            Assert.Equal("older", read[1].Detail);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void Append_CreatesTheDirectory_WhenItDoesNotExistYet()
    {
        var path = TempJournal(); // its parent directory has not been created
        try
        {
            AlertJournal.Append(new SecurityAlert(T0, "Guardian", "RunKey", "first ever alert"), path);

            Assert.True(File.Exists(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void Append_IsBounded_KeepingTheNewestEntries()
    {
        var path = TempJournal();
        try
        {
            for (var i = 0; i < AlertJournal.MaxEntries + 25; i++)
            {
                AlertJournal.Append(new SecurityAlert(T0.AddSeconds(i), "Guardian", "RunKey", $"alert-{i}"), path);
            }

            var all = AlertJournal.Read(path, int.MaxValue);

            Assert.Equal(AlertJournal.MaxEntries, all.Count);
            // The newest survived; the oldest were dropped, not the other way round.
            Assert.Equal($"alert-{AlertJournal.MaxEntries + 24}", all[0].Detail);
            Assert.DoesNotContain(all, a => a.Detail == "alert-0");
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void Append_NeverThrows_OnAnUnusableTarget()
    {
        // Journalling runs on the detection path: it must never become the thing that breaks the
        // monitor that just detected something.
        AlertJournal.Append(new SecurityAlert(T0, "Guardian", "RunKey", "x"), "\0:\\invalid<>path\\alerts.log");
    }

    [Fact]
    public void Read_MissingJournal_IsEmptyNotAnException() =>
        Assert.Empty(AlertJournal.Read(TempJournal(), 10));

    [Fact]
    public void Read_SkipsCorruptLines_AndKeepsTheGoodOnes()
    {
        var path = TempJournal();
        try
        {
            AlertJournal.Append(new SecurityAlert(T0, "Guardian", "RunKey", "good"), path);
            File.AppendAllText(path, "corrupt garbage line" + Environment.NewLine);

            var read = AlertJournal.Read(path, 10);

            Assert.Equal("good", Assert.Single(read).Detail);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void Read_ZeroOrNegativeMax_IsEmpty()
    {
        Assert.Empty(AlertJournal.Read(TempJournal(), 0));
        Assert.Empty(AlertJournal.Read(TempJournal(), -5));
    }
}
