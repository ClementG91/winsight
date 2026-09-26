using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// RA-03: entries Guardian baselined because it could read their location for the first time reach
/// the journal - and so <c>winsight alerts</c> and MCP clients - as an uncertainty, not a detection.
/// </summary>
public sealed class GuardianCoverageGainAlertTests
{
    private static AutostartEntry Task(string name, string command) =>
        new(AutostartVector.ScheduledTask, name, $@"C:\Windows\System32\Tasks\{name}", command,
            $@"C:\Tools\{name}.exe", $@"C:\Tools\{name}.exe", ImageResolutionStatus.Present,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Contoso"))
        {
            Source = "Scheduled Tasks",
        };

    private static readonly DateTimeOffset At = new(2026, 9, 24, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheNoticeSaysWhatItIsAndNamesTheEntriesWithoutTheirPayloads()
    {
        var gain = new PersistenceCoverageGain(At,
            [Task("Defrag", @"C:\Tools\Defrag.exe -enc SECRETPAYLOAD"), Task("Updater", @"C:\Tools\Updater.exe")]);

        var alert = GuardianHost.CoverageGainAlert(gain);

        Assert.Equal("Guardian", alert.Source);
        Assert.Equal(GuardianHost.CoverageGainKind, alert.Kind);
        Assert.StartsWith("2 existing startup entr(ies) became readable for the first time (Scheduled Tasks)", alert.Detail);
        Assert.Contains("cannot tell", alert.Detail);
        Assert.Contains(@"C:\Tools\Defrag.exe", alert.Detail);
        Assert.Contains("Updater", alert.Detail);
        // The command line can carry a payload and is withheld from MCP clients everywhere else.
        Assert.DoesNotContain("SECRETPAYLOAD", alert.Detail);
        foreach (var accusation in new[] { "attack", "malicious", "threat", "detected" })
        {
            Assert.DoesNotContain(accusation, alert.Detail, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ALargeGainNamesABoundedFewAndCountsTheRest()
    {
        var entries = Enumerable.Range(0, 30).Select(i => Task($"T{i}", $@"C:\Tools\T{i}.exe")).ToArray();

        var alert = GuardianHost.CoverageGainAlert(new PersistenceCoverageGain(At, entries, Unlisted: 5));

        Assert.StartsWith("35 existing startup entr(ies)", alert.Detail);
        Assert.EndsWith("; and 15 more", alert.Detail);
        Assert.Contains("T19", alert.Detail);
        Assert.DoesNotContain("T20 ", alert.Detail);
    }

    [Fact]
    public void TheToolTipCountsTheUncertainEntries()
    {
        var diagnostics = new PersistenceMonitorDiagnostics(0, 0, 0, 0, false, false, false, null)
        {
            CoverageGainEntries = 61,
        };

        Assert.Equal(
            "Guardian: 61 entr(ies) first readable this session, baselined without an alert, arrival time unknown (see winsight alerts)",
            GuardianHost.DiagnosticsLine(diagnostics));
    }

    [Fact]
    public void AlertsShowTheNoticeAsUnverifiedAndTheArrivalsAsNotable()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-coverage-gain-{Guid.NewGuid():N}", "alerts.log");
        try
        {
            AlertJournal.Append(new SecurityAlert(At, "Guardian", "RunKey", @"Planted — C:\Users\Public\p.exe [unsigned]"), path);
            AlertJournal.Append(GuardianHost.CoverageGainAlert(new PersistenceCoverageGain(At.AddMinutes(1), [Task("Defrag", "x")])), path);

            var report = Adapters.Alerts(path, max: 10);

            Assert.Equal(Severity.Unverified, report.Items[0].Severity);
            Assert.Equal(GuardianHost.CoverageGainKind, report.Items[0].Fields["kind"]);
            Assert.Equal(Severity.Notable, report.Items[1].Severity);
            Assert.Equal("1 recorded detection(s) and 1 coverage notice(s), newest first", report.Summary);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    // A journal line that merely claims the kind from another source is still a detection: only
    // Guardian writes coverage notices.
    [Fact]
    public void OnlyGuardianCanWriteACoverageNotice()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wsg-coverage-gain-{Guid.NewGuid():N}", "alerts.log");
        try
        {
            AlertJournal.Append(new SecurityAlert(At, "Ransomware", GuardianHost.CoverageGainKind, "x"), path);

            Assert.Equal(Severity.Notable, Assert.Single(Adapters.Alerts(path, max: 10).Items).Severity);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }
}
