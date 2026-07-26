using System.Globalization;
using WinSight.Ransomware;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ControlledFolderAccessCompositionTests
{
    [Fact]
    public void CodeIntegrity_FlaggedOnly_KeepsUnavailableCfaVisibleWithoutCountingItAsChecked()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            Preference: null,
            Runtime: null)));

        var report = Adapters.CodeIntegrity(flaggedOnly: true, reader);
        var item = Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");

        Assert.Equal(Severity.Notable, item.Severity);
        Assert.Equal("Unavailable", item.Fields["state"]);
        Assert.Equal("Unavailable", item.Fields["concern"]);
        Assert.Equal("Unavailable", item.Fields["allowedApplicationsVisibility"]);
        Assert.Contains("unavailable", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("third-party", item.Detail, StringComparison.OrdinalIgnoreCase);

        var unknownReport = Adapters.CodeIntegrity(
            flaggedOnly: true,
            new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
                new ControlledFolderAccessRawPreference(5, null, null),
                new ControlledFolderAccessRawRuntime("Normal", true, true)))));
        var unknownItem = Assert.Single(unknownReport.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");

        Assert.Contains("1 unavailable", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("0 unavailable", unknownReport.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(CheckedCount(report) + 1, CheckedCount(unknownReport));
        Assert.Equal(Severity.Notable, unknownItem.Severity);
        Assert.Equal("Unknown", unknownItem.Fields["state"]);
        Assert.Equal("UnknownMode", unknownItem.Fields["concern"]);
        Assert.Equal("5", unknownItem.Fields["rawStateValue"]);
        Assert.Contains("unsupported mode value 5", unknownItem.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("could not be read", unknownItem.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeIntegrity_FlaggedOnly_HidesPositivelyProtectingCfa()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            new ControlledFolderAccessRawPreference(1, null, null),
            new ControlledFolderAccessRawRuntime("Normal", true, true))));

        var report = Adapters.CodeIntegrity(flaggedOnly: true, reader);

        Assert.DoesNotContain(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");
        Assert.Contains("0 unavailable", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class SnapshotSource(ControlledFolderAccessWmiSnapshot snapshot) : IControlledFolderAccessDataSource
    {
        public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return snapshot;
        }
    }

    private static int CheckedCount(ToolReport report) => int.Parse(
        report.Summary.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0],
        CultureInfo.InvariantCulture);
}
