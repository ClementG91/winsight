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

        var report = Adapters.CodeIntegrity(flaggedOnly: true, reader, ProtectedMachine());
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
                new ControlledFolderAccessRawRuntime("Normal", true, true)))),
            ProtectedMachine());
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

        var report = Adapters.CodeIntegrity(flaggedOnly: true, reader, ProtectedMachine());

        Assert.DoesNotContain(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");
        Assert.Contains("0 unavailable", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The whole point of reading Security Center: on a machine whose antivirus is not Microsoft's,
    /// "the ransomware shield is not protecting you" is true and misleading unless it also names what
    /// is. This pins that the CFA line names the real product and calls the configuration normal.
    /// </summary>
    [Fact]
    public void CodeIntegrity_DefenderStoodDownForAThirdPartyAntivirus_NamesItAndCallsItNormal()
    {
        var cfa = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            new ControlledFolderAccessRawPreference(0, null, null),
            new ControlledFolderAccessRawRuntime("Not running", false, false))));
        var securityCenter = new SecurityCenterReader(new SecurityCenterSource([
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Bitdefender Total Security", 0x061100),
        ]));

        var report = Adapters.CodeIntegrity(flaggedOnly: false, cfa, securityCenter);
        var shield = Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");
        var antivirus = Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Antivirus");

        Assert.Equal("DefenderNotRunning", shield.Fields["concern"]);
        Assert.Contains("Bitdefender Total Security", shield.Detail, StringComparison.Ordinal);
        Assert.Contains("normal configuration", shield.Detail, StringComparison.OrdinalIgnoreCase);
        // The machine is protected, so the antivirus line itself is not an alarm.
        Assert.Equal(Severity.Info, antivirus.Severity);
        Assert.Equal("Protected", antivirus.Fields["concern"]);
        Assert.Equal("True", antivirus.Fields["hasActiveNonMicrosoftAntivirus"]);
    }

    /// <summary>
    /// The opposite case must stay blunt: nothing scanning means nothing scanning, and the CFA line
    /// must not borrow reassurance from an antivirus that is not there.
    /// </summary>
    [Fact]
    public void CodeIntegrity_DefenderNotRunningAndNothingElseScanning_StaysBlunt()
    {
        var cfa = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            new ControlledFolderAccessRawPreference(0, null, null),
            new ControlledFolderAccessRawRuntime("Not running", false, false))));
        var securityCenter = new SecurityCenterReader(new SecurityCenterSource([]));

        var report = Adapters.CodeIntegrity(flaggedOnly: false, cfa, securityCenter);
        var shield = Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");
        var antivirus = Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Antivirus");

        Assert.Equal("DefenderNotRunning", shield.Fields["concern"]);
        Assert.DoesNotContain("normal configuration", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Equal("NoAntiVirusRegistered", antivirus.Fields["concern"]);
    }

    /// <summary>
    /// A machine with one active, up-to-date antivirus. Supplied explicitly so these assertions
    /// describe the composition and not whatever antivirus the machine running the tests happens to
    /// have — Windows Server does not ship Security Center at all, which turned that item notable and
    /// broke the summary these tests read.
    /// </summary>
    private static SecurityCenterReader ProtectedMachine() =>
        new(new SecurityCenterSource([
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Windows Defender", 0x061100),
        ]));

    private sealed class SnapshotSource(ControlledFolderAccessWmiSnapshot snapshot) : IControlledFolderAccessDataSource
    {
        public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return snapshot;
        }
    }

    private sealed class SecurityCenterSource(IReadOnlyList<SecurityCenterRow> rows) : ISecurityCenterDataSource
    {
        public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return rows;
        }
    }

    private static int CheckedCount(ToolReport report) => int.Parse(
        report.Summary.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0],
        CultureInfo.InvariantCulture);
}
