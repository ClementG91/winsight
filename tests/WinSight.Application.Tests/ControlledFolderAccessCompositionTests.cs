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
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Bitdefender Total Security", 0, 1),
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
        Assert.Contains(
            "normal third-party antivirus configuration",
            shield.Detail,
            StringComparison.OrdinalIgnoreCase);
        // The machine is protected, so the antivirus line itself is not an alarm.
        Assert.Equal(Severity.Info, antivirus.Severity);
        Assert.Equal("Protected", antivirus.Fields["concern"]);
        Assert.Equal("True", antivirus.Fields["hasActiveNonMicrosoftAntivirus"]);
        Assert.Equal("Bitdefender Total Security", shield.Fields["protectedThirdPartyAntivirus"]);
        Assert.Equal("Bitdefender Total Security", shield.Fields["onThirdPartyAntivirus"]);
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
        Assert.DoesNotContain("normal", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Equal("NoAntiVirusRegistered", antivirus.Fields["concern"]);
    }

    [Fact]
    public void CodeIntegrity_ActivityUnknown_IsNotableAndDoesNotInventAnInactiveProduct()
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            ProtectingCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Future AV", 99, 1),
            ])));

        var antivirus = AntivirusItem(report);

        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Equal("ActivityStatusUnknown", antivirus.Fields["concern"]);
        Assert.Equal("Available", antivirus.Fields["reading"]);
        Assert.Equal("1", antivirus.Fields["registeredAntivirusCount"]);
        Assert.Equal("0", antivirus.Fields["onAntivirusCount"]);
        Assert.Equal("1", antivirus.Fields["activityUnknownAntivirusCount"]);
        Assert.Equal("Future AV", antivirus.Fields["antivirusProduct.0.name"]);
        Assert.Equal("Unknown", antivirus.Fields["antivirusProduct.0.activity"]);
        Assert.Equal("UpToDate", antivirus.Fields["antivirusProduct.0.signature"]);
        Assert.Equal("99", antivirus.Fields["antivirusProduct.0.rawActivity"]);
        Assert.Equal("1", antivirus.Fields["antivirusProduct.0.rawSignature"]);
        Assert.Equal("0", antivirus.Fields["antivirusProduct.0.legacyRawProductState"]);
        Assert.Contains("activity could not be established", antivirus.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not evidence that the product is On or Off", antivirus.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("nothing is scanning", antivirus.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "every On product reports signatures OUT OF DATE",
            antivirus.Detail,
            StringComparison.Ordinal);
    }

    [Fact]
    public void CodeIntegrity_SignatureUnknown_IsNotableAndDoesNotInventStaleDefinitions()
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            ProtectingCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Future AV", 0, 99),
            ])));

        var antivirus = AntivirusItem(report);

        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Equal("SignatureStatusUnknown", antivirus.Fields["concern"]);
        Assert.Equal("1", antivirus.Fields["onAntivirusCount"]);
        Assert.Equal("1", antivirus.Fields["signatureUnknownAntivirusCount"]);
        Assert.Equal("Future AV", antivirus.Fields["antivirusProduct.0.name"]);
        Assert.Equal("On", antivirus.Fields["antivirusProduct.0.activity"]);
        Assert.Equal("Unknown", antivirus.Fields["antivirusProduct.0.signature"]);
        Assert.Equal("0", antivirus.Fields["antivirusProduct.0.rawActivity"]);
        Assert.Equal("99", antivirus.Fields["antivirusProduct.0.rawSignature"]);
        Assert.Equal("0", antivirus.Fields["antivirusProduct.0.legacyRawProductState"]);
        Assert.Contains("currency could not be established", antivirus.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "not evidence that definitions are current or out of date",
            antivirus.Detail,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "every On product reports signatures OUT OF DATE",
            antivirus.Detail,
            StringComparison.Ordinal);
    }

    [Fact]
    public void CodeIntegrity_ExplicitInactiveStatesRemainDistinctInFieldsAndWording()
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            ProtectingCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Off AV", 1, 1),
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Snoozed AV", 2, 1),
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Expired AV", 3, 0),
            ])));

        var antivirus = AntivirusItem(report);

        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Equal("NoActiveAntiVirus", antivirus.Fields["concern"]);
        Assert.Equal("1", antivirus.Fields["offAntivirusCount"]);
        Assert.Equal("1", antivirus.Fields["snoozedAntivirusCount"]);
        Assert.Equal("1", antivirus.Fields["expiredAntivirusCount"]);
        Assert.Equal("0", antivirus.Fields["activityUnknownAntivirusCount"]);
        Assert.Equal("Off", antivirus.Fields["antivirusProduct.0.activity"]);
        Assert.Equal("Snoozed", antivirus.Fields["antivirusProduct.1.activity"]);
        Assert.Equal("Expired", antivirus.Fields["antivirusProduct.2.activity"]);
        Assert.Contains("Off: Off AV", antivirus.Detail, StringComparison.Ordinal);
        Assert.Contains("Snoozed: Snoozed AV", antivirus.Detail, StringComparison.Ordinal);
        Assert.Contains("Expired: Expired AV", antivirus.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void CodeIntegrity_DefenderNotRunningWithUnavailableProvider_RemainsIndeterminate()
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            DefenderNotRunningCfa(),
            new SecurityCenterReader(new ThrowingSecurityCenterSource()));

        var antivirus = AntivirusItem(report);
        var shield = ShieldItem(report);

        Assert.Equal("Unavailable", antivirus.Fields["concern"]);
        Assert.Equal(Severity.Notable, antivirus.Severity);
        Assert.Contains("could not be read", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "cannot establish whether another antivirus is active",
            shield.Detail,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("normal", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("nothing is scanning", shield.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeIntegrity_DefenderNotRunningWithUnknownActivity_RemainsIndeterminate()
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            DefenderNotRunningCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(SecurityProductKind.AntiVirus, "Future AV", 99, 1),
            ])));

        var antivirus = AntivirusItem(report);
        var shield = ShieldItem(report);

        Assert.Equal("ActivityStatusUnknown", antivirus.Fields["concern"]);
        Assert.Contains("unrecognized activity state", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "cannot establish whether that product is active",
            shield.Detail,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("normal", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "does not show another antivirus actively scanning",
            shield.Detail,
            StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(99, "SignatureStatusUnknown", "signature currency is unknown")]
    [InlineData(0, "SignaturesOutOfDate", "out-of-date signatures")]
    public void CodeIntegrity_DefenderNotRunningWithUnprotectedThirdPartyNeverReassures(
        int rawSignature,
        string expectedConcern,
        string expectedDetail)
    {
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            DefenderNotRunningCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(
                    SecurityProductKind.AntiVirus,
                    "Third Party AV",
                    0,
                    rawSignature),
            ])));

        var antivirus = AntivirusItem(report);
        var shield = ShieldItem(report);

        Assert.Equal(expectedConcern, antivirus.Fields["concern"]);
        Assert.Null(shield.Fields["protectedThirdPartyAntivirus"]);
        Assert.Equal("Third Party AV", shield.Fields["onThirdPartyAntivirus"]);
        Assert.Contains(expectedDetail, shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("normal", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("not a fault", shield.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("configuration normale", shield.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CodeIntegrity_ProductNameDelimitersRemainOneIndexedValueAndCannotForgeFields()
    {
        const string expectedName =
            "Vendor; concern=Protected antivirusProduct.9.activity=On";
        var report = Adapters.CodeIntegrity(
            flaggedOnly: false,
            ProtectingCfa(),
            new SecurityCenterReader(new SecurityCenterSource([
                new SecurityCenterRow(
                    SecurityProductKind.AntiVirus,
                    "Vendor; concern=Protected\r\nantivirusProduct.9.activity=On",
                    99,
                    1),
            ])));

        var antivirus = AntivirusItem(report);

        Assert.Equal("ActivityStatusUnknown", antivirus.Fields["concern"]);
        Assert.Equal(expectedName, antivirus.Fields["antivirusProduct.0.name"]);
        Assert.False(antivirus.Fields.ContainsKey("antivirusProduct.9.activity"));
        Assert.DoesNotContain(
            antivirus.Fields.Keys,
            key => key.Contains("concern=Protected", StringComparison.Ordinal));
    }

    [Fact]
    public void Run_Integrity_PropagatesPreCanceledCallerToken()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            Adapters.Run("integrity", cancellationToken: cancellation.Token));
    }

    [Fact]
    public void CodeIntegrity_PropagatesCancellationFromSecurityCenterSource()
    {
        using var cancellation = new CancellationTokenSource();
        var source = new CancelingSecurityCenterSource(cancellation);

        Assert.Throws<OperationCanceledException>(() =>
            Adapters.RunCore(
                "integrity",
                flaggedOnly: false,
                allowNetworkLookups: false,
                ProtectingCfa(),
                new SecurityCenterReader(source),
                cancellation.Token));
        Assert.Equal(cancellation.Token, source.SeenToken);
    }

    [Fact]
    public void CodeIntegrity_PropagatesCancellationFromControlledFolderAccessSource()
    {
        using var cancellation = new CancellationTokenSource();
        var source = new CancelingSnapshotSource(cancellation);

        Assert.Throws<OperationCanceledException>(() =>
            Adapters.RunCore(
                "integrity",
                flaggedOnly: false,
                allowNetworkLookups: false,
                new ControlledFolderAccessReader(source),
                ProtectedMachine(),
                cancellation.Token));
        Assert.Equal(cancellation.Token, source.SeenToken);
    }

    /// <summary>
    /// A machine with one active, up-to-date antivirus. Supplied explicitly so these assertions
    /// describe the composition and not whatever antivirus the machine running the tests happens to
    /// have — Windows Server does not ship Security Center at all, which turned that item notable and
    /// broke the summary these tests read.
    /// </summary>
    private static SecurityCenterReader ProtectedMachine() =>
        new(new SecurityCenterSource([
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Windows Defender", 0, 1),
        ]));

    private static ControlledFolderAccessReader ProtectingCfa() =>
        new(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            new ControlledFolderAccessRawPreference(1, null, null),
            new ControlledFolderAccessRawRuntime("Normal", true, true))));

    private static ControlledFolderAccessReader DefenderNotRunningCfa() =>
        new(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            new ControlledFolderAccessRawPreference(0, null, null),
            new ControlledFolderAccessRawRuntime("Not running", false, false))));

    private static ReportItem AntivirusItem(ToolReport report) =>
        Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Antivirus");

    private static ReportItem ShieldItem(ToolReport report) =>
        Assert.Single(report.Items, candidate =>
            candidate.Fields.TryGetValue("protection", out var protection)
            && protection == "Controlled Folder Access");

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

    private sealed class ThrowingSecurityCenterSource : ISecurityCenterDataSource
    {
        public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new System.Management.ManagementException("provider unavailable");
        }
    }

    private sealed class CancelingSecurityCenterSource(CancellationTokenSource cancellation)
        : ISecurityCenterDataSource
    {
        public CancellationToken SeenToken { get; private set; }

        public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
        {
            SeenToken = cancellationToken;
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return [];
        }
    }

    private sealed class CancelingSnapshotSource(CancellationTokenSource cancellation)
        : IControlledFolderAccessDataSource
    {
        public CancellationToken SeenToken { get; private set; }

        public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken)
        {
            SeenToken = cancellationToken;
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return new ControlledFolderAccessWmiSnapshot(null, null);
        }
    }

    private static int CheckedCount(ToolReport report) => int.Parse(
        report.Summary.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0],
        CultureInfo.InvariantCulture);
}
