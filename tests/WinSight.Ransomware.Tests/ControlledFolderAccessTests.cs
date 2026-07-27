using System.Management;
using System.Reflection;
using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class ControlledFolderAccessTriageTests
{
    [Theory]
    [InlineData(0, ControlledFolderAccessState.Disabled)]
    [InlineData(1, ControlledFolderAccessState.Enabled)]
    [InlineData(2, ControlledFolderAccessState.Audit)]
    [InlineData(3, ControlledFolderAccessState.BlockDiskModificationOnly)]
    [InlineData(4, ControlledFolderAccessState.AuditDiskModificationOnly)]
    public void StateFromValue_MapsEveryDocumentedDefenderMode(int value, ControlledFolderAccessState expected) =>
        Assert.Equal(expected, ControlledFolderAccessTriage.StateFromValue(value));

    [Theory]
    [InlineData(null)]
    public void StateFromValue_MissingValue_IsUnavailable(int? value) =>
        Assert.Equal(ControlledFolderAccessState.Unavailable, ControlledFolderAccessTriage.StateFromValue(value));

    [Theory]
    [InlineData(5)]
    [InlineData(99)]
    public void StateFromValue_UnsupportedButSuccessfullyReadValue_IsExplicitlyUnknown(int value) =>
        Assert.Equal(ControlledFolderAccessState.Unknown, ControlledFolderAccessTriage.StateFromValue(value));

    [Fact]
    public void Enabled_IsProtecting_OnlyWithPositiveNormalAntivirusAndRealTimeEvidence()
    {
        var evidence = new DefenderRuntimeEvidence("Normal", AntivirusEnabled: true, RealTimeProtectionEnabled: true);

        Assert.Equal(
            ControlledFolderAccessConcern.Protecting,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, evidence));
    }

    [Theory]
    [InlineData("Passive Mode", true, true)]
    [InlineData("Normal", false, true)]
    [InlineData("Normal", true, false)]
    public void Enabled_WithoutEveryRuntimeRequirement_IsNotReportedAsProtecting(
        string mode,
        bool antivirusEnabled,
        bool realTimeProtectionEnabled)
    {
        var evidence = new DefenderRuntimeEvidence(mode, antivirusEnabled, realTimeProtectionEnabled);

        Assert.Equal(
            ControlledFolderAccessConcern.RuntimeRequirementsNotMet,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, evidence));
    }

    [Theory]
    [InlineData(null, true, true)]
    [InlineData("Normal", null, true)]
    [InlineData("Normal", true, null)]
    public void IncompleteRuntimeEvidence_IsUnavailable_NotThirdPartyProtection(
        string? mode,
        bool? antivirusEnabled,
        bool? realTimeProtectionEnabled)
    {
        var evidence = new DefenderRuntimeEvidence(mode, antivirusEnabled, realTimeProtectionEnabled);

        Assert.Equal(
            ControlledFolderAccessConcern.Unavailable,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, evidence));
    }

    [Theory]
    [InlineData(ControlledFolderAccessState.Disabled, ControlledFolderAccessConcern.Off)]
    [InlineData(ControlledFolderAccessState.Audit, ControlledFolderAccessConcern.AuditOnly)]
    [InlineData(ControlledFolderAccessState.BlockDiskModificationOnly, ControlledFolderAccessConcern.BlockDiskModificationOnly)]
    [InlineData(ControlledFolderAccessState.AuditDiskModificationOnly, ControlledFolderAccessConcern.AuditDiskModificationOnly)]
    public void CompleteRuntimeEvidence_PreservesTheConfiguredMode(
        ControlledFolderAccessState state,
        ControlledFolderAccessConcern expected)
    {
        var passiveEvidence = new DefenderRuntimeEvidence("Passive Mode", AntivirusEnabled: false, RealTimeProtectionEnabled: false);

        Assert.Equal(expected, ControlledFolderAccessTriage.Concern(state, passiveEvidence));
    }

    [Theory]
    [InlineData(ControlledFolderAccessConcern.Protecting, false)]
    [InlineData(ControlledFolderAccessConcern.Off, true)]
    [InlineData(ControlledFolderAccessConcern.AuditOnly, true)]
    [InlineData(ControlledFolderAccessConcern.BlockDiskModificationOnly, true)]
    [InlineData(ControlledFolderAccessConcern.AuditDiskModificationOnly, true)]
    [InlineData(ControlledFolderAccessConcern.RuntimeRequirementsNotMet, true)]
    [InlineData(ControlledFolderAccessConcern.DefenderNotRunning, true)]
    [InlineData(ControlledFolderAccessConcern.Unavailable, true)]
    public void IsNotable_ExposesEveryGapAndOnlyProtectingIsQuiet(
        ControlledFolderAccessConcern concern,
        bool expected) =>
        Assert.Equal(expected, ControlledFolderAccessTriage.IsNotable(concern));

    /// <summary>
    /// Every mode Defender documents is a successful read. Treating one as unrecognized reports
    /// "we could not look" on a machine that answered — the worst way for this reader to be wrong,
    /// and what happened on any machine whose antivirus is not Defender.
    /// </summary>
    [Theory]
    [InlineData("Normal")]
    [InlineData("Passive")]
    [InlineData("Passive Mode")]
    [InlineData("SxS Passive Mode")]
    [InlineData("EDR Block Mode")]
    [InlineData("Not running")]
    [InlineData(" Normal ")]
    [InlineData("not running")]
    public void EveryDocumentedRunningMode_IsARecognizedRead(string mode)
    {
        var evidence = new DefenderRuntimeEvidence(mode, AntivirusEnabled: true, RealTimeProtectionEnabled: true);

        Assert.True(evidence.IsRecognizedRunningMode);
        Assert.NotEqual(
            ControlledFolderAccessConcern.Unavailable,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, evidence));
    }

    [Theory]
    [InlineData("Fortress Mode")]
    [InlineData("")]
    [InlineData("   ")]
    public void UndocumentedRunningMode_StaysUnavailable_RatherThanBeingGuessedAt(string mode)
    {
        var evidence = new DefenderRuntimeEvidence(mode, AntivirusEnabled: true, RealTimeProtectionEnabled: true);

        Assert.False(evidence.IsRecognizedRunningMode);
        Assert.Equal(
            ControlledFolderAccessConcern.Unavailable,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, evidence));
    }

    /// <summary>
    /// Controlled Folder Access is a Defender feature, so a stopped antivirus outranks whatever value
    /// is configured. Reporting a configured 0 as a plain "turn it on" would point the operator at a
    /// switch that changes nothing until Defender runs again.
    /// </summary>
    [Theory]
    [InlineData(ControlledFolderAccessState.Disabled)]
    [InlineData(ControlledFolderAccessState.Enabled)]
    [InlineData(ControlledFolderAccessState.Audit)]
    [InlineData(ControlledFolderAccessState.BlockDiskModificationOnly)]
    [InlineData(ControlledFolderAccessState.AuditDiskModificationOnly)]
    [InlineData(ControlledFolderAccessState.Unknown)]
    public void DefenderNotRunning_OutranksTheConfiguredMode(ControlledFolderAccessState state)
    {
        var evidence = new DefenderRuntimeEvidence(
            "Not running", AntivirusEnabled: false, RealTimeProtectionEnabled: false);

        Assert.True(evidence.IsAntivirusNotRunning);
        Assert.False(evidence.SupportsControlledFolderAccessProtection);
        Assert.Equal(
            ControlledFolderAccessConcern.DefenderNotRunning,
            ControlledFolderAccessTriage.Concern(state, evidence));
    }

    /// <summary>
    /// A stray space around Defender's own string must not downgrade a successful read, and must not
    /// promote a non-Normal mode into protection either.
    /// </summary>
    [Fact]
    public void RunningModeComparison_IgnoresSurroundingWhitespaceAndCase()
    {
        var normal = new DefenderRuntimeEvidence(
            " normal ", AntivirusEnabled: true, RealTimeProtectionEnabled: true);
        var passive = new DefenderRuntimeEvidence(
            " Passive ", AntivirusEnabled: true, RealTimeProtectionEnabled: true);

        Assert.True(normal.SupportsControlledFolderAccessProtection);
        Assert.Equal(
            ControlledFolderAccessConcern.Protecting,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, normal));
        Assert.False(passive.SupportsControlledFolderAccessProtection);
        Assert.Equal(
            ControlledFolderAccessConcern.RuntimeRequirementsNotMet,
            ControlledFolderAccessTriage.Concern(ControlledFolderAccessState.Enabled, passive));
    }
}

public sealed class ControlledFolderAccessReaderTests
{
    private static readonly string[] ProtectedFolder = [@"C:\\Users\\alice\\Documents"];
    private static readonly string[] AllowedApplication = [@"C:\\Program Files\\Safe\\safe.exe"];
    private static readonly string[] ElevationSentinel = ["N/A: Must be an administrator to view exclusions"];
    private static readonly string[] NonPathFolder = ["not-a-path"];
    private static readonly string[] AllowedApplicationWithBlank = [@"C:\\Safe\\safe.exe", ""];
    private static readonly string[] ProtectedFoldersWithBlank = [@"C:\\Users\\alice\\Documents", ""];
    private static readonly string[] BlankProtectedFolder = [" "];
    private static readonly string?[] ProtectedFoldersWithNull = [@"C:\\Users\\alice\\Documents", null];

    [Fact]
    public void Read_MapsEveryModeAndPreservesFoldersAndVisibleAllowedApplications()
    {
        var reader = Reader(
            mode: 1,
            protectedFolders: ProtectedFolder,
            allowedApplications: AllowedApplication);

        var posture = reader.Read();

        Assert.Equal(ControlledFolderAccessState.Enabled, posture.State);
        Assert.Equal(ControlledFolderAccessConcern.Protecting, posture.Concern);
        Assert.Equal([@"C:\\Users\\alice\\Documents"], posture.ProtectedFolders);
        Assert.Equal(AllowedApplicationsVisibility.Visible, posture.AllowedApplications.Visibility);
        Assert.Equal([@"C:\\Program Files\\Safe\\safe.exe"], posture.AllowedApplications.Applications);
    }

    [Theory]
    [InlineData(0, ControlledFolderAccessState.Disabled, ControlledFolderAccessConcern.Off)]
    [InlineData(1, ControlledFolderAccessState.Enabled, ControlledFolderAccessConcern.Protecting)]
    [InlineData(2, ControlledFolderAccessState.Audit, ControlledFolderAccessConcern.AuditOnly)]
    [InlineData(3, ControlledFolderAccessState.BlockDiskModificationOnly, ControlledFolderAccessConcern.BlockDiskModificationOnly)]
    [InlineData(4, ControlledFolderAccessState.AuditDiskModificationOnly, ControlledFolderAccessConcern.AuditDiskModificationOnly)]
    public void Read_MapsAllDocumentedModesThroughTheDataSourceSeam(
        int rawMode,
        ControlledFolderAccessState expectedState,
        ControlledFolderAccessConcern expectedConcern)
    {
        var posture = Reader(mode: rawMode).Read();

        Assert.Equal(expectedState, posture.State);
        Assert.Equal(expectedConcern, posture.Concern);
        Assert.Equal(expectedConcern != ControlledFolderAccessConcern.Protecting, posture.IsNotable);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(99)]
    public void Read_UnsupportedRawMode_IsUnknownNotableAndRetainsTheRawValue(int rawMode)
    {
        var posture = Reader(mode: rawMode).Read();

        Assert.Equal(ControlledFolderAccessState.Unknown, posture.State);
        Assert.Equal(ControlledFolderAccessConcern.UnknownMode, posture.Concern);
        Assert.Equal(rawMode, posture.RawStateValue);
        Assert.True(posture.IsNotable);
    }

    [Fact]
    public void Read_RealTimeProtectionDisabled_IsNotReportedAsProtecting()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            Preference(1, null, null),
            Runtime("Normal", true, false))));

        var posture = reader.Read();

        Assert.Equal(ControlledFolderAccessState.Enabled, posture.State);
        Assert.Equal(ControlledFolderAccessConcern.RuntimeRequirementsNotMet, posture.Concern);
        Assert.True(posture.IsNotable);
    }

    [Fact]
    public void Read_AllowedApplicationsElevationSentinel_IsNotMistakenForAnEmptyVisibleList()
    {
        var posture = Reader(
                mode: 1,
                allowedApplications: ElevationSentinel)
            .Read();

        Assert.Equal(AllowedApplicationsVisibility.RequiresElevation, posture.AllowedApplications.Visibility);
        Assert.Empty(posture.AllowedApplications.Applications);
    }

    [Theory]
    [InlineData(" N/A: Must be an administrator to view exclusions")]
    [InlineData("N/A: Must be an administrator to view exclusions ")]
    public void Read_PaddedElevationSentinel_IsUnavailableNotNormalisedIntoAnElevationRefusal(string value)
    {
        AssertUnavailable(Reader(mode: 1, allowedApplications: value).Read());
    }

    [Fact]
    public void Read_ArbitraryProviderNAString_IsUnavailableNotAnElevationRefusal()
    {
        var posture = Reader(mode: 1, allowedApplications: "N/A: provider failure").Read();

        AssertUnavailable(posture);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Read_BlankAllowedApplicationsString_IsUnavailable(string value)
    {
        AssertUnavailable(Reader(mode: 1, allowedApplications: value).Read());
    }

    [Fact]
    public void Read_AllowedApplicationsArrayContainingABlankValue_IsUnavailable()
    {
        AssertUnavailable(Reader(mode: 1, allowedApplications: AllowedApplicationWithBlank).Read());
    }

    [Fact]
    public void Read_AllowedApplicationsWithAnUnrecognisedProviderValue_IsUnavailable()
    {
        var posture = Reader(mode: 1, allowedApplications: 42).Read();

        Assert.Equal(ControlledFolderAccessState.Unavailable, posture.State);
        Assert.Equal(ControlledFolderAccessConcern.Unavailable, posture.Concern);
        Assert.Equal(AllowedApplicationsVisibility.Unavailable, posture.AllowedApplications.Visibility);
        Assert.Empty(posture.AllowedApplications.Applications);
    }

    [Fact]
    public void Read_ProtectedFoldersWithAnUnrecognisedProviderValue_IsUnavailable()
    {
        var posture = Reader(mode: 1, protectedFolders: NonPathFolder).Read();

        AssertUnavailable(posture);
    }

    [Theory]
    [MemberData(nameof(MalformedProtectedFolderArrays))]
    public void Read_ProtectedFoldersContainingBlankOrNull_IsUnavailable(string?[] folders)
    {
        AssertUnavailable(Reader(mode: 1, protectedFolders: folders).Read());
    }

    [Fact]
    public void Read_UnexpectedRuntimeMode_IsUnavailable()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(new ControlledFolderAccessWmiSnapshot(
            Preference(1, null, null),
            Runtime("UnexpectedMode", true, true))));

        AssertUnavailable(reader.Read());
    }

    [Fact]
    public void Read_MissingPreferenceRow_IsUnavailableAndNeverClaimedProtecting()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(
            new ControlledFolderAccessWmiSnapshot(
                Preference: null,
                Runtime: Runtime("Passive Mode", false, false))));

        var posture = reader.Read();

        AssertUnavailable(posture);
    }

    [Fact]
    public void Read_MissingRuntimeRow_IsUnavailableRatherThanClaimingProtection()
    {
        var reader = new ControlledFolderAccessReader(new SnapshotSource(
            new ControlledFolderAccessWmiSnapshot(
                Preference: Preference(1, Array.Empty<string>(), Array.Empty<string>()),
                Runtime: null)));

        AssertUnavailable(reader.Read());
    }

    [Fact]
    public void Read_ProviderFailure_IsUnavailableAndNotable()
    {
        var reader = new ControlledFolderAccessReader(new ThrowingSource(new InvalidOperationException("provider unavailable")));

        AssertUnavailable(reader.Read());
    }

    [Fact]
    public void Read_PreCancelledToken_PropagatesCancellationBeforeQueryingTheProvider()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var source = new SnapshotSource(Snapshot(1));
        var reader = new ControlledFolderAccessReader(source);

        Assert.Throws<OperationCanceledException>(() => reader.Read(cancellation.Token));
        Assert.False(source.WasRead);
    }

    [Fact]
    public void WmiDataSource_SearcherUsesFiniteSynchronousNonRewindableSelectEnumeration()
    {
        var factory = typeof(WmiControlledFolderAccessDataSource).GetMethod(
            "CreateSearcher",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.NotNull(factory);
        using var searcher = Assert.IsType<ManagementObjectSearcher>(factory.Invoke(
            null,
            [new ManagementScope(@"\\.\root\Microsoft\Windows\Defender"), "SELECT Name FROM Test"]));

        var timeout = searcher.Options.Timeout;
        Assert.InRange(timeout, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(5));
        Assert.False(searcher.Options.ReturnImmediately);
        Assert.False(searcher.Options.Rewindable);
        Assert.StartsWith("SELECT ", searcher.Query.QueryString, StringComparison.Ordinal);
    }

    private static ControlledFolderAccessReader Reader(
        int mode,
        object? protectedFolders = null,
        object? allowedApplications = null) =>
        new(new SnapshotSource(Snapshot(mode, protectedFolders, allowedApplications)));

    private static ControlledFolderAccessWmiSnapshot Snapshot(
        int mode,
        object? protectedFolders = null,
        object? allowedApplications = null) => new(
        Preference(mode, protectedFolders, allowedApplications),
        Runtime("Normal", true, true));

    private static ControlledFolderAccessRawPreference Preference(
        object? mode,
        object? protectedFolders,
        object? allowedApplications) => new(mode, protectedFolders, allowedApplications);

    private static ControlledFolderAccessRawRuntime Runtime(
        object? mode,
        object? antivirusEnabled,
        object? realTimeProtectionEnabled) => new(mode, antivirusEnabled, realTimeProtectionEnabled);

    public static TheoryData<string?[]> MalformedProtectedFolderArrays => new(
        ProtectedFoldersWithBlank,
        BlankProtectedFolder,
        ProtectedFoldersWithNull);

    private static void AssertUnavailable(ControlledFolderAccessPosture posture)
    {
        Assert.Equal(ControlledFolderAccessState.Unavailable, posture.State);
        Assert.Equal(ControlledFolderAccessConcern.Unavailable, posture.Concern);
        Assert.Equal(AllowedApplicationsVisibility.Unavailable, posture.AllowedApplications.Visibility);
        Assert.True(posture.IsNotable);
    }

    private sealed class SnapshotSource(ControlledFolderAccessWmiSnapshot snapshot) : IControlledFolderAccessDataSource
    {
        public bool WasRead { get; private set; }

        public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken)
        {
            WasRead = true;
            cancellationToken.ThrowIfCancellationRequested();
            return snapshot;
        }
    }

    private sealed class ThrowingSource(Exception exception) : IControlledFolderAccessDataSource
    {
        public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken) => throw exception;
    }
}
