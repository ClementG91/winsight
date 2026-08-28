using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// One act by the operator should produce one alert.
/// </summary>
/// <remarks>
/// Guardian raised a tray balloon per new autostart entry, and an ordinary software installation
/// creates several at once - a service, a scheduled task, a Run key, a COM registration. Six
/// balloons in a few seconds is not six times the information; it is how somebody learns to dismiss
/// this product's alerts without reading them, and the one that matters then arrives in the same
/// shape as the five that did not. Alert fatigue is a security failure, not a presentation one.
/// </remarks>
public sealed class GuardianAlertBatcherTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static PersistenceEvent Detection(string name, bool notable)
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            name,
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            $@"C:\Program Files\Vendor\{name}.exe",
            ImagePath: $@"C:\Program Files\Vendor\{name}.exe",
            ExpectedImagePath: $@"C:\Program Files\Vendor\{name}.exe",
            ImageResolutionStatus.Present,
            notable
                ? SignatureVerdict.Unsigned
                : new SignatureVerdict(SignatureState.SignedTrusted, "CN=Vendor"));
        return new PersistenceEvent(
            PersistenceIdentity.FromEntry(entry), entry, T0, T0, Observations: 1);
    }

    [Fact]
    public void OneDetectionIsAnnouncedAsItself()
    {
        var batch = GuardianAlertBatcher.Describe([Detection("a", notable: false)]);

        Assert.True(batch.IsSingle);
        Assert.Equal(1, batch.Count);
        Assert.NotNull(batch.Single);
    }

    [Fact]
    public void SeveralDetectionsBecomeOneCountedAnnouncement()
    {
        var batch = GuardianAlertBatcher.Describe(
        [
            Detection("a", notable: false),
            Detection("b", notable: false),
            Detection("c", notable: false),
        ]);

        Assert.False(batch.IsSingle);
        Assert.Equal(3, batch.Count);
        Assert.Equal(0, batch.NotableCount);
        Assert.False(batch.IsNotable);
    }

    /// <summary>
    /// A batch containing anything notable is announced as notable. Merging a real finding into a
    /// calm summary would be worse than the fatigue it was meant to cure.
    /// </summary>
    [Fact]
    public void ANotableArrivalIsNeverMergedIntoSilence()
    {
        var batch = GuardianAlertBatcher.Describe(
        [
            Detection("a", notable: false),
            Detection("b", notable: false),
            Detection("c", notable: true),
        ]);

        Assert.True(batch.IsNotable);
        Assert.Equal(1, batch.NotableCount);
    }

    /// <summary>
    /// The notable one leads, so a batch of six whose sixth is the interesting one does not present
    /// the first as its representative when the operator clicks through.
    /// </summary>
    [Fact]
    public void TheNotableDetectionRepresentsTheBatch()
    {
        var batch = GuardianAlertBatcher.Describe(
        [
            Detection("boring", notable: false),
            Detection("interesting", notable: true),
        ]);

        Assert.Equal("interesting", batch.Single!.Entry.Name);
    }

    [Fact]
    public void AnEmptyBatchAnnouncesNothing()
    {
        var batch = GuardianAlertBatcher.Describe([]);

        Assert.Equal(0, batch.Count);
        Assert.False(batch.IsSingle);
        Assert.False(batch.IsNotable);
    }

    /// <summary>
    /// The single-entry path keeps the existing keys, so nothing about a lone detection changes.
    /// </summary>
    [Theory]
    [InlineData(true, "GuardianDetectedNotable")]
    [InlineData(false, "GuardianDetectedSigned")]
    public void OneDetectionKeepsItsExistingMessage(bool notable, string expected) =>
        Assert.Equal(
            expected,
            GuardianAlertBatcher.BalloonMessageKey(
                GuardianAlertBatcher.Describe([Detection("a", notable)])));

    [Theory]
    [InlineData(true, "GuardianDetectedBatchNotable")]
    [InlineData(false, "GuardianDetectedBatchSigned")]
    public void ABatchGetsItsOwnMessage(bool notable, string expected) =>
        Assert.Equal(
            expected,
            GuardianAlertBatcher.BalloonMessageKey(
                GuardianAlertBatcher.Describe([Detection("a", notable), Detection("b", false)])));

    /// <summary>
    /// Long enough to cover an installer writing several surfaces, short enough that a real alert is
    /// not noticeably delayed.
    /// </summary>
    [Fact]
    public void TheWindowIsSecondsRatherThanMinutes()
    {
        Assert.True(GuardianAlertBatcher.DefaultWindow > TimeSpan.FromSeconds(1));
        Assert.True(GuardianAlertBatcher.DefaultWindow <= TimeSpan.FromSeconds(10));
    }
}
