using Xunit;

namespace WinSight.Core.Tests;

public sealed class AcquisitionSnapshotTests
{
    [Fact]
    public void CompleteOnlyWhenNoCoverageGapWasRecorded()
    {
        Assert.True(new AcquisitionSnapshot<int>([1]).IsComplete);
        Assert.False(new AcquisitionSnapshot<int>([1], unreadableSources: 1).IsComplete);
        Assert.False(new AcquisitionSnapshot<int>([1], unreadableItems: 1).IsComplete);
    }

    [Fact]
    public void RejectsInvalidCoverageMetadata()
    {
        Assert.Throws<ArgumentNullException>(() => new AcquisitionSnapshot<int>(null!));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new AcquisitionSnapshot<int>([], unreadableSources: -1));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new AcquisitionSnapshot<int>([], unreadableItems: -1));
    }
}
