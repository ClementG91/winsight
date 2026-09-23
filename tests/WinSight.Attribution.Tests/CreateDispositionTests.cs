using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// An open is not a write. Measured in the VM: after a program dropped a Startup-folder shortcut,
/// the shell and Defender opened it to look at it, those opens were recorded as writes, and the
/// newest-write rule would have named them as its author.
/// </summary>
public sealed class CreateDispositionTests
{
    [Fact]
    public void OpeningAnExistingFileIsNotAWrite() =>
        Assert.False(WriteAttributionWatcher.CreateCanWrite(CreateDisposition.OPEN_EXISTING));

    [Theory]
    [InlineData(CreateDisposition.SUPERSEDE)]
    [InlineData(CreateDisposition.CREATE_NEW)]
    [InlineData(CreateDisposition.OPEN_ALWAYS)]
    [InlineData(CreateDisposition.TRUNCATE_EXISTING)]
    [InlineData(CreateDisposition.CREATE_ALWAYS)]
    public void EveryDispositionThatCanCreateOrReplaceIsAWrite(CreateDisposition disposition) =>
        Assert.True(WriteAttributionWatcher.CreateCanWrite(disposition));

    /// <summary>
    /// Why only the newest write matters: a read-only opener recorded after the real writer would
    /// have been returned in its place.
    /// </summary>
    [Fact]
    public void AnOpenerRecordedAfterTheWriterWouldHaveTakenItsPlace()
    {
        var index = new WriteAttributionIndex();
        var now = DateTimeOffset.UtcNow;
        const string Target = @"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk";
        index.Record(new WriteObservation(now.AddSeconds(-3), 100, @"C:\dropper.exe", Target));
        if (WriteAttributionWatcher.CreateCanWrite(CreateDisposition.OPEN_EXISTING))
        {
            index.Record(new WriteObservation(now.AddSeconds(-2), 200, @"C:\Windows\System32\sihost.exe", Target));
        }

        Assert.Equal(@"C:\dropper.exe", index.Attribute(Target, now)?.ExecutablePath);
    }
}
