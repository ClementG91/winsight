using WinSight.Core;

using Xunit;

namespace WinSight.Core.Tests;

/// <summary>
/// WS-40. A file whose data is not on this machine - a cloud-only OneDrive file, an offline file - is
/// unreadable to an automatic read, never fetched. Measured in the VM, a read of a cloud-only
/// placeholder sent its provider two download requests and blocked for two minutes.
/// </summary>
/// <remarks>
/// A Cloud Files placeholder needs a registered sync root, which the VM gate provides. The offline
/// attribute is the same promise ("the data is elsewhere") and can be set on an ordinary NTFS file,
/// so it pins the rule here.
/// </remarks>
public sealed class RemoteDataReadTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"winsight-offline-{Guid.NewGuid():N}.bin");

    public RemoteDataReadTests() => File.WriteAllBytes(_path, [1, 2, 3, 4]);

    public void Dispose()
    {
        try
        {
            File.SetAttributes(_path, FileAttributes.Normal);
            File.Delete(_path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void AnOrdinaryFileIsLocalAndReadable()
    {
        using var lease = AutomaticFileAccess.TryAcquire(_path);

        Assert.NotNull(lease);
        Assert.True(lease.DataIsLocal);
        using var stream = lease.OpenRead();
        Assert.Equal(1, stream.ReadByte());
    }

    [Fact]
    public void AFileMarkedOfflineIsAcquiredButNeverRead()
    {
        File.SetAttributes(_path, File.GetAttributes(_path) | FileAttributes.Offline);

        using var lease = AutomaticFileAccess.TryAcquire(_path);

        // Its metadata stays observable - it exists, it has a size - but its data is not read.
        Assert.NotNull(lease);
        Assert.False(lease.DataIsLocal);
        Assert.Equal(4, lease.Length);
        var refused = Assert.Throws<IOException>(() => lease.OpenRead());
        Assert.Contains("not on this machine", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSignatureReportTreatsAnOfflineFileAsUnreadable()
    {
        File.SetAttributes(_path, File.GetAttributes(_path) | FileAttributes.Offline);

        Assert.Null(new FileSignatureReporter(new NativeSignatureVerifier()).Describe(_path));
    }
}
