using WinSight.Attribution;
using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The live NT-device to drive-letter mapping every kernel path is translated through.
/// </summary>
/// <remarks>
/// <b>Why this had no tests.</b> <see cref="KernelPathNormalizer"/> is deliberately pure and is
/// tested exhaustively against invented machine layouts - which is right, and which is also why the
/// one component that reads the real layout was never exercised at all. If <c>Current()</c> returns
/// an empty map, every ETW file path stays in <c>\Device\HarddiskVolumeN\</c> form, the normaliser
/// has nothing to match, and file attributions silently stop resolving. The pure half would still
/// pass every one of its tests.
///
/// These assertions hold on any Windows machine: they check the shape and the invariants, not this
/// machine's particular volumes.
/// </remarks>
public sealed class VolumeMapTests
{
    [Fact]
    public void TheSystemDriveIsMappedToADevice()
    {
        var systemDrive = Path.GetPathRoot(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows))!.TrimEnd('\\');

        var map = VolumeMap.Current();

        Assert.Contains(map, entry =>
            string.Equals(entry.Value, systemDrive, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Keys are NT device names and values are drive letters, in that order. Inverting them is a
    /// mistake that would leave the map looking populated while matching nothing, because the
    /// normaliser looks up the device.
    /// </summary>
    [Fact]
    public void KeysAreDevicesAndValuesAreDriveLetters()
    {
        var map = VolumeMap.Current();

        Assert.NotEmpty(map);
        Assert.All(map, entry =>
        {
            Assert.StartsWith(@"\Device\", entry.Key, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(2, entry.Value.Length);
            Assert.Equal(':', entry.Value[1]);
        });
    }

    /// <summary>
    /// Two letters can name one device - a SUBST, or a folder mounted at a second letter. The map
    /// keeps the first, so a machine with one cannot produce a duplicate key or a different answer
    /// between two reads.
    /// </summary>
    [Fact]
    public void OneDeviceMapsToOneLetterAndTheAnswerIsStable()
    {
        var first = VolumeMap.Current();
        var second = VolumeMap.Current();

        Assert.Equal(first.Count, second.Count);
        foreach (var entry in first)
        {
            Assert.Equal(entry.Value, second[entry.Key]);
        }
    }

    /// <summary>
    /// The lookup is case-insensitive, because ETW reports the device name in whatever casing the
    /// kernel used and a case-sensitive map would drop the attribution rather than resolve it.
    /// </summary>
    [Fact]
    public void TheLookupIgnoresCase()
    {
        var map = VolumeMap.Current();
        var device = map.Keys.First();

        Assert.True(map.ContainsKey(device.ToUpperInvariant()));
        Assert.True(map.ContainsKey(device.ToLowerInvariant()));
    }

    /// <summary>
    /// The end-to-end claim: what this map reads is what the normaliser consumes, so a kernel path
    /// on the system volume must come back as a real, rooted Win32 path.
    /// </summary>
    [Fact]
    public void AKernelPathOnTheSystemVolumeNormalizesToAWin32Path()
    {
        var map = VolumeMap.Current();
        var systemDrive = Path.GetPathRoot(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows))!.TrimEnd('\\');
        var device = map.First(entry =>
            string.Equals(entry.Value, systemDrive, StringComparison.OrdinalIgnoreCase)).Key;

        var normalized = new KernelPathNormalizer(map)
            .NormalizeFilePath($@"{device}\Windows\System32\ntdll.dll");

        Assert.Equal($@"{systemDrive}\Windows\System32\ntdll.dll", normalized);
    }
}
