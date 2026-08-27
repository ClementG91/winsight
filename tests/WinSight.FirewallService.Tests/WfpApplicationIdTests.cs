using System.Text;

using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The application-id fallback that stops one unresolvable path from disarming the whole policy.
/// </summary>
/// <remarks>
/// <b>The defect.</b> <c>FwpmGetAppIdFromFileName0</c> opens the target file to learn its volume, so
/// it fails as soon as the binary is gone. Every WFP call site turned that into a
/// <c>Win32Exception</c>, which the coordinator classifies as a failed transition, which rolls the
/// entire policy back to audit-only, deletes every filter and returns the service to demand-start.
/// Deleting one's own blocked binary and provoking a reconcile therefore disarmed outbound
/// enforcement for every application on the machine, persistently and without privilege.
///
/// <b>What is asserted here.</b> The id is a path, not a handle, so the same bytes are rebuilt from
/// the volume mapping — which is what makes the filter outlive the file, and makes the block still
/// be in force when the application comes back. These tests pin the byte-level shape (lower case,
/// UTF-16, null-terminated) because a filter built from a subtly wrong id installs cleanly and
/// silently matches nothing, which is worse than the failure it replaces.
/// </remarks>
public sealed class WfpApplicationIdTests
{
    private static string? FixedVolume(string drive) =>
        drive.Equals("C:", StringComparison.OrdinalIgnoreCase) ? @"\Device\HarddiskVolume3" : null;

    [Fact]
    public void ADrivePathBecomesItsNtDevicePath()
    {
        Assert.True(WfpApplicationId.TryDerive(@"C:\Apps\Agent.exe", FixedVolume, out var appId));

        Assert.Equal(@"\device\harddiskvolume3\apps\agent.exe", Decode(appId));
    }

    /// <summary>
    /// WFP compares ids as raw bytes and its own are lower-cased and null-terminated, so both are
    /// part of the value rather than presentation.
    /// </summary>
    [Fact]
    public void TheIdIsLowerCasedUtf16AndNullTerminated()
    {
        Assert.True(WfpApplicationId.TryDerive(@"C:\A.exe", FixedVolume, out var appId));

        const string Expected = @"\device\harddiskvolume3\a.exe";
        Assert.Equal((Expected.Length + 1) * 2, appId.Length);
        Assert.Equal(Encoding.Unicode.GetBytes(Expected), appId[..(Expected.Length * 2)]);
        Assert.Equal(0, appId[^1]);
        Assert.Equal(0, appId[^2]);
    }

    [Fact]
    public void AnNtPathIsAcceptedAsAlreadyResolved()
    {
        Assert.True(WfpApplicationId.TryDerive(
            @"\Device\HarddiskVolume7\Tools\X.exe", _ => null, out var appId));

        Assert.Equal(@"\device\harddiskvolume7\tools\x.exe", Decode(appId));
    }

    /// <summary>
    /// A path with no volume must be refused rather than guessed: an invented id installs a filter
    /// that matches nothing while the status claims the application is blocked, which is a false
    /// assurance and strictly worse than reporting the block as inapplicable.
    /// </summary>
    [Theory]
    [InlineData(@"\\server\share\a.exe")]
    [InlineData(@"Z:\gone\a.exe")]
    [InlineData("a.exe")]
    [InlineData(@"C:")]
    [InlineData("")]
    [InlineData("   ")]
    public void APathWithNoResolvableVolumeIsRefused(string path) =>
        Assert.False(WfpApplicationId.TryDerive(path, FixedVolume, out _));

    /// <summary>A resolver that answers with something that is not a device path is not trusted.</summary>
    [Theory]
    [InlineData("")]
    [InlineData(@"C:\somewhere")]
    public void AResolverAnswerThatIsNotADevicePathIsRefused(string answer) =>
        Assert.False(WfpApplicationId.TryDerive(@"C:\a.exe", _ => answer, out _));

    [Fact]
    public void AResolverThatThrowsIsRefusedRatherThanPropagated() =>
        Assert.False(WfpApplicationId.TryDerive(
            @"C:\a.exe",
            _ => throw new System.ComponentModel.Win32Exception(1),
            out _));

    /// <summary>Forward slashes are legal in Win32 paths and must not survive into an NT path.</summary>
    [Fact]
    public void ForwardSlashesAreNormalised()
    {
        Assert.True(WfpApplicationId.TryDerive("C:/Apps/Agent.exe", FixedVolume, out var appId));

        Assert.Equal(@"\device\harddiskvolume3\apps\agent.exe", Decode(appId));
    }

    /// <summary>
    /// The live resolver must agree with the fixture on this machine's own system drive, or the
    /// fixture is testing a shape the product never produces.
    /// </summary>
    [Fact]
    public void TheLiveResolverProducesADevicePathForTheSystemDrive()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);

        Assert.True(WfpApplicationId.TryDerive(Path.Combine(system, "cmd.exe"), out var appId));

        var text = Decode(appId);
        Assert.StartsWith(@"\device\", text, StringComparison.Ordinal);
        Assert.EndsWith(@"\cmd.exe", text, StringComparison.Ordinal);
        Assert.Equal(text, text.ToLowerInvariant());
    }

    /// <summary>
    /// The whole point: an application that no longer exists still yields an id, so its filter is
    /// installed and verified instead of failing the transition that holds every other block.
    /// </summary>
    [Fact]
    public void AMissingBinaryStillYieldsAnId()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"winsight-absent-{Guid.NewGuid():N}.exe");
        Assert.False(File.Exists(missing));

        Assert.True(WfpApplicationId.TryDerive(missing, out var appId));
        Assert.NotEmpty(appId);
    }

    private static string Decode(byte[] appId) =>
        Encoding.Unicode.GetString(appId, 0, appId.Length - 2);
}
