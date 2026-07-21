using WinSight.Hosts;

using Xunit;

namespace WinSight.Hosts.Tests;

/// <summary>
/// "The hosts file has no entries" and "the hosts file could not be read" must not render the same.
/// </summary>
/// <remarks>
/// On Windows the hosts file is readable by every user by default, so a refusal means its
/// permissions were changed. That is exactly what someone who has just pointed a bank or an update
/// server at their own address would do next, and the reader used to answer both cases with an
/// empty list — reported as "0 entries, 0 flagged", a clean bill of health over an unknown file.
/// </remarks>
public sealed class HostsReadabilityTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-hosts-{Guid.NewGuid():N}");

    public HostsReadabilityTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void AReadableFileIsNeitherMissingNorUnreadable()
    {
        var path = Path.Combine(_directory, "hosts");
        File.WriteAllLines(path, ["# comment", "127.0.0.1  telemetry.example.com"]);

        var snapshot = new HostsReader(path).Read();

        Assert.False(snapshot.Unreadable);
        Assert.False(snapshot.Missing);
        Assert.Single(snapshot.Entries);
    }

    [Fact]
    public void AReadableButEmptyFileIsNotUnreadable()
    {
        // The honest "nothing to report" case, which must stay quiet.
        var path = Path.Combine(_directory, "hosts");
        File.WriteAllLines(path, ["# only comments here"]);

        var snapshot = new HostsReader(path).Read();

        Assert.False(snapshot.Unreadable);
        Assert.Empty(snapshot.Entries);
    }

    [Fact]
    public void AnAbsentFileIsMissing_NotUnreadable()
    {
        // Windows works fine without the file; absent is normal and must not raise anything.
        var snapshot = new HostsReader(Path.Combine(_directory, "does-not-exist")).Read();

        Assert.True(snapshot.Missing);
        Assert.False(snapshot.Unreadable);
        Assert.Empty(snapshot.Entries);
    }

    [Fact]
    public void AFileThatCannotBeOpenedIsReportedAsUnreadable()
    {
        // Exclusive-locked stands in for permission-denied: both surface as the same refusal to the
        // reader, and a real ACL change cannot be made portably from a test.
        var path = Path.Combine(_directory, "hosts");
        File.WriteAllLines(path, ["127.0.0.1  bank.example.com"]);
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);

        var snapshot = new HostsReader(path).Read();

        Assert.True(snapshot.Unreadable);
        Assert.False(snapshot.Missing);
        Assert.Empty(snapshot.Entries);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
