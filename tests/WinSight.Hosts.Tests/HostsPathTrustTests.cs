using Xunit;

namespace WinSight.Hosts.Tests;

[CollectionDefinition("Hosts environment", DisableParallelization = true)]
public sealed class HostsEnvironmentCollection;

[Collection("Hosts environment")]
public sealed class HostsPathTrustTests
{
    [Theory]
    [InlineData(@"C:\untrusted-windows")]
    [InlineData(@"\\untrusted.invalid\windows")]
    public void DefaultPathIgnoresAnInheritedSystemRoot(string poisonedRoot)
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        var previous = Environment.GetEnvironmentVariable("SystemRoot");
        try
        {
            Environment.SetEnvironmentVariable("SystemRoot", poisonedRoot);

            Assert.Equal(expected, HostsReader.DefaultPath());
            // Not tautological: the expected path was computed before poisoning the variable.
            Assert.DoesNotContain("untrusted", HostsReader.DefaultPath(), StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SystemRoot", previous);
        }
    }

    [Theory]
    [InlineData(@"\\untrusted.invalid\share\hosts")]
    [InlineData(@"\\?\UNC\untrusted.invalid\share\hosts")]
    [InlineData(@"\Device\Mup\untrusted.invalid\share\hosts")]
    public void ARemoteSourceIsUnavailableWithoutAFileRead(string path)
    {
        var snapshot = new HostsReader(path).Read();

        Assert.True(snapshot.Unreadable);
        Assert.False(snapshot.Missing);
        Assert.Empty(snapshot.Entries);
    }
}
