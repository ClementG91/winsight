using WinSight.Application;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class AdaptersSignatureTests
{
    [Fact]
    public void DescribeSignatureReportsAnUnsignedLocalFileAsNotableWithHashes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"winsight-sign-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, [0xDE, 0xAD, 0xBE, 0xEF]);
        try
        {
            var report = Adapters.DescribeSignature(path);

            Assert.Equal("signature", report.Tool);
            var item = Assert.Single(report.Items);
            Assert.Equal(Severity.Notable, item.Severity); // unsigned is noteworthy
            Assert.Equal("signature", item.Fields["kind"]);
            Assert.Equal("Unsigned", item.Fields["state"]);
            Assert.False(string.IsNullOrEmpty(item.Fields["sha256"]));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DescribeSignatureRefusesANonLocalArgument()
    {
        var report = Adapters.DescribeSignature(@"\\server\share\evil.exe");

        var item = Assert.Single(report.Items);
        Assert.Equal(Severity.Notable, item.Severity);
        Assert.Equal("signatureTarget", item.Fields["kind"]);
        Assert.Equal(1, report.NotableCount);
    }
}
