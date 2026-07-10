using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

public sealed class CommandLineTests
{
    [Fact]
    public void ExtractExecutable_QuotedPathWithArgs_ReturnsExe()
    {
        var exe = Path.Combine(Path.GetTempPath(), $"winsight_{Guid.NewGuid():N}.exe");
        File.WriteAllText(exe, "stub");
        try
        {
            var cmd = $"\"{exe}\" --run /silent";
            Assert.Equal(Path.GetFullPath(exe), CommandLine.ExtractExecutable(cmd));
        }
        finally
        {
            File.Delete(exe);
        }
    }

    [Fact]
    public void ExtractExecutable_NonExistent_ReturnsNull()
    {
        Assert.Null(CommandLine.ExtractExecutable(@"C:\nope\ghost.exe --x"));
    }

    [Fact]
    public void ExtractExecutable_Empty_ReturnsNull()
    {
        Assert.Null(CommandLine.ExtractExecutable("   "));
        Assert.Null(CommandLine.ExtractExecutable(null));
    }
}

public sealed class SignatureVerifierTests
{
    [Fact]
    public void Verify_MissingFile_IsMissing()
    {
        var v = new SignatureVerifier().Verify(@"C:\does\not\exist.exe");
        Assert.Equal(SignatureState.Missing, v.State);
        Assert.False(v.IsSigned);
    }

    [Fact]
    public void Verify_UnsignedFile_IsUnsigned()
    {
        var f = Path.Combine(Path.GetTempPath(), $"winsight_{Guid.NewGuid():N}.bin");
        File.WriteAllText(f, "not a signed PE");
        try
        {
            var v = new SignatureVerifier().Verify(f);
            Assert.Equal(SignatureState.Unsigned, v.State);
        }
        finally
        {
            File.Delete(f);
        }
    }
}
