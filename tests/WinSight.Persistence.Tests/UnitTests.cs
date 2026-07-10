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

public sealed class WinlogonTests
{
    [Fact]
    public void SplitCommands_DropsEmptiesFromTrailingComma()
    {
        Assert.Equal(new[] { "userinit.exe" }, WinlogonEnumerator.SplitCommands("userinit.exe,"));
    }

    [Fact]
    public void SplitCommands_SplitsAppendedPayload()
    {
        Assert.Equal(
            new[] { "explorer.exe", "C:\\evil.exe" },
            WinlogonEnumerator.SplitCommands("explorer.exe, C:\\evil.exe"));
    }
}

public sealed class ScheduledTaskTests
{
    private const string TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Actions Context="Author">
            <Exec>
              <Command>C:\Windows\System32\notepad.exe</Command>
              <Arguments>/A</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;

    [Fact]
    public void ParseTaskCommands_ExtractsExecCommand_NamespaceAgnostic()
    {
        Assert.Equal(new[] { @"C:\Windows\System32\notepad.exe" },
            ScheduledTaskEnumerator.ParseTaskCommands(TaskXml));
    }

    [Fact]
    public void ParseTaskCommands_InvalidXml_IsEmpty()
    {
        Assert.Empty(ScheduledTaskEnumerator.ParseTaskCommands("<not xml"));
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
