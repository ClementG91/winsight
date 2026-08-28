using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Two ways to walk past the command-line triage that cost an attacker almost nothing.
/// </summary>
public sealed class InterpreterEvasionTests
{
    /// <summary>
    /// PowerShell resolves any unambiguous prefix of a parameter name, so <c>-e</c> is
    /// <c>-EncodedCommand</c>. Matching the literal "-enc" meant writing two fewer characters
    /// defeated the rule.
    /// </summary>
    [Theory]
    [InlineData("powershell.exe -e SQBFAFgA")]
    [InlineData("powershell.exe -ec SQBFAFgA")]
    [InlineData("powershell.exe -en SQBFAFgA")]
    [InlineData("powershell.exe -enc SQBFAFgA")]
    [InlineData("powershell.exe -encod SQBFAFgA")]
    [InlineData("powershell.exe -EncodedCommand SQBFAFgA")]
    [InlineData("powershell.exe -nop -w hidden -e SQBFAFgA")]
    [InlineData("powershell.exe /e SQBFAFgA")]
    [InlineData("powershell.exe -e:SQBFAFgA")]
    public void EveryAbbreviationOfEncodedCommandIsCaught(string commandLine) =>
        Assert.Equal(
            InterpreterAbuse.EncodedCommand,
            InterpreterAbuseTriage.Classify("powershell.exe", commandLine));

    /// <summary>
    /// The switch must be a whole token, or an ordinary path containing those letters would be read
    /// as an encoded payload - a false accusation against installed software.
    /// </summary>
    [Theory]
    [InlineData(@"powershell.exe -File C:\tools\-encoder\build.ps1")]
    [InlineData(@"powershell.exe -File C:\enc\run.ps1")]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -File run.ps1")]
    [InlineData("powershell.exe -NoProfile -Command Get-Date")]
    public void AnOrdinaryCommandLineIsNotMistakenForOne(string commandLine) =>
        Assert.Equal(
            InterpreterAbuse.None,
            InterpreterAbuseTriage.Classify("powershell.exe", commandLine));

    [Theory]
    [InlineData("-e x", true)]
    [InlineData("-EncodedCommand x", true)]
    [InlineData("/enc x", true)]
    [InlineData("-encodedcommandy x", false)]
    [InlineData("-execute x", false)]
    [InlineData("something-enc x", false)]
    [InlineData("", false)]
    public void TheSwitchDetectorIsExactAboutTokenBoundaries(string commandLine, bool expected) =>
        Assert.Equal(expected, InterpreterAbuseTriage.ContainsEncodedCommandSwitch(commandLine));

    /// <summary>
    /// Copying powershell.exe to updater.exe (MITRE T1036.003) took the entry out of the interpreter
    /// table entirely, so the rule never ran. The name the vendor compiled into the image survives
    /// the copy.
    /// </summary>
    [Fact]
    public void ARenamedInterpreterIsStillRecognisedByItsCompiledInName()
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            "Updater",
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            @"C:\Users\me\AppData\Local\updater.exe -enc SQBFAFgA",
            ImagePath: @"C:\Users\me\AppData\Local\updater.exe",
            ExpectedImagePath: @"C:\Users\me\AppData\Local\updater.exe",
            ImageResolutionStatus.Present,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Windows"),
            OriginalFileName: "PowerShell.EXE");

        Assert.Equal(InterpreterAbuse.EncodedCommand, entry.Abuse);
        Assert.True(entry.IsSuspicious);
    }

    /// <summary>
    /// And a file whose compiled-in name is ordinary is not promoted into the table by it, so the
    /// addition cannot manufacture findings.
    /// </summary>
    [Fact]
    public void AnOrdinaryCompiledInNameChangesNothing()
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            "Vendor",
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            @"C:\Program Files\Vendor\agent.exe --service",
            ImagePath: @"C:\Program Files\Vendor\agent.exe",
            ExpectedImagePath: @"C:\Program Files\Vendor\agent.exe",
            ImageResolutionStatus.Present,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Vendor"),
            OriginalFileName: "agent.exe");

        Assert.Equal(InterpreterAbuse.None, entry.Abuse);
        Assert.False(entry.IsSuspicious);
    }

    /// <summary>The field is optional, so every existing construction site keeps its behaviour.</summary>
    [Fact]
    public void WithoutACompiledInNameTheFileNameStillDecides()
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            "x",
            @"HKCU\...\Run",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc SQBFAFgA",
            ImagePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ExpectedImagePath: null,
            ImageResolutionStatus.Present,
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Windows"));

        Assert.Equal(InterpreterAbuse.EncodedCommand, entry.Abuse);
    }
}
