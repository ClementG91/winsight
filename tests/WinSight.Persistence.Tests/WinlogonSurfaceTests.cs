using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Which Winlogon values the scan reads.
/// </summary>
/// <remarks>
/// <b>What was missing.</b> Only Shell and Userinit were read, and the surface was named as though
/// those were the whole of it. Three more values on the same key launch a program around sign-in
/// and were invisible: <c>Taskman</c>, which Winlogon runs instead of Task Manager - persistence
/// and a way to stop somebody looking at the process list, in one value; <c>AppSetup</c>, which
/// userinit runs at every logon before the shell; and <c>UIHost</c>, launched as SYSTEM before
/// anybody has signed in.
///
/// They are absent on an ordinary machine - they were absent on the desktop this was written on -
/// which is exactly why nothing noticed they were unread. A value that only exists when somebody
/// set it is a value worth reading.
/// </remarks>
public sealed class WinlogonSurfaceTests
{
    [Theory]
    [InlineData("Shell")]
    [InlineData("Userinit")]
    [InlineData("Taskman")]
    [InlineData("AppSetup")]
    [InlineData("UIHost")]
    public void TheValuesWindowsExecutesAreRead(string value) =>
        Assert.Contains(value, WinlogonEnumerator.ExecutedValues, StringComparer.Ordinal);

    /// <summary>
    /// Values Windows has not executed since Vista are deliberately absent. Enumerating one would
    /// add a finding an operator cannot act on, which costs more than the coverage is worth.
    /// </summary>
    [Theory]
    [InlineData("GinaDLL")]
    [InlineData("Notify")]
    [InlineData("VmApplet")]
    public void LegacyValuesModernWindowsIgnoresAreNot(string value) =>
        Assert.DoesNotContain(value, WinlogonEnumerator.ExecutedValues, StringComparer.Ordinal);

    [Fact]
    public void TheSetIsExactlyTheFiveExecutedValues() =>
        Assert.Equal(5, WinlogonEnumerator.ExecutedValues.Count);

    /// <summary>
    /// Every value is comma-split, because the hijack is appending to a value that already holds
    /// the default. A value read whole would judge "explorer.exe,evil.exe" as one command whose
    /// leading token is explorer.
    /// </summary>
    [Fact]
    public void AnAppendedPayloadIsSplitOutFromTheDefault()
    {
        var commands = WinlogonEnumerator.SplitCommands(@"explorer.exe,C:\Users\Public\evil.exe");

        Assert.Equal(["explorer.exe", @"C:\Users\Public\evil.exe"], commands);
    }

    /// <summary>The live scan reads this surface without throwing, whatever this machine holds.</summary>
    [Fact]
    public void TheSurfaceEnumeratesOnThisMachine()
    {
        var entries = new WinlogonEnumerator().Enumerate().ToArray();

        Assert.All(entries, entry => Assert.Equal(AutostartVector.Winlogon, entry.Vector));
        Assert.All(entries, entry => Assert.Contains(
            entry.Name, WinlogonEnumerator.ExecutedValues, StringComparer.Ordinal));
    }
}
