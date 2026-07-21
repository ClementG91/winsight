using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The candidate list is the finding. "This service path is unquoted" is a lint result; "anyone who
/// can write C:\Program.exe owns this SYSTEM service" is something an operator can act on, and
/// getting the list wrong sends them to inspect an innocent file.
/// </summary>
public sealed class UnquotedPathTests
{
    [Fact]
    public void NamesEveryPathTriedBeforeTheIntendedBinary()
    {
        var candidates = UnquotedPath.HijackCandidates(@"C:\Program Files\My App\svc.exe -k net");

        Assert.Equal(
            [@"C:\Program.exe", @"C:\Program Files\My.exe"],
            candidates);
    }

    // The sequence Microsoft documents for CreateProcess with a null application name: it splits at
    // each space, not at each directory. Order matters operationally — the first writable candidate
    // is the one that wins, so it is the one to go and look at.
    [Fact]
    public void ListsCandidatesInTheOrderWindowsTriesThem()
    {
        var candidates = UnquotedPath.HijackCandidates(@"c:\program files\sub dir\program name.exe");

        Assert.Equal(
            [@"c:\program.exe", @"c:\program files\sub.exe", @"c:\program files\sub dir\program.exe"],
            candidates);
    }

    // A space inside a directory name creates a candidate; a backslash does not. Getting this
    // backwards would invent a finding per directory level on every service on the machine.
    [Fact]
    public void OnlySpacesSplit_NotDirectorySeparators()
    {
        var candidates = UnquotedPath.HijackCandidates(@"C:\a b c\d\svc.exe");

        Assert.Equal([@"C:\a.exe", @"C:\a b.exe"], candidates);
    }

    // The common, correct case — and the fix an operator applies. It must read as safe.
    [Fact]
    public void AQuotedImageIsNotHijackable()
    {
        Assert.False(UnquotedPath.IsHijackable(@"""C:\Program Files\My App\svc.exe"" -k net"));
        Assert.Empty(UnquotedPath.HijackCandidates(@"""C:\Program Files\My App\svc.exe"""));
    }

    [Fact]
    public void APathWithoutSpacesIsNotHijackable()
    {
        Assert.False(UnquotedPath.IsHijackable(@"C:\Windows\System32\svchost.exe -k netsvcs"));
    }

    // A driver's ImagePath is an NT path loaded by the kernel, not by CreateProcess, so the prefix
    // rule does not apply. Flagging every driver on the machine would drown the real findings.
    [Theory]
    [InlineData(@"\SystemRoot\System32\drivers\my driver.sys")]
    [InlineData(@"\??\C:\Program Files\thing\drv.sys")]
    public void ADriverNtPathIsNotHijackable(string imagePath) =>
        Assert.False(UnquotedPath.IsHijackable(imagePath));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NothingToReadIsNotAFinding(string? commandLine) =>
        Assert.False(UnquotedPath.IsHijackable(commandLine));

    // Without an .exe there is no way to tell where the executable ends, and a guess would name an
    // innocent file as the thing to inspect.
    [Fact]
    public void ACommandLineWithNoExecutableNameIsRefused() =>
        Assert.Empty(UnquotedPath.HijackCandidates(@"C:\some path\thing --flag"));

    [Fact]
    public void DoesNotTreatAnExeSubstringAsTheExecutable() =>
        Assert.Empty(UnquotedPath.HijackCandidates(@"C:\my folder\svc.exefoo"));

    // A relative fragment is not something CreateProcess resolves to a plantable file here, and
    // listing it would send an operator looking for a path that does not exist.
    [Fact]
    public void OnlyRootedPrefixesBecomeCandidates()
    {
        var candidates = UnquotedPath.HijackCandidates(@"my app\svc.exe");

        Assert.Empty(candidates);
    }

    [Fact]
    public void ArgumentsAfterTheExecutableDoNotBecomeCandidates()
    {
        // "-k" and "net" are arguments, not prefixes of the image; including them would invent two
        // findings per service.
        var candidates = UnquotedPath.HijackCandidates(@"C:\Program Files\App\svc.exe -k net");

        Assert.Equal([@"C:\Program.exe"], candidates);
    }
}
