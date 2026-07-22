using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// Which directory the scan probes — and, on a writable machine, names in a finding.
/// </summary>
/// <remarks>
/// This had no coverage at all: <c>ExecutableDirectory</c> is internal and the test project could
/// not see it, so the one function that decides <i>which directory to accuse</i> was never exercised.
/// It also carried its own reading of the command line, taking the first <c>.exe</c> anywhere in the
/// string, while <see cref="UnquotedPath"/> had been hardened to require that <c>.exe</c> end a
/// token. Two parsers of one string in one feature, disagreeing on exactly the inputs the hardening
/// was for.
/// </remarks>
public sealed class ExecutableDirectoryTests
{
    [Theory]
    [InlineData(@"C:\Program Files\App\svc.exe", @"C:\Program Files\App")]
    [InlineData(@"C:\Program Files\App\svc.exe -k netsvcs", @"C:\Program Files\App")]
    [InlineData(@"""C:\Program Files\App\svc.exe"" -k netsvcs", @"C:\Program Files\App")]
    // A registered image does not have to be an .exe, and its directory is just as plantable.
    [InlineData(@"C:\Program Files\App\run.bat", @"C:\Program Files\App")]
    [InlineData(@"C:\Program Files\App\run.cmd -x", @"C:\Program Files\App")]
    public void ReadsTheDirectoryTheServiceActuallyRunsFrom(string commandLine, string expected)
        => Assert.Equal(expected, HijackScanner.ExecutableDirectory(commandLine));

    // The divergence. An earlier `.exe` that does not end a token is not the executable, and
    // resolving to its parent would probe — and accuse — a directory the service never used.
    [Fact]
    public void AnEarlierDotExeInsideAPathSegmentIsNotTheExecutable()
    {
        var directory = HijackScanner.ExecutableDirectory(@"C:\Tools\7z.exe.bak\svc.exe -k");

        Assert.Equal(@"C:\Tools\7z.exe.bak", directory);
    }

    // The bug fixed in UnquotedPath, asserted here too: both readings must survive it.
    [Fact]
    public void ADotExeInsideAnArgumentIsNotTheExecutable()
    {
        var directory = HijackScanner.ExecutableDirectory(@"C:\Program Files\App\svc.exe -c C:\other.exe");

        Assert.Equal(@"C:\Program Files\App", directory);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    // A driver's NT path is loaded by the kernel, not searched for in a directory.
    [InlineData(@"\SystemRoot\System32\drivers\foo.sys")]
    [InlineData(@"\??\C:\Windows\System32\drivers\foo.sys")]
    // Nothing that names an executable this rule can reason about.
    [InlineData(@"C:\Program Files\App\readme.txt")]
    [InlineData(@"""")]
    [InlineData(@"""""")]
    // Relative: there is no directory to probe without knowing the working directory.
    [InlineData(@"svc.exe -k")]
    public void SaysNothingRatherThanGuess(string? commandLine)
        => Assert.Null(HijackScanner.ExecutableDirectory(commandLine));

    /// <summary>
    /// The two readings of the command line must agree about where the executable ends.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Program Files\App\svc.exe -k netsvcs")]
    [InlineData(@"C:\Tools\7z.exe.bak\svc.exe -k")]
    [InlineData(@"C:\Program Files\App\svc.exe -c C:\other.exe")]
    public void TheDirectoryIsAlwaysTheParentOfTheSpanUnquotedPathUsed(string commandLine)
    {
        var span = UnquotedPath.ExecutableSpan(commandLine);

        Assert.NotNull(span);
        Assert.Equal(Path.GetDirectoryName(span), HijackScanner.ExecutableDirectory(commandLine));
    }
}
