using System.Text;
using System.Text.RegularExpressions;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Every shipped PowerShell script must parse under the shell a clean Windows actually opens.
/// </summary>
/// <remarks>
/// <b>The defect this pins.</b> Windows PowerShell 5.1 reads a <c>.ps1</c> with no byte-order mark as
/// <i>ANSI</i>, not UTF-8. A UTF-8 em dash is three bytes, and the last of them is 0x94 — which in
/// code page 1252 is a right double quotation mark. PowerShell treats smart quotes as string
/// delimiters, so one em dash in a comment opens a string that is never closed and the whole file
/// fails to parse, with an error pointing at some unrelated line near the end.
///
/// Three shipped scripts had exactly this, including the runtime validation script — which exists to
/// be run on a freshly imaged VM, whose default shell is 5.1. It failed on its first real use.
///
/// <b>Why CI could not see it.</b> Every workflow step runs <c>shell: pwsh</c>, and PowerShell 7
/// reads scripts as UTF-8. The entire class of bug is invisible from there, and from any developer
/// machine where <c>pwsh</c> is the habit. This test is the substitute for a shell CI does not use.
///
/// ASCII-only is preferred over adding a BOM: it is correct under every encoding, every code page and
/// every tool, and costs nothing but a hyphen.
/// </remarks>
public sealed class PowerShellScriptEncodingTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    public static TheoryData<string> EveryScript()
    {
        var data = new TheoryData<string>();
        foreach (var script in Directory.GetFiles(Path.Combine(RepositoryRoot, "scripts"), "*.ps1"))
        {
            data.Add(Path.GetFileName(script));
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(EveryScript))]
    public void AScriptIsReadableByWindowsPowerShell(string fileName)
    {
        var path = Path.Combine(RepositoryRoot, "scripts", fileName);
        var bytes = File.ReadAllBytes(path);
        var hasBom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        if (hasBom)
        {
            // A BOM tells 5.1 the file is UTF-8, so non-ASCII is safe.
            return;
        }

        var offending = Regex.Matches(File.ReadAllText(path), @"[^\x00-\x7F]")
            .Select(match => $"U+{(int)match.Value[0]:X4} '{match.Value}'")
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            offending.Length == 0,
            $"scripts/{fileName} has no BOM, so Windows PowerShell 5.1 reads it as ANSI and these "
            + $"characters change meaning: {string.Join(", ", offending)}. Use ASCII, or save the "
            + "file with a UTF-8 BOM.");
    }

    /// <summary>
    /// Guards the guard: shows the byte that causes the reinterpretation really is produced.
    /// </summary>
    /// <remarks>
    /// The rule above forbids something; this shows the thing it forbids is not hypothetical. An em
    /// dash encodes to three UTF-8 bytes ending in <c>0x94</c>, and <c>0x94</c> in the ANSI code page
    /// Windows PowerShell 5.1 falls back to is a right double quotation mark — a character PowerShell
    /// opens a string on.
    ///
    /// Only the byte sequence is asserted. Code page 1252 is deliberately not loaded: this project
    /// builds with <c>InvariantGlobalization</c>, so asking .NET for it throws, and pulling in an
    /// encoding package to restate a fixed property of a legacy code page would be a poor trade.
    /// </remarks>
    [Theory]
    [InlineData('—')]   // U+2014 em dash, the one that broke three scripts
    [InlineData('’')]   // U+2019 right single quote, the other common paste-in
    public void TheCharactersThisRuleForbidsEncodeToBytesAnsiRereadsAsQuotes(char forbidden)
    {
        var utf8 = Encoding.UTF8.GetBytes(forbidden.ToString());

        Assert.Equal(3, utf8.Length);
        Assert.Equal(0xE2, utf8[0]);
        // 0x94 and 0x99 are the right double and right single quotation marks in cp1252.
        Assert.Contains(utf8[2], new byte[] { 0x94, 0x99 });
    }

    [Fact]
    public void TheRepositoryActuallyHasScriptsToCheck()
    {
        // A theory over an empty set passes silently. This is the floor under it.
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(RepositoryRoot, "scripts"), "*.ps1"));
    }
}
