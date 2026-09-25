using System.Text.RegularExpressions;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// No script in <c>scripts/</c> derives a parameter default from its own location.
/// </summary>
/// <remarks>
/// <b>The failure.</b> Windows PowerShell 5.1 leaves <c>$PSScriptRoot</c> and <c>$PSCommandPath</c>
/// empty while it evaluates the parameter defaults of an advanced script (<c>[CmdletBinding()]</c>)
/// started with <c>powershell.exe -File</c>; the same script run with <c>&amp;</c>, or by PowerShell 7,
/// sees them (measured on Windows 11 26200). A default such as
/// <c>(Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification')</c> therefore threw
/// before the first line of the script ran: the storage protection, the qualification runner and the
/// provenance verifier could not start the way their README starts them. Such values are resolved in
/// the body instead, where the script's location is always known.
/// </remarks>
public sealed class ScriptParameterDefaultContractTests
{
    private static readonly string Scripts = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "scripts"));

    private static readonly Regex ScriptLocation = new(
        @"\$(PSScriptRoot|PSCommandPath|MyInvocation)\b", RegexOptions.IgnoreCase);

    /// <summary>
    /// The script's own <c>param(...)</c> block, up to its matching parenthesis (quoted strings and
    /// comments skipped), without its comment lines.
    /// </summary>
    private static string? ParamBlock(string path)
    {
        var text = File.ReadAllText(path);
        var start = Regex.Match(text, @"^param\s*\(", RegexOptions.IgnoreCase | RegexOptions.Multiline);
        if (!start.Success)
        {
            return null;
        }
        var depth = 0;
        for (var i = start.Index + start.Length - 1; i < text.Length; i++)
        {
            switch (text[i])
            {
                case '#':
                    var lineEnd = text.IndexOf('\n', i);
                    i = lineEnd < 0 ? text.Length : lineEnd;
                    break;
                case '\'' or '"':
                    var closing = text.IndexOf(text[i], i + 1);
                    i = closing < 0 ? text.Length : closing;
                    break;
                case '(':
                    depth++;
                    break;
                case ')' when --depth == 0:
                    return string.Join('\n', text[start.Index..(i + 1)].Split('\n')
                        .Where(line => !line.TrimStart().StartsWith('#')));
            }
        }
        return null;
    }

    private static IEnumerable<string> ScriptNames() => Directory
        .GetFiles(Scripts, "*.ps1", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(Scripts, path))
        .Order(StringComparer.Ordinal);

    public static TheoryData<string> AllScripts() => new(ScriptNames());

    [Theory]
    [MemberData(nameof(AllScripts))]
    public void NoParameterDefaultDependsOnTheScriptsOwnLocation(string script)
    {
        var block = ParamBlock(Path.Combine(Scripts, script));

        if (block is not null)
        {
            Assert.DoesNotMatch(ScriptLocation, block);
        }
    }

    [Fact]
    public void TheScriptsAreFound()
    {
        Assert.Contains(Path.Combine("validation", "hyperv", "WinSightQualRunner.ps1"), ScriptNames());
        Assert.NotNull(ParamBlock(Path.Combine(Scripts, "validation", "hyperv", "Protect-WinSightVmStorage.ps1")));
    }
}
