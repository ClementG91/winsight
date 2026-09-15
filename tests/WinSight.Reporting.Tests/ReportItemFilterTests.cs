using WinSight.Reporting;

using Xunit;

namespace WinSight.Reporting.Tests;

public sealed class ReportItemFilterTests
{
    private static ReportItem Item(
        Severity severity = Severity.Info, string? signature = null, string? signer = null)
    {
        var fields = new Dictionary<string, string?>();
        if (signature is not null)
        {
            fields["signature"] = signature;
        }
        if (signer is not null)
        {
            fields["signer"] = signer;
        }
        return new ReportItem(severity, "t", "d", fields);
    }

    [Theory]
    [InlineData("Unsigned", true)]
    [InlineData("SignedUntrusted", true)]
    [InlineData("SignedTrusted", false)]
    [InlineData("Unknown", false)] // could-not-verify is not the same as unsigned
    public void UnsignedMatchesEverythingButTrustedAndUnknown(string state, bool expected) =>
        Assert.Equal(expected, ReportItemFilter.Matches(Item(signature: state), ReportFilterToken.Unsigned));

    [Fact]
    public void UnsignedDoesNotMatchAnItemWithNoSignatureField() =>
        Assert.False(ReportItemFilter.Matches(Item(), ReportFilterToken.Unsigned));

    [Theory]
    [InlineData("CN=Microsoft Windows, O=Microsoft Corporation", false)]
    [InlineData("CN=Contoso Ltd", true)]
    [InlineData(null, true)] // no signer at all counts as non-Microsoft
    public void NonMicrosoftMatchesAnythingNotSignedByMicrosoft(string? signer, bool expected) =>
        Assert.Equal(expected, ReportItemFilter.Matches(Item(signer: signer), ReportFilterToken.NonMicrosoft));

    [Fact]
    public void ApplyCombinesTokensWithAnd()
    {
        var items = new[]
        {
            Item(Severity.Notable, "Unsigned", "CN=Contoso"),        // unsigned + non-Microsoft
            Item(Severity.Notable, "SignedTrusted", "CN=Contoso"),   // non-Microsoft, but trusted
            Item(Severity.Info, "Unsigned", "CN=Microsoft Windows"), // unsigned, but Microsoft-named
        };

        var both = ReportItemFilter.Apply(items, [ReportFilterToken.Unsigned, ReportFilterToken.NonMicrosoft]);

        var only = Assert.Single(both);
        Assert.Equal("Unsigned", only.Fields["signature"]);
        Assert.Equal("CN=Contoso", only.Fields["signer"]);
    }

    [Fact]
    public void ApplyWithNoTokensReturnsTheItemsUnchanged()
    {
        var items = new[] { Item(), Item(Severity.Notable) };
        Assert.Same(items, ReportItemFilter.Apply(items, []));
    }
}
