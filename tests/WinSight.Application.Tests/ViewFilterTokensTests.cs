using WinSight.Application;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class ViewFilterTokensTests
{
    [Fact]
    public void NoFilterOptionsYieldNoTokens() =>
        Assert.Empty(CliContract.ViewFilterTokens(["processes", "--json"]));

    [Fact]
    public void UnsignedAndNonMicrosoftAreRecognisedInAFixedOrder()
    {
        var tokens = CliContract.ViewFilterTokens(["processes", "--nonmicrosoft", "--unsigned"]);

        Assert.Equal([ReportFilterToken.Unsigned, ReportFilterToken.NonMicrosoft], tokens);
    }

    [Fact]
    public void TheMatchIsCaseInsensitive() =>
        Assert.Contains(ReportFilterToken.Unsigned, CliContract.ViewFilterTokens(["--UNSIGNED"]));
}
