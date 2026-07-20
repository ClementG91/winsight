using System.Globalization;

using WinSight.Dashboard;

using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class RemainingWidthConverterTests
{
    private static readonly RemainingWidthConverter Converter = new();

    private static object Convert(object? width, object? reserve) =>
        Converter.Convert(width, typeof(double), reserve, CultureInfo.InvariantCulture);

    [Fact]
    public void LeavesTheReserveToTheOtherContent()
    {
        Assert.Equal(572d, Convert(832d, "260"));
    }

    [Fact]
    public void AWideContainerStillLeavesRoomForAnUnwrappedRow()
    {
        // The point of the reserve is that it only bites when the container is small. At the
        // dashboard's default width the buttons must still get enough room for a single row.
        Assert.True((double)Convert(832d, "260") > 500);
    }

    [Fact]
    public void ANarrowContainerTightensTheCapSoTheRowWraps()
    {
        // At the window's minimum width the buttons have to give way, which is what makes them wrap
        // instead of overflowing past the edge.
        Assert.Equal(314d, Convert(574d, "260"));
    }

    [Fact]
    public void AnUnknownWidthImposesNoCap()
    {
        // The first layout pass runs before the container has a width. Returning zero there would
        // collapse the panel; no constraint merely leaves it unwrapped for that one pass.
        Assert.Equal(double.PositiveInfinity, Convert(null, "260"));
        Assert.Equal(double.PositiveInfinity, Convert(0d, "260"));
        Assert.Equal(double.PositiveInfinity, Convert(double.NaN, "260"));
        Assert.Equal(double.PositiveInfinity, Convert(double.PositiveInfinity, "260"));
        Assert.Equal(double.PositiveInfinity, Convert(-40d, "260"));
    }

    [Fact]
    public void AContainerTooNarrowToSplitImposesNoCapRatherThanHidingTheButtons()
    {
        // A cap below one button's width would be honoured literally and render nothing. An
        // overflowing row is recoverable by resizing; buttons that do not exist are not.
        Assert.Equal(double.PositiveInfinity, Convert(300d, "260"));
        Assert.Equal(double.PositiveInfinity, Convert(260d, "260"));
    }

    [Fact]
    public void AMissingOrUnreadableReserveMeansNoReserve()
    {
        // Losing the reserve costs the text some width; treating it as an enormous one would cap
        // the buttons away entirely.
        Assert.Equal(832d, Convert(832d, null));
        Assert.Equal(832d, Convert(832d, "not a number"));
        Assert.Equal(832d, Convert(832d, -50d));
    }

    [Fact]
    public void TheReserveIsReadTheSameWayOnEveryMachine()
    {
        // The reserve is authored in XAML, so a culture using a comma as the decimal separator must
        // still read "260.5" as written rather than failing to parse it.
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("fr-FR");
            Assert.Equal(571.5d, Convert(832d, "260.5"));
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public void AReserveSuppliedAsANumberWorksToo()
    {
        Assert.Equal(572d, Convert(832d, 260d));
    }

    [Fact]
    public void ConvertingBackIsRefused()
    {
        Assert.Throws<NotSupportedException>(
            () => Converter.ConvertBack(572d, typeof(double), "260", CultureInfo.InvariantCulture));
    }
}
