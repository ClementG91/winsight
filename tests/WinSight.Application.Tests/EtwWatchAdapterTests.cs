using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Pins the CLI boundary around the live ETW commands without opening an ETW session. Native error
/// text can include paths or localized diagnostics, so only a stable token may cross this boundary.
/// </summary>
/// <remarks>
/// <b>The exit code changed deliberately, from 1 to ObservationFailed.</b> These three assertions
/// used to require 1, which is also what a scan returns when it <i>finds</i> something. A live ETW
/// pump that never came up and a scan that found a rogue Run key were therefore indistinguishable to
/// anything automating WinSight - which the README recommends doing from a scheduled task. Findings
/// stay in 0/1 and failures moved to 10 and above, so a caller testing only for non-zero is
/// unaffected while one that wants the distinction can now have it.
/// </remarks>
public sealed class EtwWatchAdapterTests
{
    [Fact]
    public void AResourceFailureReturnsANonzeroStableRedactedDiagnostic()
    {
        using var error = new StringWriter();

        var exitCode = Adapters.RunEtwWatch(
            () => throw EtwComFailure(unchecked((int)0x800705AA)),
            error,
            CancellationToken.None);

        Assert.Equal(CliContract.ObservationFailed, exitCode);
        Assert.Equal(
            $"[ETW_RESOURCE_EXHAUSTED] Live ETW observation is unavailable.{Environment.NewLine}",
            error.ToString());
        Assert.DoesNotContain("native ETW detail", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnexpectedFailureRemainsRedactedAndNonzero()
    {
        using var error = new StringWriter();

        var exitCode = Adapters.RunEtwWatch(
            () => throw new InvalidOperationException(@"C:\operator-private\trace.etl"),
            error,
            CancellationToken.None);

        Assert.Equal(CliContract.ObservationFailed, exitCode);
        Assert.Equal(
            $"[ETW_UNEXPECTED_FAILURE] Live ETW observation is unavailable.{Environment.NewLine}",
            error.ToString());
        Assert.DoesNotContain("operator-private", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ARequestedCancellationIsASuccessfulWatchShutdown()
    {
        using var cancellation = new CancellationTokenSource();
        using var error = new StringWriter();
        cancellation.Cancel();

        var exitCode = Adapters.RunEtwWatch(
            () => throw new OperationCanceledException(),
            error,
            cancellation.Token);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public void AnUnexpectedNormalWatchReturnIsReportedAsUnavailable()
    {
        using var error = new StringWriter();

        var exitCode = Adapters.RunEtwWatch(
            static () => { },
            error,
            CancellationToken.None);

        Assert.Equal(CliContract.ObservationFailed, exitCode);
        Assert.Equal(
            $"[ETW_UNEXPECTED_FAILURE] Live ETW observation is unavailable.{Environment.NewLine}",
            error.ToString());
    }

    [Fact]
    public void ANormalWatchReturnAfterCancellationIsSilentSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        using var error = new StringWriter();
        cancellation.Cancel();

        var exitCode = Adapters.RunEtwWatch(
            static () => { },
            error,
            cancellation.Token);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
    }

    private static System.Runtime.InteropServices.COMException EtwComFailure(int hresult)
    {
        try
        {
            System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(hresult);
        }
        catch (System.Runtime.InteropServices.COMException failure)
        {
            return failure;
        }

        throw new InvalidOperationException($"HRESULT 0x{hresult:X8} did not produce a COM exception.");
    }
}
