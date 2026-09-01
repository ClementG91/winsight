using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// Why an observational feature is unavailable, reduced to a token an operator can act on.
/// </summary>
/// <remarks>
/// <b>What was untested.</b> The lifecycle's decisions were covered through a managed fake, which
/// was right - but the classifier beneath them was not, and it is the part that decides what an
/// operator is told when ETW refuses. Windows reports the same condition two ways depending on which
/// layer surfaces it: TraceEvent throws <see cref="Win32Exception"/> in some paths and
/// <see cref="COMException"/> carrying an HRESULT-wrapped Win32 code in others. Only one of each
/// pair was exercised, so a mistake in the HRESULT arithmetic - the <c>0x80070000</c> fold - would
/// have turned "run this elevated" into "unexpected failure" for every COM-surfaced error, with
/// nothing failing.
///
/// This matters more than a percentage: <c>ETW_ACCESS_DENIED</c> tells someone to elevate,
/// <c>ETW_SESSION_COLLISION</c> tells them another instance owns the session, and
/// <c>ETW_UNEXPECTED_FAILURE</c> tells them nothing at all.
/// </remarks>
public sealed class EtwFailureClassificationTests
{
    private const int ErrorNotEnoughMemory = 8;
    private const int ErrorOutOfMemory = 14;
    private const int ErrorAccessDenied = 5;
    private const int ErrorAlreadyExists = 183;
    private const int ErrorNoSystemResources = 1450;
    private const int ErrorNotEnoughQuota = 1816;

    // CA2201 exists to stop production code raising a runtime-reserved exception. Constructing one
    // is the point here: TraceEvent surfaces exactly this type from the COM layer, and a classifier
    // tested only against the types it is convenient to build is tested against the wrong half.
#pragma warning disable CA2201
    private static COMException AsCom(int win32) =>
        new("native failure", unchecked((int)(0x80070000u | (uint)win32)));

    private static COMException AsComRaw(int hresult) => new("other facility", hresult);
#pragma warning restore CA2201

    [Theory]
    [InlineData(ErrorAccessDenied, EtwFailureCode.AccessDenied)]
    [InlineData(ErrorAlreadyExists, EtwFailureCode.SessionCollision)]
    [InlineData(ErrorNoSystemResources, EtwFailureCode.ResourceExhausted)]
    [InlineData(ErrorNotEnoughMemory, EtwFailureCode.ResourceExhausted)]
    [InlineData(ErrorOutOfMemory, EtwFailureCode.ResourceExhausted)]
    [InlineData(ErrorNotEnoughQuota, EtwFailureCode.ResourceExhausted)]
    public void AWin32ErrorIsClassifiedTheSameWhicheverLayerSurfacesIt(
        int win32, EtwFailureCode expected)
    {
        Assert.Equal(expected, EtwFailure.Classify(new Win32Exception(win32)));
        Assert.Equal(expected, EtwFailure.Classify(AsCom(win32)));
    }

    [Fact]
    public void ManagedAccessFailuresAreAccessDenied()
    {
        Assert.Equal(
            EtwFailureCode.AccessDenied, EtwFailure.Classify(new UnauthorizedAccessException()));
        Assert.Equal(EtwFailureCode.AccessDenied, EtwFailure.Classify(new SecurityException()));
    }

    [Theory]
    [InlineData(typeof(PlatformNotSupportedException))]
    [InlineData(typeof(NotSupportedException))]
    [InlineData(typeof(DllNotFoundException))]
    [InlineData(typeof(EntryPointNotFoundException))]
    public void AMissingPlatformIsNotAFailureOfThisMachinesConfiguration(Type exceptionType)
    {
        var exception = (Exception)Activator.CreateInstance(exceptionType)!;

        Assert.Equal(EtwFailureCode.PlatformUnavailable, EtwFailure.Classify(exception));
    }

    /// <summary>
    /// An HRESULT from any facility other than Win32 must not be decoded as a Win32 error. A COM
    /// error whose low word happens to equal 5 is not access denied.
    /// </summary>
    [Fact]
    public void AnHresultFromAnotherFacilityIsNotDecodedAsWin32()
    {
        var notWin32Facility = AsComRaw(unchecked((int)0x80040005));

        Assert.Equal(EtwFailureCode.Unexpected, EtwFailure.Classify(notWin32Facility));
    }

    [Fact]
    public void AnUnrecognisedFailureIsReportedAsUnexpectedRatherThanGuessedAt() =>
        Assert.Equal(
            EtwFailureCode.Unexpected, EtwFailure.Classify(new InvalidOperationException()));

    [Fact]
    public void ClassifyRefusesANullException() =>
        Assert.Throws<ArgumentNullException>(() => EtwFailure.Classify(null!));

    /// <summary>
    /// Catastrophic failures are not conditions of the ETW feature and must not be swallowed into
    /// one: a process out of memory is not "this observational feature is unavailable".
    /// </summary>
    [Theory]
    [InlineData(typeof(OutOfMemoryException))]
    [InlineData(typeof(StackOverflowException))]
    [InlineData(typeof(AccessViolationException))]
    public void CatastrophicFailuresAreNotAnObservationalStatus(Type exceptionType)
    {
        var exception = (Exception)Activator.CreateInstance(exceptionType)!;

        Assert.True(EtwFailure.IsCatastrophic(exception));
    }

    [Theory]
    [InlineData(typeof(UnauthorizedAccessException))]
    [InlineData(typeof(InvalidOperationException))]
    public void AnOrdinaryFailureIsNotCatastrophic(Type exceptionType)
    {
        var exception = (Exception)Activator.CreateInstance(exceptionType)!;

        Assert.False(EtwFailure.IsCatastrophic(exception));
    }

    /// <summary>
    /// The tokens are a diagnostic contract: they appear in CLI output and service logs, so an
    /// operator's runbook and a support thread both key on the exact strings.
    /// </summary>
    [Theory]
    [InlineData(EtwFailureCode.None, "ETW_NONE")]
    [InlineData(EtwFailureCode.AccessDenied, "ETW_ACCESS_DENIED")]
    [InlineData(EtwFailureCode.ResourceExhausted, "ETW_RESOURCE_EXHAUSTED")]
    [InlineData(EtwFailureCode.SessionCollision, "ETW_SESSION_COLLISION")]
    [InlineData(EtwFailureCode.PlatformUnavailable, "ETW_PLATFORM_UNAVAILABLE")]
    [InlineData(EtwFailureCode.Unexpected, "ETW_UNEXPECTED_FAILURE")]
    public void EveryFailureCodeHasItsOwnStableToken(EtwFailureCode code, string expected) =>
        Assert.Equal(expected, EtwFailure.Token(code));

    /// <summary>
    /// No two codes share a token, or a runbook keyed on one would silently match the other.
    /// </summary>
    [Fact]
    public void TheTokensAreDistinct()
    {
        var tokens = Enum.GetValues<EtwFailureCode>().Select(EtwFailure.Token).ToArray();

        Assert.Equal(tokens.Length, tokens.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// The token never carries a native message, a path or a session name. It is what gets logged,
    /// and the whole point of reducing the exception to a code is that nothing native escapes.
    /// </summary>
    [Fact]
    public void ATokenLeaksNothingFromTheUnderlyingFailure()
    {
        var revealing = new Win32Exception(
            ErrorAccessDenied, @"session \\.\pipe\secret could not be created by DOMAIN\alice");

        var token = EtwFailure.Token(EtwFailure.Classify(revealing));

        Assert.Equal("ETW_ACCESS_DENIED", token);
        Assert.DoesNotContain("alice", token, StringComparison.OrdinalIgnoreCase);
    }
}
