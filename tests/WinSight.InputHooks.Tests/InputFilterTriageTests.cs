using WinSight.Core;

using Xunit;

namespace WinSight.InputHooks.Tests;

/// <summary>
/// The judgement calls. These are the ones worth arguing with in a test rather than discovering on
/// a live machine: what counts as expected, and what a keylogger could do to look expected.
/// </summary>
public sealed class InputFilterTriageTests
{
    private static InputFilter Filter(
        string name,
        SignatureState state = SignatureState.SignedTrusted,
        InputStack stack = InputStack.Keyboard) =>
        new(stack,
            FilterPosition.Upper,
            name,
            state == SignatureState.Missing ? null : $@"C:\Windows\System32\drivers\{name}.sys",
            new SignatureVerdict(state, state == SignatureState.SignedTrusted ? "Contoso" : null),
            InputFilterTriage.IsWindowsClassDriver(stack, name));

    [Theory]
    [InlineData(InputStack.Keyboard, "kbdclass")]
    [InlineData(InputStack.Mouse, "mouclass")]
    public void TheWindowsClassDriverIsExpected(InputStack stack, string name)
    {
        var filter = Filter(name, stack: stack);

        Assert.Equal(InputFilterConcern.Expected, InputFilterTriage.Concern(filter));
        Assert.False(InputFilterTriage.IsNotable(InputFilterConcern.Expected));
    }

    [Fact]
    public void TheClassDriverIsOnlyExpectedInItsOwnStack()
    {
        // mouclass has no business above the keyboard class driver; treating names as globally
        // benign would let one be borrowed for the other stack.
        Assert.NotEqual(
            InputFilterConcern.Expected,
            InputFilterTriage.Concern(Filter("mouclass", stack: InputStack.Keyboard)));
    }

    [Fact]
    public void ASignedThirdPartyDriverIsStillReported()
    {
        // A signed kernel keylogger is still a kernel keylogger. Touchpad drivers legitimately
        // appear here, and reading one line is a small price for not hiding the other case.
        var concern = InputFilterTriage.Concern(Filter("SynTP"));

        Assert.Equal(InputFilterConcern.ThirdParty, concern);
        Assert.True(InputFilterTriage.IsNotable(concern));
    }

    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    public void AnUnsignedOrUntrustedDriverInTheInputPathIsTheLoudestCase(SignatureState state)
    {
        var concern = InputFilterTriage.Concern(Filter("evilkbd", state));

        Assert.Equal(InputFilterConcern.Untrusted, concern);
        Assert.True(InputFilterTriage.IsNotable(concern));
    }

    [Fact]
    public void AFilterWhoseDriverIsGoneIsReportedRatherThanDropped()
    {
        // A class key naming a driver that is not there is odd in its own right — a removal that
        // did not finish, or a file deleted after install.
        Assert.Equal(
            InputFilterConcern.Missing,
            InputFilterTriage.Concern(Filter("ghostkbd", SignatureState.Missing)));
    }

    [Fact]
    public void AnUnverifiableDriverIsNotTreatedAsSuspicious()
    {
        // Unknown means verification could not run, which is not evidence of anything. The project
        // rule is that WinSight never cries wolf on a file it merely failed to check.
        Assert.Equal(
            InputFilterConcern.ThirdParty,
            InputFilterTriage.Concern(Filter("unverifiable", SignatureState.Unknown)));
    }

    [Theory]
    [InlineData("KBDCLASS")]
    [InlineData("  kbdclass  ")]
    public void TheClassDriverIsRecognisedRegardlessOfCaseOrPadding(string name)
    {
        // The registry values are not consistently cased and may carry stray whitespace; a
        // keylogger should not be able to hide behind either.
        Assert.True(InputFilterTriage.IsWindowsClassDriver(InputStack.Keyboard, name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankNameIsNeverTheClassDriver(string? name)
    {
        Assert.False(InputFilterTriage.IsWindowsClassDriver(InputStack.Keyboard, name));
    }

    [Fact]
    public void ANameThatMerelyResemblesTheClassDriverIsNotExpected()
    {
        // The obvious disguise: kbdclass2, kbdclass_, kbdclasss.
        Assert.False(InputFilterTriage.IsWindowsClassDriver(InputStack.Keyboard, "kbdclass2"));
        Assert.False(InputFilterTriage.IsWindowsClassDriver(InputStack.Keyboard, "kbdclas"));
    }
}
