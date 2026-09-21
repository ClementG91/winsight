using WinSight.Core;

using Xunit;

namespace WinSight.InputHooks.Tests;

/// <summary>
/// The judgement calls. These are the ones worth arguing with in a test rather than discovering on
/// a live machine: what counts as expected, and what a keylogger could do to look expected.
/// </summary>
public sealed class InputFilterTriageTests
{
    private const string SystemDirectory = @"C:\Windows\System32";
    private const string WindowsSigner = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    private const string WhqlSigner =
        "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    /// <summary>
    /// A filter as the scanner builds it: the class-driver flag is computed by the same rule, from
    /// the name, the image and its signature, never supplied by the test.
    /// </summary>
    private static InputFilter Filter(
        string name,
        SignatureState state = SignatureState.SignedTrusted,
        InputStack stack = InputStack.Keyboard,
        string signer = "CN=Contoso Touchpad, O=Contoso",
        string? imagePath = null)
    {
        var path = state == SignatureState.Missing ? null : imagePath ?? $@"{SystemDirectory}\drivers\{name}.sys";
        var signature = new SignatureVerdict(state, state is SignatureState.SignedTrusted or SignatureState.SignedUntrusted ? signer : null);
        return new InputFilter(
            stack,
            FilterPosition.Upper,
            name,
            path,
            signature,
            InputFilterTriage.IsWindowsClassDriver(stack, name, path, signature, SystemDirectory));
    }

    [Theory]
    [InlineData(InputStack.Keyboard, "kbdclass")]
    [InlineData(InputStack.Mouse, "mouclass")]
    public void TheWindowsClassDriverIsExpected(InputStack stack, string name)
    {
        var filter = Filter(name, stack: stack, signer: WindowsSigner);

        Assert.Equal(InputFilterConcern.Expected, InputFilterTriage.Concern(filter));
        Assert.False(InputFilterTriage.IsNotable(InputFilterConcern.Expected));
    }

    /// <summary>In-box drivers also live in the driver store, which is still inside System32.</summary>
    [Fact]
    public void TheClassDriverIsStillExpectedFromTheDriverStore()
    {
        var filter = Filter(
            "kbdclass",
            signer: WindowsSigner,
            imagePath: $@"{SystemDirectory}\DriverStore\FileRepository\keyboard.inf_amd64_0123\kbdclass.sys");

        Assert.Equal(InputFilterConcern.Expected, InputFilterTriage.Concern(filter));
    }

    [Fact]
    public void TheClassDriverIsOnlyExpectedInItsOwnStack()
    {
        // mouclass has no business above the keyboard class driver; treating names as globally
        // benign would let one be borrowed for the other stack - even the genuine Windows file.
        Assert.NotEqual(
            InputFilterConcern.Expected,
            InputFilterTriage.Concern(Filter("mouclass", stack: InputStack.Keyboard, signer: WindowsSigner)));
    }

    /// <summary>
    /// The attack the name-only rule allowed: the kbdclass service's ImagePath repointed at another
    /// driver keeps the one line in the keyboard stack reading "the class driver Windows installs".
    /// Whatever stands behind the name, if it is not the Windows file it is reported as posing as it.
    /// </summary>
    [Theory]
    [InlineData(SignatureState.SignedTrusted, "CN=Contoso Touchpad, O=Contoso", @"C:\Windows\System32\drivers\kbdclass.sys")]
    [InlineData(SignatureState.SignedTrusted, WhqlSigner, @"C:\Windows\System32\drivers\kbdclass.sys")]
    [InlineData(SignatureState.SignedTrusted, WindowsSigner, @"C:\ProgramData\Input\kbdclass.sys")]
    [InlineData(SignatureState.SignedTrusted, WindowsSigner, @"C:\Windows\System32\..\..\ProgramData\kbdclass.sys")]
    [InlineData(SignatureState.SignedTrusted, WindowsSigner, @"C:\Windows\System32\drivers\beep.sys")]
    [InlineData(SignatureState.Unsigned, "", @"C:\Windows\System32\drivers\kbdclass.sys")]
    [InlineData(SignatureState.SignedUntrusted, WindowsSigner, @"C:\Windows\System32\drivers\kbdclass.sys")]
    public void AnythingButTheWindowsFileUnderTheClassDriverNameIsImpersonatingIt(
        SignatureState state, string signer, string imagePath)
    {
        var filter = Filter("kbdclass", state, signer: signer, imagePath: imagePath);

        var concern = InputFilterTriage.Concern(filter);

        Assert.False(filter.IsWindowsClassDriver);
        Assert.Equal(InputFilterConcern.Impersonating, concern);
        Assert.True(InputFilterTriage.IsNotable(concern));
    }

    /// <summary>
    /// A chain that validates only through a root in the scanning account's own store is one kernel
    /// code integrity never consults, and minting a "Microsoft Windows" certificate under such a root
    /// takes no privilege.
    /// </summary>
    [Theory]
    [InlineData("kbdclass", WindowsSigner, InputFilterConcern.Impersonating)]
    [InlineData("evilkbd", "CN=Contoso Touchpad, O=Contoso", InputFilterConcern.Untrusted)]
    public void AFilterTrustedOnlyThroughAUserInstalledRootIsNeverVouchedFor(
        string name, string signer, InputFilterConcern expected)
    {
        var signature = new SignatureVerdict(
            SignatureState.SignedTrusted, signer, SignatureTrustAnchor.UserInstalledRoot);
        var path = $@"{SystemDirectory}\drivers\{name}.sys";
        var filter = new InputFilter(
            InputStack.Keyboard,
            FilterPosition.Upper,
            name,
            path,
            signature,
            InputFilterTriage.IsWindowsClassDriver(InputStack.Keyboard, name, path, signature, SystemDirectory));

        Assert.False(filter.IsWindowsClassDriver);
        Assert.Equal(expected, InputFilterTriage.Concern(filter));
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

    /// <summary>
    /// An image registered where no local path reaches was never looked at. It used to be replaced
    /// by the same-named file in the drivers folder, so under the class driver's own name it was
    /// verified as the in-box driver and reported as expected. The flag is set here on purpose: no
    /// flag outranks an image nobody could look at.
    /// </summary>
    [Theory]
    [InlineData("kbdclass")]
    [InlineData("evilkbd")]
    public void AnImageNoLocalPathReachesIsNeverExpected(string name)
    {
        var filter = new InputFilter(
            InputStack.Keyboard,
            FilterPosition.Upper,
            name,
            ImagePath: null,
            SignatureVerdict.Unknown,
            IsWindowsClassDriver: true,
            DriverImageSource.Unresolvable,
            RegisteredImagePath: $@"\Device\HarddiskVolume3\x\{name}.sys");

        var concern = InputFilterTriage.Concern(filter);

        Assert.Equal(InputFilterConcern.Unresolvable, concern);
        Assert.True(InputFilterTriage.IsNotable(concern));
    }

    [Theory]
    [InlineData("unverifiable")]
    [InlineData("kbdclass")]
    public void AnUnverifiableDriverIsNeitherSuspectedNorVouchedFor(string name)
    {
        // Unknown means verification could not run, which is not evidence of anything. The project
        // rule is that WinSight never cries wolf on a file it merely failed to check - nor calls it
        // third-party, or an impostor of the class driver, which would be claims of the same kind.
        var concern = InputFilterTriage.Concern(Filter(name, SignatureState.Unknown));

        Assert.Equal(InputFilterConcern.Unverified, concern);
        Assert.True(InputFilterTriage.IsNotable(concern));
    }

    [Theory]
    [InlineData("KBDCLASS")]
    [InlineData("  kbdclass  ")]
    public void TheClassDriverNameIsRecognisedRegardlessOfCaseOrPadding(string name)
    {
        // The registry values are not consistently cased and may carry stray whitespace; a
        // keylogger should not be able to hide behind either.
        Assert.True(InputFilterTriage.HasClassDriverName(InputStack.Keyboard, name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankNameIsNeverTheClassDriver(string? name)
    {
        Assert.False(InputFilterTriage.HasClassDriverName(InputStack.Keyboard, name));
        Assert.False(InputFilterTriage.IsWindowsClassDriver(
            InputStack.Keyboard,
            name,
            $@"{SystemDirectory}\drivers\kbdclass.sys",
            new SignatureVerdict(SignatureState.SignedTrusted, WindowsSigner),
            SystemDirectory));
    }

    [Fact]
    public void ANameThatMerelyResemblesTheClassDriverIsNotExpected()
    {
        // The obvious disguise: kbdclass2, kbdclass_, kbdclasss.
        Assert.False(InputFilterTriage.HasClassDriverName(InputStack.Keyboard, "kbdclass2"));
        Assert.False(InputFilterTriage.HasClassDriverName(InputStack.Keyboard, "kbdclas"));
    }
}
