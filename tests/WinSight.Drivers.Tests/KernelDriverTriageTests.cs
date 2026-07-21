using WinSight.Core;

using Xunit;

namespace WinSight.Drivers.Tests;

/// <summary>
/// The judgement calls. These are the ones worth arguing with in a test rather than
/// discovering on a live machine: what Windows genuinely ships, and what a driver could
/// do to look as though Windows shipped it.
/// </summary>
public sealed class KernelDriverTriageTests
{
    private const string SystemDirectory = @"C:\Windows\System32";
    private const string WindowsSigner = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    private const string WhqlSigner =
        "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    private static KernelDriver Driver(
        string name,
        SignatureState state = SignatureState.SignedTrusted,
        string? signer = WindowsSigner,
        string? imagePath = @"C:\Windows\System32\drivers\acpi.sys")
    {
        var signature = new SignatureVerdict(state, signer);
        var resolved = state == SignatureState.Missing ? null : imagePath;
        return new KernelDriver(
            name,
            DriverKind.Kernel,
            DriverStart.Boot,
            resolved,
            imagePath,
            signature,
            KernelDriverTriage.IsWindowsProvided(resolved, signature, SystemDirectory));
    }

    [Fact]
    public void AWindowsSignedDriverInsideSystem32IsExpected()
    {
        var concern = KernelDriverTriage.Concern(Driver("acpi"));

        Assert.Equal(KernelDriverConcern.WindowsProvided, concern);
        Assert.False(KernelDriverTriage.IsNotable(concern));
    }

    [Fact]
    public void AnAttestationSignedDriverIsNotMistakenForOneWindowsShips()
    {
        // The trap this scanner exists to avoid. WHQL and attestation signing put
        // Microsoft's name on THIRD-PARTY drivers — "Microsoft Windows Hardware
        // Compatibility Publisher" — and a substring match on "Microsoft Windows"
        // swallows it whole. Bring-your-own-vulnerable-driver attacks are exactly a
        // properly attested driver loaded for what it lets an attacker do.
        var driver = Driver(
            "nvlddmkm",
            signer: WhqlSigner,
            imagePath: @"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_1\nvlddmkm.sys");

        Assert.False(driver.IsWindowsProvided);
        Assert.Equal(KernelDriverConcern.ThirdParty, KernelDriverTriage.Concern(driver));
    }

    [Fact]
    public void AWindowsSignedDriverRunningFromOutsideSystem32IsNotExpected()
    {
        // A genuine Microsoft driver staged somewhere a user can write is the classic
        // way a vulnerable one gets loaded. The signature is real; the location is the tell.
        var driver = Driver("staged", imagePath: @"C:\Users\operator\Downloads\rtcore64.sys");

        Assert.False(driver.IsWindowsProvided);
        Assert.Equal(KernelDriverConcern.ThirdParty, KernelDriverTriage.Concern(driver));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32Extra\drivers\x.sys")]
    [InlineData(@"C:\Windows\System32.old\x.sys")]
    public void ADirectoryThatMerelyStartsLikeSystem32IsNotInsideIt(string imagePath)
    {
        Assert.False(KernelDriverTriage.IsWindowsProvided(
            imagePath, new SignatureVerdict(SignatureState.SignedTrusted, WindowsSigner), SystemDirectory));
    }

    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    public void UnsignedOrUntrustedKernelCodeIsTheLoudestCase(SignatureState state)
    {
        var concern = KernelDriverTriage.Concern(Driver("evildrv", state, signer: null));

        Assert.Equal(KernelDriverConcern.Untrusted, concern);
        Assert.True(KernelDriverTriage.IsNotable(concern));
    }

    [Fact]
    public void ARegistrationWhoseImageIsGoneIsReportedRatherThanDropped()
    {
        // Uninstalled software leaves these behind, but so does a driver that deleted
        // its own file after loading. Either way the operator should see the orphan.
        var concern = KernelDriverTriage.Concern(Driver("ace-game-0", SignatureState.Missing));

        Assert.Equal(KernelDriverConcern.Missing, concern);
        Assert.True(KernelDriverTriage.IsNotable(concern));
    }

    [Fact]
    public void AnUnverifiableDriverIsNotTreatedAsSuspicious()
    {
        // Unknown means verification could not run, which is not evidence of anything. The
        // project rule is that WinSight never cries wolf on a file it merely failed to check.
        var concern = KernelDriverTriage.Concern(Driver("unverifiable", SignatureState.Unknown, signer: null));

        Assert.Equal(KernelDriverConcern.Unverified, concern);
        Assert.False(KernelDriverTriage.IsNotable(concern));
    }

    [Fact]
    public void AnUnverifiableDriverIsNotQuietlyCalledThirdPartyEither()
    {
        // Filing it under ThirdParty would not flag anything, but it would assert a
        // provenance that was never established — and it would hide the case where
        // catalog verification has failed wholesale, which is what makes a genuinely
        // unsigned driver vanish into a crowd of unverifiable ones.
        Assert.NotEqual(
            KernelDriverConcern.ThirdParty,
            KernelDriverTriage.Concern(Driver("unverifiable", SignatureState.Unknown, signer: null)));
    }

    [Fact]
    public void ASignedThirdPartyDriverIsListedWithoutBeingFlagged()
    {
        // Several hundred drivers are registered on a normal machine. A flagged view that
        // answers with every non-Microsoft one is a flagged view nobody opens twice.
        var concern = KernelDriverTriage.Concern(Driver(
            "ProtonVPNCallout",
            signer: "CN=Proton AG, O=Proton AG, S=Genève, C=CH",
            imagePath: @"C:\Program Files\Proton\VPN\ProtonVPN.CalloutDriver.sys"));

        Assert.Equal(KernelDriverConcern.ThirdParty, concern);
        Assert.False(KernelDriverTriage.IsNotable(concern));
    }

    [Theory]
    [InlineData(WindowsSigner, "Microsoft Windows")]
    [InlineData(WhqlSigner, "Microsoft Windows Hardware Compatibility Publisher")]
    [InlineData("CN=Proton AG, O=Proton AG, C=CH", "Proton AG")]
    [InlineData("O=Contoso, CN=Contoso Driver Signing, C=US", "Contoso Driver Signing")]
    [InlineData("CN=Only Attribute", "Only Attribute")]
    public void TheCommonNameIsReadWholeAndNotJustToTheFirstSpace(string subject, string expected)
    {
        Assert.Equal(expected, KernelDriverTriage.SignerCommonName(subject));
    }

    [Theory]
    [InlineData("CN=\"Contoso, Inc.\", O=Contoso", "Contoso, Inc.")]
    [InlineData(@"CN=Contoso\, Inc., O=Contoso", "Contoso, Inc.")]
    public void ACommonNameContainingACommaSurvivesTheAttributeBoundary(string subject, string expected)
    {
        // A signer whose legal name carries a comma would otherwise be truncated, and a
        // truncated name is one that can be made to collide with a shorter real one.
        Assert.Equal(expected, KernelDriverTriage.SignerCommonName(subject));
    }

    [Theory]
    [InlineData("O=ACN=Ltd, CN=Real Signer", "Real Signer")]
    [InlineData("O=Contoso, C=US", null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void ACommonNameIsOnlyReadWhereAnAttributeMayStart(string? subject, string? expected)
    {
        Assert.Equal(expected, KernelDriverTriage.SignerCommonName(subject));
    }

    [Fact]
    public void AnUnsignedFileIsNeverWindowsProvidedNoMatterWhatTheSubjectClaims()
    {
        // A verdict of Unsigned with a signer string attached is nonsense, but the trust
        // decision must rest on the chain rather than on the accompanying text.
        Assert.False(KernelDriverTriage.IsWindowsProvided(
            @"C:\Windows\System32\drivers\evil.sys",
            new SignatureVerdict(SignatureState.Unsigned, WindowsSigner),
            SystemDirectory));
    }

    [Fact]
    public void ADriverWithNoResolvedImageIsNeverWindowsProvided()
    {
        Assert.False(KernelDriverTriage.IsWindowsProvided(
            null, new SignatureVerdict(SignatureState.SignedTrusted, WindowsSigner), SystemDirectory));
    }
}
