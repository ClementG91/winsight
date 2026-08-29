using WinSight.Core;
using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Somebody else's code, validly signed, registered to load into a privileged process.
/// </summary>
/// <remarks>
/// <b>What was missed.</b> Every autostart entry was judged on its signature alone, so a DLL that
/// signs cleanly was reported as routine wherever it was registered - including in LSASS, in the
/// print spooler running as SYSTEM, in the logon UI before anyone has authenticated, and in every
/// process on the machine that links user32. Those are not places a program starts; they are places
/// a DLL is loaded into somebody else's process.
///
/// A third-party DLL there is a real finding with nothing wrong with its signature. It is how an
/// attacker holding a code-signing certificate - stolen, bought, or a compromised vendor's - reaches
/// a process they could not otherwise touch. Calling it routine because the signature validates is
/// the same mistake as calling a Microsoft-attested driver an in-box one, which this codebase
/// already refuses to make for drivers and for keyboard filters.
///
/// <b>These surfaces are normally empty.</b> The scan that produced 4538 autostart items on a real
/// desktop found nothing here at all, and the flagged count did not move when this rule was added.
/// That is what makes them worth flagging: a list that is normally empty is a list somebody reads.
/// A detector that is silent and one that is broken look identical from the outside, so these tests
/// are the only thing that says which this is.
/// </remarks>
public sealed class PrivilegedSurfaceTriageTests
{
    private static AutostartEntry Entry(
        AutostartVector vector,
        SignatureState state = SignatureState.SignedTrusted,
        string? signer = "CN=Contoso Ltd, O=Contoso, C=GB",
        SignatureTrustAnchor anchor = SignatureTrustAnchor.Unspecified) =>
        new(
            vector,
            "thing",
            "location",
            @"C:\Program Files\Contoso\thing.dll",
            @"C:\Program Files\Contoso\thing.dll",
            @"C:\Program Files\Contoso\thing.dll",
            ImageResolutionStatus.Present,
            new SignatureVerdict(state, signer, anchor));

    /// <summary>The hosts where a loaded DLL inherits privilege it could not otherwise reach.</summary>
    public static TheoryData<AutostartVector> PrivilegedSurfaces() => Data(
        AutostartVector.AppInitDll,
        AutostartVector.AppCertDll,
        AutostartVector.LsaPackage,
        AutostartVector.SecurityProvider,
        AutostartVector.CredentialProvider,
        AutostartVector.PrintMonitor,
        AutostartVector.PrintProvider,
        AutostartVector.TimeProvider,
        AutostartVector.BootExecute,
        AutostartVector.NetshHelper,
        AutostartVector.Winlogon,
        AutostartVector.WmiSubscription);

    /// <summary>Where ordinary software lives, in its thousands.</summary>
    public static TheoryData<AutostartVector> OrdinarySurfaces() => Data(
        AutostartVector.RunKey,
        AutostartVector.RunOnceEx,
        AutostartVector.Service,
        AutostartVector.ScheduledTask,
        AutostartVector.StartupFolder,
        AutostartVector.ComHijack,
        AutostartVector.BrowserHelperObject,
        AutostartVector.ActiveSetup,
        AutostartVector.Screensaver);

    private static TheoryData<AutostartVector> Data(params AutostartVector[] vectors)
    {
        var data = new TheoryData<AutostartVector>();
        foreach (var vector in vectors)
        {
            data.Add(vector);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(PrivilegedSurfaces))]
    public void ThirdPartyCodeOnAPrivilegedSurfaceIsAdverse(AutostartVector vector)
    {
        var entry = Entry(vector);

        Assert.True(PrivilegedSurfaceTriage.IsPrivilegedSurface(vector));
        Assert.True(PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(entry));
        Assert.True(entry.IsAdverse);
        Assert.False(entry.IsUnverified);
    }

    /// <summary>
    /// The rule must not leak into the surfaces where ordinary software lives. Flagging every
    /// non-Microsoft signer among four thousand Run keys and COM registrations would produce a
    /// report nobody opens - which is the failure that costs more than the one being fixed.
    /// </summary>
    [Theory]
    [MemberData(nameof(OrdinarySurfaces))]
    public void ThirdPartyCodeOnAnOrdinarySurfaceIsNot(AutostartVector vector)
    {
        var entry = Entry(vector);

        Assert.False(PrivilegedSurfaceTriage.IsPrivilegedSurface(vector));
        Assert.False(entry.IsAdverse);
        Assert.False(entry.IsSuspicious);
    }

    [Theory]
    [InlineData("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")]
    [InlineData("CN=Microsoft Windows Publisher, O=Microsoft Corporation, C=US")]
    [InlineData("CN=Microsoft Corporation, O=Microsoft Corporation, C=US")]
    public void MicrosoftsOwnCodeOnAPrivilegedSurfaceIsNotAFinding(string signer)
    {
        var entry = Entry(AutostartVector.LsaPackage, signer: signer);

        Assert.False(PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(entry));
        Assert.False(entry.IsAdverse);
    }

    /// <summary>
    /// The common name is compared entire. Microsoft attests other people's code under longer names
    /// off the same issuer, and every one of them means "somebody else wrote this" - the gap
    /// bring-your-own-vulnerable-driver attacks live in, which this codebase already refuses to fall
    /// into for drivers.
    /// </summary>
    [Theory]
    [InlineData("CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation")]
    [InlineData("CN=Microsoft Windows Early Launch Anti-malware Publisher, O=Microsoft Corporation")]
    [InlineData("CN=Microsoft Windows Third Party Component CA 2014, O=Microsoft Corporation")]
    public void AnAttestedThirdPartySignerIsNotMicrosoftsOwnCode(string signer)
    {
        var entry = Entry(AutostartVector.CredentialProvider, signer: signer);

        Assert.True(PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(entry));
        Assert.True(entry.IsAdverse);
    }

    /// <summary>
    /// A name is worth no more than the root it chains to. "Microsoft Corporation" is trivial to
    /// mint, and a certificate trusted only through a store any account can write is exactly how
    /// somebody would spell it.
    /// </summary>
    [Fact]
    public void AMicrosoftNameRestingOnAUserInstalledRootIsStillForeign()
    {
        var entry = Entry(
            AutostartVector.LsaPackage,
            signer: "CN=Microsoft Corporation, O=Microsoft Corporation, C=US",
            anchor: SignatureTrustAnchor.UserInstalledRoot);

        Assert.True(PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(entry));
        Assert.True(entry.IsAdverse);
    }

    /// <summary>
    /// This rule adds a finding about where trusted third-party code runs. It must not restate one
    /// the signature model already made: an unsigned or untrusted image is adverse for its own
    /// reason, and one that could not be checked is unverified rather than adverse.
    /// </summary>
    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    [InlineData(SignatureState.Unknown)]
    public void ThisRuleOnlySpeaksAboutSignaturesThatValidated(SignatureState state)
    {
        var entry = Entry(AutostartVector.AppInitDll, state, signer: null);

        Assert.False(PrivilegedSurfaceTriage.IsForeignCodeInAPrivilegedHost(entry));
    }

    /// <summary>
    /// Every vector is classified one way or the other, so a surface added later cannot fall through
    /// unconsidered.
    /// </summary>
    [Fact]
    public void EveryVectorIsClassified()
    {
        var privileged = Enum.GetValues<AutostartVector>()
            .Count(PrivilegedSurfaceTriage.IsPrivilegedSurface);

        Assert.Equal(12, privileged);
    }
}
