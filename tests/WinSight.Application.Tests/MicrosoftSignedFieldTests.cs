using WinSight.Application;
using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The <c>microsoftSigned</c> field every signed-image report carries, which the
/// <c>--nonmicrosoft</c> view filter relies on. It must be set only for Microsoft's own trusted
/// signature: set for an impostor, the filter hides exactly the row the operator asked to see.
/// </summary>
public sealed class MicrosoftSignedFieldTests
{
    [Theory]
    [InlineData("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")]
    [InlineData("CN=Microsoft Windows Publisher, O=Microsoft Corporation")]
    [InlineData("CN=Microsoft Corporation, O=Microsoft Corporation")]
    public void MicrosoftsOwnTrustedSignatureIsMarked(string signer) =>
        Assert.Equal("true", Adapters.MicrosoftSignedField(
            new SignatureVerdict(SignatureState.SignedTrusted, signer, SignatureTrustAnchor.MachineRoot)));

    [Theory]
    // Attested third-party code, under a longer name off the same issuer.
    [InlineData(SignatureState.SignedTrusted, "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation", SignatureTrustAnchor.MachineRoot)]
    // A name that merely contains "Microsoft".
    [InlineData(SignatureState.SignedTrusted, "CN=NotMicrosoft Ltd", SignatureTrustAnchor.MachineRoot)]
    // Microsoft's name on a chain only a user-installed root makes valid.
    [InlineData(SignatureState.SignedTrusted, "CN=Microsoft Windows", SignatureTrustAnchor.UserInstalledRoot)]
    // Microsoft's name on a chain that did not validate at all.
    [InlineData(SignatureState.SignedUntrusted, "CN=Microsoft Windows", SignatureTrustAnchor.Unspecified)]
    [InlineData(SignatureState.Unknown, null, SignatureTrustAnchor.Unspecified)]
    [InlineData(SignatureState.Unsigned, null, SignatureTrustAnchor.Unspecified)]
    public void AnythingElseIsNotMarked(SignatureState state, string? signer, SignatureTrustAnchor anchor) =>
        Assert.Null(Adapters.MicrosoftSignedField(new SignatureVerdict(state, signer, anchor)));
}
