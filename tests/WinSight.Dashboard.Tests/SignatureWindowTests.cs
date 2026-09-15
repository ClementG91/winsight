using System.IO;
using System.Threading;
using System.Windows;

using WinSight.Core;

using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// The Explorer verb's signature window: what it shows for a verdict, which caveats it states, and that
/// a refused path shows nothing a reader could mistake for a verdict.
/// </summary>
/// <remarks>
/// Joins the localization collection (culture-dependent text) and creates no Application instance,
/// because another test owns the process's single one.
/// </remarks>
[Collection(LocalizationCollection.Name)]
public sealed class SignatureWindowTests
{
    private static FileSignatureReport Report(
        SignatureState state = SignatureState.SignedTrusted,
        string? signer = "CN=Microsoft Windows, O=Microsoft Corporation",
        SignatureTrustAnchor anchor = SignatureTrustAnchor.MachineRoot,
        RevocationStanding revocation = RevocationStanding.NotRevoked) =>
        new(@"C:\Windows\System32\notepad.exe", state, signer, anchor, revocation, "AA11", "BB22", "CC33");

    [Fact]
    public void ATrustedSignatureShowsItsSignerAndHashesWithNoCaveat() => RunSta(() =>
    {
        var window = new SignatureWindow(@"C:\Windows\System32\notepad.exe", _ => null);

        window.Render(Report());

        Assert.Equal(LocalizationManager.Instance["SignatureStateSignedTrusted"], window.StateText.Text);
        Assert.Contains("Microsoft", window.SignerText.Text, StringComparison.Ordinal);
        Assert.Equal(Visibility.Collapsed, window.NotePanel.Visibility);
        Assert.Equal(Visibility.Visible, window.HashesPanel.Visibility);
        Assert.Equal("CC33", window.Sha256Box.Text);
        Assert.True(window.Sha256Box.IsReadOnly); // copyable, not editable
        window.Close();
    });

    [Fact]
    public void AnUnsignedFileSaysSoAndNamesNoSigner() => RunSta(() =>
    {
        var window = new SignatureWindow(@"C:\tmp\a.exe", _ => null);

        window.Render(Report(SignatureState.Unsigned, signer: null, anchor: SignatureTrustAnchor.Unspecified,
            revocation: RevocationStanding.Unspecified));

        Assert.Equal(LocalizationManager.Instance["SignatureStateUnsigned"], window.StateText.Text);
        Assert.Equal(LocalizationManager.Instance["SignatureNoSigner"], window.SignerText.Text);
        window.Close();
    });

    [Fact]
    public void ARefusedPathShowsNoVerdictAndNoHashes() => RunSta(() =>
    {
        var window = new SignatureWindow(@"\\server\share\evil.exe", _ => null);

        window.Render(null);

        Assert.Equal(LocalizationManager.Instance["SignatureNotLocalFile"], window.StateText.Text);
        Assert.Equal(Visibility.Collapsed, window.HashesPanel.Visibility);
        Assert.Equal(string.Empty, window.SignerText.Text);
        window.Close();
    });

    [Fact]
    public void ACaveatIsShownBesideTheVerdict() => RunSta(() =>
    {
        var window = new SignatureWindow(@"C:\tmp\a.exe", _ => null);

        window.Render(Report(anchor: SignatureTrustAnchor.UserInstalledRoot));

        Assert.Equal(Visibility.Visible, window.NotePanel.Visibility);
        Assert.Equal(LocalizationManager.Instance["SignatureUserInstalledRoot"], window.NoteText.Text);
        window.Close();
    });

    [Theory]
    [InlineData(SignatureState.SignedTrusted, SignatureTrustAnchor.MachineRoot, RevocationStanding.NotRevoked, null)]
    [InlineData(SignatureState.SignedTrusted, SignatureTrustAnchor.MachineRoot, RevocationStanding.NotChecked, "SignatureRevocationNotChecked")]
    [InlineData(SignatureState.SignedTrusted, SignatureTrustAnchor.UserInstalledRoot, RevocationStanding.NotChecked, "SignatureUserInstalledRoot")]
    [InlineData(SignatureState.SignedUntrusted, SignatureTrustAnchor.Unspecified, RevocationStanding.Revoked, "SignatureRevoked")]
    [InlineData(SignatureState.Unsigned, SignatureTrustAnchor.Unspecified, RevocationStanding.Unspecified, null)]
    public void TheMostImportantCaveatIsChosen(
        SignatureState state, SignatureTrustAnchor anchor, RevocationStanding revocation, string? expectedKey) =>
        Assert.Equal(expectedKey, SignatureWindow.NoteKeyFor(Report(state, anchor: anchor, revocation: revocation)));

    private static void RunSta(Action body)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var original = LocalizationManager.Instance.CurrentCode;
            try
            {
                LocalizationManager.Instance.SetCulture("en");
                body();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                LocalizationManager.Instance.SetCulture(original);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The signature window test did not finish.");
        Assert.Null(failure);
    }
}
