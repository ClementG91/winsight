using System.IO;
using System.Windows;

using WinSight.Core;
using WinSight.Reporting;

namespace WinSight.Dashboard;

/// <summary>
/// The What's Your Sign? window, opened from File Explorer's "Check signature with WinSight" verb: one
/// file's Authenticode standing, its signer, any caveat on that trust, and its identification hashes.
/// </summary>
/// <remarks>
/// The window is a view. The verdict comes from the same shared verifier every scan uses, through
/// <c>Adapters.ReportSignature</c>, so a file cannot read one way here and another in the CLI.
/// Verification can be slow (a catalog check, a large file to hash), so it runs off the UI thread and
/// the window says it is checking meanwhile. The requested path is untrusted: anything that is not an
/// ordinary local file is refused by the reporter, never opened.
/// </remarks>
public partial class SignatureWindow : Window
{
    private readonly string? _requestedPath;
    private readonly Func<string?, FileSignatureReport?> _describe;

    public SignatureWindow(string? requestedPath, Func<string?, FileSignatureReport?> describe)
    {
        ArgumentNullException.ThrowIfNull(describe);
        InitializeComponent();
        _requestedPath = requestedPath;
        _describe = describe;
        FileText.Text = UntrustedDisplayText.Neutralize(requestedPath ?? string.Empty);
        StateText.Text = Text["SignatureChecking"];
        Loaded += OnLoaded;
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        try
        {
            Render(await Task.Run(() => _describe(_requestedPath)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or InvalidOperationException)
        {
            ShowOnlyState(Text["SignatureCheckFailed"]);
        }
    }

    /// <summary>Shows a verification result; null means the path was not an ordinary local file.</summary>
    internal void Render(FileSignatureReport? report)
    {
        if (report is null)
        {
            ShowOnlyState(Text["SignatureNotLocalFile"]);
            return;
        }

        FileText.Text = UntrustedDisplayText.Neutralize(report.Path);
        StateText.Text = Text.GetOrFallback($"SignatureState{report.State}", report.State.ToString());
        SignerText.Text = report.Signer is null
            ? Text["SignatureNoSigner"]
            : UntrustedDisplayText.Neutralize(report.Signer);

        var noteKey = NoteKeyFor(report);
        NoteText.Text = noteKey is null ? string.Empty : Text[noteKey];
        NotePanel.Visibility = noteKey is null ? Visibility.Collapsed : Visibility.Visible;

        Md5Box.Text = report.Md5 ?? string.Empty;
        Sha1Box.Text = report.Sha1 ?? string.Empty;
        Sha256Box.Text = report.Sha256 ?? string.Empty;
        HashesPanel.Visibility = Visibility.Visible;
    }

    /// <summary>
    /// The caveat worth stating beside a verdict, if any: a revoked certificate, trust that rests only on
    /// a root this user could have installed, or a valid signature whose revocation was never checked.
    /// </summary>
    internal static string? NoteKeyFor(FileSignatureReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Revocation == RevocationStanding.Revoked)
        {
            return "SignatureRevoked";
        }
        if (report.RestsOnUserInstalledTrust)
        {
            return "SignatureUserInstalledRoot";
        }
        return report.State == SignatureState.SignedTrusted && report.Revocation == RevocationStanding.NotChecked
            ? "SignatureRevocationNotChecked"
            : null;
    }

    private void ShowOnlyState(string message)
    {
        StateText.Text = message;
        SignerText.Text = string.Empty;
        NotePanel.Visibility = Visibility.Collapsed;
        HashesPanel.Visibility = Visibility.Collapsed;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
