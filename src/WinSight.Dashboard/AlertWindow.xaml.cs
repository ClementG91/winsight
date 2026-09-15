using System.IO;
using System.Windows;

using WinSight.Application;
using WinSight.Persistence;
using WinSight.Reporting;
using WinSight.Response;

namespace WinSight.Dashboard;

/// <summary>
/// The decision surface for a Guardian persistence alert: it shows what appeared and offers Allow,
/// Block or Decide later.
/// </summary>
/// <remarks>
/// Deliberately thin. Every decision is carried out by <see cref="GuardianAlertPresenter"/>, which is
/// unit tested; this window renders the alert, calls one presenter method per button, and reports
/// what actually happened - a rule that could not be stored is shown as a failure, never as "allowed".
/// "Decide later" is both the default and the cancel action, so no keystroke can remove a startup item
/// by accident: an alert never auto-selects a destructive default.
/// </remarks>
public partial class AlertWindow : Window
{
    private readonly GuardianAlertPresenter _presenter;
    private readonly AutostartEntry _entry;

    public AlertWindow(AutostartEntry entry, GuardianAlertPresenter presenter)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(presenter);
        InitializeComponent();
        _entry = entry;
        _presenter = presenter;

        ItemText.Text = UntrustedDisplayText.Neutralize($"{entry.Vector}/{entry.Name}");
        LocationText.Text = UntrustedDisplayText.Neutralize(entry.Location);
        ProgramText.Text = UntrustedDisplayText.Neutralize(entry.ImagePath ?? entry.Command);

        var options = GuardianAlertPresenter.Describe(entry);
        BlockButton.IsEnabled = options.CanBlock;
        HintText.Text = Text[options.CanBlock ? "AlertBlockHint" : "AlertRefusedUnavailable"];
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    // Each confirmation carries the exact id to undo it with, so "reversible" is something the operator
    // can act on rather than a claim: `winsight restore <id>` for a block, `winsight revoke <id>` for an
    // allow. A rule that could not be stored is a failure, never reported as allowed.
    private void AllowButton_Click(object sender, RoutedEventArgs e) => Decide(() =>
        _presenter.Allow(_entry) is { } rule ? Text.Format("AlertAllowed", rule.Id) : Text["AlertFailed"]);

    private void BlockButton_Click(object sender, RoutedEventArgs e) => Decide(() =>
    {
        var result = _presenter.Block(_entry);
        return result.Outcome == ResponseOutcome.Succeeded
            ? Text.Format("AlertBlocked", result.ActionId)
            : Text[MessageKeyFor(result.Outcome)];
    });

    private void LaterButton_Click(object sender, RoutedEventArgs e) => Close();

    /// <summary>The localized message key for an outcome. Anything unrecognised reads as a failure.</summary>
    internal static string MessageKeyFor(ResponseOutcome outcome) => outcome switch
    {
        ResponseOutcome.Succeeded => "AlertBlocked",
        ResponseOutcome.TargetChanged or ResponseOutcome.TargetNotFound => "AlertRefusedChanged",
        ResponseOutcome.NotAuthorized or ResponseOutcome.NotSupported => "AlertRefusedUnavailable",
        _ => "AlertFailed",
    };

    /// <summary>
    /// Runs one decision and shows its result, then stops offering decisions so the operator cannot act
    /// twice on the same alert. An environmental failure is reported, never allowed to take down the
    /// dashboard from a button handler.
    /// </summary>
    private void Decide(Func<string> decision)
    {
        string message;
        try
        {
            message = decision();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException or InvalidOperationException)
        {
            message = Text["AlertFailed"];
        }
        StatusText.Text = message;
        StatusPanel.Visibility = Visibility.Visible;
        AllowButton.IsEnabled = false;
        BlockButton.IsEnabled = false;
    }
}
