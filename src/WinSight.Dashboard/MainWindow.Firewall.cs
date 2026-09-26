using System.IO;
using System.Windows;
using WinSight.Application;
using WinSight.Firewall;
using WinSight.Reporting;

namespace WinSight.Dashboard;

public partial class MainWindow
{
    private async void FirewallBlockAppButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = Text["FirewallSelectAppTitle"],
            Filter = Text["FirewallExeFilter"],
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var path = dialog.FileName;
        await RunFirewallMutationAsync(
            token => _firewallGateway.SetPolicyAsync(new AppFirewallPolicy(path, OutboundAction.Block), token),
            isBlock: true);
    }

    private async void FirewallAllowSelectedButton_Click(object sender, RoutedEventArgs e) =>
        await SetSelectedFirewallPolicyAsync(OutboundAction.Allow);

    private async void FirewallBlockSelectedButton_Click(object sender, RoutedEventArgs e) =>
        await SetSelectedFirewallPolicyAsync(OutboundAction.Block);

    private async void FirewallRemoveSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedFirewallPath() is not { } path)
        {
            return;
        }

        await RunFirewallMutationAsync(token => _firewallGateway.RemovePolicyAsync(path, token), isBlock: false);
    }

    private async void FirewallEnableEnforcementButton_Click(object sender, RoutedEventArgs e)
    {
        // Arming is the one action that starts cutting real traffic, so it is confirmed and
        // named for what it does. The service refuses it unless this dashboard is elevated.
        var confirm = System.Windows.MessageBox.Show(
            this,
            Text["FirewallEnableEnforcementConfirm"],
            Text["FirewallEnableEnforcement"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await RunFirewallMutationAsync(
            token => _firewallGateway.EnableEnforcementAsync(token),
            isBlock: false,
            messageKey: FirewallControlPresenter.EnableEnforcementMessageKey);
    }

    private async void FirewallEmergencyButton_Click(object sender, RoutedEventArgs e)
    {
        var confirm = System.Windows.MessageBox.Show(
            this,
            Text["FirewallEmergencyConfirm"],
            Text["FirewallEmergencyDisable"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        await RunFirewallMutationAsync(token => _firewallGateway.EmergencyDisableAsync(token), isBlock: false);
    }

    private async Task SetSelectedFirewallPolicyAsync(OutboundAction action)
    {
        // Ruling covers a stored policy and an app still awaiting a decision; removal, below, only
        // covers a stored policy.
        if (SelectedActionableFirewallPath() is not { } path)
        {
            return;
        }

        await RunFirewallMutationAsync(
            token => _firewallGateway.SetPolicyAsync(new AppFirewallPolicy(path, action), token),
            isBlock: action == OutboundAction.Block);
    }

    private string? SelectedActionableFirewallPath() =>
        ResultsGrid.SelectedItem is FindingView finding
            ? FirewallControlPresenter.ActionablePath(finding.Item)
            : null;

    private string? SelectedFirewallPath() =>
        ResultsGrid.SelectedItem is FindingView finding
            ? FirewallControlPresenter.PolicyPath(finding.Item)
            : null;

    private async void BlockOutboundButton_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not FindingView finding || finding.BlockablePath is not { } path)
        {
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            this,
            Text.Format("BlockOutboundConfirm", path),
            Text["BlockOutbound"],
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            var result = await _firewallGateway.SetPolicyAsync(
                new AppFirewallPolicy(path, OutboundAction.Block), CancellationToken.None);
            // Tell the user whether the block is live or only saved until enforcement is on.
            var enforcing = result == FirewallMutationResult.Applied
                && (await _firewallGateway.GetViewAsync(CancellationToken.None)).EnforcementEnabled;
            SummaryText.Text = Text[FirewallControlPresenter.OutcomeMessageKey(result, isBlock: true, enforcing)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or TimeoutException or InvalidOperationException)
        {
            SummaryText.Text = Text.Format(
                "ActionFailed", UntrustedDisplayText.Neutralize(ex.Message));
        }
    }

    private async Task RunFirewallMutationAsync(
        Func<CancellationToken, Task<FirewallMutationResult>> mutate,
        bool isBlock,
        Func<FirewallMutationResult, FirewallEnforcementState, string>? messageKey = null)
    {
        // These run from async void event handlers, so an unexpected exception would have no
        // caller to catch it and would tear down the whole tray app. The gateway already
        // maps transport faults to a result; this net covers anything else (e.g. a pipe ACL
        // denial surfacing as UnauthorizedAccessException) with a message instead of a crash.
        try
        {
            var result = await mutate(CancellationToken.None);
            // Re-read the live status so the grid and controls reflect the change, then set
            // the outcome last (the refresh rewrites the summary) with enforcement context.
            var view = await RefreshFirewallAsync();
            SummaryText.Text = Text[messageKey is null
                ? FirewallControlPresenter.OutcomeMessageKey(result, isBlock, view.EnforcementEnabled)
                : messageKey(result, view.EffectiveState)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or TimeoutException or InvalidOperationException)
        {
            SummaryText.Text = Text.Format(
                "ActionFailed", UntrustedDisplayText.Neutralize(ex.Message));
        }
    }

    private async Task<FirewallServiceView> RefreshFirewallAsync()
    {
        var view = await _firewallGateway.GetViewAsync(CancellationToken.None);
        _latestFirewallView = view;
        StoreFirewallReports(view);
        if (ToolPicker.SelectedItem is DashboardTool tool && tool.Command == FirewallServiceAdapter.ReportTool)
        {
            ShowToolContext(tool);
        }
        return view;
    }

    private void StoreFirewallReports(FirewallServiceView view)
    {
        // One authenticated IPC read supplies both presentations. Toggling the display filter must
        // neither perform a hidden network-control operation nor make the controls disappear.
        _reportCache.Store(FirewallServiceAdapter.BuildReport(view, flaggedOnly: false), flaggedOnly: false);
        _reportCache.Store(FirewallServiceAdapter.BuildReport(view, flaggedOnly: true), flaggedOnly: true);
    }

    private void UpdateFirewallEnableControl(FirewallServiceView? view)
    {
        var state = view is null
            ? FirewallControlPresenter.EnableControl(
                serviceAvailable: false,
                enforcementEnabled: false,
                FirewallEnforcementState.AuditOnly)
            : FirewallControlPresenter.EnableControl(
                view.ServiceAvailable,
                view.EnforcementEnabled,
                view.EffectiveState);
        FirewallEnableEnforcementButton.Content = Text[state.LabelKey];
        FirewallEnableEnforcementButton.IsEnabled = state.IsEnabled;
    }
}
