using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using WinSight.Application;
using WinSight.Core;
using WinSight.Reporting;

namespace WinSight.Dashboard;

public partial class MainWindow
{
    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (ToolPicker.SelectedItem is not DashboardTool tool)
        {
            return;
        }

        var cancellation = new CancellationTokenSource();
        _scanCancellation = cancellation;
        SetScanningState(tool, scanning: true);
        ResultsGrid.ItemsSource = null;
        _visibleReports = [];
        ExportButton.IsEnabled = false;
        CopyButton.IsEnabled = false;
        OpenLocationButton.IsEnabled = false;
        SelectedFindingText.Text = string.Empty;
        var flaggedOnly = FlaggedOnly.IsChecked == true;

        try
        {
            if (tool.Command == "outbound-firewall")
            {
                // Live status over the authenticated pipe (I/O, not a CPU scan). When
                // the service is not installed this degrades to "unavailable".
                var view = await _firewallGateway.GetViewAsync(cancellation.Token);
                _latestFirewallView = view;
                StoreFirewallReports(view);
            }
            else if (tool.Command == "all")
            {
                var progress = new Progress<ScanProgress>(UpdateProgress);
                var reports = await Task.Run(
                    () => Adapters.RunOverview(flaggedOnly, progress, cancellationToken: cancellation.Token),
                    cancellation.Token);
                _reportCache.StoreOverview(reports, flaggedOnly);
            }
            else
            {
                var report = await Task.Run(
                    () => Adapters.Run(
                        tool.Command,
                        flaggedOnly,
                        cancellationToken: cancellation.Token),
                    cancellation.Token);
                _reportCache.Store(report, flaggedOnly);
            }

            ShowToolContext(tool);
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            ProgressText.Text = Text["ProgressComplete"];
        }
        catch (OperationCanceledException)
        {
            _reportCache.Remove(tool, flaggedOnly);
            if (tool.Command == FirewallServiceAdapter.ReportTool)
            {
                _latestFirewallView = null;
            }
            ShowToolContext(tool);
            SummaryText.Text = Text["ScanCancelledSummary"];
            ProgressText.Text = Text["ProgressCancelled"];
        }
        catch (UnauthorizedAccessException)
        {
            _reportCache.Remove(tool, flaggedOnly);
            if (tool.Command == FirewallServiceAdapter.ReportTool)
            {
                _latestFirewallView = null;
            }
            ShowToolContext(tool);
            SummaryText.Text = Text["InsufficientSummary"];
            ProgressText.Text = Text["ProgressInsufficient"];
        }
        catch (Exception ex)
        {
            _reportCache.Remove(tool, flaggedOnly);
            if (tool.Command == FirewallServiceAdapter.ReportTool)
            {
                _latestFirewallView = null;
            }
            ShowToolContext(tool);
            SummaryText.Text = Text.Format(
                "ScanFailed", UntrustedDisplayText.Neutralize(ex.Message));
            ProgressText.Text = Text["UnexpectedError"];
        }
        finally
        {
            SetScanningState(tool, scanning: false);
            if (ReferenceEquals(_scanCancellation, cancellation))
            {
                _scanCancellation = null;
            }
            cancellation.Dispose();
        }
    }

    private void SetScanningState(DashboardTool tool, bool scanning)
    {
        ScanButton.IsEnabled = !scanning;
        ToolPicker.IsEnabled = !scanning;
        FlaggedOnly.IsEnabled = !scanning;
        LanguagePicker.IsEnabled = !scanning;
        SettingsButton.IsEnabled = !scanning;
        if (scanning)
        {
            _progressCommand = tool.Command;
        }
        ProgressPanel.Visibility = scanning || string.Equals(_progressCommand, tool.Command, StringComparison.OrdinalIgnoreCase)
            ? Visibility.Visible
            : Visibility.Collapsed;
        // Cancel is offered for every scan, not only the overview. The single longest scan in the
        // product is `modules` - measured at 9 991 modules across 155 processes - and it was the one
        // an operator could not stop, while the business layer had accepted a cancellation token all
        // along. Every tool below the UI either honours the token or completes in well under a
        // second, so the button is never a promise the scan cannot keep.
        CancelButton.Visibility = scanning ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.IsEnabled = scanning;

        if (scanning)
        {
            ScanProgressBar.Value = 0;
            ScanProgressBar.IsIndeterminate = tool.Command != "all";
            ProgressText.Text = tool.Command == "all"
                ? Text["OverviewPreparing"]
                : Text.Format("SingleScan", tool.Label);
            SummaryText.Text = Text["ReadingWindows"];
        }
    }

    private void UpdateProgress(ScanProgress progress)
    {
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = progress.Percent;
        var tool = DashboardTools.ForCommand(progress.Command);
        ProgressText.Text = Text.Format(
            "ProgressFormat",
            progress.Completed,
            progress.Total,
            tool?.Label ?? progress.Command);
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _scanCancellation?.Cancel();
        CancelButton.IsEnabled = false;
        ProgressText.Text = Text["StopRequested"];
    }

    private void ToolPicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ToolPicker.SelectedItem is DashboardTool tool)
        {
            ShowToolContext(tool);
        }
    }

    private void FlaggedOnly_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initializing && ToolPicker.SelectedItem is DashboardTool tool)
        {
            ShowToolContext(tool);
        }
    }

    private void LanguagePicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing || LanguagePicker.SelectedItem is not UiLanguage language)
        {
            return;
        }

        var selectedCommand = (ToolPicker.SelectedItem as DashboardTool)?.Command ?? "all";
        Text.SetCulture(language.Code, remember: true);
        DashboardTools.Reload();
        ToolPicker.ItemsSource = DashboardTools.All;
        ToolPicker.SelectedItem = DashboardTools.ForCommand(selectedCommand) ?? DashboardTools.All[0];
        RefreshTrayText();

        if (ToolPicker.SelectedItem is DashboardTool selectedTool)
        {
            ShowToolContext(selectedTool);
        }
    }

    private void RefreshTrayText()
    {
        _openTrayItem.Text = Text["TrayOpen"];
        _retryGuardianTrayItem.Text = Text["TrayRetryGuardian"];
        _exitTrayItem.Text = Text["TrayExit"];
        _trayIcon.Text = Text["TrayText"];
    }

    private void ShowToolContext(DashboardTool tool)
    {
        ShowToolExplanation(tool);
        var selection = _reportCache.Select(tool, FlaggedOnly.IsChecked == true);
        ProgressPanel.Visibility = string.Equals(_progressCommand, tool.Command, StringComparison.OrdinalIgnoreCase)
                                   && (_scanCancellation is not null || selection.Available)
            ? Visibility.Visible
            : Visibility.Collapsed;
        ScanButton.Content = Text[selection.Available ? "RefreshAnalysis" : "StartAnalysis"];
        System.Windows.Automation.AutomationProperties.SetName(
            ScanButton,
            Text[selection.Available ? "RefreshAnalysisAutomation" : "StartAnalysisAutomation"]);

        // The interactive firewall controls appear for the firewall tool once a status has
        // been read (a scan happened). They stay visible even when the service is
        // unavailable so the user is not left without controls; each action then reports
        // the "service unavailable" outcome rather than silently doing nothing.
        var showFirewallControls = tool.Command == FirewallServiceAdapter.ReportTool && selection.Available;
        FirewallActionsPanel.Visibility = showFirewallControls ? Visibility.Visible : Visibility.Collapsed;
        if (showFirewallControls)
        {
            UpdateFirewallEnableControl(_latestFirewallView);
        }

        if (!selection.Available)
        {
            _visibleReports = [];
            ResultsGrid.ItemsSource = null;
            SummaryText.Text = Text.Format("RunThisAnalysis", tool.Label);
            SelectedFindingText.Text = tool.Command switch
            {
                "all" => Text["NoOverviewResults"],
                _ when Adapters.OverviewCommands.Contains(tool.Command, StringComparer.OrdinalIgnoreCase) =>
                    Text["NoAnalysisForTool"],
                _ => Text["NotIncludedInOverview"],
            };
            CopyButton.IsEnabled = false;
            OpenLocationButton.IsEnabled = false;
            ExportButton.IsEnabled = false;
            return;
        }

        ShowReports(selection.Reports, selection.Categorize, selection.CapturedAt!.Value);
    }

    private void ShowReports(
        IReadOnlyList<ToolReport> reports,
        bool categorize,
        DateTimeOffset capturedAt)
    {
        _visibleReports = reports;
        var findings = reports.SelectMany(report => report.Items.Select(item =>
        {
            var presentation = DashboardFindingPresenter.Present(report.Tool, item, Text);
            var title = categorize
                ? $"{DashboardTools.ForReport(report.Tool)?.Label ?? report.Tool} · {presentation.Title}"
                : presentation.Title;
            return new FindingView(
                item.Severity switch
                {
                    Severity.Notable => Text["NotableSeverity"],
                    Severity.Unverified => Text["UnverifiedSeverity"],
                    _ => Text["InfoSeverity"],
                },
                UntrustedDisplayText.Neutralize(title),
                UntrustedDisplayText.Neutralize(presentation.Detail),
                item,
                FirewallActionPresenter.BlockableExecutable(report.Tool, item));
        })).ToList();
        ResultsGrid.ItemsSource = findings;
        SummaryText.Text = Text.Format(
            "ResultsCapturedAt",
            DashboardResultSummary.Format(
                Text,
                findings.Count,
                reports.Sum(report => report.NotableCount)),
            capturedAt.ToLocalTime());
        SelectedFindingText.Text = findings.Count == 0
            ? Text["NoItems"]
            : Text["SelectFinding"];
        ExportButton.IsEnabled = true;
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new VirusTotalSettingsWindow { Owner = this };
        if (dialog.ShowDialog() == true && dialog.SavedMessage is { Length: > 0 } message)
        {
            SummaryText.Text = message;
        }
    }

    private void ShowToolExplanation(DashboardTool tool)
    {
        SelectedToolTitle.Text = tool.Label;
        SelectedToolDescription.Text = tool.Description;
        GuidanceText.Text = tool.Guidance;
        WindowsToolButton.Visibility = tool.WindowsAction == DashboardWindowsAction.None
            ? Visibility.Collapsed
            : Visibility.Visible;
        WindowsToolButton.Tag = tool.WindowsAction;
        WindowsToolButton.Content = Text[DashboardWindowsActions.LabelResource(tool.WindowsAction)];
    }

    private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not FindingView finding)
        {
            CopyButton.IsEnabled = false;
            OpenLocationButton.IsEnabled = false;
            BlockOutboundButton.IsEnabled = false;
            SetFirewallRowButtonsEnabled(canRule: false, canRemove: false);
            SelectedFindingText.Text = string.Empty;
            return;
        }

        CopyButton.IsEnabled = true;
        OpenLocationButton.IsEnabled = FindingActions.ExistingAbsolutePath(finding.Item) is not null;
        BlockOutboundButton.IsEnabled = finding.BlockablePath is not null;
        SetFirewallRowButtonsEnabled(
            canRule: FirewallControlPresenter.ActionablePath(finding.Item) is not null,
            canRemove: FirewallControlPresenter.IsPolicyRow(finding.Item));
        SelectedFindingText.Text = Text.Format(
            "FindingSelectionFormat",
            finding.SeverityLabel,
            finding.Title,
            finding.Detail);
    }

    /// <param name="canRule">
    /// Whether an allow or block applies: true for a stored policy and for an app still awaiting a
    /// decision.
    /// </param>
    /// <param name="canRemove">
    /// Whether removal applies. Only a stored policy can be removed — offering it for an app that
    /// has no policy yet would promise an action that does nothing.
    /// </param>
    private void SetFirewallRowButtonsEnabled(bool canRule, bool canRemove)
    {
        FirewallAllowSelectedButton.IsEnabled = canRule;
        FirewallBlockSelectedButton.IsEnabled = canRule;
        FirewallRemoveSelectedButton.IsEnabled = canRemove;
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not FindingView finding)
        {
            return;
        }

        var text = new StringBuilder()
            .Append(finding.SeverityLabel)
            .Append(": ")
            .AppendLine(finding.Title)
            .AppendLine(finding.Detail);
        foreach (var field in finding.Item.Fields.OrderBy(field => field.Key, StringComparer.Ordinal))
        {
            text.Append(field.Key).Append(": ").AppendLine(field.Value);
        }
        TryUserAction(
            () => System.Windows.Clipboard.SetText(text.ToString()),
            Text["Copied"]);
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_visibleReports.Count == 0)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = Text["ExportDialogTitle"],
            FileName = $"winsight-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            DefaultExt = ".json",
            Filter = Text["JsonFilter"],
            AddExtension = true,
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        TryUserAction(() =>
        {
            using var writer = File.CreateText(dialog.FileName);
            ReportRenderer.RenderJson(_visibleReports, writer);
        }, Text.Format("Exported", dialog.FileName));
    }

    private void OpenLocationButton_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not FindingView finding || FindingActions.ExistingAbsolutePath(finding.Item) is not { } path)
        {
            return;
        }

        var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        var startInfo = new ProcessStartInfo(explorer) { UseShellExecute = false };
        VirusTotalConfiguration.RemoveFromChildEnvironment(startInfo);
        startInfo.ArgumentList.Add(Directory.Exists(path) ? path : $"/select,{path}");
        TryUserAction(() => _ = Process.Start(startInfo), Text["LocationOpened"]);
    }

    private void WindowsToolButton_Click(object sender, RoutedEventArgs e)
    {
        if (WindowsToolButton.Tag is not DashboardWindowsAction action || action == DashboardWindowsAction.None)
        {
            return;
        }

        var startInfo = DashboardWindowsActions.StartInfo(action);
        TryUserAction(() => _ = Process.Start(startInfo), Text["WindowsToolOpened"]);
    }
}
