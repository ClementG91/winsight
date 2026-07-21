using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using WinSight.Application;
using WinSight.Attribution;
using WinSight.AvMonitor;
using WinSight.Firewall;
using WinSight.Persistence;
using WinSight.Ransomware;
using WinSight.Reporting;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace WinSight.Dashboard;

public partial class MainWindow : Window, IDisposable
{
    private readonly Drawing.Icon? _applicationIcon;
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ToolStripItem _openTrayItem;
    private readonly Forms.ToolStripItem _exitTrayItem;
    private IReadOnlyList<ToolReport> _reports = [];
    private IReadOnlyList<ToolReport> _visibleReports = [];
    private string? _lastScanCommand;
    private CancellationTokenSource? _scanCancellation;
    private readonly FirewallServiceGateway _firewallGateway = FirewallServiceAdapter.CreateGateway();
    private readonly PersistenceMonitor _guardian = GuardianHost.CreateDefault();
    // Read-only like Guardian, so it runs unconditionally: it only reads the capability records
    // Windows already keeps. Ransomware protection stays opt-in because it alone writes.
    private readonly AvWatchHost _avWatch = new();
    // Opt-in: created only when the operator enables ransomware protection, because it is the one
    // feature that WRITES (decoy files) into their personal folders. Null means off, nothing planted.
    private RansomwareMonitor? _ransomware;
    // Names the program behind a persistence alert. Null when the dashboard is not elevated: a
    // kernel trace session is privileged, and WinSight is deliberately unprivileged by default, so
    // attribution is a bonus for an elevated run rather than a reason to demand elevation.
    private AttributionHost? _attribution;
    private bool _allowClose;
    private bool _disposed;
    private bool _initializing = true;
    private bool _shownTrayHint;

    public MainWindow()
    {
        InitializeComponent();
        DashboardTools.Reload();
        ToolPicker.ItemsSource = DashboardTools.All;
        ToolPicker.SelectedIndex = 0;

        var menu = new Forms.ContextMenuStrip();
        _openTrayItem = menu.Items.Add(Text["TrayOpen"], null, (_, _) => Dispatcher.Invoke(ShowFromTray));
        _exitTrayItem = menu.Items.Add(Text["TrayExit"], null, (_, _) => Dispatcher.Invoke(ExitApplication));
        _applicationIcon = TryLoadApplicationIcon();
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = _applicationIcon ?? Drawing.SystemIcons.Shield,
            Text = Text["TrayText"],
            Visible = true,
            ContextMenuStrip = menu,
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowFromTray);
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized)
            {
                HideToTray();
            }
        };

        LanguagePicker.ItemsSource = Text.SupportedLanguages;
        LanguagePicker.SelectedValue = Text.CurrentCode;
        _initializing = false;

        Loaded += (_, _) => StartGuardian();
    }

    /// <summary>
    /// Begins real-time persistence monitoring (Guardian) for as long as the dashboard runs. Seeding
    /// the baseline is a full persistence scan, so it runs off the UI thread to keep startup snappy;
    /// a genuinely new startup item then raises a tray balloon.
    /// </summary>
    private void StartGuardian()
    {
        StartCameraMicWatch();
        StartAttribution();
        _guardian.Detected += OnGuardianDetected;
        Task.Run(() =>
        {
            try
            {
                _guardian.Start();
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                // Monitoring is best-effort: if the initial scan cannot run, the dashboard still
                // works and the on-demand persistence scan is unaffected.
            }
        });
    }

    /// <summary>
    /// Begins watching registry writes so a persistence alert can name the program that installed
    /// the entry, when the dashboard is elevated enough to open a kernel trace session.
    /// </summary>
    /// <remarks>
    /// Started only when elevated, deliberately. Starting it regardless would open a privileged
    /// session on every launch just to have it refused, and the refusal would be indistinguishable
    /// from a quiet machine. Unelevated, the alert simply carries no author — which is the honest
    /// answer, and never blocks the detection itself.
    /// </remarks>
    private void StartAttribution()
    {
        if (!AttributionHost.IsElevated())
        {
            return;
        }
        _attribution = new AttributionHost();
        _attribution.Start();
    }

    /// <summary>
    /// Begins real-time camera/microphone watching for as long as the dashboard runs.
    /// </summary>
    /// <remarks>
    /// The detector existed but nothing hosted it, so "your webcam just turned on" — the signal an
    /// OverSight-class monitor exists to give — never reached anyone using the app. Only activations
    /// raise a balloon; a device being released is not a security event, though both are journalled
    /// so the record shows how long something was watching or listening.
    /// </remarks>
    private void StartCameraMicWatch()
    {
        _avWatch.Detected += OnCameraMicDetected;
        _avWatch.Start();
    }

    private void OnCameraMicDetected(object? sender, DeviceEvent e)
    {
        var usage = e.Usage;
        // Journal first, for the same reason as every other detection: Windows may drop the balloon
        // and a detection that leaves no trace is indistinguishable from no detection.
        AlertJournal.Append(new SecurityAlert(
            DateTimeOffset.Now,
            "Camera/Mic",
            $"{usage.Kind}{(e.Kind == AvEventKind.Activated ? "Activated" : "Deactivated")}",
            usage.App));

        if (e.Kind != AvEventKind.Activated)
        {
            return;
        }

        var message = usage.Kind == DeviceKind.Webcam
            ? Text["AvWebcamActivated"]
            : Text["AvMicrophoneActivated"];
        Dispatcher.Invoke(() =>
        {
            if (_disposed)
            {
                return;
            }
            _trayIcon.ShowBalloonTip(
                5000,
                Text["AvBalloonTitle"],
                $"{AvPresenter.DisplayName(usage)} — {message}",
                Forms.ToolTipIcon.Warning);
        });
    }

    /// <summary>
    /// Turns on ransomware protection. This is opt-in because it is the only WinSight feature that
    /// writes into the operator's own folders: it sweeps decoys orphaned by an earlier crash, plants
    /// fresh hidden ones, and watches them. Planting is file I/O, so it runs off the UI thread.
    /// </summary>
    private void RansomwareProtection_Checked(object sender, RoutedEventArgs e)
    {
        if (_initializing || _disposed || _ransomware is not null)
        {
            return;
        }

        var monitor = RansomwareHost.CreateDefault();
        monitor.Detected += OnRansomwareDetected;
        _ransomware = monitor;
        Task.Run(() =>
        {
            try
            {
                monitor.Start();
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                // Best-effort: a folder we cannot write leaves protection partial, not broken.
            }
        });
    }

    private void RansomwareProtection_Unchecked(object sender, RoutedEventArgs e) => StopRansomwareProtection();

    /// <summary>Stops protection and removes every planted decoy. Safe to call when already off.</summary>
    private void StopRansomwareProtection()
    {
        var monitor = _ransomware;
        _ransomware = null;
        if (monitor is null)
        {
            return;
        }
        monitor.Detected -= OnRansomwareDetected;
        monitor.Dispose(); // removes the decoys
    }

    private void OnRansomwareDetected(object? sender, RansomwareDetectedEventArgs e)
    {
        // Journal FIRST, balloon second. Windows may suppress the balloon entirely (Focus Assist, or
        // its throttling of an app posting several toasts quickly), and a detection that leaves no
        // trace is indistinguishable from no detection at all.
        AlertJournal.Append(new SecurityAlert(DateTimeOffset.Now, "Ransomware", e.Kind.ToString(), e.Path));

        Dispatcher.Invoke(() =>
        {
            if (_disposed)
            {
                return;
            }
            // Louder and longer than a persistence alert: this is the one event where minutes matter.
            _trayIcon.ShowBalloonTip(
                10000,
                Text["RansomwareBalloonTitle"],
                $"{Text[RansomwarePresenter.AlertMessageKey(e.Kind)]}\n{RansomwarePresenter.Detail(e.Kind, e.Path)}",
                RansomwarePresenter.IsCritical(e.Kind) ? Forms.ToolTipIcon.Error : Forms.ToolTipIcon.Warning);
        });
    }

    private void OnGuardianDetected(object? sender, PersistenceDetectedEventArgs e)
    {
        var detection = e.Detected;
        AlertJournal.Append(new SecurityAlert(
            DateTimeOffset.Now,
            "Guardian",
            detection.Entry.Vector.ToString(),
            PersistenceMonitorPresenter.AlertDetail(
                detection,
                _attribution is { } attribution ? attribution.Attribute : null)));

        Dispatcher.Invoke(() =>
        {
            if (_disposed)
            {
                return;
            }
            _trayIcon.ShowBalloonTip(
                5000,
                Text["GuardianBalloonTitle"],
                $"{detection.Entry.Vector}/{detection.Entry.Name} — {Text[PersistenceMonitorPresenter.BalloonMessageKey(detection)]}",
                detection.IsNotable ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
        });
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    private static Drawing.Icon? TryLoadApplicationIcon()
    {
        try
        {
            return string.IsNullOrWhiteSpace(Environment.ProcessPath)
                ? null
                : Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath);
        }
        catch (Exception ex) when (ex is ArgumentException or ExternalException or FileNotFoundException)
        {
            return null;
        }
    }

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
        _lastScanCommand = null;
        ExportButton.IsEnabled = false;
        CopyButton.IsEnabled = false;
        OpenLocationButton.IsEnabled = false;
        SelectedFindingText.Text = string.Empty;

        try
        {
            var flaggedOnly = FlaggedOnly.IsChecked == true;
            if (tool.Command == "outbound-firewall")
            {
                // Live status over the authenticated pipe (I/O, not a CPU scan). When
                // the service is not installed this degrades to "unavailable".
                var view = await _firewallGateway.GetViewAsync(cancellation.Token);
                _reports = [FirewallServiceAdapter.BuildReport(view)];
            }
            else if (tool.Command == "all")
            {
                var progress = new Progress<ScanProgress>(UpdateProgress);
                _reports = await Task.Run(
                    () => Adapters.RunOverview(flaggedOnly, progress, cancellationToken: cancellation.Token),
                    cancellation.Token);
            }
            else
            {
                _reports = await Task.Run(
                    () => (IReadOnlyList<ToolReport>)[Adapters.Run(
                        tool.Command,
                        flaggedOnly,
                        cancellationToken: cancellation.Token)],
                    cancellation.Token);
            }

            _lastScanCommand = tool.Command;
            ShowToolContext(tool);
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            ProgressText.Text = Text["ProgressComplete"];
        }
        catch (OperationCanceledException)
        {
            _reports = [];
            _lastScanCommand = null;
            SummaryText.Text = Text["ScanCancelledSummary"];
            ProgressText.Text = Text["ProgressCancelled"];
        }
        catch (UnauthorizedAccessException)
        {
            _reports = [];
            _lastScanCommand = null;
            SummaryText.Text = Text["InsufficientSummary"];
            ProgressText.Text = Text["ProgressInsufficient"];
        }
        catch (Exception ex)
        {
            _reports = [];
            _lastScanCommand = null;
            SummaryText.Text = Text.Format("ScanFailed", ex.Message);
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
        ProgressPanel.Visibility = scanning || _reports.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = scanning && tool.Command == "all" ? Visibility.Visible : Visibility.Collapsed;
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
        _exitTrayItem.Text = Text["TrayExit"];
        _trayIcon.Text = Text["TrayText"];
    }

    private void ShowToolContext(DashboardTool tool)
    {
        ShowToolExplanation(tool);
        var selection = DashboardReportRouter.Select(tool, _lastScanCommand, _reports);

        // The interactive firewall controls appear for the firewall tool once a status has
        // been read (a scan happened). They stay visible even when the service is
        // unavailable so the user is not left without controls; each action then reports
        // the "service unavailable" outcome rather than silently doing nothing.
        var showFirewallControls = tool.Command == FirewallServiceAdapter.ReportTool && selection.Available;
        FirewallActionsPanel.Visibility = showFirewallControls ? Visibility.Visible : Visibility.Collapsed;

        if (!selection.Available)
        {
            _visibleReports = [];
            ResultsGrid.ItemsSource = null;
            SummaryText.Text = Text.Format("RunThisAnalysis", tool.Label);
            SelectedFindingText.Text = Text["NoAnalysisForTool"];
            CopyButton.IsEnabled = false;
            OpenLocationButton.IsEnabled = false;
            ExportButton.IsEnabled = false;
            return;
        }

        ShowReports(selection.Reports, selection.Categorize);
    }

    private void ShowReports(IReadOnlyList<ToolReport> reports, bool categorize)
    {
        _visibleReports = reports;
        var findings = reports.SelectMany(report => report.Items.Select(item =>
        {
            var presentation = DashboardFindingPresenter.Present(report.Tool, item, Text);
            var title = categorize
                ? $"{DashboardTools.ForReport(report.Tool)?.Label ?? report.Tool} · {presentation.Title}"
                : presentation.Title;
            return new FindingView(
                item.Severity == Severity.Notable ? Text["NotableSeverity"] : Text["InfoSeverity"],
                title,
                presentation.Detail,
                item,
                FirewallActionPresenter.BlockableExecutable(report.Tool, item));
        })).ToList();
        ResultsGrid.ItemsSource = findings;
        SummaryText.Text = DashboardResultSummary.Format(
            Text,
            findings.Count,
            reports.Sum(report => report.NotableCount));
        SelectedFindingText.Text = findings.Count == 0
            ? Text["NoItems"]
            : Text["SelectFinding"];
        ExportButton.IsEnabled = true;
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new VirusTotalSettingsWindow { Owner = this };
        _ = dialog.ShowDialog();
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
            SummaryText.Text = Text.Format("ActionFailed", ex.Message);
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
            SummaryText.Text = Text.Format("ActionFailed", ex.Message);
        }
    }

    private async Task<FirewallServiceView> RefreshFirewallAsync()
    {
        var view = await _firewallGateway.GetViewAsync(CancellationToken.None);
        _reports = [FirewallServiceAdapter.BuildReport(view)];
        _lastScanCommand = FirewallServiceAdapter.ReportTool;
        if (ToolPicker.SelectedItem is DashboardTool tool && tool.Command == FirewallServiceAdapter.ReportTool)
        {
            ShowToolContext(tool);
        }
        return view;
    }

    private void TryUserAction(Action action, string successMessage)
    {
        try
        {
            action();
            SummaryText.Text = successMessage;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException
                                     or UnauthorizedAccessException or ExternalException)
        {
            SummaryText.Text = Text.Format("ActionFailed", ex.Message);
        }
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void HideToTray()
    {
        Hide();
        if (!_shownTrayHint)
        {
            _trayIcon.ShowBalloonTip(2500, "WinSight", Text["TrayHintMessage"], Forms.ToolTipIcon.Info);
            _shownTrayHint = true;
        }
    }

    private void ExitApplication()
    {
        _scanCancellation?.Cancel();
        _allowClose = true;
        Close();
    }

    internal void ExitForSmokeTest() => ExitApplication();

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_allowClose)
        {
            e.Cancel = true;
            HideToTray();
            return;
        }

        Dispose();
        base.OnClosing(e);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _scanCancellation?.Dispose();
        StopRansomwareProtection(); // removes any planted decoys before we go
        _guardian.Detected -= OnGuardianDetected;
        _guardian.Dispose();
        _avWatch.Detected -= OnCameraMicDetected;
        _avWatch.Dispose();
        _attribution?.Dispose(); // closes the trace session before the process goes
        _attribution = null;
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _applicationIcon?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

public sealed record FindingView(
    string SeverityLabel, string Title, string Detail, ReportItem Item, string? BlockablePath = null);
