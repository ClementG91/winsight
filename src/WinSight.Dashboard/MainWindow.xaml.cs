using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using WinSight.Application;
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
            if (tool.Command == "all")
            {
                var progress = new Progress<ScanProgress>(UpdateProgress);
                _reports = await Task.Run(
                    () => Adapters.RunOverview(flaggedOnly, progress, cancellationToken: cancellation.Token),
                    cancellation.Token);
            }
            else
            {
                _reports = await Task.Run(
                    () => (IReadOnlyList<ToolReport>)[Adapters.Run(tool.Command, flaggedOnly)],
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
            var title = categorize
                ? $"{DashboardTools.ForReport(report.Tool)?.Label ?? report.Tool} · {item.Title}"
                : item.Title;
            return new FindingView(
                item.Severity == Severity.Notable ? Text["NotableSeverity"] : Text["InfoSeverity"],
                title,
                LocalizeFindingDetail(item),
                item);
        })).ToList();
        ResultsGrid.ItemsSource = findings;
        SummaryText.Text = Text.Format("ResultsSummary", findings.Count, reports.Sum(report => report.NotableCount));
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

    private string LocalizeFindingDetail(ReportItem item)
    {
        if (!item.Fields.TryGetValue("status", out var status) || string.IsNullOrWhiteSpace(status))
        {
            return item.Detail;
        }

        var label = Text[$"PersistenceStatus{status}"];
        var evidence = FirstNonEmpty(item, "image", "expectedImage", "command") ?? item.Detail;
        var suffix = item.Fields.TryGetValue("vtMalicious", out var malicious) &&
                     item.Fields.TryGetValue("vtTotal", out var total) &&
                     !string.IsNullOrWhiteSpace(malicious) && !string.IsNullOrWhiteSpace(total)
            ? $"{label}; VT {malicious}/{total}"
            : label;
        return $"{evidence}  [{suffix}]";
    }

    private static string? FirstNonEmpty(ReportItem item, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (item.Fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }
        return null;
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
        WindowsToolButton.Content = Text[WindowsActionLabel(tool.WindowsAction)];
    }

    private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not FindingView finding)
        {
            CopyButton.IsEnabled = false;
            OpenLocationButton.IsEnabled = false;
            SelectedFindingText.Text = string.Empty;
            return;
        }

        CopyButton.IsEnabled = true;
        OpenLocationButton.IsEnabled = FindingActions.ExistingAbsolutePath(finding.Item) is not null;
        SelectedFindingText.Text = Text.Format(
            "FindingSelectionFormat",
            finding.SeverityLabel,
            finding.Title,
            finding.Detail);
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

        var startInfo = WindowsActionStartInfo(action);
        TryUserAction(() => _ = Process.Start(startInfo), Text["WindowsToolOpened"]);
    }

    private static string WindowsActionLabel(DashboardWindowsAction action) => action switch
    {
        DashboardWindowsAction.StartupApps => "OpenStartupSettings",
        DashboardWindowsAction.Privacy => "OpenPrivacySettings",
        DashboardWindowsAction.Network => "OpenResourceMonitor",
        DashboardWindowsAction.NetworkSettings => "OpenNetworkSettings",
        DashboardWindowsAction.Firewall => "OpenFirewall",
        DashboardWindowsAction.Processes => "OpenTaskManager",
        DashboardWindowsAction.InstalledApps => "OpenInstalledApps",
        DashboardWindowsAction.Certificates => "OpenCertificates",
        _ => "OpenWindowsTool",
    };

    private static ProcessStartInfo WindowsActionStartInfo(DashboardWindowsAction action)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (action is DashboardWindowsAction.Processes or DashboardWindowsAction.Network)
        {
            var executable = action == DashboardWindowsAction.Processes ? "Taskmgr.exe" : "resmon.exe";
            return new ProcessStartInfo(Path.Combine(system, executable)) { UseShellExecute = false };
        }

        if (action is DashboardWindowsAction.Firewall or DashboardWindowsAction.Certificates)
        {
            var startInfo = new ProcessStartInfo(Path.Combine(system, "mmc.exe")) { UseShellExecute = false };
            startInfo.ArgumentList.Add(Path.Combine(
                system,
                action == DashboardWindowsAction.Firewall ? "wf.msc" : "certlm.msc"));
            return startInfo;
        }

        var settingsUri = action switch
        {
            DashboardWindowsAction.StartupApps => "ms-settings:startupapps",
            DashboardWindowsAction.Privacy => "ms-settings:privacy-webcam",
            DashboardWindowsAction.NetworkSettings => "ms-settings:network-status",
            DashboardWindowsAction.InstalledApps => "ms-settings:appsfeatures",
            _ => throw new InvalidOperationException("No Windows action is configured."),
        };
        return new ProcessStartInfo(settingsUri) { UseShellExecute = true };
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
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _applicationIcon?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

public sealed record FindingView(string SeverityLabel, string Title, string Detail, ReportItem Item);

public enum DashboardWindowsAction
{
    None,
    StartupApps,
    Privacy,
    Network,
    NetworkSettings,
    Firewall,
    Processes,
    InstalledApps,
    Certificates,
}

public sealed record DashboardTool(
    string Label,
    string Command,
    string ReportName,
    string ShortDescription,
    string Description,
    string Guidance,
    DashboardWindowsAction WindowsAction = DashboardWindowsAction.None);

public static class DashboardTools
{
    private static IReadOnlyList<DashboardTool> _all = Build();

    public static IReadOnlyList<DashboardTool> All => _all;

    public static void Reload() => _all = Build();

    private static IReadOnlyList<DashboardTool> Build() =>
    [
        Tool("Overview", "all", "all"),
        Tool("Persistence", "persistence", "persistence", DashboardWindowsAction.StartupApps),
        Tool("Av", "av", "camera-mic", DashboardWindowsAction.Privacy),
        Tool("Network", "net", "connections", DashboardWindowsAction.Network),
        Tool("Dns", "dns", "dns", DashboardWindowsAction.NetworkSettings),
        Tool("Firewall", "firewall", "firewall", DashboardWindowsAction.Firewall),
        Tool("Processes", "processes", "processes", DashboardWindowsAction.Processes),
        Tool("Modules", "modules", "modules", DashboardWindowsAction.Processes),
        Tool("Extensions", "extensions", "extensions", DashboardWindowsAction.InstalledApps),
        Tool("Certificates", "certs", "certificates", DashboardWindowsAction.Certificates),
        Tool("Hosts", "hosts", "hosts"),
    ];

    private static DashboardTool Tool(
        string resourceName,
        string command,
        string reportName,
        DashboardWindowsAction windowsAction = DashboardWindowsAction.None)
    {
        var text = LocalizationManager.Instance;
        var prefix = $"Tool{resourceName}";
        return new DashboardTool(
            text[$"{prefix}Label"],
            command,
            reportName,
            text[$"{prefix}Short"],
            text[$"{prefix}Description"],
            text[$"{prefix}Guidance"],
            windowsAction);
    }

    public static DashboardTool? ForCommand(string command) =>
        All.FirstOrDefault(tool => tool.Command.Equals(command, StringComparison.OrdinalIgnoreCase));

    public static DashboardTool? ForReport(string reportName) =>
        All.FirstOrDefault(tool => tool.ReportName.Equals(reportName, StringComparison.OrdinalIgnoreCase));
}
