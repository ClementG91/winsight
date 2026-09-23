using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using WinSight.Application;
using WinSight.Attribution;
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
    private readonly Forms.ToolStripItem _retryGuardianTrayItem;
    private readonly DashboardReportCache _reportCache = new();
    private IReadOnlyList<ToolReport> _visibleReports = [];
    private string? _progressCommand;
    private FirewallServiceView? _latestFirewallView;
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

    // Which file writes attribution is allowed to remember. Long-lived and shared: the trace thread
    // reads it on every file event while the UI thread updates it as protection is toggled.
    private readonly AttributionScope _attributionScope = new();
    private readonly ProtectionSettingsStore _protectionSettings = ProtectionSettingsStore.Default;

    // What each real-time monitor actually managed to do, as opposed to what was switched on. These
    // are read by RefreshProtectionHealth and are the difference between a green badge that means
    // something and one that only means a checkbox is ticked.
    private volatile bool _guardianStarted;
    private volatile bool _guardianStartFailed;
    private bool _cameraMicStarted;

    // Monitor health can change without any UI event: a camera/mic worker can fail, a directory
    // watch can be lost. Polling the cheap counters keeps the badge from freezing on "active".
    private readonly System.Windows.Threading.DispatcherTimer _protectionHealthTimer = new()
    {
        Interval = TimeSpan.FromSeconds(5),
    };

    // Guardian detections waiting to be announced together, and the timer that decides when
    // "together" has ended. Both are touched only on the UI thread.
    private readonly List<PersistenceEvent> _pendingDetections = [];
    private readonly System.Windows.Threading.DispatcherTimer _guardianBalloonTimer = new()
    {
        Interval = GuardianAlertBatcher.DefaultWindow,
    };
    private SecurityAlert? _pendingAlert;
    private bool _allowClose;
    private bool _disposed;
    private bool _initializing = true;
    private bool _shownTrayHint;

    // Decides what a Guardian alert offers and carries out Allow/Block; UI-free and unit tested. The
    // open decision windows are tracked per item so they close with the dashboard, so the same item
    // never gets two windows, and so a burst cannot stack an unbounded number of topmost windows -
    // past the cap the coalesced balloon remains the fallback, so no alert is ever lost.
    private readonly GuardianAlertPresenter _alertPresenter = new();
    private readonly Dictionary<PersistenceIdentity, AlertWindow> _openAlertWindows = [];
    private const int MaxOpenAlertWindows = 3;

    /// <summary>
    /// The detection the balloon currently on screen is about, so clicking it can land the operator on
    /// that entry rather than on the dashboard's front page. Null when the balloon carries no alert
    /// (the "still running in the notification area" hint), which must not navigate anywhere.
    /// </summary>
    private SecurityAlert? _balloonAlert;

    /// <summary>The catalog command whose report renders <see cref="AlertJournal"/>.</summary>
    private const string AlertsCommand = "alerts";

    public MainWindow(bool startMonitors = true)
    {
        InitializeComponent();
        DashboardTools.Reload();
        ToolPicker.ItemsSource = DashboardTools.All;
        ToolPicker.SelectedIndex = 0;

        var menu = new Forms.ContextMenuStrip();
        _openTrayItem = menu.Items.Add(Text["TrayOpen"], null, (_, _) => Dispatcher.Invoke(ShowFromTray));
        // Shown only while Guardian has undelivered alerts or an unrecovered scan/save, so the retry
        // the monitor exposes is reachable after its bounded automatic attempts have stopped.
        _retryGuardianTrayItem = menu.Items.Add(Text["TrayRetryGuardian"], null, (_, _) => Dispatcher.Invoke(RetryGuardian));
        _retryGuardianTrayItem.Visible = false;
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
        // A detection balloon that cannot be clicked open is a dead end: it names a threat, vanishes
        // after a few seconds, and leaves the operator to find the matching entry themselves. Clicking
        // it opens the dashboard on that exact alert.
        _trayIcon.BalloonTipClicked += (_, _) => Dispatcher.Invoke(ShowAlertFromBalloon);
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized)
            {
                HideToTray();
            }
        };

        _guardianBalloonTimer.Tick += FlushGuardianBalloon;
        _protectionHealthTimer.Tick += RefreshProtectionHealthOnTick;

        LanguagePicker.ItemsSource = Text.SupportedLanguages;
        LanguagePicker.SelectedValue = Text.CurrentCode;
        _initializing = false;

        if (startMonitors)
        {
            Loaded += (_, _) => StartGuardian();
            CrashReporter.Recovered += OnRecoveredFromUiError;
        }
    }

    /// <summary>
    /// Says that a failing UI handler was absorbed and monitoring continues. The notice is the point:
    /// absorbing silently would trade one invisible failure for another.
    /// </summary>
    private void OnRecoveredFromUiError(string? report)
    {
        if (_disposed)
        {
            return;
        }
        _balloonAlert = null; // nothing to navigate to
        _trayIcon.ShowBalloonTip(
            8000,
            Text["RecoveredBalloonTitle"],
            report is null
                ? Text["RecoveredBalloonBodyNoReport"]
                : Text.Format("RecoveredBalloonBody", CrashReporter.LogDirectory),
            Forms.ToolTipIcon.Warning);
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
            SummaryText.Text = Text.Format(
                "ActionFailed", UntrustedDisplayText.Neutralize(ex.Message));
        }
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>Raises the dashboard from the tray or behind other windows, as a second launch asks.</summary>
    internal void BringToFront() => ShowFromTray();

    /// <summary>
    /// Opens the dashboard on the detection whose balloon was just clicked.
    /// </summary>
    /// <remarks>
    /// A balloon is a few seconds of text that then disappears; acting on it means finding the entry
    /// again, and until this existed clicking one did nothing at all. Reading the journal is a local
    /// file read rather than a scan, so it runs inline and the alert is already selected by the time
    /// the window finishes appearing.
    ///
    /// The window is raised whatever else happens: even if the entry cannot be matched — a journal
    /// that failed to write, or one trimmed past this alert — a click must still open the app rather
    /// than appear to be ignored.
    /// </remarks>
    private void ShowAlertFromBalloon()
    {
        if (_disposed)
        {
            return;
        }

        ShowFromTray();
        if (_balloonAlert is not { } alert || DashboardTools.ForCommand(AlertsCommand) is not { } alertsTool)
        {
            return;
        }

        // A scan in flight owns the results grid and the tool selection: it will assign both when it
        // completes. Navigating over it would show the alert for a moment and then have the finishing
        // scan overwrite it, which reads as the click having been undone. The window is already up, so
        // say where the alert is instead of racing a scan the operator started themselves.
        if (_scanCancellation is not null)
        {
            SummaryText.Text = Text["AlertPendingScan"];
            return;
        }

        TryUserAction(
            () =>
            {
                _reportCache.Store(Adapters.Run(AlertsCommand, flaggedOnly: false), flaggedOnly: false);
                FlaggedOnly.IsChecked = false;
                // Assigning the selection only refreshes the grid when it actually changes, so the
                // context is shown explicitly for the case where Alerts was already the open tool.
                ToolPicker.SelectedItem = alertsTool;
                ShowToolContext(alertsTool);
                SelectJournalledAlert(alert);
            },
            Text["AlertOpenedFromNotification"]);
    }

    /// <summary>
    /// Selects the row for one journalled detection. The timestamp is the identity: the journal writes
    /// it round-trippable and the report carries it back unchanged.
    /// </summary>
    private void SelectJournalledAlert(SecurityAlert alert)
    {
        if (ResultsGrid.ItemsSource is not IEnumerable<FindingView> findings)
        {
            return;
        }

        var stamp = alert.TimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        var match = findings.FirstOrDefault(finding =>
            finding.Item.Fields.TryGetValue("time", out var time)
            && string.Equals(time, stamp, StringComparison.Ordinal));
        if (match is null)
        {
            return;
        }

        ResultsGrid.SelectedItem = match; // raises ResultsGrid_SelectionChanged, which fills the detail pane
        ResultsGrid.ScrollIntoView(match);
    }

    private void HideToTray()
    {
        Hide();
        if (!_shownTrayHint)
        {
            // Carries no detection, so a click on it must open the dashboard without jumping to an
            // unrelated older alert.
            _balloonAlert = null;
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

        CrashReporter.Recovered -= OnRecoveredFromUiError;
        _scanCancellation?.Dispose();
        _guardianBalloonTimer.Stop();
        _guardianBalloonTimer.Tick -= FlushGuardianBalloon;
        // Decision windows are not owned by this (often hidden) window, so close them explicitly: with
        // the default shutdown mode an open one would otherwise keep the process alive after exit.
        foreach (var alertWindow in _openAlertWindows.Values.ToList())
        {
            alertWindow.Close();
        }
        _openAlertWindows.Clear();
        _protectionHealthTimer.Stop();
        _protectionHealthTimer.Tick -= RefreshProtectionHealthOnTick;
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
