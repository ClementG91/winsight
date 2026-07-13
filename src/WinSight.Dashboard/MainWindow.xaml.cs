using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using WinSight.Application;
using WinSight.Reporting;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace WinSight.Dashboard;

public partial class MainWindow : Window
{
    private readonly Forms.NotifyIcon _trayIcon;
    private IReadOnlyList<ToolReport> _reports = [];
    private bool _allowClose;
    private bool _shownTrayHint;

    public MainWindow()
    {
        InitializeComponent();
        ToolPicker.ItemsSource = DashboardTools.All;
        ToolPicker.SelectedIndex = 0;

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Ouvrir WinSight", null, (_, _) => Dispatcher.Invoke(ShowFromTray));
        menu.Items.Add("Quitter", null, (_, _) => Dispatcher.Invoke(ExitApplication));
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = Drawing.SystemIcons.Shield,
            Text = "WinSight",
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
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (ToolPicker.SelectedItem is not DashboardTool tool)
        {
            return;
        }

        ScanButton.IsEnabled = false;
        ToolPicker.IsEnabled = false;
        SummaryText.Text = "Analyse en cours…";
        ResultsGrid.ItemsSource = null;
        try
        {
            var flaggedOnly = FlaggedOnly.IsChecked == true;
            _reports = await Task.Run(() => tool.Command == "all"
                ? Adapters.RunOverview(flaggedOnly)
                : (IReadOnlyList<ToolReport>)[Adapters.Run(tool.Command, flaggedOnly)]);

            ReportPicker.ItemsSource = _reports;
            ReportPicker.Visibility = _reports.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
            ReportPicker.SelectedIndex = 0;
            ShowReport(_reports[0]);
        }
        catch (Exception ex)
        {
            _reports = [];
            ReportPicker.Visibility = Visibility.Collapsed;
            SummaryText.Text = $"Échec : {ex.Message}";
        }
        finally
        {
            ScanButton.IsEnabled = true;
            ToolPicker.IsEnabled = true;
        }
    }

    private void ReportPicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReportPicker.SelectedItem is ToolReport report)
        {
            ShowReport(report);
        }
    }

    private void ShowReport(ToolReport report)
    {
        SummaryText.Text = $"{report.Tool} — {report.Summary}";
        ResultsGrid.ItemsSource = report.Items;
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
            _trayIcon.ShowBalloonTip(2500, "WinSight", "WinSight continue dans la zone de notification.", Forms.ToolTipIcon.Info);
            _shownTrayHint = true;
        }
    }

    private void ExitApplication()
    {
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

        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        base.OnClosing(e);
    }
}

public sealed record DashboardTool(string Label, string Command);

public static class DashboardTools
{
    public static IReadOnlyList<DashboardTool> All { get; } =
    [
        new("Vue d’ensemble", "all"),
        new("Persistance", "persistence"),
        new("Caméra et microphone", "av"),
        new("Connexions", "net"),
        new("DNS", "dns"),
        new("Pare-feu", "firewall"),
        new("Processus", "processes"),
        new("Modules chargés", "modules"),
        new("Extensions navigateur", "extensions"),
        new("Certificats racine", "certs"),
        new("Fichier hosts", "hosts"),
    ];
}
