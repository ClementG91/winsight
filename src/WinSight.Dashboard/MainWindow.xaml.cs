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
    private readonly Forms.NotifyIcon _trayIcon;
    private IReadOnlyList<ToolReport> _reports = [];
    private CancellationTokenSource? _scanCancellation;
    private bool _allowClose;
    private bool _disposed;
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
            Text = "WinSight — sécurité locale",
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

        var cancellation = new CancellationTokenSource();
        _scanCancellation = cancellation;
        SetScanningState(tool, scanning: true);
        ResultsGrid.ItemsSource = null;
        ReportPicker.Visibility = Visibility.Collapsed;
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
                    () => Adapters.RunOverview(flaggedOnly, progress, cancellation.Token),
                    cancellation.Token);
            }
            else
            {
                _reports = await Task.Run(
                    () => (IReadOnlyList<ToolReport>)[Adapters.Run(tool.Command, flaggedOnly)],
                    cancellation.Token);
            }

            ReportPicker.ItemsSource = _reports;
            ReportPicker.Visibility = _reports.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
            ReportPicker.SelectedIndex = 0;
            ShowReport(_reports[0]);
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            ProgressText.Text = "Analyse terminée.";
            ExportButton.IsEnabled = true;
        }
        catch (OperationCanceledException)
        {
            _reports = [];
            SummaryText.Text = "Analyse arrêtée proprement entre deux étapes.";
            ProgressText.Text = "Analyse arrêtée.";
        }
        catch (UnauthorizedAccessException)
        {
            _reports = [];
            SummaryText.Text = "Droits insuffisants. Cette analyse nécessite peut-être un lancement en administrateur.";
            ProgressText.Text = "Analyse impossible avec les droits actuels.";
        }
        catch (Exception ex)
        {
            _reports = [];
            SummaryText.Text = $"L’analyse a échoué : {ex.Message}";
            ProgressText.Text = "Une erreur inattendue est survenue.";
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
        ProgressPanel.Visibility = scanning || _reports.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = scanning && tool.Command == "all" ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.IsEnabled = scanning;

        if (scanning)
        {
            ScanProgressBar.Value = 0;
            ScanProgressBar.IsIndeterminate = tool.Command != "all";
            ProgressText.Text = tool.Command == "all"
                ? "Préparation de la vue d’ensemble…"
                : $"Analyse « {tool.Label} » en cours…";
            SummaryText.Text = "WinSight lit les informations Windows. Aucune modification n’est effectuée.";
        }
    }

    private void UpdateProgress(ScanProgress progress)
    {
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = progress.Percent;
        var tool = DashboardTools.ForCommand(progress.Command);
        ProgressText.Text = $"{progress.Completed}/{progress.Total} — {tool?.Label ?? progress.Command}";
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _scanCancellation?.Cancel();
        CancelButton.IsEnabled = false;
        ProgressText.Text = "Arrêt demandé — l’étape en cours se termine sans être interrompue brutalement…";
    }

    private void ToolPicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ToolPicker.SelectedItem is DashboardTool tool)
        {
            ShowToolExplanation(tool);
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
        var findings = report.Items.Select(item => new FindingView(
            item.Severity == Severity.Notable ? "À vérifier" : "Information",
            item.Title,
            item.Detail,
            item)).ToList();
        ResultsGrid.ItemsSource = findings;
        SummaryText.Text = $"{findings.Count} résultat(s) affiché(s) · {report.NotableCount} à vérifier";
        SelectedFindingText.Text = findings.Count == 0
            ? "Aucun élément à afficher avec le filtre actuel. Cela ne garantit pas l’absence de menace."
            : "Sélectionnez une ligne pour afficher les actions sûres disponibles.";

        if (DashboardTools.ForReport(report.Tool) is { } reportTool)
        {
            ShowToolExplanation(reportTool);
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
        SelectedFindingText.Text = $"{finding.SeverityLabel} — {finding.Title}\n{finding.Detail}";
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
            "Détails copiés dans le presse-papiers.");
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_reports.Count == 0)
        {
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Exporter le rapport WinSight",
            FileName = $"winsight-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            DefaultExt = ".json",
            Filter = "Rapport JSON (*.json)|*.json",
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
            ReportRenderer.RenderJson(_reports, writer);
        }, $"Rapport exporté : {dialog.FileName}");
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
        TryUserAction(() => _ = Process.Start(startInfo), "Emplacement ouvert dans l’Explorateur.");
    }

    private void WindowsToolButton_Click(object sender, RoutedEventArgs e)
    {
        if (WindowsToolButton.Tag is not DashboardWindowsAction action || action == DashboardWindowsAction.None)
        {
            return;
        }

        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        ProcessStartInfo startInfo;
        if (action == DashboardWindowsAction.Processes)
        {
            startInfo = new ProcessStartInfo(Path.Combine(system, "Taskmgr.exe")) { UseShellExecute = false };
        }
        else
        {
            startInfo = new ProcessStartInfo(Path.Combine(system, "mmc.exe")) { UseShellExecute = false };
            startInfo.ArgumentList.Add(Path.Combine(system,
                action == DashboardWindowsAction.Firewall ? "wf.msc" : "certlm.msc"));
        }
        TryUserAction(() => _ = Process.Start(startInfo), "Outil Windows ouvert.");
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
            SummaryText.Text = $"Action impossible : {ex.Message}";
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
            _trayIcon.ShowBalloonTip(2500, "WinSight", "WinSight continue dans la zone de notification.", Forms.ToolTipIcon.Info);
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
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

public sealed record FindingView(string SeverityLabel, string Title, string Detail, ReportItem Item);

public enum DashboardWindowsAction
{
    None,
    Firewall,
    Processes,
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
    public static IReadOnlyList<DashboardTool> All { get; } =
    [
        new("Vue d’ensemble", "all", "all", "Le contrôle recommandé en un clic",
            "Vérifie les principaux signaux : démarrage automatique, caméra/micro, connexions, DNS, extensions, hosts et certificats.",
            "Commencez par les lignes « À vérifier ». Une alerte est un indice : contrôlez le nom, l’emplacement et l’éditeur avant toute action."),
        new("Démarrage automatique", "persistence", "persistence", "Ce qui se lance avec Windows",
            "Recherche les programmes, services et réglages capables de revenir à chaque démarrage ou connexion.",
            "Un élément inconnu ou non signé mérite une vérification. N’effacez pas une entrée système sans sauvegarde ni confirmation."),
        new("Caméra et microphone", "av", "camera-mic", "Applications ayant utilisé vos capteurs",
            "Montre les applications enregistrées par Windows comme ayant utilisé la webcam ou le microphone, et celles actives maintenant.",
            "Si un capteur est actif sans raison, fermez l’application concernée puis vérifiez ses autorisations dans les paramètres de confidentialité."),
        new("Connexions réseau", "net", "connections", "Programmes connectés à Internet",
            "Relie les connexions TCP/UDP aux programmes qui les ont ouvertes et à leur signature numérique.",
            "Une connexion externe n’est pas forcément malveillante. Vérifiez d’abord le programme, son chemin et sa signature."),
        new("Noms de domaine (DNS)", "dns", "dns", "Sites récemment contactés",
            "Affiche le cache DNS Windows : les noms de domaine récemment résolus par la machine.",
            "Le cache DNS indique une résolution, pas nécessairement une visite volontaire. Corrélez avec les connexions et les programmes actifs."),
        new("Pare-feu Windows", "firewall", "firewall", "Règles réseau actuellement actives",
            "Inventorie les règles du pare-feu Microsoft Defender. Le blocage automatique WinSight reste désactivé tant que le service WFP sécurisé n’est pas livré.",
            "Utilisez l’outil Windows pour modifier une règle. Conservez une voie de récupération avant de bloquer un service système.",
            DashboardWindowsAction.Firewall),
        new("Processus", "processes", "processes", "Programmes en cours d’exécution",
            "Liste les processus, leur chemin, leur parent, leur ligne de commande et leur signature.",
            "Un processus non signé peut être légitime. Ouvrez son emplacement et confirmez sa provenance avant de le terminer.",
            DashboardWindowsAction.Processes),
        new("Modules chargés", "modules", "modules", "Bibliothèques utilisées par les programmes",
            "Recherche les DLL non signées ou non fiables chargées dans les processus accessibles.",
            "Cette analyse peut être longue. Une DLL inconnue dans un programme signé mérite une investigation, pas une suppression immédiate."),
        new("Extensions navigateur", "extensions", "extensions", "Extensions avec accès étendu",
            "Inspecte les extensions Chromium et signale les permissions capables de lire ou modifier de nombreuses pages.",
            "Désactivez depuis le navigateur les extensions inutiles ou inconnues, puis vérifiez leur éditeur et leur fiche officielle."),
        new("Certificats de confiance", "certs", "certificates", "Autorités capables de valider le HTTPS",
            "Recherche les certificats racine présentant des signaux risqués : clé privée locale, signature faible ou clé trop courte.",
            "Ne supprimez jamais un certificat d’entreprise sans l’avis de votre administrateur. Comparez l’émetteur et l’usage attendu.",
            DashboardWindowsAction.Certificates),
        new("Fichier hosts", "hosts", "hosts", "Redirections locales de sites",
            "Détecte les redirections pouvant détourner un site ou bloquer les services de sécurité et de mise à jour.",
            "Les bloqueurs de publicité utilisent aussi ce fichier. Vérifiez le domaine et l’adresse avant de modifier quoi que ce soit."),
    ];

    public static DashboardTool? ForCommand(string command) =>
        All.FirstOrDefault(tool => tool.Command.Equals(command, StringComparison.OrdinalIgnoreCase));

    public static DashboardTool? ForReport(string reportName) =>
        All.FirstOrDefault(tool => tool.ReportName.Equals(reportName, StringComparison.OrdinalIgnoreCase));
}
