using System.Windows;
using System.Windows.Threading;

namespace WinSight.Dashboard;

public partial class App : System.Windows.Application
{
    private DashboardSingleInstance? _instance;

    private void Application_Startup(object sender, StartupEventArgs e)
    {
        // First thing: without this a crash leaves no trace at all — no message, no log — which
        // makes a user's "it crashed" impossible to diagnose. Local-only, never sent anywhere.
        CrashReporter.Install(this);

        // Before any window is built: the palette is seven hard-coded colours, and Windows'
        // high-contrast mode - the setting people with low vision actually use - changed nothing
        // at all. It follows the setting live rather than at startup only.
        HighContrastPalette.Attach(this);

        VirusTotalSettingsStore.Default.ApplyToCurrentProcess();

        var languageIndex = Array.FindIndex(
            e.Args,
            argument => argument.Equals("--language", StringComparison.OrdinalIgnoreCase));
        if (languageIndex >= 0 && languageIndex + 1 < e.Args.Length)
        {
            LocalizationManager.Instance.SetCulture(e.Args[languageIndex + 1]);
        }

        var startup = DashboardStartupPolicy.FromArguments(e.Args);
        if (startup.SignatureMode)
        {
            // Opened from the Explorer "Check signature with WinSight" verb: only the signature window -
            // no dashboard, no monitors, no second tray icon per right-click - and the process ends
            // when it closes. The path is untrusted and is validated before anything opens it.
            new SignatureWindow(startup.SignaturePath, WinSight.Application.Adapters.ReportSignature).Show();
            return;
        }
        if (startup.StartMonitors)
        {
            // One interactive dashboard per user and session: a second one duplicated every monitor,
            // alert window and journal entry. A second launch raises the first and ends here.
            _instance = DashboardSingleInstance.Acquire();
            if (!_instance.IsPrimary)
            {
                _instance.Dispose();
                _instance = null;
                Shutdown(0);
                return;
            }
            Exit += (_, _) => _instance?.Dispose();
        }
        var window = new MainWindow(startup.StartMonitors);
        window.Show();
        _instance?.OnActivationRequested(() => window.Dispatcher.BeginInvoke(window.BringToFront));

        // Exercises construction, XAML loading, bindings, layout and tray setup in CI
        // without requiring an interactive test driver. A startup crash is a failed
        // process, so the publish workflow cannot ship a broken dashboard again.
        if (startup.ExitAfterIdle)
        {
            _ = window.Dispatcher.InvokeAsync(window.ExitForSmokeTest, DispatcherPriority.ApplicationIdle);
        }
    }
}

/// <summary>
/// Keeps the smoke path from racing long-lived native monitors during its immediate shutdown.
/// The smoke test validates construction, XAML, bindings and tray setup; starting ETW or device
/// watchers would add no coverage and can outlive the deliberately short-lived process.
/// </summary>
/// <remarks>
/// <c>--signature &lt;path&gt;</c> selects signature mode, the Explorer verb's entry point. A missing path
/// still selects it (the window then says there is no local file) rather than silently opening the full
/// dashboard, which is not what the operator asked for.
/// </remarks>
internal readonly record struct DashboardStartupPolicy(
    bool StartMonitors, bool ExitAfterIdle, bool SignatureMode = false, string? SignaturePath = null)
{
    internal static DashboardStartupPolicy FromArguments(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var list = arguments.ToList();
        var smokeTest = list.Contains("--smoke-test", StringComparer.OrdinalIgnoreCase);
        var signatureIndex = list.FindIndex(argument => argument.Equals("--signature", StringComparison.OrdinalIgnoreCase));
        var signatureMode = signatureIndex >= 0;
        var signaturePath = signatureMode && signatureIndex + 1 < list.Count ? list[signatureIndex + 1] : null;
        return new DashboardStartupPolicy(
            StartMonitors: !smokeTest && !signatureMode,
            ExitAfterIdle: smokeTest,
            SignatureMode: signatureMode,
            SignaturePath: signaturePath);
    }
}
