using System.Windows;
using System.Windows.Threading;

namespace WinSight.Dashboard;

public partial class App : System.Windows.Application
{
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
        var window = new MainWindow(startup.StartMonitors);
        window.Show();

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
internal readonly record struct DashboardStartupPolicy(bool StartMonitors, bool ExitAfterIdle)
{
    internal static DashboardStartupPolicy FromArguments(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var smokeTest = arguments.Contains("--smoke-test", StringComparer.OrdinalIgnoreCase);
        return new DashboardStartupPolicy(StartMonitors: !smokeTest, ExitAfterIdle: smokeTest);
    }
}
