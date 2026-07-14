using System.Windows;
using System.Windows.Threading;

namespace WinSight.Dashboard;

public partial class App : System.Windows.Application
{
    private void Application_Startup(object sender, StartupEventArgs e)
    {
        var languageIndex = Array.FindIndex(
            e.Args,
            argument => argument.Equals("--language", StringComparison.OrdinalIgnoreCase));
        if (languageIndex >= 0 && languageIndex + 1 < e.Args.Length)
        {
            LocalizationManager.Instance.SetCulture(e.Args[languageIndex + 1]);
        }

        var window = new MainWindow();
        window.Show();

        // Exercises construction, XAML loading, bindings, layout and tray setup in CI
        // without requiring an interactive test driver. A startup crash is a failed
        // process, so the publish workflow cannot ship a broken dashboard again.
        if (e.Args.Contains("--smoke-test", StringComparer.OrdinalIgnoreCase))
        {
            _ = window.Dispatcher.InvokeAsync(window.ExitForSmokeTest, DispatcherPriority.ApplicationIdle);
        }
    }
}
