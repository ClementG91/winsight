using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using WinSight.Core;
using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class VirusTotalSettingsWindowTests
{
    private static readonly string[] DashboardCultures = ["en", "fr", "es"];

    [Fact]
    public void ValidSave_PersistsKeyClosesDialogAndExposesHonestConfirmation()
    {
        Exception? failure = null;
        var completed = false;
        var thread = new Thread(() =>
        {
            var directory = Path.Combine(Path.GetTempPath(), $"winsight-vt-window-{Guid.NewGuid():N}");
            var path = Path.Combine(directory, "key.bin");
            var key = new string('a', 64);
            App? app = null;
            try
            {
                app = new App();
                app.InitializeComponent();
                app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                LocalizationManager.Instance.SetCulture("fr");

                var store = new VirusTotalSettingsStore(path);
                var window = new VirusTotalSettingsWindow(store) { Width = 500 };
                var widthDifference = double.NaN;
                var saveWidth = double.NaN;
                var saveRight = double.NaN;
                window.Loaded += (_, _) =>
                {
                    window.UpdateLayout();
                    widthDifference = Math.Abs(
                        window.GetKeyButton.ActualWidth - window.SaveSettingsButton.ActualWidth);
                    saveWidth = window.SaveSettingsButton.ActualWidth;
                    saveRight = window.SaveSettingsButton
                        .TranslatePoint(new Point(window.SaveSettingsButton.ActualWidth, 0), window)
                        .X;

                    window.ApiKeyBox.Password = key;
                    window.SaveSettingsButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                };

                Assert.True(window.ShowDialog());
                Assert.InRange(widthDifference, 0, 0.5);
                Assert.True(saveWidth >= 200);
                Assert.True(saveRight <= window.ActualWidth);
                Assert.Equal(key, store.LoadStoredKey());
                Assert.Equal(LocalizationManager.Instance["VtSaved"], window.SavedMessage);
                Assert.Contains("format", window.SavedMessage, StringComparison.OrdinalIgnoreCase);

                foreach (var culture in DashboardCultures)
                {
                    AssertConstrainedDashboard(culture);
                }
                completed = true;
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                VirusTotalConfiguration.SetStoredProcessKey(null);
                app?.Shutdown();
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The VirusTotal settings dialog did not finish.");
        Assert.Null(failure);
        Assert.True(completed);
    }

    private static void AssertConstrainedDashboard(string culture)
    {
        LocalizationManager.Instance.SetCulture(culture);
        using var dashboard = new MainWindow(startMonitors: false)
        {
            Width = 960,
            Height = 620,
            WindowStartupLocation = WindowStartupLocation.Manual,
            Left = 0,
            Top = 0,
        };
        dashboard.Show();
        var scroller = Assert.IsType<ScrollViewer>(dashboard.FindName("RightContentScroller"));
        var firewallPanel = Assert.IsType<Border>(dashboard.FindName("FirewallActionsPanel"));
        var results = Assert.IsType<Border>(dashboard.FindName("ResultsPanel"));
        var guidance = Assert.IsType<TextBlock>(dashboard.FindName("GuidanceText"));
        var export = Assert.IsType<Button>(dashboard.FindName("ExportButton"));
        var settings = Assert.IsType<Button>(dashboard.FindName("SettingsButton"));
        var localBadge = Assert.IsType<Border>(dashboard.FindName("LocalAnalysisBadge"));
        firewallPanel.Visibility = Visibility.Visible;
        guidance.Text = string.Join(' ', Enumerable.Repeat(
            "Long localized guidance must remain reachable at enlarged text sizes.", 12));
        guidance.FontSize = 20;
        dashboard.UpdateLayout();

        Assert.True(
            scroller.ScrollableHeight > 0,
            $"Expected {culture} vertical overflow: window={dashboard.ActualHeight}, "
            + $"viewport={scroller.ViewportHeight}, extent={scroller.ExtentHeight}.");
        Assert.True(results.ActualHeight >= 220);
        Assert.True(scroller.ExtentWidth <= scroller.ViewportWidth + 0.5,
            $"The {culture} content pane overflows horizontally.");
        Assert.True(settings.ActualWidth > 0);
        var badgeRight = localBadge.TranslatePoint(new Point(localBadge.ActualWidth, 0), dashboard).X;
        Assert.InRange(badgeRight, 0, dashboard.ActualWidth);

        scroller.ScrollToTop();
        dashboard.Activate();
        export.IsEnabled = true;
        Assert.True(export.Focus());
        dashboard.UpdateLayout();
        Assert.True(scroller.VerticalOffset > 0,
            $"Keyboard focus did not reveal the lower {culture} action.");

        scroller.ScrollToEnd();
        dashboard.UpdateLayout();
        var exportBottom = export.TranslatePoint(new Point(0, export.ActualHeight), dashboard).Y;
        var exportRight = export.TranslatePoint(new Point(export.ActualWidth, 0), dashboard).X;
        Assert.True(export.IsVisible);
        Assert.InRange(exportBottom, 0, dashboard.ActualHeight);
        Assert.InRange(exportRight, 0, dashboard.ActualWidth);
        dashboard.ExitForSmokeTest();
    }
}
