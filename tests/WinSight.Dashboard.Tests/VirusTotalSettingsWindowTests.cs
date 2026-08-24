using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using WinSight.Core;
using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class VirusTotalSettingsWindowTests
{
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
}
