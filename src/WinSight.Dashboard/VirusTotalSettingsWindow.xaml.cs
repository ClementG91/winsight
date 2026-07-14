using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;

namespace WinSight.Dashboard;

public partial class VirusTotalSettingsWindow : Window
{
    private readonly VirusTotalSettingsStore _store = VirusTotalSettingsStore.Default;

    public VirusTotalSettingsWindow()
    {
        InitializeComponent();
        RefreshStatus();
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    private void RefreshStatus()
    {
        StatusText.Text = _store.EnvironmentOverrideActive
            ? Text["VtStatusEnvironment"]
            : _store.HasStoredKey
                ? Text["VtStatusEnabled"]
                : Text["VtStatusDisabled"];
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        var key = ApiKeyBox.Password.Trim();
        if (!VirusTotalSettingsStore.IsPlausibleApiKey(key))
        {
            ShowError(Text["VtInvalidKey"]);
            return;
        }

        TrySettingsAction(() =>
        {
            _store.Save(key);
            _store.ApplySavedKeyToCurrentProcess(key);
            ApiKeyBox.Clear();
            StatusText.Text = _store.EnvironmentOverrideActive
                ? Text["VtSavedEnvironment"]
                : Text["VtSaved"];
        });
    }

    private void DisableButton_Click(object sender, RoutedEventArgs e)
    {
        TrySettingsAction(() =>
        {
            _store.Clear();
            _store.DisableForCurrentProcess();
            ApiKeyBox.Clear();
            StatusText.Text = _store.EnvironmentOverrideActive
                ? Text["VtDisabledEnvironment"]
                : Text["VtDisabled"];
        });
    }

    private void GetKeyButton_Click(object sender, RoutedEventArgs e)
    {
        TrySettingsAction(() => _ = Process.Start(new ProcessStartInfo(
            "https://www.virustotal.com/gui/my-apikey")
        {
            UseShellExecute = true,
        }));
    }

    private void TrySettingsAction(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex) when (ex is ArgumentException or IOException
                                     or UnauthorizedAccessException or SecurityException
                                     or CryptographicException or Win32Exception or ExternalException)
        {
            ShowError(Text.Format("VtSettingsError", ex.Message));
        }
    }

    private void ShowError(string message) => System.Windows.MessageBox.Show(
        this,
        message,
        Text["SettingsTitle"],
        MessageBoxButton.OK,
        MessageBoxImage.Warning);
}
