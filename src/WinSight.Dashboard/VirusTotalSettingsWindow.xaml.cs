using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using WinSight.Core;

namespace WinSight.Dashboard;

public partial class VirusTotalSettingsWindow : Window
{
    private readonly VirusTotalSettingsStore _store;

    public VirusTotalSettingsWindow()
        : this(VirusTotalSettingsStore.Default)
    {
    }

    internal VirusTotalSettingsWindow(VirusTotalSettingsStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        InitializeComponent();
        RefreshStatus();
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    public string? SavedMessage { get; private set; }

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

        if (!TrySettingsAction(() =>
        {
            _store.Save(key);
            _store.ApplySavedKeyToCurrentProcess(key);
            ApiKeyBox.Clear();
        }))
        {
            return;
        }

        SavedMessage = _store.EnvironmentOverrideActive
            ? Text["VtSavedEnvironment"]
            : Text["VtSaved"];
        DialogResult = true;
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
        TrySettingsAction(() =>
        {
            var explorer = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "explorer.exe");
            var startInfo = new ProcessStartInfo(explorer) { UseShellExecute = false };
            startInfo.ArgumentList.Add("https://www.virustotal.com/gui/my-apikey");
            VirusTotalConfiguration.RemoveFromChildEnvironment(startInfo);
            _ = Process.Start(startInfo);
        });
    }

    private bool TrySettingsAction(Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException
                                     or UnauthorizedAccessException or SecurityException
                                     or CryptographicException or Win32Exception or ExternalException)
        {
            ShowError(Text.Format("VtSettingsError", ex.Message));
            return false;
        }
    }

    private void ShowError(string message) => System.Windows.MessageBox.Show(
        this,
        message,
        Text["SettingsTitle"],
        MessageBoxButton.OK,
        MessageBoxImage.Warning);
}
