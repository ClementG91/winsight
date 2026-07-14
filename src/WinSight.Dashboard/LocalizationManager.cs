using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Resources;
using System.Security;

namespace WinSight.Dashboard;

public sealed record UiLanguage(string Code, string NativeName)
{
    public override string ToString() => NativeName;
}

/// <summary>
/// Provides runtime-switchable satellite-resource localization. The neutral
/// resource is English; unsupported Windows cultures therefore fail safely to
/// English instead of exposing resource keys to users.
/// </summary>
public sealed class LocalizationManager : INotifyPropertyChanged
{
    private static readonly ResourceManager Resources = new(
        "WinSight.Dashboard.Localization.Strings",
        typeof(LocalizationManager).Assembly);

    private static readonly IReadOnlyList<UiLanguage> Languages =
    [
        new("en", "English"),
        new("fr", "Français"),
        new("es", "Español"),
    ];

    private CultureInfo _culture;

    private LocalizationManager()
    {
        var preferred = ReadPreference() ?? CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        _culture = CultureInfo.GetCultureInfo(NormalizeCode(preferred));
        CultureInfo.CurrentUICulture = _culture;
        CultureInfo.DefaultThreadCurrentUICulture = _culture;
    }

    public static LocalizationManager Instance { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<UiLanguage> SupportedLanguages => Languages;

    public string CurrentCode => _culture.TwoLetterISOLanguageName;

    public CultureInfo Culture => _culture;

    public string this[string key] =>
        Resources.GetString(key, _culture)
        ?? Resources.GetString(key, CultureInfo.InvariantCulture)
        ?? $"[{key}]";

    public string Format(string key, params object?[] arguments) =>
        string.Format(_culture, this[key], arguments);

    public void SetCulture(string? code, bool remember = false)
    {
        var normalized = NormalizeCode(code);
        if (normalized == CurrentCode)
        {
            if (remember)
            {
                WritePreference(normalized);
            }
            return;
        }

        _culture = CultureInfo.GetCultureInfo(normalized);
        CultureInfo.CurrentUICulture = _culture;
        CultureInfo.DefaultThreadCurrentUICulture = _culture;
        if (remember)
        {
            WritePreference(normalized);
        }
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CurrentCode)));
    }

    public static string NormalizeCode(string? code)
    {
        if (!string.IsNullOrWhiteSpace(code))
        {
            var language = code.Split('-', '_')[0].ToLowerInvariant();
            if (Languages.Any(candidate => candidate.Code == language))
            {
                return language;
            }
        }
        return "en";
    }

    private static string PreferencePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight",
        "ui-language.txt");

    private static string? ReadPreference()
    {
        try
        {
            return File.Exists(PreferencePath) ? File.ReadAllText(PreferencePath).Trim() : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return null;
        }
    }

    private static void WritePreference(string code)
    {
        try
        {
            var directory = Path.GetDirectoryName(PreferencePath)!;
            Directory.CreateDirectory(directory);
            File.WriteAllText(PreferencePath, code);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Localization still changes for the current session when persistence
            // is unavailable (locked profile, policy, or read-only environment).
        }
    }
}
