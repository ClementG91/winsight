using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// The per-account variables Windows gives a process running as another account (WS-46): the
/// profile folders derived from its <c>ProfileList</c> entry, then, when its hive is loaded, its
/// redirected shell folders and the variables it defines itself.
/// </summary>
internal static class AccountEnvironment
{
    private const string UserShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

    /// <summary>
    /// The variables of <paramref name="sid"/>, or null when its profile is unknown. The caller
    /// treats null as "cannot say" and must not fall back to the scanner's own profile.
    /// </summary>
    internal static IReadOnlyDictionary<string, string>? For(string sid, Func<string, string?>? profileDirectory = null)
    {
        var profile = (profileDirectory ?? (s => UserHiveEnumerator.ProfileDirectory(s)))(sid);
        if (string.IsNullOrWhiteSpace(profile) || !Path.IsPathFullyQualified(profile))
        {
            return null;
        }
        var root = Path.GetPathRoot(profile) ?? string.Empty;
        var local = Path.Combine(profile, "AppData", "Local");
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["USERPROFILE"] = profile,
            ["APPDATA"] = Path.Combine(profile, "AppData", "Roaming"),
            ["LOCALAPPDATA"] = local,
            ["TEMP"] = Path.Combine(local, "Temp"),
            ["TMP"] = Path.Combine(local, "Temp"),
            ["HOMEDRIVE"] = root.TrimEnd('\\'),
            ["HOMEPATH"] = profile[(root.TrimEnd('\\').Length)..],
        };
        OverlayHive(sid, environment);
        return environment;
    }

    /// <summary>
    /// The account's own settings, read raw from its hive when it is loaded: folder redirection moves
    /// <c>AppData</c>, and <c>HKU\&lt;sid&gt;\Environment</c> defines per-account variables. Each value is
    /// expanded once against what is known so far, as the logon does. <c>Path</c> is left alone: the
    /// account's additions are appended to the machine's, not substituted for it.
    /// </summary>
    private static void OverlayHive(string sid, Dictionary<string, string> environment)
    {
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            using var hive = users.OpenSubKey(sid);
            if (hive is null)
            {
                return;
            }
            using (var folders = hive.OpenSubKey(UserShellFolders))
            {
                Overlay(folders, environment, ("AppData", "APPDATA"), ("Local AppData", "LOCALAPPDATA"));
            }
            using var variables = hive.OpenSubKey("Environment");
            if (variables is null)
            {
                return;
            }
            foreach (var name in variables.GetValueNames())
            {
                if (name.Length > 0 && !name.Equals("Path", StringComparison.OrdinalIgnoreCase))
                {
                    Overlay(variables, environment, (name, name));
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            // The derived profile folders stand: they are what Windows uses when nothing overrides them.
        }
    }

    private static void Overlay(
        RegistryKey? key, Dictionary<string, string> environment, params (string Value, string Variable)[] pairs)
    {
        if (key is null)
        {
            return;
        }
        foreach (var (value, variable) in pairs)
        {
            if (key.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string raw
                && raw.Trim().Length > 0)
            {
                environment[variable] = CommandLine.Expand(raw.Trim(), LoaderContext.ForAccount(environment));
            }
        }
    }
}
