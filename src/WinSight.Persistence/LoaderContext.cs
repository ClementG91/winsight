namespace WinSight.Persistence;

/// <summary>
/// How the process that loads an autostart entry sees the machine: whether WOW64 redirects its
/// <c>System32</c>, and whose environment expands the variables in its command.
/// </summary>
/// <remarks>
/// The scanner's own view is right only for a 64-bit consumer running as the account that scans.
/// A DLL registered under <c>WOW6432Node</c> is loaded by 32-bit processes, where
/// <c>System32</c> is <c>SysWOW64</c> and <c>%ProgramFiles%</c> is <c>Program Files (x86)</c>
/// (WS-45); a Run value in another account's hive, or a task that runs as another account, expands
/// <c>%APPDATA%</c> to that account's folder, not the scanner's (WS-46). Resolving either in the
/// scanner's view verifies a different file from the one Windows loads, or calls a real one missing.
/// </remarks>
public sealed record LoaderContext
{
    /// <summary>A 64-bit consumer running as the account that scans: no translation.</summary>
    public static LoaderContext Native { get; } = new();

    /// <summary>A 32-bit consumer running as the account that scans.</summary>
    public static LoaderContext Wow64Process { get; } = new() { Wow64 = true };

    /// <summary>The entry is loaded into a 32-bit process, where the file system redirector applies.</summary>
    public bool Wow64 { get; init; }

    /// <summary>
    /// The variables of the account the entry runs as, overriding the scanner's; null when that
    /// account is the scanner's own. Keys compare case-insensitively.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Environment { get; init; }

    /// <summary>
    /// Variables whose value belongs to one account. For another account's entry, one that account
    /// does not define is left unexpanded rather than answered with the scanner's own value: an
    /// unresolved path is honest, a path into the wrong profile is not.
    /// </summary>
    internal static readonly IReadOnlySet<string> PerAccountVariables = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH", "HOMESHARE",
        "USERNAME", "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE", "USERDNSDOMAIN", "LOGONSERVER",
        "OneDrive", "OneDriveConsumer", "OneDriveCommercial", "SESSIONNAME", "CLIENTNAME",
    };

    /// <summary>A consumer running as another account, with that account's variables.</summary>
    public static LoaderContext ForAccount(IReadOnlyDictionary<string, string> environment, bool wow64 = false) =>
        new() { Environment = environment, Wow64 = wow64 };
}
