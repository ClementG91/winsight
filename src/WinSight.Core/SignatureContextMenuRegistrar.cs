using Microsoft.Win32;

namespace WinSight.Core;

/// <summary>
/// Registers and removes the per-user Explorer context-menu verb that opens WinSight's signature
/// window for a file (the What's Your Sign? entry point), out of process: a classic
/// <c>HKCU\Software\Classes\*\shell</c> verb that launches the dashboard with <c>--signature "%1"</c>,
/// never an in-process shell extension that would load into every Explorer window.
/// </summary>
/// <remarks>
/// Per-user under <c>HKCU</c>, so it installs and uninstalls without elevation and affects only this
/// user. On Windows 11 the verb appears under "Show more options"; the modern menu needs a packaged
/// <c>IExplorerCommand</c> and is out of scope. The command line quotes both the executable and the
/// <c>%1</c> substitution so a path with spaces is passed as one argument.
/// </remarks>
public sealed class SignatureContextMenuRegistrar
{
    private const string VerbKeyName = "WinSight.Signature";
    private const string VerbLabel = "Check signature with WinSight";
    private const string DefaultClassesRoot = @"Software\Classes";

    private readonly string _exePath;
    private readonly string _verbKeyPath;

    public SignatureContextMenuRegistrar(string exePath) : this(exePath, DefaultClassesRoot)
    {
    }

    internal SignatureContextMenuRegistrar(string exePath, string classesRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(exePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(classesRoot);
        _exePath = exePath;
        _verbKeyPath = $@"{classesRoot}\*\shell\{VerbKeyName}";
    }

    /// <summary>The command line the verb runs, with both the exe and the substituted path quoted.</summary>
    public string CommandLine => $"\"{_exePath}\" --signature \"%1\"";

    /// <summary>Installs (or refreshes) the verb for the current user.</summary>
    public void Register()
    {
        using var verb = Registry.CurrentUser.CreateSubKey(_verbKeyPath);
        verb.SetValue(null, VerbLabel);
        verb.SetValue("Icon", $"\"{_exePath}\",0");
        using var command = verb.CreateSubKey("command");
        command.SetValue(null, CommandLine);
    }

    /// <summary>Removes the verb. Quiet when it is not present.</summary>
    public void Unregister() =>
        Registry.CurrentUser.DeleteSubKeyTree(_verbKeyPath, throwOnMissingSubKey: false);

    /// <summary>True when the verb is present and its command runs this executable.</summary>
    public bool IsRegistered()
    {
        using var command = Registry.CurrentUser.OpenSubKey($@"{_verbKeyPath}\command");
        return command?.GetValue(null) is string current
            && string.Equals(current, CommandLine, StringComparison.OrdinalIgnoreCase);
    }
}
