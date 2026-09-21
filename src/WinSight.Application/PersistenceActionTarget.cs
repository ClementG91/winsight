using System.Text.RegularExpressions;

using Microsoft.Win32;

using WinSight.Persistence;

namespace WinSight.Application;

/// <summary>The kind of persistence a response action operates on.</summary>
public enum PersistenceActionKind
{
    /// <summary>A registry value under a Run/RunOnce key.</summary>
    RegistryValue,

    /// <summary>A file in a Startup folder.</summary>
    StartupFile,
}

/// <summary>
/// A structured, actionable description of a persistence entry, resolved from an
/// <see cref="AutostartEntry"/> only for the vectors a response action currently supports and at the
/// privilege it needs. Anything else resolves to null so the caller reports "not supported" rather
/// than acting on a guess.
/// </summary>
/// <param name="Kind">Registry value or startup file.</param>
/// <param name="Privilege">Whether it can be acted on by the current user or needs the service tier.</param>
/// <param name="DisplayName">A short, non-sensitive label.</param>
/// <param name="Hive">The registry hive, for a registry value.</param>
/// <param name="SubKey">The exact subkey path (as spelled on the machine), for a registry value.</param>
/// <param name="ValueName">The value name, for a registry value.</param>
/// <param name="FilePath">The full startup-file path, for a startup file.</param>
/// <param name="RevalidationToken">
/// What must still be true for the action to proceed: the value's data, or the startup file's
/// resolved command. A mismatch at action time means the entry changed since the alert.
/// </param>
public sealed record PersistenceActionTarget(
    PersistenceActionKind Kind,
    WinSight.Response.ResponsePrivilege Privilege,
    string DisplayName,
    RegistryHive? Hive,
    string? SubKey,
    string? ValueName,
    string? FilePath,
    string RevalidationToken)
{
    /// <summary>A stable rule key for this entry, so an Allow rule can suppress future alerts.</summary>
    public string RuleItemKey => Kind == PersistenceActionKind.RegistryValue
        ? $"reg:{Hive}\\{SubKey}\\{ValueName}".ToLowerInvariant()
        : $"file:{FilePath}".ToLowerInvariant();
}

/// <summary>Builds a <see cref="PersistenceActionTarget"/> from an alert's <see cref="AutostartEntry"/>.</summary>
public static class PersistenceActionResolver
{
    // "HKCU\Software\...\Run [Registry64]" - the exact shape the Run-key enumerator emits.
    private static readonly Regex RunKeyLocation =
        new(@"^(?<hive>HKCU|HKLM)\\(?<sub>.+) \[(?:Registry64|Registry32)\]$", RegexOptions.Compiled);

    /// <summary>
    /// The actionable target for this entry, or null when its vector, location or privilege is not
    /// yet supported. Only HKCU Run/RunOnce values and per-user startup files are user-actionable
    /// today; HKLM and all-users items resolve to a service-tier target that the current build cannot
    /// carry out (so the caller reports "not supported" until the service response tier ships).
    /// </summary>
    public static PersistenceActionTarget? Resolve(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return entry.Vector switch
        {
            AutostartVector.RunKey or AutostartVector.RunOnceEx => ResolveRegistryValue(entry),
            AutostartVector.StartupFolder => ResolveStartupFile(entry),
            _ => null,
        };
    }

    private static PersistenceActionTarget? ResolveRegistryValue(AutostartEntry entry)
    {
        var match = RunKeyLocation.Match(entry.Location);
        if (!match.Success || string.IsNullOrEmpty(entry.Name))
        {
            return null;
        }
        var hive = match.Groups["hive"].Value == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
        var privilege = hive == RegistryHive.CurrentUser
            ? WinSight.Response.ResponsePrivilege.CurrentUser
            : WinSight.Response.ResponsePrivilege.Service;
        return new PersistenceActionTarget(
            PersistenceActionKind.RegistryValue, privilege,
            $"{entry.Vector}/{entry.Name}",
            hive, match.Groups["sub"].Value, entry.Name, FilePath: null,
            RevalidationToken: entry.Command);
    }

    private static PersistenceActionTarget? ResolveStartupFile(AutostartEntry entry)
    {
        // Location is "<label>: <directory>"; the file is <directory>\<name>.
        var separator = entry.Location.IndexOf(": ", StringComparison.Ordinal);
        if (separator < 0 || string.IsNullOrEmpty(entry.Name))
        {
            return null;
        }
        var directory = entry.Location[(separator + 2)..];
        if (!Path.IsPathFullyQualified(directory))
        {
            return null;
        }
        string filePath;
        try
        {
            filePath = Path.GetFullPath(Path.Combine(directory, entry.Name));
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return null;
        }
        // Only this user's own startup folder is user-actionable. Another profile's needs the service.
        var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var privilege = !string.IsNullOrEmpty(userStartup)
            && directory.StartsWith(userStartup, StringComparison.OrdinalIgnoreCase)
            ? WinSight.Response.ResponsePrivilege.CurrentUser
            : WinSight.Response.ResponsePrivilege.Service;
        // The alert names the path; the mutator additionally compares the captured bytes and marks
        // that exact open file handle for deletion. A same-path replacement is refused rather than
        // deleted, and restore uses CreateNew so an occupant can never be overwritten.
        return new PersistenceActionTarget(
            PersistenceActionKind.StartupFile, privilege,
            $"{entry.Vector}/{entry.Name}",
            Hive: null, SubKey: null, ValueName: null, filePath,
            RevalidationToken: filePath);
    }
}
