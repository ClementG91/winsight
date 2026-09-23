using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Session Manager BootExecute, native-mode commands run by smss.exe at boot,
/// before Win32 starts (default: "autocheck autochk *"). Anything appended here is a
/// very early, stealthy persistence vector.
/// </summary>
public sealed class BootExecuteEnumerator : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private const string Path = @"SYSTEM\CurrentControlSet\Control\Session Manager";

    public string Surface => "BootExecute";

    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.Registry(RegistryHive.LocalMachine, RegistryView.Registry64, Path),
    };

    public IEnumerable<RawAutostart> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(Path);
        if (key?.GetValue("BootExecute") is not string[] commands)
        {
            yield break;
        }
        foreach (var command in commands)
        {
            if (command.Trim().Length > 0)
            {
                yield return new RawAutostart(
                    AutostartVector.BootExecute, "BootExecute", $"HKLM\\{Path} [BootExecute]",
                    StripSessionManagerVerb(command));
            }
        }
    }

    /// <summary>
    /// Drops the Session Manager <c>autocheck</c> verb so the entry names the image smss.exe
    /// actually runs.
    /// </summary>
    /// <remarks>
    /// The stock Windows value is <c>autocheck autochk *</c>: <c>autocheck</c> is smss's verb, and
    /// <c>autochk.exe</c> is the native binary. Reading the raw value leading-token-first resolved
    /// <c>autocheck</c> to nothing, so the operating system's own default BootExecute entry was
    /// reported with no resolvable image on every machine — a permanent false positive on one of
    /// the highest-value persistence surfaces. Anything an attacker appends here keeps its own
    /// image name and is judged on it.
    /// </remarks>
    internal static string StripSessionManagerVerb(string command)
    {
        const string Verb = "autocheck ";
        var trimmed = command.TrimStart();
        return trimmed.StartsWith(Verb, StringComparison.OrdinalIgnoreCase)
            ? trimmed[Verb.Length..].TrimStart()
            : command;
    }
}
