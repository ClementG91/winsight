using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Autostart entries in the registry hives of accounts other than the one running the scan, and an
/// honest count of the profiles whose hive could not be read.
/// </summary>
/// <remarks>
/// <b>The blind spot.</b> Every per-user enumerator opened <see cref="RegistryHive.CurrentUser"/>
/// and nothing else, so on a machine with more than one account, persistence installed under
/// <c>HKU\S-1-5-21-…-1002\…\Run</c> was invisible. Worse, the coverage accounting had nothing to
/// count: <c>UnreadableLocations</c> only records places a scan <i>tried</i> to read, so
/// <c>IsPartial</c> stayed false and the report claimed a complete scan of a machine it had only
/// half looked at.
///
/// <b>Elevation makes it worse, not better.</b> Running as administrator — the mode WinSight
/// recommends for attribution and scheduled tasks — repoints <c>HKCU</c> at the administrator's own
/// hive, so the standard user's Run keys are lost precisely when the operator believes they are
/// seeing more.
///
/// <b>What "could not be read" means here.</b> A user who is not logged on has no hive under
/// <c>HKEY_USERS</c> at all: their <c>NTUSER.DAT</c> is a file on disk, and loading it is a
/// privileged, machine-modifying act this read-only tool will not perform. Those profiles are
/// therefore counted as unread rather than being quietly ignored — a counted blind spot is worth
/// far more than an uncounted one.
/// </remarks>
public sealed class UserHiveEnumerator : IAutostartEnumerator
{
    private static readonly string[] SubKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];

    private const string ProfileList =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private readonly Func<string?> _currentUserSid;
    private int _unreadable;

    /// <param name="currentUserSid">
    /// The SID already covered by the HKCU enumerators, so it is not reported twice. Injected so
    /// the de-duplication is testable.
    /// </param>
    public UserHiveEnumerator(Func<string?>? currentUserSid = null) =>
        _currentUserSid = currentUserSid ?? CurrentSid;

    public string Surface => "Other user hives";

    /// <inheritdoc />
    /// <remarks>
    /// One per real user profile whose hive is not loaded, plus one per loaded hive that refused to
    /// open. Both are places persistence can sit and this scan did not see.
    /// </remarks>
    public int UnreadableLocations => Volatile.Read(ref _unreadable);

    public IEnumerable<RawAutostart> Enumerate()
    {
        Volatile.Write(ref _unreadable, 0);

        var current = _currentUserSid();
        var loaded = LoadedHiveSids();

        foreach (var sid in loaded)
        {
            if (IsCoveredElsewhere(sid, current))
            {
                continue;
            }
            foreach (var entry in ReadHive(sid))
            {
                yield return entry;
            }
        }

        // Every real profile that has no hive loaded is a location this scan could not look at.
        foreach (var sid in ProfileSids())
        {
            if (!IsCoveredElsewhere(sid, current) && !loaded.Contains(sid))
            {
                Interlocked.Increment(ref _unreadable);
            }
        }
    }

    /// <summary>
    /// SIDs that are not another human's hive: the account already scanned through HKCU, the
    /// machine's own service accounts, and the <c>_Classes</c> companion hives, which are the same
    /// user's and are reached through their own key.
    /// </summary>
    private static bool IsCoveredElsewhere(string sid, string? currentUserSid) =>
        sid.Equals(currentUserSid, StringComparison.OrdinalIgnoreCase)
        || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)
        || sid.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase)
        || !sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);

    private List<RawAutostart> ReadHive(string sid)
    {
        var entries = new List<RawAutostart>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            RegistryKey? hive;
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                hive = users.OpenSubKey(sid);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException
                                         or System.Security.SecurityException
                                         or IOException)
            {
                Interlocked.Increment(ref _unreadable);
                continue;
            }
            if (hive is null)
            {
                continue;
            }

            using (hive)
            {
                foreach (var sub in SubKeys)
                {
                    entries.AddRange(ReadValues(hive, sid, view, sub));
                }
            }
        }
        return entries;
    }

    private List<RawAutostart> ReadValues(
        RegistryKey hive, string sid, RegistryView view, string sub)
    {
        var entries = new List<RawAutostart>();
        RegistryKey? key;
        try
        {
            key = hive.OpenSubKey(sub);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            Interlocked.Increment(ref _unreadable);
            return entries;
        }
        if (key is null)
        {
            return entries;
        }

        using (key)
        {
            var location = $"HKU\\{sid}\\{RegistryViews.Describe(sub, view)} [{view}]";
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is string command && command.Length > 0)
                {
                    entries.Add(new RawAutostart(AutostartVector.RunKey, name, location, command));
                }
            }
        }
        return entries;
    }

    private HashSet<string> LoadedHiveSids()
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            foreach (var name in users.GetSubKeyNames())
            {
                sids.Add(name);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            Interlocked.Increment(ref _unreadable);
        }
        return sids;
    }

    /// <summary>Real user profiles on this machine, from the profile list Windows maintains.</summary>
    internal static List<string> ProfileSids()
    {
        var sids = new List<string>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64);
            using var profiles = baseKey.OpenSubKey(ProfileList);
            if (profiles is null)
            {
                return sids;
            }
            foreach (var sid in profiles.GetSubKeyNames())
            {
                if (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
                {
                    sids.Add(sid);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            // The caller counts what it could not read; an unreadable profile list simply yields
            // no additional profiles rather than an invented one.
        }
        return sids;
    }

    /// <summary>The profile directory for a SID, or null when it is not recorded or not readable.</summary>
    internal static string? ProfileDirectory(string sid)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64);
            using var profile = baseKey.OpenSubKey($@"{ProfileList}\{sid}");
            return profile?.GetValue("ProfileImagePath") as string is { Length: > 0 } path
                ? Environment.ExpandEnvironmentVariables(path)
                : null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or IOException)
        {
            return null;
        }
    }

    private static string? CurrentSid()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.User?.Value;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
