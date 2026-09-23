using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Per-user COM server registrations (HKCU\Software\Classes\CLSID\{clsid}\
/// InprocServer32). A user-level CLSID that shadows a system one lets malware load
/// its DLL whenever that COM object is instantiated, COM hijacking (MITRE
/// T1546.015). HKCU is scanned (not the thousands of legitimate HKLM system CLSIDs),
/// which is where the high-signal per-user hijacks live.
/// </summary>
public sealed class ComHijackEnumerator : IAutostartEnumerator
{
    private int _unreadable;
    public int UnreadableLocations => _unreadable;
    public bool CanConfirmAbsence => true;

    private const string Path = @"SOFTWARE\Classes\CLSID";

    public string Surface => "COM (HKCU CLSID)";

    /// <summary>
    /// The server keys a CLSID registration can name, in the order COM consults them.
    /// </summary>
    /// <remarks>
    /// Only <c>InprocServer32</c> was read, which is three of the four ways a CLSID can point at
    /// code and none of the fifth. <c>LocalServer32</c> names an executable rather than a DLL, and
    /// <c>TreatAs</c> is the sharpest of the lot: it redirects the class to a completely different
    /// CLSID, so a hijack written that way left no trace anywhere in the report - the entry
    /// WinSight showed was the legitimate server of a class that COM no longer instantiates.
    /// </remarks>
    private static readonly (string Key, string? Value)[] ServerKeys =
    [
        ("InprocServer32", null),
        ("InprocServer", null),
        ("InprocHandler32", null),
        ("LocalServer32", null),
        ("TreatAs", null),
    ];

    public IEnumerable<RawAutostart> Enumerate()
    {
        // Both views: a 32-bit COM server registered under the WOW6432Node twin is loaded into
        // every 32-bit host that instantiates the class, and was previously invisible.
        _unreadable = 0;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
            using var root = baseKey.OpenSubKey(Path);
            if (root is null)
            {
                continue;
            }
            using var machineBase = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var machineRoot = OpenMachineClasses(machineBase);
            foreach (var clsid in root.GetSubKeyNames())
            {
                foreach (var entry in ServerEntries(root, machineRoot, clsid, view))
                {
                    yield return entry;
                }
            }
        }
    }

    /// <summary>How a per-user class registration relates to the machine's registration of it.</summary>
    internal enum ComMachineRelation
    {
        /// <summary>The machine does not register the class: a per-user class, or a phantom one.</summary>
        UserOnly,

        /// <summary>The machine registers the same server: a duplicate with no effect.</summary>
        SameServer,

        /// <summary>The per-user value sends a machine class to another server (T1546.015).</summary>
        DifferentServer,
    }

    /// <summary>Pure classification of a per-user server value against the machine's.</summary>
    internal static ComMachineRelation Classify(string userValue, string? machineValue, bool machineClassExists)
    {
        if (!machineClassExists)
        {
            return ComMachineRelation.UserOnly;
        }
        return machineValue is not null && NormalizeServer(machineValue) == NormalizeServer(userValue)
            ? ComMachineRelation.SameServer
            : ComMachineRelation.DifferentServer;
    }

    private static string NormalizeServer(string value) =>
        Environment.ExpandEnvironmentVariables(value.Trim().Trim('"').Trim()).ToLowerInvariant();

    private static RegistryKey? OpenMachineClasses(RegistryKey machineBase)
    {
        try
        {
            return machineBase.OpenSubKey(Path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    // An unreadable machine registration is not evidence of a duplicate: the entry stays, unflagged.
    private static ComMachineRelation MachineRelation(RegistryKey? machineRoot, string clsid, string key, string userValue)
    {
        if (machineRoot is null)
        {
            return ComMachineRelation.UserOnly;
        }
        try
        {
            using var machineClass = machineRoot.OpenSubKey(clsid);
            if (machineClass is null)
            {
                return ComMachineRelation.UserOnly;
            }
            using var server = machineClass.OpenSubKey(key);
            return Classify(userValue, server?.GetValue(null) as string, machineClassExists: true);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return ComMachineRelation.UserOnly;
        }
    }

    private List<RawAutostart> ServerEntries(RegistryKey root, RegistryKey? machineRoot, string clsid, RegistryView view)
    {
        var entries = new List<RawAutostart>();
        foreach (var (key, _) in ServerKeys)
        {
            try
            {
                using var server = root.OpenSubKey($@"{clsid}\{key}");
                if (server?.GetValue(null) is string target && target.Trim().Length > 0)
                {
                    // A TreatAs value is a CLSID, not a path: report the binary the redirection
                    // ends at, so the signature model sees a file. Reporting the raw GUID made the
                    // legitimate OLE mapping Windows ships read as "no resolvable image" on every
                    // machine, while saying nothing about the code the class actually loads - which
                    // is the entire point of following a TreatAs.
                    var command = key == "TreatAs"
                        ? ClsidResolver.ResolveInprocServer(target.Trim(), view) ?? target
                        : target;
                    var relation = MachineRelation(machineRoot, clsid, key, target);
                    if (relation == ComMachineRelation.SameServer)
                    {
                        // The machine registers this class with this very server: the per-user copy
                        // changes nothing COM loads. Such duplicates were 3,842 of 3,896 per-user
                        // classes on the audit machine and buried the few that matter. If the value
                        // is later pointed elsewhere, it reappears here, as an arrival.
                        continue;
                    }
                    entries.Add(new RawAutostart(
                        AutostartVector.ComHijack, $"{clsid} [{key}]",
                        $"HKCU\\{RegistryViews.Describe(Path, view)}\\{clsid}\\{key}", command,
                        relation == ComMachineRelation.DifferentServer,
                        // An in-process server in the 32-bit view is loaded by 32-bit hosts.
                        key is "InprocServer32" or "TreatAs" ? RawAutostart.LoaderFor(view) : null));
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                _unreadable++;
            }
        }
        return entries;
    }
}
