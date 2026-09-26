using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using WinSight.Core;

namespace WinSight.Hosts;

/// <summary>Where Windows reads the hosts file from, and whether that is the standard place.</summary>
/// <param name="Path">
/// The hosts file to read, or null when the configured directory names nothing a local path reaches
/// (a relative path, or a variable with no trustworthy value).
/// </param>
/// <param name="Relocated">
/// True when <c>Tcpip\Parameters\DataBasePath</c> points somewhere other than the standard
/// <c>System32\drivers\etc</c>.
/// </param>
/// <param name="Registered">The <c>DataBasePath</c> value as registered, when there is one.</param>
/// <param name="Unverified">
/// True when the registry value could not be read, so the standard location was assumed.
/// </param>
public sealed record HostsLocation(string? Path, bool Relocated, string? Registered, bool Unverified);

/// <summary>The hosts file's active entries, and what reading it actually did.</summary>
/// <param name="Entries">The active mappings. Empty when the file could not be read.</param>
/// <param name="Unreadable">
/// True when the file exists but could not be opened. On Windows it is world-readable by default,
/// so this is itself worth reporting rather than a missing detail.
/// </param>
/// <param name="Missing">True when there is no hosts file, which is normal and harmless.</param>
public sealed record HostsSnapshot(
    IReadOnlyList<HostEntry> Entries,
    bool Unreadable,
    bool Missing,
    int MalformedLines);

/// <summary>
/// Reads and parses the Windows hosts file into its active entries. Read-only. Parsing
/// is a pure static so it can be tested without touching the real file; the default
/// path resolves the system hosts file.
/// </summary>
public sealed class HostsReader(string? path = null)
{
    private readonly string _path = path ?? DefaultPath();

    private const string TcpipParameters = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

    /// <summary><c>%SystemRoot%\System32\drivers\etc\hosts</c>.</summary>
    public static string DefaultPath()
    {
        var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        return Path.Combine(systemDirectory, "drivers", "etc", "hosts");
    }

    /// <summary>
    /// The hosts file Windows actually uses: the one in the directory named by
    /// <c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath</c>.
    /// </summary>
    /// <remarks>
    /// <b>Why the standard path is not enough.</b> The resolver reads its database files - hosts
    /// among them - from that directory. Pointing the value at a folder of one's own moves every
    /// override out of the file a scan looks at, which then reports a clean, unmodified hosts file.
    /// </remarks>
    public static HostsLocation ResolveLocation()
    {
        string? registered;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(TcpipParameters);
            registered = key?.GetValue(
                "DataBasePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return new HostsLocation(DefaultPath(), Relocated: false, Registered: null, Unverified: true);
        }
        return ResolveLocation(
            registered,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.System));
    }

    /// <summary>The hosts file a registered <c>DataBasePath</c> value names. Pure, for tests.</summary>
    /// <remarks>
    /// <c>%SystemRoot%</c> and <c>%windir%</c> are expanded from the Windows directory the system
    /// reports, never from this process's environment, which whoever launched the scan could have
    /// set (see <see cref="DefaultPath"/>). Any other variable has no trustworthy value here, so a
    /// value using one is reported as relocated to somewhere unresolvable rather than guessed at.
    /// </remarks>
    internal static HostsLocation ResolveLocation(string? registered, string windowsDirectory, string systemDirectory)
    {
        var standardDirectory = Path.Combine(systemDirectory, "drivers", "etc");
        var standard = Path.Combine(standardDirectory, "hosts");
        if (string.IsNullOrWhiteSpace(registered))
        {
            return new HostsLocation(standard, Relocated: false, Registered: null, Unverified: false);
        }

        var expanded = Regex.Replace(
            registered.Trim().Trim('"').Trim(),
            "%(?:SystemRoot|windir)%",
            _ => windowsDirectory,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        string directory;
        try
        {
            if (expanded.Contains('%') || !Path.IsPathFullyQualified(expanded))
            {
                return new HostsLocation(null, Relocated: true, registered, Unverified: false);
            }
            directory = Path.GetFullPath(expanded)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new HostsLocation(null, Relocated: true, registered, Unverified: false);
        }

        var isStandard = string.Equals(
            directory,
            Path.GetFullPath(standardDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
        return isStandard
            ? new HostsLocation(standard, Relocated: false, registered, Unverified: false)
            : new HostsLocation(Path.Combine(directory, "hosts"), Relocated: true, registered, Unverified: false);
    }

    /// <summary>The active entries, or an empty list when the file could not be read.</summary>
    /// <remarks>
    /// Kept for callers that only want the entries. Prefer <see cref="Read"/>: an empty list here
    /// cannot be told apart from a file nobody was allowed to open.
    /// </remarks>
    public IReadOnlyList<HostEntry> Snapshot() => Read().Entries;

    /// <summary>The active entries, and whether the file could be read at all.</summary>
    /// <remarks>
    /// <b>Why the distinction is a security signal, not just bookkeeping.</b> On Windows the hosts
    /// file is readable by every user by default. A scan that returns nothing therefore means one of
    /// two very different things: the file has no active entries, or something changed its
    /// permissions. The second is exactly what an attacker who has just pointed a banking or update
    /// domain at their own address would want, and reporting it as "0 entries, 0 flagged" hands
    /// them a clean bill of health.
    /// </remarks>
    public HostsSnapshot Read()
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(_path);
            if (lease is null)
            {
                return AutomaticFileAccess.IsLocal(_path)
                    ? new HostsSnapshot([], Unreadable: false, Missing: true, MalformedLines: 0)
                    : new HostsSnapshot([], Unreadable: true, Missing: false, MalformedLines: 0);
            }
            if (lease.IsDirectory)
            {
                return new HostsSnapshot([], Unreadable: true, Missing: false, MalformedLines: 0);
            }
            using var stream = lease.OpenRead();
            using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
            var parsed = ParseWithCoverage(ReadLines(reader));
            if (!lease.IsCurrent())
            {
                return new HostsSnapshot([], Unreadable: true, Missing: false, MalformedLines: 0);
            }
            return new HostsSnapshot(parsed.Entries, Unreadable: false, Missing: false, parsed.MalformedLines);
        }
        catch (FileNotFoundException)
        {
            // Genuinely absent is not suspicious: Windows works fine without the file, and it is
            // materially different from "present but refused".
            return new HostsSnapshot([], Unreadable: false, Missing: true, MalformedLines: 0);
        }
        catch (DirectoryNotFoundException)
        {
            return new HostsSnapshot([], Unreadable: false, Missing: true, MalformedLines: 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new HostsSnapshot([], Unreadable: true, Missing: false, MalformedLines: 0);
        }
    }

    /// <summary>
    /// Parses hosts-file lines: strips comments/blanks, then each active line is an IP
    /// followed by one or more hostnames (a line may map several names to one address).
    /// </summary>
    public static IReadOnlyList<HostEntry> Parse(IEnumerable<string> lines) =>
        ParseWithCoverage(lines).Entries;

    private static IEnumerable<string> ReadLines(StreamReader reader)
    {
        while (reader.ReadLine() is { } line)
        {
            yield return line;
        }
    }

    internal static (IReadOnlyList<HostEntry> Entries, int MalformedLines) ParseWithCoverage(
        IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        var entries = new List<HostEntry>();
        var malformedLines = 0;
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] == '#')
            {
                continue;
            }
            // A trailing inline comment is legal on an entry line.
            var hash = trimmed.IndexOf('#');
            if (hash >= 0)
            {
                trimmed = trimmed[..hash].Trim();
            }

            var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out _))
            {
                malformedLines++;
                continue;
            }
            var ip = parts[0];
            for (var i = 1; i < parts.Length; i++)
            {
                entries.Add(new HostEntry(ip, parts[i]));
            }
        }
        return (entries, malformedLines);
    }
}
