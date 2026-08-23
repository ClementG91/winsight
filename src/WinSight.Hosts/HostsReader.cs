using System.Net;

namespace WinSight.Hosts;

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

    /// <summary><c>%SystemRoot%\System32\drivers\etc\hosts</c>.</summary>
    public static string DefaultPath()
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        return Path.Combine(systemRoot, "System32", "drivers", "etc", "hosts");
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
            var parsed = ParseWithCoverage(File.ReadLines(_path));
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
