namespace WinSight.Hosts;

/// <summary>
/// Reads and parses the Windows hosts file into its active entries. Read-only. Parsing
/// is a pure static so it can be tested without touching the real file; the default
/// path resolves the system hosts file.
/// </summary>
public sealed class HostsReader
{
    private readonly string _path;

    public HostsReader(string? path = null) => _path = path ?? DefaultPath();

    /// <summary><c>%SystemRoot%\System32\drivers\etc\hosts</c>.</summary>
    public static string DefaultPath()
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        return Path.Combine(systemRoot, "System32", "drivers", "etc", "hosts");
    }

    public IReadOnlyList<HostEntry> Snapshot()
    {
        try
        {
            return Parse(File.ReadLines(_path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<HostEntry>();
        }
    }

    /// <summary>
    /// Parses hosts-file lines: strips comments/blanks, then each active line is an IP
    /// followed by one or more hostnames (a line may map several names to one address).
    /// </summary>
    public static IReadOnlyList<HostEntry> Parse(IEnumerable<string> lines)
    {
        var entries = new List<HostEntry>();
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
            if (parts.Length < 2)
            {
                continue;
            }
            var ip = parts[0];
            for (var i = 1; i < parts.Length; i++)
            {
                entries.Add(new HostEntry(ip, parts[i]));
            }
        }
        return entries;
    }
}
