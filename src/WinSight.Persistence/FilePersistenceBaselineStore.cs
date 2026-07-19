using System.Text;

namespace WinSight.Persistence;

/// <summary>
/// A file-backed <see cref="IPersistenceBaselineStore"/>. It writes the baseline as a small,
/// tab-separated text file under the user's local application data, atomically (temp file + move) so
/// a crash mid-write cannot corrupt it. Reads are bounded and tolerant: a missing, truncated, or
/// otherwise unreadable file yields null, which the monitor treats as a first run — never a crash.
/// </summary>
public sealed class FilePersistenceBaselineStore : IPersistenceBaselineStore
{
    // A machine's autostart surfaces total a few hundred entries; the cap only guards against a
    // pathological or tampered file being read whole into memory.
    private const int MaxBaselineEntries = 20_000;
    private const string Header = "#winsight-guardian-baseline v1";

    private readonly string _path;

    public FilePersistenceBaselineStore(string? path = null)
    {
        _path = path ?? DefaultPath();
    }

    /// <summary>The default local-only location: <c>%LocalAppData%\WinSight\guardian-baseline.tsv</c>.</summary>
    public static string DefaultPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight",
        "guardian-baseline.tsv");

    public IReadOnlySet<PersistenceIdentity>? Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            using var reader = new StreamReader(_path, Encoding.UTF8);
            if (reader.ReadLine() != Header)
            {
                return null; // unknown/corrupt format: safest to treat as a first run
            }

            var result = new HashSet<PersistenceIdentity>();
            string? line;
            while ((line = reader.ReadLine()) is not null && result.Count < MaxBaselineEntries)
            {
                var parts = line.Split('\t');
                if (parts.Length != 3 || !Enum.TryParse<AutostartVector>(parts[0], out var vector))
                {
                    continue; // skip a malformed line rather than discarding the whole baseline
                }
                result.Add(new PersistenceIdentity(vector, parts[1], parts[2]));
            }

            return result.Count > 0 ? result : null;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    public void Save(IReadOnlyCollection<PersistenceIdentity> baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var builder = new StringBuilder();
            builder.Append(Header).Append('\n');
            var written = 0;
            foreach (var id in baseline)
            {
                if (written >= MaxBaselineEntries)
                {
                    break;
                }
                // A tab or newline in a name/target would break the line format; such an identity
                // simply is not persisted (vanishingly rare for real registry names / paths).
                if (id.Name.IndexOfAny(['\t', '\n', '\r']) >= 0 ||
                    id.Target.IndexOfAny(['\t', '\n', '\r']) >= 0)
                {
                    continue;
                }
                builder.Append(id.Vector).Append('\t').Append(id.Name).Append('\t').Append(id.Target).Append('\n');
                written++;
            }

            var temp = _path + ".tmp";
            File.WriteAllText(temp, builder.ToString(), Encoding.UTF8);
            File.Move(temp, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Persisting the baseline is best-effort: if it cannot be written, live monitoring still
            // works this session; only cross-run reconciliation is skipped next launch.
        }
    }
}
