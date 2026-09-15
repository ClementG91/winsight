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
    private const long MaxBaselineBytes = 16 * 1024 * 1024;
    // v3 preserves argument case/whitespace, location and source ownership. Older lossy identities
    // cannot be migrated faithfully: reseed them silently once instead of reporting every entry.
    private const string Header = "#winsight-guardian-baseline v3";

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
            if (!File.Exists(_path) || new FileInfo(_path).Length > MaxBaselineBytes)
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
            var lines = 0;
            while ((line = reader.ReadLine()) is not null)
            {
                if (++lines > MaxBaselineEntries)
                {
                    return null;
                }
                var parts = line.Split('\t');
                if (parts.Length != 6 || !Enum.TryParse<AutostartVector>(parts[0], out var vector)
                    || !Enum.IsDefined(vector))
                {
                    continue; // skip a malformed line rather than discarding the whole baseline
                }
                try
                {
                    result.Add(new PersistenceIdentity(vector, Decode(parts[1]), Decode(parts[2]),
                        Decode(parts[3]), Decode(parts[4]), Decode(parts[5])));
                }
                catch (FormatException)
                {
                    // Corrupt base64 is not an identity.
                }
            }

            return lines == 0 || result.Count > 0 ? result : null;
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>Writes the baseline atomically (temp file, then replace).</summary>
    /// <exception cref="IOException">The file could not be written; the previous file is intact.</exception>
    /// <exception cref="InvalidDataException">The baseline exceeds the format limits and was not written.</exception>
    /// <remarks>
    /// Failures are thrown rather than swallowed: the monitor records them and retries, so a baseline
    /// that silently stopped persisting is visible instead of looking like working cross-run detection.
    /// </remarks>
    public void Save(IReadOnlyCollection<PersistenceIdentity> baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        if (baseline.Count > MaxBaselineEntries)
        {
            // Do not replace a usable baseline with a truncated one.
            throw new InvalidDataException(
                $"The Guardian baseline has {baseline.Count} entries, above the {MaxBaselineEntries} limit.");
        }
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
                // Encode every string so quotes, tabs, newlines and argument case round-trip.
                builder.Append(id.Vector).Append('\t').Append(Encode(id.Name)).Append('\t')
                    .Append(Encode(id.Target)).Append('\t').Append(Encode(id.Arguments)).Append('\t')
                    .Append(Encode(id.Location)).Append('\t').Append(Encode(id.Source)).Append('\n');
                written++;
            }

            if (builder.Length > MaxBaselineBytes - 3)
            {
                throw new InvalidDataException("The encoded Guardian baseline exceeds the file size limit.");
            }
            var temp = _path + ".tmp";
            File.WriteAllText(temp, builder.ToString(), Encoding.UTF8);
            File.Move(temp, _path, overwrite: true);
        }
    }

    private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    private static string Decode(string value) => Encoding.UTF8.GetString(Convert.FromBase64String(value));
}
