using System.Security.Cryptography;
using System.Text;

using WinSight.Core;

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
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);

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

    public IReadOnlySet<PersistenceIdentity>? Load() => LoadWithCoverage()?.Identities;

    /// <summary>
    /// Loads the identities and, after them, the coverage lines (WS-70). A file written without a
    /// coverage marker - every v0.13 baseline - loads with null coverage.
    /// </summary>
    public PersistedBaseline? LoadWithCoverage()
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(_path);
            if (lease is null || lease.IsDirectory || lease.Length > MaxBaselineBytes)
            {
                return null;
            }

            using var stream = lease.OpenRead(FileOptions.SequentialScan);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            if (reader.ReadLine() != Header)
            {
                return null; // unknown/corrupt format: safest to treat as a first run
            }

            var result = new HashSet<PersistenceIdentity>();
            Dictionary<string, IReadOnlyList<string>>? coverage = null;
            string? line;
            var lines = 0;
            var identityLines = 0;
            while ((line = reader.ReadLine()) is not null)
            {
                if (++lines > MaxBaselineEntries * 2)
                {
                    return null;
                }
                if (line == CoverageMarker)
                {
                    coverage ??= new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
                    continue;
                }
                if (line.StartsWith(CoveredPrefix, StringComparison.Ordinal))
                {
                    if (coverage is not null)
                    {
                        TryReadCovered(line, coverage);
                    }
                    continue;
                }
                if (++identityLines > MaxBaselineEntries)
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

            if (!lease.IsCurrent())
            {
                return null;
            }
            if (identityLines > 0 && result.Count == 0)
            {
                return null; // lines present but none readable: corrupt, reseed
            }
            return new PersistedBaseline(result, coverage is null ? null : new PersistenceCoverageMap(coverage));
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
    public void Save(IReadOnlyCollection<PersistenceIdentity> baseline) => Save(baseline, coverage: null);

    /// <summary>Writes the baseline and, when given, the coverage it reflects, in one atomic file.</summary>
    /// <remarks>
    /// Coverage lines follow the identities under a marker line. None of them has the six fields of
    /// an identity, so a v0.13 reader skips them and still loads the baseline after a downgrade.
    /// </remarks>
    public void Save(IReadOnlyCollection<PersistenceIdentity> baseline, PersistenceCoverageMap? coverage)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        if (baseline.Count > MaxBaselineEntries)
        {
            // Do not replace a usable baseline with a truncated one.
            throw new InvalidDataException(
                $"The Guardian baseline has {baseline.Count} entries, above the {MaxBaselineEntries} limit.");
        }
        using (BaselineLock.Acquire(_path))
        {
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
            if (coverage is not null)
            {
                builder.Append(CoverageMarker).Append('\n');
                foreach (var (source, scopes) in coverage.Sources)
                {
                    builder.Append(CoveredPrefix).Append(Encode(source));
                    foreach (var scope in scopes)
                    {
                        builder.Append('\t').Append(Encode(scope));
                    }
                    builder.Append('\n');
                }
            }

            if (builder.Length > MaxBaselineBytes - 3)
            {
                throw new InvalidDataException("The encoded Guardian baseline exceeds the file size limit.");
            }
            // The central writer creates a unique handle-relative temp file, flushes it and renames
            // it over the target atomically. An empty baseline reseeds silently, and whatever
            // arrived before a crash is absorbed without an alert.
            if (!AtomicFile.TryWrite(_path, Encoding.UTF8.GetBytes(builder.ToString())))
            {
                throw new IOException("The Guardian baseline could not be written safely.");
            }
        }
    }

    // Coverage: a marker, then one line per source seen in full: the source, then the scopes it could
    // not read (none: complete). Everything encoded, like the identities.
    private const string CoverageMarker = "@coverage";
    private const string CoveredPrefix = "@covered\t";

    private static void TryReadCovered(string line, Dictionary<string, IReadOnlyList<string>> coverage)
    {
        var parts = line[CoveredPrefix.Length..].Split('\t');
        try
        {
            coverage[Decode(parts[0])] = parts.Skip(1).Select(Decode).ToArray();
        }
        catch (FormatException)
        {
            // A corrupt line loses coverage for that one source. Only whoever can write this file can
            // corrupt it, and they could as well add their own identity: no new exposure.
        }
    }

    private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    private static string Decode(string value) => Encoding.UTF8.GetString(Convert.FromBase64String(value));

    /// <summary>Stable per-path mutex name, exposed internally for the real concurrency test.</summary>
    internal static string LockNameFor(string path)
    {
        var canonical = Path.GetFullPath(path).ToUpperInvariant();
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..32];
        return $@"Local\WinSight.PersistenceBaseline.{key}";
    }

    private sealed class BaselineLock : IDisposable
    {
        private readonly Mutex _mutex;
        private readonly bool _held;

        private BaselineLock(Mutex mutex, bool held)
        {
            _mutex = mutex;
            _held = held;
        }

        public static BaselineLock Acquire(string path)
        {
            var mutex = new Mutex(initiallyOwned: false, LockNameFor(path));
            bool held;
            try
            {
                held = mutex.WaitOne(LockWait);
            }
            catch (AbandonedMutexException)
            {
                held = true;
            }
            if (!held)
            {
                mutex.Dispose();
                throw new IOException("Timed out waiting for another Guardian baseline writer.");
            }
            return new BaselineLock(mutex, held: true);
        }

        public void Dispose()
        {
            if (_held)
            {
                _mutex.ReleaseMutex();
            }
            _mutex.Dispose();
        }
    }
}
