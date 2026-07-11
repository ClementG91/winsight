namespace WinSight.Core;

/// <summary>
/// A caching decorator over any <see cref="ISignatureVerifier"/>. A file's verdict is
/// cached keyed by its path AND last-write time, so unchanged binaries are verified
/// once — a big win when several tools (persistence + connections in one `all` run)
/// check the same system binaries, and across repeated scans. The cache invalidates
/// automatically when a file changes (different mtime). Not thread-safe; scans are
/// sequential.
/// </summary>
public sealed class CachingSignatureVerifier : ISignatureVerifier
{
    private readonly ISignatureVerifier _inner;
    private readonly Dictionary<string, (DateTime Mtime, SignatureVerdict Verdict)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public CachingSignatureVerifier(ISignatureVerifier inner) => _inner = inner;

    public SignatureVerdict Verify(string path) =>
        VerifyMany([path]).TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        var misses = new List<string>();

        foreach (var path in paths)
        {
            if (TryGetCached(path, out var verdict))
            {
                results[path] = verdict;
            }
            else
            {
                misses.Add(path);
            }
        }

        if (misses.Count > 0)
        {
            var fresh = _inner.VerifyMany(misses);
            foreach (var path in misses)
            {
                var verdict = fresh.TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;
                results[path] = verdict;
                Store(path, verdict);
            }
        }
        return results;
    }

    private bool TryGetCached(string path, out SignatureVerdict verdict)
    {
        verdict = default;
        var mtime = LastWrite(path);
        if (mtime is { } m && _cache.TryGetValue(path, out var entry) && entry.Mtime == m)
        {
            verdict = entry.Verdict;
            return true;
        }
        return false;
    }

    private void Store(string path, SignatureVerdict verdict)
    {
        if (LastWrite(path) is { } mtime)
        {
            _cache[path] = (mtime, verdict);
        }
    }

    private static DateTime? LastWrite(string path)
    {
        try
        {
            return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
