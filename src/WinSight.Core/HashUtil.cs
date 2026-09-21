using System.Security.Cryptography;

namespace WinSight.Core;

/// <summary>File hashing helpers (for reputation lookups).</summary>
public static class HashUtil
{
    /// <summary>Lowercase hex SHA-256 of a file, or null when it can't be read.</summary>
    public static string? Sha256File(string path)
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(path);
            if (lease is null || lease.IsDirectory)
            {
                return null;
            }
            using var stream = lease.OpenRead();
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            return lease.IsCurrent() ? hash : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
