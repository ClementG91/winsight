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
            if (!File.Exists(path))
            {
                return null;
            }
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
