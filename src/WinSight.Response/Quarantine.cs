using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>What a quarantined item was, so it can be restored to exactly where it came from.</summary>
public enum QuarantineItemKind
{
    /// <summary>A registry value (name, kind and data), keyed by its full key path.</summary>
    RegistryValue,

    /// <summary>An exported registry subtree, keyed by its root key path.</summary>
    RegistrySubtree,

    /// <summary>A file moved out of a startup folder, keyed by its original full path.</summary>
    File,

    /// <summary>A scheduled task definition, keyed by its task path.</summary>
    ScheduledTask,
}

/// <summary>The metadata stored beside a quarantined payload.</summary>
/// <param name="Id">Unique id; also the payload file name.</param>
/// <param name="Kind">What the item is.</param>
/// <param name="OriginLocation">Where it came from and must be restored to.</param>
/// <param name="DisplayName">A short, non-sensitive label for the operator.</param>
/// <param name="PayloadSha256">SHA-256 of the payload, verified on restore.</param>
/// <param name="QuarantinedUtc">When it was quarantined.</param>
/// <param name="ActionId">The response action that created it.</param>
public sealed record QuarantineItem(
    Guid Id,
    QuarantineItemKind Kind,
    string OriginLocation,
    string DisplayName,
    string PayloadSha256,
    DateTimeOffset QuarantinedUtc,
    Guid ActionId);

/// <summary>
/// A per-user store for removed items, so every removal is reversible. Each item is a JSON manifest
/// plus an opaque payload file, both under a directory whose DACL grants only the current user.
/// </summary>
/// <remarks>
/// Reversible removal is the safety property the whole response layer rests on: WinSight disables or
/// removes only what it can put back, and restore verifies the payload hash and that the origin is
/// still free before writing it back — the same "a path is not proof" discipline the decoy cleanup
/// uses. The store never restores to a non-local path.
/// </remarks>
public sealed class Quarantine
{
    private const long MaxPayloadBytes = 64 * 1024 * 1024;

    private readonly string _root;

    public Quarantine(string? root = null) => _root = root ?? DefaultRoot();

    /// <summary>Where quarantined items live, beside WinSight's other per-user state.</summary>
    private static string DefaultRoot() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight", "quarantine");

    /// <summary>
    /// Stores a payload and its metadata, returning the stored item. Returns null when the payload is
    /// too large or the store could not be written.
    /// </summary>
    public QuarantineItem? Store(
        QuarantineItemKind kind, string originLocation, string displayName, Guid actionId,
        ReadOnlySpan<byte> payload, DateTimeOffset nowUtc)
    {
        if (payload.Length > MaxPayloadBytes)
        {
            return null;
        }
        var id = Guid.NewGuid();
        var item = new QuarantineItem(id, kind, originLocation, displayName,
            Convert.ToHexString(SHA256.HashData(payload)), nowUtc, actionId);
        try
        {
            EnsureRoot();
            if (!AtomicFile.TryWrite(PayloadPath(id), payload))
            {
                return null;
            }
            if (!AtomicFile.TryWrite(ManifestPath(id), JsonSerializer.SerializeToUtf8Bytes(item)))
            {
                AtomicFile.TryDelete(PayloadPath(id));
                return null;
            }
            return item;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>The payload of a stored item, verified against its recorded hash, or null.</summary>
    public byte[]? ReadPayload(QuarantineItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        try
        {
            var path = PayloadPath(item.Id);
            if (!AutomaticFileAccess.IsLocal(path) || !File.Exists(path)
                || new FileInfo(path).Length > MaxPayloadBytes)
            {
                return null;
            }
            var bytes = File.ReadAllBytes(path);
            return Convert.ToHexString(SHA256.HashData(bytes)).Equals(item.PayloadSha256, StringComparison.OrdinalIgnoreCase)
                ? bytes : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>Every stored item, newest first. Corrupt or unreadable entries are skipped.</summary>
    public IReadOnlyList<QuarantineItem> List()
    {
        var items = new List<QuarantineItem>();
        try
        {
            if (!Directory.Exists(_root))
            {
                return items;
            }
            foreach (var manifest in Directory.EnumerateFiles(_root, "*.json"))
            {
                try
                {
                    if (JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllBytes(manifest)) is { } item)
                    {
                        items.Add(item);
                    }
                }
                catch (Exception ex) when (ex is IOException or JsonException)
                {
                    // Skip a corrupt manifest.
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // An unreadable store lists nothing.
        }
        return items.OrderByDescending(item => item.QuarantinedUtc).ToArray();
    }

    /// <summary>Permanently removes a stored item after it has been restored or discarded.</summary>
    public void Remove(Guid id)
    {
        AtomicFile.TryDelete(ManifestPath(id));
        AtomicFile.TryDelete(PayloadPath(id));
    }

    private void EnsureRoot()
    {
        if (Directory.Exists(_root))
        {
            return;
        }
        var directory = Directory.CreateDirectory(_root);
        try
        {
            // Restrict to the current user: a quarantined payload can be the original malicious file,
            // and it must not become readable or writable by other accounts on the machine.
            var current = WindowsIdentity.GetCurrent().User;
            if (current is not null)
            {
                var security = new DirectorySecurity();
                security.SetOwner(current);
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    current, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                directory.SetAccessControl(security);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or PlatformNotSupportedException)
        {
            // The directory still lives under the user's own profile; the tightened DACL is defence
            // in depth, not the only boundary.
        }
    }

    private string ManifestPath(Guid id) => Path.Combine(_root, $"{id:N}.json");

    private string PayloadPath(Guid id) => Path.Combine(_root, $"{id:N}.bin");
}
