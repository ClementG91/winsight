using System.Text;
using System.Text.Json;

using Microsoft.Win32;

using WinSight.Core;

namespace WinSight.Application;

/// <summary>
/// The production <see cref="IPersistenceMutator"/> for the vectors a user can act on without the
/// service: Run/RunOnce values in the current user's hive, and files in the current user's Startup
/// folder. Registry values are read and rewritten through the 64-bit view using the exact key path
/// the entry was found under, so a value in a WOW6432Node key round-trips correctly.
/// </summary>
/// <remarks>
/// The payload preserves the value's kind (a REG_EXPAND_SZ restored as REG_SZ would silently stop
/// expanding its variables), so restore recreates the entry exactly. It only ever touches HKCU and a
/// path under the user's own Startup folder; a target outside those is refused, so a misresolved
/// target cannot make this write somewhere unexpected.
/// </remarks>
public sealed class RegistryAndFilePersistenceMutator : IPersistenceMutator
{
    private sealed record RegistryPayload(int Kind, string? StringData, byte[]? BinaryData, string[]? MultiData);

    public PersistenceSnapshot? Capture(PersistenceActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Kind == PersistenceActionKind.RegistryValue
            ? CaptureRegistry(target)
            : CaptureFile(target);
    }

    public bool Remove(PersistenceActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Kind == PersistenceActionKind.RegistryValue ? RemoveRegistry(target) : RemoveFile(target);
    }

    public bool OriginIsFree(PersistenceActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Kind == PersistenceActionKind.RegistryValue)
        {
            using var key = OpenSubKey(target, writable: false);
            return key is not null && key.GetValue(target.ValueName) is null;
        }
        return target.FilePath is { } path && AutomaticFileAccess.IsLocal(path) && !File.Exists(path);
    }

    public bool Restore(PersistenceActionTarget target, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(payload);
        return target.Kind == PersistenceActionKind.RegistryValue
            ? RestoreRegistry(target, payload)
            : RestoreFile(target, payload);
    }

    private PersistenceSnapshot? CaptureRegistry(PersistenceActionTarget target)
    {
        try
        {
            using var key = OpenSubKey(target, writable: false);
            var value = key?.GetValue(target.ValueName);
            if (key is null || value is null)
            {
                return null;
            }
            var kind = key.GetValueKind(target.ValueName);
            var payload = kind switch
            {
                RegistryValueKind.Binary => new RegistryPayload((int)kind, null, (byte[])value, null),
                RegistryValueKind.MultiString => new RegistryPayload((int)kind, null, null, (string[])value),
                _ => new RegistryPayload((int)kind, Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture), null, null),
            };
            var token = value as string ?? Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            return new PersistenceSnapshot(JsonSerializer.SerializeToUtf8Bytes(payload), token);
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            return null;
        }
    }

    private bool RemoveRegistry(PersistenceActionTarget target)
    {
        try
        {
            using var key = OpenSubKey(target, writable: true);
            if (key is null || key.GetValue(target.ValueName) is null)
            {
                return false;
            }
            key.DeleteValue(target.ValueName!, throwOnMissingValue: false);
            return true;
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            return false;
        }
    }

    private bool RestoreRegistry(PersistenceActionTarget target, byte[] payload)
    {
        try
        {
            var restored = JsonSerializer.Deserialize<RegistryPayload>(payload);
            if (restored is null)
            {
                return false;
            }
            using var key = OpenSubKey(target, writable: true, create: true);
            if (key is null)
            {
                return false;
            }
            var kind = (RegistryValueKind)restored.Kind;
            object data = kind switch
            {
                RegistryValueKind.Binary => restored.BinaryData ?? [],
                RegistryValueKind.MultiString => restored.MultiData ?? [],
                RegistryValueKind.DWord => int.Parse(restored.StringData ?? "0", System.Globalization.CultureInfo.InvariantCulture),
                RegistryValueKind.QWord => long.Parse(restored.StringData ?? "0", System.Globalization.CultureInfo.InvariantCulture),
                _ => restored.StringData ?? string.Empty,
            };
            key.SetValue(target.ValueName!, data, kind);
            return true;
        }
        catch (Exception ex) when (IsRegistryFailure(ex) || ex is JsonException or FormatException or OverflowException)
        {
            return false;
        }
    }

    private static PersistenceSnapshot? CaptureFile(PersistenceActionTarget target)
    {
        try
        {
            var path = target.FilePath;
            if (path is null || !AutomaticFileAccess.IsLocal(path) || !File.Exists(path)
                || new FileInfo(path).Length > 64 * 1024 * 1024)
            {
                return null;
            }
            return new PersistenceSnapshot(File.ReadAllBytes(path), path);
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return null;
        }
    }

    private static bool RemoveFile(PersistenceActionTarget target)
    {
        try
        {
            var path = target.FilePath;
            if (path is null || !AutomaticFileAccess.IsLocal(path) || !File.Exists(path))
            {
                return false;
            }
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return false;
        }
    }

    private static bool RestoreFile(PersistenceActionTarget target, byte[] payload)
    {
        try
        {
            var path = target.FilePath;
            if (path is null || !AutomaticFileAccess.IsLocal(path) || File.Exists(path))
            {
                return false;
            }
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            {
                return false;
            }
            // CreateNew so a race that re-creates the origin between the free check and here does not
            // overwrite the new occupant.
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(payload);
            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return false;
        }
    }

    private static RegistryKey? OpenSubKey(PersistenceActionTarget target, bool writable, bool create = false)
    {
        if (target.Hive != RegistryHive.CurrentUser || target.SubKey is null)
        {
            // Only the current user's hive is user-actionable; anything else needs the service tier.
            return null;
        }
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        return create
            ? baseKey.CreateSubKey(target.SubKey, writable)
            : baseKey.OpenSubKey(target.SubKey, writable);
    }

    private static bool IsRegistryFailure(Exception ex) =>
        ex is UnauthorizedAccessException or System.Security.SecurityException or IOException
            or ArgumentException or InvalidCastException;

    private static bool IsFileFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException;
}
