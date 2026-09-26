using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

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
///
/// <b>Registry atomicity, and what happens without it.</b> A registry value has no compare-and-delete
/// or create-if-absent primitive; the only way to make the comparison and the change indivisible is a
/// registry transaction (TxR), which a concurrent non-transacted writer aborts. Where Windows has TxR
/// active, the comparison and the change share one transaction. Current Windows 11 builds answer
/// <c>ERROR_RM_NOT_ACTIVE</c> for both hives, and failing closed there made Block refuse every
/// registry value it was offered. Without TxR the comparison and the change therefore go through one
/// open key handle and are verified afterwards: a removal re-reads the value (a program that
/// re-creates its entry at once is reported, not hidden behind a success), and a restore re-reads
/// what it wrote. The residue is a window of microseconds between the comparison and the change in
/// which a concurrent writer's value could be removed without being quarantined, or overwritten by a
/// restore.
/// </remarks>
public sealed class RegistryAndFilePersistenceMutator : IPersistenceMutator
{
    private readonly bool _useTransactions;

    public RegistryAndFilePersistenceMutator()
        : this(useTransactions: true)
    {
    }

    /// <param name="useTransactions">False forces the verified non-transacted path, so tests exercise
    /// it on machines where TxR is active.</param>
    internal RegistryAndFilePersistenceMutator(bool useTransactions) => _useTransactions = useTransactions;

    private const int KeyQueryValue = 0x0001;
    private const int KeySetValue = 0x0002;
    private const int KeyCreateSubKey = 0x0004;
    private const int KeyWow6464Key = 0x0100;
    private const int ErrorRmNotActive = 6801;
    private const int ErrorRmMetadataCorrupt = 6802;
    private const int ErrorDirectoryNotRm = 6803;
    private const int ErrorTransactionsUnsupportedRemote = 6805;

    private sealed record RegistryPayload(int Kind, string? StringData, byte[]? BinaryData, string[]? MultiData);

    public PersistenceSnapshot? Capture(PersistenceActionTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Kind == PersistenceActionKind.RegistryValue
            ? CaptureRegistry(target)
            : CaptureFile(target);
    }

    public PersistenceMutationOutcome RemoveIfUnchanged(
        PersistenceActionTarget target, PersistenceSnapshot expected)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(expected);
        return target.Kind == PersistenceActionKind.RegistryValue
            ? RemoveRegistryIfUnchanged(target, expected)
            : RemoveFileIfUnchanged(target, expected);
    }

    public PersistenceMutationOutcome RestoreIfFree(PersistenceActionTarget target, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(payload);
        return target.Kind == PersistenceActionKind.RegistryValue
            ? RestoreRegistryIfFree(target, payload)
            : RestoreFileIfFree(target, payload);
    }

    private PersistenceSnapshot? CaptureRegistry(PersistenceActionTarget target)
    {
        try
        {
            using var key = OpenSubKey(target, writable: false);
            return key is null ? null : CaptureRegistryValue(key, target.ValueName!);
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            return null;
        }
    }

    private static PersistenceSnapshot? CaptureRegistryValue(RegistryKey key, string valueName)
    {
        var raw = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (raw is null)
        {
            return null;
        }
        var expanded = key.GetValue(valueName);
        var kind = key.GetValueKind(valueName);
        var payload = kind switch
        {
            RegistryValueKind.Binary => new RegistryPayload((int)kind, null, (byte[])raw, null),
            RegistryValueKind.MultiString => new RegistryPayload((int)kind, null, null, (string[])raw),
            _ => new RegistryPayload((int)kind,
                Convert.ToString(raw, System.Globalization.CultureInfo.InvariantCulture), null, null),
        };
        var token = expanded as string
            ?? Convert.ToString(expanded, System.Globalization.CultureInfo.InvariantCulture)
            ?? string.Empty;
        return new PersistenceSnapshot(JsonSerializer.SerializeToUtf8Bytes(payload), token);
    }

    private PersistenceMutationOutcome RemoveRegistryIfUnchanged(
        PersistenceActionTarget target, PersistenceSnapshot expected)
    {
        if (target.Hive != RegistryHive.CurrentUser || target.SubKey is null || target.ValueName is null)
        {
            // Only the current user's hive is user-actionable; anything else needs the service tier.
            return PersistenceMutationOutcome.Failed;
        }
        if (!_useTransactions)
        {
            return RemoveRegistryIfUnchangedDirect(target, expected);
        }
        try
        {
            using var transaction = CreateTransaction(
                IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, "WinSight persistence removal");
            if (transaction.IsInvalid)
            {
                return IsTransactionUnavailable(Marshal.GetLastPInvokeError())
                    ? RemoveRegistryIfUnchangedDirect(target, expected)
                    : PersistenceMutationOutcome.Failed;
            }
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            var status = RegOpenKeyTransacted(
                baseKey.Handle,
                target.SubKey!,
                0,
                KeyQueryValue | KeySetValue | KeyWow6464Key,
                out var transactedHandle,
                transaction,
                IntPtr.Zero);
            if (status != 0)
            {
                transactedHandle?.Dispose();
                return status switch
                {
                    2 => PersistenceMutationOutcome.TargetNotFound,
                    _ when IsTransactionUnavailable(status) =>
                        RemoveRegistryIfUnchangedDirect(target, expected),
                    _ => PersistenceMutationOutcome.Failed,
                };
            }
            using var key = RegistryKey.FromHandle(transactedHandle, RegistryView.Registry64);
            var current = CaptureRegistryValue(key, target.ValueName!);
            if (current is null)
            {
                return PersistenceMutationOutcome.TargetNotFound;
            }
            if (!current.Payload.AsSpan().SequenceEqual(expected.Payload)
                || !string.Equals(current.RevalidationToken, expected.RevalidationToken, StringComparison.Ordinal))
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            key.DeleteValue(target.ValueName!, throwOnMissingValue: true);
            return CommitTransaction(transaction)
                ? PersistenceMutationOutcome.Succeeded
                : PersistenceMutationOutcome.Failed;
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            return PersistenceMutationOutcome.Failed;
        }
    }

    private PersistenceMutationOutcome RestoreRegistryIfFree(PersistenceActionTarget target, byte[] payload)
    {
        if (target.Hive != RegistryHive.CurrentUser || target.SubKey is null || target.ValueName is null)
        {
            return PersistenceMutationOutcome.Failed;
        }
        try
        {
            var restored = JsonSerializer.Deserialize<RegistryPayload>(payload);
            if (restored is null)
            {
                return PersistenceMutationOutcome.Failed;
            }
            if (!_useTransactions)
            {
                return RestoreRegistryIfFreeDirect(target, restored);
            }
            using var transaction = CreateTransaction(
                IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, "WinSight persistence restore");
            if (transaction.IsInvalid)
            {
                return IsTransactionUnavailable(Marshal.GetLastPInvokeError())
                    ? RestoreRegistryIfFreeDirect(target, restored)
                    : PersistenceMutationOutcome.Failed;
            }
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            var status = RegCreateKeyTransacted(
                baseKey.Handle,
                target.SubKey!,
                0,
                null,
                0,
                KeyQueryValue | KeySetValue | KeyCreateSubKey | KeyWow6464Key,
                IntPtr.Zero,
                out var transactedHandle,
                out _,
                transaction,
                IntPtr.Zero);
            if (status != 0)
            {
                transactedHandle?.Dispose();
                return IsTransactionUnavailable(status)
                    ? RestoreRegistryIfFreeDirect(target, restored)
                    : PersistenceMutationOutcome.Failed;
            }
            using var key = RegistryKey.FromHandle(transactedHandle, RegistryView.Registry64);
            if (key.GetValue(target.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not null)
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            SetRegistryValue(key, target.ValueName!, restored);
            if (CommitTransaction(transaction))
            {
                return PersistenceMutationOutcome.Succeeded;
            }
            // A concurrent non-transacted writer aborts TxR. If it populated the origin, describe
            // the safety refusal accurately instead of flattening it to an I/O failure.
            using var live = OpenSubKey(target, writable: false);
            return live?.GetValue(target.ValueName) is not null
                ? PersistenceMutationOutcome.TargetChanged
                : PersistenceMutationOutcome.Failed;
        }
        catch (Exception ex) when (IsRegistryFailure(ex)
                                     || ex is JsonException or FormatException or OverflowException)
        {
            return PersistenceMutationOutcome.Failed;
        }
    }

    /// <summary>
    /// Compare-and-delete without a registry transaction: one key handle for the comparison and the
    /// deletion, then a re-read. See the class remarks for the window this leaves.
    /// </summary>
    private static PersistenceMutationOutcome RemoveRegistryIfUnchangedDirect(
        PersistenceActionTarget target, PersistenceSnapshot expected)
    {
        try
        {
            using var key = OpenSubKey(target, writable: true);
            if (key is null)
            {
                return PersistenceMutationOutcome.TargetNotFound;
            }
            var current = CaptureRegistryValue(key, target.ValueName!);
            if (current is null)
            {
                return PersistenceMutationOutcome.TargetNotFound;
            }
            if (!current.Payload.AsSpan().SequenceEqual(expected.Payload)
                || !string.Equals(current.RevalidationToken, expected.RevalidationToken, StringComparison.Ordinal))
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            try
            {
                key.DeleteValue(target.ValueName!, throwOnMissingValue: true);
            }
            catch (ArgumentException)
            {
                // Removed by somebody else in the window: it is gone, but not by this action.
                return PersistenceMutationOutcome.TargetNotFound;
            }
            // A program that re-creates its entry the moment it disappears has not been blocked, and
            // saying Succeeded would tell the operator it is gone while it is live again.
            return CaptureRegistryValue(key, target.ValueName!) is null
                ? PersistenceMutationOutcome.Succeeded
                : PersistenceMutationOutcome.Reasserted;
        }
        catch (Exception ex) when (IsRegistryFailure(ex))
        {
            return PersistenceMutationOutcome.Failed;
        }
    }

    /// <summary>
    /// Restore-if-absent without a registry transaction: one key handle for the check and the write,
    /// then a re-read of exactly what was written.
    /// </summary>
    private static PersistenceMutationOutcome RestoreRegistryIfFreeDirect(
        PersistenceActionTarget target, RegistryPayload restored)
    {
        try
        {
            using var key = OpenSubKey(target, writable: true, create: true);
            if (key is null)
            {
                return PersistenceMutationOutcome.Failed;
            }
            if (key.GetValue(target.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not null)
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            SetRegistryValue(key, target.ValueName!, restored);
            var written = CaptureRegistryValue(key, target.ValueName!);
            return written is not null
                   && written.Payload.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(restored))
                ? PersistenceMutationOutcome.Succeeded
                : PersistenceMutationOutcome.TargetChanged;
        }
        catch (Exception ex) when (IsRegistryFailure(ex) || ex is FormatException or OverflowException)
        {
            return PersistenceMutationOutcome.Failed;
        }
    }

    private static void SetRegistryValue(RegistryKey key, string valueName, RegistryPayload restored)
    {
        var kind = (RegistryValueKind)restored.Kind;
        object data = kind switch
        {
            RegistryValueKind.Binary => restored.BinaryData ?? [],
            RegistryValueKind.MultiString => restored.MultiData ?? [],
            RegistryValueKind.DWord => int.Parse(
                restored.StringData ?? "0", System.Globalization.CultureInfo.InvariantCulture),
            RegistryValueKind.QWord => long.Parse(
                restored.StringData ?? "0", System.Globalization.CultureInfo.InvariantCulture),
            _ => restored.StringData ?? string.Empty,
        };
        key.SetValue(valueName, data, kind);
    }

    private static PersistenceSnapshot? CaptureFile(PersistenceActionTarget target)
    {
        try
        {
            var path = target.FilePath;
            using var lease = AutomaticFileAccess.TryAcquire(path);
            if (lease is null || lease.IsDirectory || lease.Length > 64 * 1024 * 1024)
            {
                return null;
            }
            var payload = new byte[checked((int)lease.Length)];
            using var stream = lease.OpenRead();
            stream.ReadExactly(payload);
            return lease.IsCurrent()
                ? new PersistenceSnapshot(payload, lease.FullPath)
                : null;
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return null;
        }
    }

    private static PersistenceMutationOutcome RemoveFileIfUnchanged(
        PersistenceActionTarget target, PersistenceSnapshot expected)
    {
        try
        {
            var path = target.FilePath;
            if (path is null)
            {
                return PersistenceMutationOutcome.Failed;
            }
            using var lease = AutomaticFileAccess.TryAcquireForDelete(path);
            if (lease is null)
            {
                return AutomaticFileAccess.IsLocal(path)
                    ? PersistenceMutationOutcome.TargetNotFound
                    : PersistenceMutationOutcome.TargetChanged;
            }
            if (lease.Length > 64 * 1024 * 1024)
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            var payload = new byte[checked((int)lease.Length)];
            using (var stream = lease.OpenRead())
            {
                stream.ReadExactly(payload);
            }
            if (!payload.AsSpan().SequenceEqual(expected.Payload))
            {
                return PersistenceMutationOutcome.TargetChanged;
            }
            return lease.TryDelete()
                ? PersistenceMutationOutcome.Succeeded
                : PersistenceMutationOutcome.Failed;
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return PersistenceMutationOutcome.Failed;
        }
    }

    private static PersistenceMutationOutcome RestoreFileIfFree(
        PersistenceActionTarget target, byte[] payload)
    {
        try
        {
            var path = target.FilePath;
            if (path is null)
            {
                return PersistenceMutationOutcome.Failed;
            }
            if (AutomaticFileAccess.TryCreateNewFile(path, payload))
            {
                return PersistenceMutationOutcome.Succeeded;
            }
            return AutomaticFileAccess.FileExists(path) || !AutomaticFileAccess.IsLocal(path)
                ? PersistenceMutationOutcome.TargetChanged
                : PersistenceMutationOutcome.Failed;
        }
        catch (Exception ex) when (IsFileFailure(ex))
        {
            return target.FilePath is { } path
                && (AutomaticFileAccess.FileExists(path) || !AutomaticFileAccess.IsLocal(path))
                ? PersistenceMutationOutcome.TargetChanged
                : PersistenceMutationOutcome.Failed;
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

    [DllImport("KtmW32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeTransactionHandle CreateTransaction(
        IntPtr transactionAttributes,
        IntPtr unitOfWork,
        uint createOptions,
        uint isolationLevel,
        uint isolationFlags,
        uint timeout,
        string description);

    [DllImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CommitTransaction(SafeTransactionHandle transaction);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyTransacted(
        SafeRegistryHandle key,
        string subKey,
        uint options,
        int desiredAccess,
        out SafeRegistryHandle result,
        SafeTransactionHandle transaction,
        IntPtr extendedParameter);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegCreateKeyTransacted(
        SafeRegistryHandle key,
        string subKey,
        int reserved,
        string? keyClass,
        uint options,
        int desiredAccess,
        IntPtr securityAttributes,
        out SafeRegistryHandle result,
        out uint disposition,
        SafeTransactionHandle transaction,
        IntPtr extendedParameter);

    private sealed class SafeTransactionHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }

    private static bool IsRegistryFailure(Exception ex) =>
        ex is UnauthorizedAccessException or System.Security.SecurityException or IOException
            or ArgumentException or InvalidCastException;

    private static bool IsTransactionUnavailable(int error) => error is
        ErrorRmNotActive or ErrorRmMetadataCorrupt or ErrorDirectoryNotRm
        or ErrorTransactionsUnsupportedRemote;

    private static bool IsFileFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException;
}
