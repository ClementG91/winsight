using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Whether a journal entry records durable intent or the final result.</summary>
public enum ActionJournalPhase
{
    Completed,
    Prepared,
}

/// <summary>One recorded response attempt: what was tried, on what, and how it ended.</summary>
/// <param name="ActionId">Correlates the request, this record and any undo.</param>
/// <param name="Kind">The action attempted.</param>
/// <param name="Outcome">Whether it succeeded and, if not, the stable reason.</param>
/// <param name="Target">A short, non-sensitive description (name, not payload).</param>
/// <param name="AtUtc">When it completed.</param>
/// <param name="Reversible">Whether an undo exists.</param>
/// <param name="UndoneByActionId">The action id that reversed this one, when it was undone.</param>
/// <param name="Phase">Prepared before mutation, completed after the result is known.</param>
public sealed record ActionJournalEntry(
    Guid ActionId,
    ResponseActionKind Kind,
    ResponseOutcome Outcome,
    string Target,
    DateTimeOffset AtUtc,
    bool Reversible,
    Guid? UndoneByActionId = null,
    ActionJournalPhase Phase = ActionJournalPhase.Completed);

/// <summary>The journal operations required by response coordinators.</summary>
public interface IActionJournal
{
    bool TryAppend(ActionJournalEntry entry);
    ActionJournalWriteResult TryAppendWithStatus(ActionJournalEntry entry) =>
        new(TryAppend(entry) ? ActionJournalWriteStatus.Appended : ActionJournalWriteStatus.Unavailable);
    void MarkUndone(Guid actionId, Guid undoActionId);
    IReadOnlyList<ActionJournalEntry> Read(int max = 200);
}

/// <summary>
/// An append-only record of every response attempt, kept so an operator (and, read-only, an MCP
/// client) can see what WinSight did and undo it. Bounded and rotated atomically, one entry per line.
/// </summary>
/// <remarks>
/// It is written from the same process that performs the action, never from MCP: the MCP server can
/// read this file but has no way to write it or to invoke an action. A failed write is a defect the
/// caller can surface, not a silent gap — the caller decides whether an action whose journal write
/// failed should be treated as done.
/// </remarks>
public sealed class ActionJournal : IActionJournal
{
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);

    private readonly string _path;
    private readonly TimeSpan _lockWait;

    public ActionJournal(string? path = null) : this(path, LockWait) { }

    internal ActionJournal(string? path, TimeSpan lockWait)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lockWait, TimeSpan.Zero);
        _path = path ?? DefaultPath();
        _lockWait = lockWait;
    }

    /// <summary>The first of four bounded recovery-evidence slots.</summary>
    public string RecoveryEvidencePath => _path + ".corrupt.jsonl";

    /// <summary>Where the action journal lives, beside WinSight's other per-user state.</summary>
    public static string DefaultPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight", "action-journal.jsonl");

    /// <summary>Appends an entry. Returns false when it could not be written durably.</summary>
    public bool TryAppend(ActionJournalEntry entry) => TryAppendWithStatus(entry).Durable;

    /// <summary>Preflights retention before append; failed rotation never masquerades as a durable write.</summary>
    public ActionJournalWriteResult TryAppendWithStatus(ActionJournalEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.Target is null || entry.ActionId == Guid.Empty || !Enum.IsDefined(entry.Kind)
            || !Enum.IsDefined(entry.Outcome) || !Enum.IsDefined(entry.Phase))
        {
            return new(ActionJournalWriteStatus.InvalidRecord);
        }
        var bytes = ActionJournalStorage.Encode(entry);
        if (bytes is null)
        {
            return new(ActionJournalWriteStatus.InvalidRecord);
        }
        try
        {
            using var gate = JournalLock.Acquire(_path, _lockWait);
            if (!ActionJournalEvidence.Maintain(_path))
            {
                return new(ActionJournalWriteStatus.EvidencePreservationFailed);
            }
            var snapshot = ReadSnapshotLocked(ActionJournalReader.MaxLines);
            if (snapshot.Unreadable)
            {
                return new(ActionJournalWriteStatus.Unavailable);
            }
            var damaged = snapshot.MalformedEntries > 0 || snapshot.LimitReached
                || snapshot.SourceBytes > ActionJournalReader.MaxBytes;
            var rotate = snapshot.LinesScanned >= ActionJournalReader.MaxLines
                || snapshot.SourceBytes + bytes.Length + 1 > ActionJournalReader.MaxBytes;
            if (rotate)
            {
                if (damaged && !PreserveEvidenceLocked())
                {
                    return new(ActionJournalWriteStatus.EvidencePreservationFailed);
                }
                var entries = new[] { entry }.Concat(snapshot.Entries).ToArray();
                return ReplaceLocked(entries, ActionJournalReader.MaxBytes / 2,
                    ActionJournalReader.MaxLines / 2, ActionJournalWriteStatus.Rotated);
            }
            // A valid last record without a final newline must not merge with this record.
            var payload = snapshot.EndsWithNewline ? bytes : new byte[] { (byte)'\n' }.Concat(bytes).ToArray();
            return new(AutomaticFileAccess.TryAppendFile(_path, payload)
                ? ActionJournalWriteStatus.Appended : ActionJournalWriteStatus.Unavailable);
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            return new(ActionJournalWriteStatus.Unavailable);
        }
    }

    /// <summary>
    /// Marks the entry with <paramref name="actionId"/> as undone by <paramref name="undoActionId"/>.
    /// Best-effort: a failure only means the history shows the original and the undo as two entries.
    /// </summary>
    public void MarkUndone(Guid actionId, Guid undoActionId) => _ = TryMarkUndone(actionId, undoActionId);

    /// <summary>Updates history atomically, or reports why the annotation could not be persisted.</summary>
    public ActionJournalWriteResult TryMarkUndone(Guid actionId, Guid undoActionId)
    {
        if (actionId == Guid.Empty || undoActionId == Guid.Empty)
        {
            return new(ActionJournalWriteStatus.InvalidRecord);
        }
        try
        {
            using var gate = JournalLock.Acquire(_path, _lockWait);
            if (!ActionJournalEvidence.Maintain(_path))
            {
                return new(ActionJournalWriteStatus.EvidencePreservationFailed);
            }
            var snapshot = ReadSnapshotLocked(ActionJournalReader.MaxLines);
            if (snapshot.Unreadable)
            {
                return new(ActionJournalWriteStatus.Unavailable);
            }
            var entries = snapshot.Entries.ToList();
            var index = entries.FindIndex(e =>
                e.ActionId == actionId && e.Phase == ActionJournalPhase.Completed);
            if (index < 0)
            {
                return new(ActionJournalWriteStatus.TargetNotFound);
            }
            if ((snapshot.MalformedEntries > 0 || snapshot.LimitReached
                    || snapshot.SourceBytes > ActionJournalReader.MaxBytes) && !PreserveEvidenceLocked())
            {
                return new(ActionJournalWriteStatus.EvidencePreservationFailed);
            }
            entries[index] = entries[index] with { UndoneByActionId = undoActionId };
            return ReplaceLocked(entries, ActionJournalReader.MaxBytes,
                ActionJournalReader.MaxLines, ActionJournalWriteStatus.Updated);
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            return new(ActionJournalWriteStatus.Unavailable);
        }
    }

    /// <summary>The most recent entries, newest first. Empty when there is no readable journal.</summary>
    public IReadOnlyList<ActionJournalEntry> Read(int max = 200) => ReadWithCoverage(max).Entries;

    /// <summary>Most recent actions plus availability/corruption/budget information for the read tail.</summary>
    public ActionJournalSnapshot ReadWithCoverage(int max = 200)
    {
        try
        {
            using var gate = JournalLock.Acquire(_path, _lockWait);
            return ActionJournalEvidence.Coverage(_path, ReadSnapshotLocked(max));
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            return new ActionJournalSnapshot([], Unreadable: true);
        }
    }

    private ActionJournalSnapshot ReadSnapshotLocked(int max)
    {
        using var lease = AutomaticFileAccess.TryAcquire(_path, out var missing);
        if (lease is null)
        {
            return new ActionJournalSnapshot([], Unreadable: !missing);
        }
        if (lease.IsDirectory)
        {
            return new ActionJournalSnapshot([], Unreadable: true);
        }
        using var stream = lease.OpenRead(FileOptions.RandomAccess);
        var snapshot = ActionJournalReader.Read(stream, max);
        return lease.IsCurrent() ? snapshot : new ActionJournalSnapshot([], Unreadable: true);
    }

    private bool PreserveEvidenceLocked() => ActionJournalStorage.Preserve(_path, RecoveryEvidencePath);

    private ActionJournalWriteResult ReplaceLocked(IEnumerable<ActionJournalEntry> newestFirst,
        int byteBudget, int entryBudget, ActionJournalWriteStatus success) =>
        ActionJournalStorage.Replace(_path, newestFirst, byteBudget, entryBudget, success);

    private static bool IsUnavailable(Exception ex) => ex is IOException or UnauthorizedAccessException
        or System.Security.SecurityException or ArgumentException or NotSupportedException
        or WaitHandleCannotBeOpenedException;

    internal static string LockNameFor(string path)
    {
        var key = Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())))[..32];
        return $@"Global\WinSight.ActionJournal.{key}";
    }

    private sealed class JournalLock : IDisposable
    {
        private readonly Mutex _mutex;
        private readonly bool _held;

        private JournalLock(Mutex mutex, bool held)
        {
            _mutex = mutex;
            _held = held;
        }

        public static JournalLock Acquire(string path, TimeSpan wait)
        {
            var mutex = new Mutex(initiallyOwned: false, LockNameFor(path));
            bool held;
            try
            {
                held = mutex.WaitOne(wait);
            }
            catch (AbandonedMutexException)
            {
                held = true;
            }
            if (!held)
            {
                mutex.Dispose();
                throw new IOException("Timed out waiting for the action-journal lock.");
            }
            return new JournalLock(mutex, held);
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
