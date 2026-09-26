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
    private const int MaxEntries = 10_000;
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);

    private readonly string _path;

    public ActionJournal(string? path = null) => _path = path ?? DefaultPath();

    /// <summary>Where the action journal lives, beside WinSight's other per-user state.</summary>
    public static string DefaultPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight", "action-journal.jsonl");

    /// <summary>Appends an entry. Returns false when it could not be written durably.</summary>
    public bool TryAppend(ActionJournalEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        try
        {
            using var gate = JournalLock.Acquire(_path);
            if (!AutomaticFileAccess.IsLocal(_path))
            {
                return false;
            }
            var line = JsonSerializer.Serialize(entry) + "\n";
            if (!AutomaticFileAccess.TryAppendFile(_path, Encoding.UTF8.GetBytes(line)))
            {
                return false;
            }
            TrimLocked();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Marks the entry with <paramref name="actionId"/> as undone by <paramref name="undoActionId"/>.
    /// Best-effort: a failure only means the history shows the original and the undo as two entries.
    /// </summary>
    public void MarkUndone(Guid actionId, Guid undoActionId)
    {
        try
        {
            using var gate = JournalLock.Acquire(_path);
            var entries = ReadLocked();
            var index = entries.FindLastIndex(e =>
                e.ActionId == actionId && e.Phase == ActionJournalPhase.Completed);
            if (index < 0)
            {
                return;
            }
            entries[index] = entries[index] with { UndoneByActionId = undoActionId };
            WriteAllLocked(entries);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException or NotSupportedException)
        {
            // History stays as two independent entries.
        }
    }

    /// <summary>The most recent entries, newest first. Empty when there is no readable journal.</summary>
    public IReadOnlyList<ActionJournalEntry> Read(int max = 200)
    {
        try
        {
            using var gate = JournalLock.Acquire(_path);
            var entries = ReadLocked()
                .Select((entry, index) => (entry, index))
                .GroupBy(item => item.entry.ActionId)
                .Select(group => group.Last())
                .OrderByDescending(item => item.index)
                .Select(item => item.entry)
                .ToList();
            return max > 0 && entries.Count > max ? entries.GetRange(0, max) : entries;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException or NotSupportedException)
        {
            return [];
        }
    }

    private List<ActionJournalEntry> ReadLocked()
    {
        var entries = new List<ActionJournalEntry>();
        using var lease = AutomaticFileAccess.TryAcquire(_path);
        if (lease is null || lease.IsDirectory)
        {
            return entries;
        }
        using var stream = lease.OpenRead();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            try
            {
                if (JsonSerializer.Deserialize<ActionJournalEntry>(line) is { } entry)
                {
                    entries.Add(entry);
                }
            }
            catch (JsonException)
            {
                // Skip a corrupt line rather than discarding the whole journal.
            }
        }
        return lease.IsCurrent() ? entries : [];
    }

    private void TrimLocked()
    {
        var entries = ReadLocked();
        if (entries.Count > MaxEntries)
        {
            WriteAllLocked(entries.GetRange(entries.Count - MaxEntries, MaxEntries));
        }
    }

    private void WriteAllLocked(List<ActionJournalEntry> entries)
    {
        var builder = new StringBuilder();
        foreach (var entry in entries)
        {
            builder.Append(JsonSerializer.Serialize(entry)).Append('\n');
        }
        AtomicFile.TryWrite(_path, Encoding.UTF8.GetBytes(builder.ToString()));
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

        public static JournalLock Acquire(string path)
        {
            var key = Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())))[..32];
            var mutex = new Mutex(initiallyOwned: false, $@"Local\WinSight.ActionJournal.{key}");
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
