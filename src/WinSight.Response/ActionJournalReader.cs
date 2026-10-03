using System.Text.Json;

namespace WinSight.Response;

/// <summary>Coverage of the inspected tail, not a claim about the complete historical file.</summary>
public sealed record ActionJournalSnapshot(
    IReadOnlyList<ActionJournalEntry> Entries,
    bool Unreadable = false,
    int MalformedEntries = 0,
    bool LimitReached = false,
    long BytesRead = 0,
    int LinesScanned = 0);

/// <summary>Reads JSONL backwards with fixed buffers, including corrupt bytes in every budget.</summary>
internal static class ActionJournalReader
{
    internal const int MaxBytes = 16 * 1024 * 1024;
    internal const int MaxLineBytes = 16 * 1024;
    internal const int MaxLines = 10_000;

    internal static ActionJournalSnapshot Read(Stream stream, int max)
    {
        max = max <= 0 ? MaxLines : Math.Min(max, MaxLines);
        var entries = new List<ActionJournalEntry>();
        var seen = new HashSet<Guid>();
        var block = new byte[8192];
        var line = new byte[MaxLineBytes];
        var length = 0;
        var oversized = false;
        var malformed = 0;
        var lines = 0;
        var bytes = 0L;
        var remaining = stream.Length;
        var end = remaining;
        while (remaining > 0 && bytes < MaxBytes && lines < MaxLines && entries.Count < max)
        {
            var count = (int)Math.Min(block.Length, Math.Min(remaining, MaxBytes - bytes));
            var start = remaining - count;
            stream.Position = start;
            stream.ReadExactly(block.AsSpan(0, count));
            bytes += count;
            for (var i = count - 1; i >= 0; i--)
            {
                remaining = start + i;
                if (block[i] == (byte)'\n')
                {
                    if (remaining != end - 1)
                    {
                        FinishLine();
                    }
                    if (lines >= MaxLines || entries.Count >= max)
                    {
                        break;
                    }
                }
                else if (length < line.Length)
                {
                    line[length++] = block[i];
                }
                else
                {
                    oversized = true;
                }
            }
        }
        if (remaining == 0 && (length > 0 || oversized) && lines < MaxLines && entries.Count < max)
        {
            FinishLine();
        }
        return new ActionJournalSnapshot(entries, MalformedEntries: malformed,
            LimitReached: remaining > 0 && (lines >= MaxLines || bytes >= MaxBytes),
            BytesRead: bytes, LinesScanned: lines);

        void FinishLine()
        {
            lines++;
            if (oversized)
            {
                malformed++;
            }
            else if (length > 0)
            {
                Array.Reverse(line, 0, length);
                var content = line.AsSpan(0, length);
                if (content.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
                {
                    content = content[3..];
                }
                if (!content.Trim(new byte[] { (byte)'\r', (byte)' ', (byte)'\t' }).IsEmpty)
                {
                    try
                    {
                        var entry = JsonSerializer.Deserialize<ActionJournalEntry>(content);
                        if (entry is null || entry.ActionId == Guid.Empty || entry.Target is null
                            || !Enum.IsDefined(entry.Kind) || !Enum.IsDefined(entry.Outcome)
                            || !Enum.IsDefined(entry.Phase))
                        {
                            malformed++;
                        }
                        else if (seen.Add(entry.ActionId))
                        {
                            entries.Add(entry);
                        }
                    }
                    catch (JsonException)
                    {
                        malformed++;
                    }
                }
            }
            length = 0;
            oversized = false;
        }
    }
}
