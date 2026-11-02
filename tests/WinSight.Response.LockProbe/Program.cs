using System.Diagnostics;
using System.Text.Json;

using WinSight.Core;
using WinSight.Response;

namespace WinSight.Response.LockProbe;

/// <summary>Bounded subprocess oracle for the response tests; never shipped with the product.</summary>
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "hold")
        {
            using var gate = new FileStream(args[1], FileMode.OpenOrCreate, FileAccess.Read, FileShare.None);
            Console.WriteLine("ready");
            _ = Console.ReadLine();
            return 0;
        }
        if (args.Length == 2 && args[0] == "quota")
        {
            var quota = new VirusTotalQuotaLimiter(args[1],
                () => new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero), new(64, 64, 64));
            Console.WriteLine("ready");
            _ = Console.ReadLine();
            for (var i = 0; i < 20; i++)
            {
                if (!quota.TryAcquire(out _))
                {
                    Console.Error.WriteLine("A serialized quota admission was refused.");
                    return 5;
                }
            }
            Console.WriteLine("20");
            return 0;
        }
        if (args.Length != 4 || args[0] != "write")
        {
            return 3;
        }
        var journal = new ActionJournal(args[1]);
        var store = new RuleStore(args[2]);
        var ids = new List<Guid>();
        Console.WriteLine("ready");
        _ = Console.ReadLine();
        var started = Stopwatch.GetTimestamp();
        bool TraceStep(int ordinal, string phase, Func<bool> operation)
        {
            Trace(ordinal, phase, "begin");
            var succeeded = operation();
            Trace(ordinal, phase, succeeded ? "succeeded" : "refused");
            return succeeded;
        }
        void Trace(int ordinal, string phase, string status)
        {
            try
            {
                Console.Error.WriteLine(FormattableString.Invariant(
                    $"WSPROBE:{ordinal}:{phase}:{status}:{Stopwatch.GetTimestamp() - started}:{Stopwatch.Frequency}"));
            }
            catch (Exception) { /* Diagnostics must not change the write predicate or exit code. */ }
        }
        for (var i = 0; i < 24; i++)
        {
            var id = Guid.NewGuid();
            var entry = new ActionJournalEntry(id, ResponseActionKind.AddRule, ResponseOutcome.Succeeded,
                args[3], DateTimeOffset.UtcNow, true, Phase: ActionJournalPhase.Prepared);
            if (!TraceStep(i, "prepared", () => journal.TryAppend(entry))
                || !TraceStep(i, "completed", () => journal.TryAppend(entry with { Phase = ActionJournalPhase.Completed }))
                || !TraceStep(i, "undo", () => journal.TryMarkUndone(id, id).Durable)
                || !TraceStep(i, "rule", () => store.Add(new ResponseRule(id, RuleScopeKind.Persistence, RuleDecision.Allow,
                    RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: $"{args[3]}:{i}")) is not null))
            {
                Console.Error.WriteLine("A serialized update was refused.");
                return 4;
            }
            ids.Add(id);
        }
        Console.WriteLine(JsonSerializer.Serialize(ids));
        return 0;
    }
}
