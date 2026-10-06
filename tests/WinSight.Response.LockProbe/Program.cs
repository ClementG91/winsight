using System.Text.Json;

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
        if (args.Length != 4 || args[0] != "write")
        {
            return 3;
        }
        var journal = new ActionJournal(args[1]);
        var store = new RuleStore(args[2]);
        var ids = new List<Guid>();
        Console.WriteLine("ready");
        _ = Console.ReadLine();
        for (var i = 0; i < 24; i++)
        {
            var id = Guid.NewGuid();
            var entry = new ActionJournalEntry(id, ResponseActionKind.AddRule, ResponseOutcome.Succeeded,
                args[3], DateTimeOffset.UtcNow, true, Phase: ActionJournalPhase.Prepared);
            if (!journal.TryAppend(entry) || !journal.TryAppend(entry with { Phase = ActionJournalPhase.Completed })
                || !journal.TryMarkUndone(id, id).Durable
                || store.Add(new ResponseRule(id, RuleScopeKind.Persistence, RuleDecision.Allow,
                    RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: $"{args[3]}:{i}")) is null)
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
