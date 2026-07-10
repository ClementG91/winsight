using WinSight.AvMonitor;
using WinSight.Core;
using WinSight.Persistence;

// winsight — the unified suite entry point. One binary runs every WinSight tool, so
// a user gets the whole picture from a single command (the "suite" value that the
// scattered Windows equivalents lack). Read-only.
//
// Usage:
//   winsight                 run all checks
//   winsight persistence     autostart scan only
//   winsight av              camera/mic monitor only
//   winsight --flagged       (with any of the above) show only noteworthy items

var flaggedOnly = args.Contains("--flagged");
var command = args.FirstOrDefault(a => !a.StartsWith('-'))?.ToLowerInvariant() ?? "all";

var flagged = 0;
switch (command)
{
    case "persistence":
        flagged += RunPersistence(flaggedOnly);
        break;
    case "av":
    case "avmonitor":
        flagged += RunAv(flaggedOnly);
        break;
    case "all":
        flagged += RunPersistence(flaggedOnly);
        Console.WriteLine();
        flagged += RunAv(flaggedOnly);
        break;
    default:
        Console.Error.WriteLine($"unknown command '{command}' (persistence | av | all)");
        return 2;
}

// Non-zero exit when anything is flagged — CI/tray/automation friendly.
return flagged > 0 ? 1 : 0;

static int RunPersistence(bool flaggedOnly)
{
    var entries = new PersistenceScanner().Scan();
    var flagged = entries.Count(e => e.IsSuspicious);
    Console.WriteLine($"== persistence == {entries.Count} autostart item(s), {flagged} flagged");
    foreach (var e in entries.Where(e => !flaggedOnly || e.IsSuspicious)
                 .OrderByDescending(e => e.IsSuspicious).ThenBy(e => e.Vector))
    {
        var sig = e.Signature.State switch
        {
            SignatureState.SignedTrusted => "signed",
            SignatureState.SignedUntrusted => "UNTRUSTED",
            SignatureState.Unsigned => "UNSIGNED",
            _ => "no image",
        };
        Console.WriteLine($"  {(e.IsSuspicious ? "[!]" : "[ ]")} {e.Vector}/{e.Name} — {e.ImagePath ?? e.Command} ({sig})");
    }
    return flagged;
}

static int RunAv(bool flaggedOnly)
{
    var usages = new CapabilityAccessReader().Read();
    var live = usages.Count(u => u.Active);
    Console.WriteLine($"== camera/mic == {usages.Count} recorded use(s), {live} live now");
    foreach (var u in usages.Where(u => !flaggedOnly || u.Active).OrderByDescending(u => u.Active))
    {
        var device = u.Kind == DeviceKind.Webcam ? "webcam" : "mic";
        Console.WriteLine($"  {(u.Active ? "[LIVE]" : "[ ]   ")} {device}/{u.App}");
    }
    return live;
}
