using WinSight.Core;
using WinSight.Persistence;

// winsight-persistence — KnockKnock-class console scanner. Prints every autostart
// item and flags the ones worth a look (unresolved image, unsigned, or untrusted).
// Read-only: it reveals persistence, it never changes anything.
//
// Usage: winsight-persistence [--suspicious-only]

var suspiciousOnly = args.Contains("--suspicious-only");

var entries = new PersistenceScanner().Scan();
var shown = suspiciousOnly ? entries.Where(e => e.IsSuspicious).ToList() : entries.ToList();

Console.WriteLine($"WinSight — persistence scan: {entries.Count} autostart item(s), " +
                  $"{entries.Count(e => e.IsSuspicious)} flagged.");
Console.WriteLine(new string('-', 72));

foreach (var e in shown.OrderByDescending(e => e.IsSuspicious).ThenBy(e => e.Vector))
{
    var mark = e.IsSuspicious ? "[!]" : "[ ]";
    Console.WriteLine($"{mark} {e.Vector}: {e.Name}");
    Console.WriteLine($"      at   {e.Location}");
    Console.WriteLine($"      cmd  {e.Command}");
    Console.WriteLine($"      img  {e.ImagePath ?? "<unresolved>"}");
    Console.WriteLine($"      sig  {Describe(e.Signature)}");
}

// Non-zero exit when anything is flagged, so the scan is CI/automation friendly.
return shown.Any(e => e.IsSuspicious) ? 1 : 0;

static string Describe(SignatureVerdict v) => v.State switch
{
    SignatureState.SignedTrusted => $"signed, trusted — {v.Signer}",
    SignatureState.SignedUntrusted => $"signed, UNTRUSTED chain — {v.Signer}",
    SignatureState.Unsigned => "UNSIGNED",
    _ => "no image / missing",
};
