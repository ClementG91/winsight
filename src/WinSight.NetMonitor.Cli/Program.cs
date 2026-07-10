using WinSight.Core;
using WinSight.NetMonitor;

// winsight-netmonitor — Netiquette-class connection monitor. Lists active TCP/UDP
// connections with their owning process + signature, flagging external, established
// connections owned by unsigned/unresolved processes. Read-only.
//
// Usage: winsight-netmonitor [--external-only]

var externalOnly = args.Contains("--external-only");

var connections = new ConnectionMonitor().Snapshot();
var shown = (externalOnly ? connections.Where(c => c.External) : connections)
    .OrderByDescending(c => c.Noteworthy)
    .ThenByDescending(c => c.External)
    .ToList();

var noteworthy = connections.Count(c => c.Noteworthy);
Console.WriteLine($"WinSight — connections: {connections.Count} total, {noteworthy} noteworthy.");
Console.WriteLine(new string('-', 72));

foreach (var c in shown)
{
    var mark = c.Noteworthy ? "[!]" : "[ ]";
    Console.WriteLine($"{mark} {c.Protocol} {c.Local} -> {c.Remote} {c.State}");
    Console.WriteLine($"      {c.Process} (pid {c.Pid}) — {Describe(c.Signature)}");
}

return noteworthy > 0 ? 1 : 0;

static string Describe(SignatureVerdict v) => v.State switch
{
    SignatureState.SignedTrusted => "signed",
    SignatureState.SignedUntrusted => "signed, UNTRUSTED",
    SignatureState.Unsigned => "UNSIGNED",
    _ => "no image",
};
