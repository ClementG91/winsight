using WinSight.AvMonitor;

// winsight-avmonitor — OverSight-class camera/microphone monitor. Reports which apps
// have used the webcam/mic and flags anything using them RIGHT NOW. Read-only.
//
// Usage: winsight-avmonitor [--active-only]

var activeOnly = args.Contains("--active-only");

var usages = new CapabilityAccessReader().Read();
var shown = (activeOnly ? usages.Where(u => u.Active) : usages)
    .OrderByDescending(u => u.Active)
    .ThenByDescending(u => u.LastStart ?? DateTime.MinValue)
    .ToList();

var live = usages.Count(u => u.Active);
Console.WriteLine($"WinSight — camera/mic monitor: {usages.Count} recorded use(s), {live} live now.");
Console.WriteLine(new string('-', 72));

foreach (var u in shown)
{
    var mark = u.Active ? "[LIVE]" : "[ ]   ";
    var device = u.Kind == DeviceKind.Webcam ? "webcam" : "mic";
    var when = u.Active
        ? $"in use since {Fmt(u.LastStart)}"
        : $"last used {Fmt(u.LastStop ?? u.LastStart)}";
    Console.WriteLine($"{mark} {device,-6} {u.App}");
    Console.WriteLine($"        {(u.Packaged ? "packaged app" : "desktop app")} — {when}");
}

// Non-zero exit when a device is live, for automation/tray integration.
return live > 0 ? 1 : 0;

static string Fmt(DateTime? t) => t is null ? "unknown" : t.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
