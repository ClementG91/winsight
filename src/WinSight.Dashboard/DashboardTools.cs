namespace WinSight.Dashboard;

public enum DashboardWindowsAction
{
    None,
    StartupApps,
    Privacy,
    Network,
    NetworkSettings,
    Firewall,
    Processes,
    InstalledApps,
    Certificates,
}

public sealed record DashboardTool(
    string Label,
    string Command,
    string ReportName,
    string ShortDescription,
    string Description,
    string Guidance,
    DashboardWindowsAction WindowsAction = DashboardWindowsAction.None);

/// <summary>Localized catalog shared by navigation, progress and report routing.</summary>
public static class DashboardTools
{
    private static IReadOnlyList<DashboardTool> _all = Build();

    public static IReadOnlyList<DashboardTool> All => _all;

    public static void Reload() => _all = Build();

    private static IReadOnlyList<DashboardTool> Build() =>
    [
        Tool("Overview", "all", "all"),
        Tool("Persistence", "persistence", "persistence", DashboardWindowsAction.StartupApps),
        Tool("Av", "av", "camera-mic", DashboardWindowsAction.Privacy),
        Tool("Network", "net", "connections", DashboardWindowsAction.Network),
        Tool("Dns", "dns", "dns", DashboardWindowsAction.NetworkSettings),
        Tool("Firewall", "firewall", "firewall", DashboardWindowsAction.Firewall),
        Tool("OutboundFirewall", "outbound-firewall", "outbound-firewall", DashboardWindowsAction.Firewall),
        Tool("Processes", "processes", "processes", DashboardWindowsAction.Processes),
        Tool("Modules", "modules", "modules", DashboardWindowsAction.Processes),
        Tool("Extensions", "extensions", "extensions", DashboardWindowsAction.InstalledApps),
        Tool("Certificates", "certs", "certificates", DashboardWindowsAction.Certificates),
        Tool("Hosts", "hosts", "hosts"),
        Tool("Input", "input", "input"),
        Tool("Integrity", "integrity", "integrity"),
        Tool("Drivers", "drivers", "drivers"),
        Tool("Alerts", "alerts", "alerts"),
    ];

    private static DashboardTool Tool(
        string resourceName,
        string command,
        string reportName,
        DashboardWindowsAction windowsAction = DashboardWindowsAction.None)
    {
        var text = LocalizationManager.Instance;
        var prefix = $"Tool{resourceName}";
        return new DashboardTool(
            text[$"{prefix}Label"],
            command,
            reportName,
            text[$"{prefix}Short"],
            text[$"{prefix}Description"],
            text[$"{prefix}Guidance"],
            windowsAction);
    }

    public static DashboardTool? ForCommand(string command) =>
        All.FirstOrDefault(tool => tool.Command.Equals(command, StringComparison.OrdinalIgnoreCase));

    public static DashboardTool? ForReport(string reportName) =>
        All.FirstOrDefault(tool => tool.ReportName.Equals(reportName, StringComparison.OrdinalIgnoreCase));
}
