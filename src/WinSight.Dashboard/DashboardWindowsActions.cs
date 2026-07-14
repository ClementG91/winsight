using System.Diagnostics;
using System.IO;

namespace WinSight.Dashboard;

/// <summary>Allowlisted launch descriptions for trusted Windows management surfaces.</summary>
public static class DashboardWindowsActions
{
    public static string LabelResource(DashboardWindowsAction action) => action switch
    {
        DashboardWindowsAction.StartupApps => "OpenStartupSettings",
        DashboardWindowsAction.Privacy => "OpenPrivacySettings",
        DashboardWindowsAction.Network => "OpenResourceMonitor",
        DashboardWindowsAction.NetworkSettings => "OpenNetworkSettings",
        DashboardWindowsAction.Firewall => "OpenFirewall",
        DashboardWindowsAction.Processes => "OpenTaskManager",
        DashboardWindowsAction.InstalledApps => "OpenInstalledApps",
        DashboardWindowsAction.Certificates => "OpenCertificates",
        _ => "OpenWindowsTool",
    };

    public static ProcessStartInfo StartInfo(DashboardWindowsAction action)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (action is DashboardWindowsAction.Processes or DashboardWindowsAction.Network)
        {
            var executable = action == DashboardWindowsAction.Processes ? "Taskmgr.exe" : "resmon.exe";
            return new ProcessStartInfo(Path.Combine(system, executable)) { UseShellExecute = false };
        }

        if (action is DashboardWindowsAction.Firewall or DashboardWindowsAction.Certificates)
        {
            var startInfo = new ProcessStartInfo(Path.Combine(system, "mmc.exe")) { UseShellExecute = false };
            startInfo.ArgumentList.Add(Path.Combine(
                system,
                action == DashboardWindowsAction.Firewall ? "wf.msc" : "certlm.msc"));
            return startInfo;
        }

        var settingsUri = action switch
        {
            DashboardWindowsAction.StartupApps => "ms-settings:startupapps",
            DashboardWindowsAction.Privacy => "ms-settings:privacy-webcam",
            DashboardWindowsAction.NetworkSettings => "ms-settings:network-status",
            DashboardWindowsAction.InstalledApps => "ms-settings:appsfeatures",
            _ => throw new InvalidOperationException("No Windows action is configured."),
        };
        return new ProcessStartInfo(settingsUri) { UseShellExecute = true };
    }
}
