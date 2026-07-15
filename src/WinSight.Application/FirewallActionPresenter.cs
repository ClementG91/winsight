using WinSight.Reporting;

namespace WinSight.Application;

/// <summary>
/// Bridges any finding that owns an on-disk program to the outbound firewall: given a tool
/// and one of its report items, it returns the executable whose outbound traffic makes
/// sense to block, or null when the finding is not a blockable program (a DLL, a
/// non-program tool, a missing or relative path). It is the single place that knows which
/// field each tool stores the image under, kept UI-agnostic so it is unit-tested without a
/// UI and the WPF layer stays a thin shell.
/// </summary>
public static class FirewallActionPresenter
{
    public static string? BlockableExecutable(string tool, ReportItem item)
    {
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(item);

        // The field each tool records the owning executable under; other tools (certs,
        // hosts, modules/DLLs, ...) do not own outbound traffic and are not offered.
        var key = tool switch
        {
            "connections" => "image",
            "processes" => "path",
            "persistence" => "image",
            _ => null,
        };
        if (key is null)
        {
            return null;
        }

        var path = item.Fields.TryGetValue(key, out var value) ? value : null;
        return IsBlockableExecutable(path) ? path : null;
    }

    private static bool IsBlockableExecutable(string? path) =>
        !string.IsNullOrWhiteSpace(path)
        && Path.IsPathFullyQualified(path)
        && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
}
