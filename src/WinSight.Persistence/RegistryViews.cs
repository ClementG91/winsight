using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Renders a registry path the way it actually appears on the machine, so an entry found through
/// the 32-bit view names the key an operator can go and look at.
/// </summary>
/// <remarks>
/// <b>Why the rendered path matters here specifically.</b> Reporting a WOW6432Node finding under its
/// unredirected path sends the operator to a key that does not contain it, and - worse for this
/// codebase - the write-attribution index matches an observed kernel write against the reported
/// location as a prefix. The kernel reports <c>\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\...</c>; an
/// enumerator claiming <c>HKLM\SOFTWARE\...</c> never matches it, so every 32-bit persistence write
/// was unattributable by construction.
///
/// <b>Which surfaces read both views is a separate decision.</b> Redirection is not the same
/// question as exploitability: the view that matters is the one the consumer of the key reads.
/// Winlogon, the Session Manager, LSA, the spooler and the time service are all 64-bit processes, so
/// their WOW6432Node twins hold values nothing ever executes and reading them would manufacture
/// findings. IFEO, SilentProcessExit, AppInit_DLLs and COM registrations are read by the loader on
/// behalf of the process being started, so for those the 32-bit half governs every 32-bit process
/// on the machine and reading only the 64-bit half is a real blind spot.
/// </remarks>
internal static class RegistryViews
{
    private const string Wow6432Node = "WOW6432Node";

    /// <summary>
    /// <paramref name="path"/> as it is spelled in <paramref name="view"/>, inserting
    /// <c>WOW6432Node</c> where the redirection puts it.
    /// </summary>
    internal static string Describe(string path, RegistryView view)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (view != RegistryView.Registry32)
        {
            return path;
        }

        // Redirection happens immediately below SOFTWARE (and below SOFTWARE\Classes, which is
        // reached through the same first component here). Nothing under SYSTEM is redirected.
        const string Software = "SOFTWARE";
        return path.StartsWith(Software + "\\", StringComparison.OrdinalIgnoreCase)
            ? $"{Software}\\{Wow6432Node}\\{path[(Software.Length + 1)..]}"
            : path.Equals(Software, StringComparison.OrdinalIgnoreCase)
                ? $"{Software}\\{Wow6432Node}"
                : path;
    }
}
