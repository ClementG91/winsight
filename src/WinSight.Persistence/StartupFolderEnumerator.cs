using System.Runtime.InteropServices;

namespace WinSight.Persistence;

/// <summary>
/// The Startup folders (per-user and all-users) — anything dropped here runs at
/// logon, a classic malware persistence spot. Shortcuts (.lnk) are resolved to their
/// target executable via WScript.Shell (COM), so the signature check sees the real
/// binary; non-shortcut files are reported as-is. Resolution is best-effort — a .lnk
/// that cannot be resolved falls back to the shortcut path.
/// </summary>
public sealed class StartupFolderEnumerator : IAutostartEnumerator
{
    public string Surface => "Startup folders";

    public IEnumerable<RawAutostart> Enumerate()
    {
        foreach (var (dir, label) in Folders())
        {
            foreach (var file in SafeFiles(dir))
            {
                yield return new RawAutostart(
                    AutostartVector.StartupFolder,
                    Path.GetFileName(file),
                    $"{label}: {dir}",
                    ResolveCommand(file));
            }
        }
    }

    private static IEnumerable<(string Dir, string Label)> Folders()
    {
        yield return (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User startup");
        yield return (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Common startup");
    }

    private static string ResolveCommand(string file)
    {
        if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            var target = ResolveShortcut(file);
            return string.IsNullOrEmpty(target) ? file : target;
        }
        return file;
    }

    // Resolves a .lnk's target executable via WScript.Shell. COM interop can fail in
    // several ways (missing object, binder, access) — any failure degrades to null.
    private static string? ResolveShortcut(string lnkPath)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null)
        {
            return null;
        }
        object? shell = null;
        try
        {
            shell = Activator.CreateInstance(type);
            dynamic wsh = shell!;
            dynamic shortcut = wsh.CreateShortcut(lnkPath);
            return (string?)shortcut.TargetPath;
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            if (shell is not null)
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }

    private static string[] SafeFiles(string dir)
    {
        try
        {
            return Directory.Exists(dir) ? Directory.GetFiles(dir) : Array.Empty<string>();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<string>();
        }
    }
}
