using System.ComponentModel;
using System.Diagnostics;
using WinSight.Core;

namespace WinSight.Modules;

/// <summary>
/// Enumerates the DLLs loaded into every accessible running process and batch-checks
/// each distinct module's Authenticode signature — surfacing unsigned/untrusted DLLs
/// injected or side-loaded into legitimate processes. Read-only; processes that can't
/// be opened (protected, cross-bitness, already exited) are skipped, never guessed.
/// </summary>
public sealed class ModuleLister
{
    private readonly ISignatureVerifier _verifier;

    public ModuleLister(ISignatureVerifier? verifier = null) =>
        _verifier = verifier ?? new NativeSignatureVerifier();

    public IReadOnlyList<LoadedModule> Snapshot()
    {
        var raw = new List<(int Pid, string Proc, string Mod, string? Path)>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var name = p.ProcessName;
                foreach (ProcessModule m in p.Modules)
                {
                    raw.Add((p.Id, name, m.ModuleName, SafePath(m)));
                }
            }
            catch (Exception ex) when (
                ex is Win32Exception or InvalidOperationException or NotSupportedException)
            {
                // Access denied / process exited / cross-bitness — skip, don't fabricate.
            }
            finally
            {
                p.Dispose();
            }
        }

        var verdicts = _verifier.VerifyMany(
            raw.Where(r => r.Path is not null).Select(r => r.Path!)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList());

        return raw.Select(r => new LoadedModule(
            r.Pid, r.Proc, r.Mod, r.Path,
            r.Path is not null && verdicts.TryGetValue(r.Path, out var v) ? v : SignatureVerdict.Missing)).ToList();
    }

    private static string? SafePath(ProcessModule module)
    {
        try
        {
            return module.FileName;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}
