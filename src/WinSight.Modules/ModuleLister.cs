using System.ComponentModel;
using System.Diagnostics;
using WinSight.Core;

namespace WinSight.Modules;

/// <summary>
/// Enumerates the DLLs loaded into every accessible running process and batch-checks
/// each distinct module's Authenticode signature, surfacing unsigned/untrusted DLLs
/// injected or side-loaded into legitimate processes. Read-only; processes that can't
/// be opened (protected, cross-bitness, already exited) are skipped, never guessed.
/// </summary>
public sealed class ModuleLister(ISignatureVerifier? verifier = null)
{
    private readonly ISignatureVerifier _verifier = verifier ?? new NativeSignatureVerifier();

    public IReadOnlyList<LoadedModule> Snapshot(CancellationToken cancellationToken = default) =>
        Collect(Process.GetProcesses(), cancellationToken);

    /// <summary>
    /// The modules of one process, or nothing when it is not running.
    /// </summary>
    /// <remarks>
    /// <b>Why this exists beside the full sweep.</b> The per-process drill-down needs exactly one
    /// process, and <see cref="Snapshot"/> walks every one of them: measured on a real desktop,
    /// 14 253 modules across 222 processes in 57 seconds. That is a good answer to "what is loaded
    /// anywhere on this machine" and an unusable one for a view opened on a single pid.
    ///
    /// A pid that is not running answers with nothing rather than throwing. That is the normal case
    /// here, not an edge one: a drill-down is most often opened on a process that just did something
    /// interesting and exited, which is precisely the case worth investigating.
    /// </remarks>
    public IReadOnlyList<LoadedModule> SnapshotFor(int pid, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Process process;
        try
        {
            process = Process.GetProcessById(pid);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return [];
        }
        return Collect([process], cancellationToken);
    }

    /// <summary>
    /// Reads and verifies the modules of the given processes, disposing every one of them.
    /// </summary>
    /// <remarks>
    /// Shared by both entry points so the single-process path cannot drift from the sweep — the
    /// skip-don't-fabricate rule below is the whole reason this scanner can be trusted, and a second
    /// copy of it is a second chance to get it wrong.
    /// </remarks>
    private List<LoadedModule> Collect(
        IReadOnlyList<Process> processes, CancellationToken cancellationToken)
    {
        var raw = new List<(int Pid, string Proc, string Mod, string? Path)>();
        foreach (var p in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
                // Access denied / process exited / cross-bitness, skip, don't fabricate.
            }
            finally
            {
                p.Dispose();
            }
        }

        var verdicts = _verifier.VerifyMany(
            raw.Where(r => r.Path is not null).Select(r => r.Path!)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            cancellationToken);

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
