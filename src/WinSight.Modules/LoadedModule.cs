using WinSight.Core;

namespace WinSight.Modules;

/// <summary>
/// A DLL currently loaded into a running process, with its on-disk path and
/// Authenticode verdict. An unsigned or untrusted module loaded into an otherwise
/// signed process is the classic DLL-injection / search-order-hijack signal.
/// </summary>
/// <param name="Pid">Host process id.</param>
/// <param name="ProcessName">Host process image name.</param>
/// <param name="ModuleName">Module file name (e.g. ntdll.dll).</param>
/// <param name="Path">Full module path, when resolvable.</param>
/// <param name="Signature">Authenticode verdict of the module file.</param>
public sealed record LoadedModule(
    int Pid,
    string ProcessName,
    string ModuleName,
    string? Path,
    SignatureVerdict Signature)
{
    /// <summary>
    /// A loaded module whose file is unsigned or untrusted — worth a look. Modules
    /// with no resolvable path are not flagged.
    /// </summary>
    public bool Unsigned =>
        Path is not null &&
        Signature.State is SignatureState.Unsigned or SignatureState.SignedUntrusted;
}
