using WinSight.Core;

namespace WinSight.Processes;

/// <summary>
/// A running process with its on-disk image, parent, command line and signature —
/// the TaskExplorer-class unit.
/// </summary>
/// <param name="Pid">Process id.</param>
/// <param name="Name">Image name (e.g. explorer.exe).</param>
/// <param name="Path">Full executable path, when resolvable.</param>
/// <param name="ParentPid">Parent process id.</param>
/// <param name="CommandLine">Full command line, when available.</param>
/// <param name="Signature">Authenticode verdict of the executable.</param>
public sealed record ProcessInfo(
    int Pid,
    string Name,
    string? Path,
    int ParentPid,
    string? CommandLine,
    SignatureVerdict Signature)
{
    /// <summary>
    /// A running process whose on-disk image is unsigned or untrusted — worth a look.
    /// Processes with no resolvable image (protected/system) are not flagged.
    /// </summary>
    public bool Unsigned =>
        Path is not null &&
        Signature.State is SignatureState.Unsigned or SignatureState.SignedUntrusted;
}
