using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>
/// A live network connection attributed to its owning process and that process's
/// signature, the Netiquette-class "who is talking to whom" unit.
/// </summary>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="Local">Local endpoint.</param>
/// <param name="Remote">Remote endpoint.</param>
/// <param name="State">TCP state (empty for UDP).</param>
/// <param name="Pid">Owning process id.</param>
/// <param name="Process">Owning process name (or a placeholder when unresolved).</param>
/// <param name="ImagePath">Owning process executable, when resolvable.</param>
/// <param name="Signature">Authenticode verdict of the owning executable.</param>
public sealed record Connection(
    string Protocol,
    string Local,
    string Remote,
    string State,
    int Pid,
    string Process,
    string? ImagePath,
    SignatureVerdict Signature)
{
    /// <summary>True when the remote is an off-box, routable destination.</summary>
    public bool External => NetstatParser.IsExternal(NetstatParser.RemoteAddress(Remote));

    /// <summary>
    /// A triage hint: an ESTABLISHED connection to the outside world owned by a
    /// process whose executable is unsigned, untrusted, or unresolved.
    /// </summary>
    public bool Noteworthy =>
        External &&
        State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase) &&
        Signature.State is SignatureState.Unsigned
            or SignatureState.SignedUntrusted
            or SignatureState.Missing;
}
