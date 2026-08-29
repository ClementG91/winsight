using WinSight.Core;

namespace WinSight.Persistence;

/// <summary>
/// Which autostart surfaces load code into a privileged or universal host, and what somebody
/// else's code sitting on one of them means.
/// </summary>
/// <remarks>
/// <b>The gap this closes.</b> Every autostart entry was judged on its signature alone: signed and
/// trusted meant nothing to report, wherever it was registered. But these particular surfaces are
/// not places a program merely starts - they are places a DLL is loaded <i>into somebody else's
/// process</i>, and the process is LSASS, the print spooler running as SYSTEM, the logon UI before
/// anybody has authenticated, or every process on the machine that links user32.
///
/// A validly signed third-party DLL in one of those positions is a real finding even though nothing
/// about its signature is wrong. It is how an attacker with a code-signing certificate - stolen,
/// bought, or belonging to a compromised vendor - gets code into a process they could not otherwise
/// touch, and it is how several commodity families persist. Reporting it as routine because the
/// signature validates is the same mistake as calling an attested driver an in-box one.
///
/// <b>Why this is not noisy.</b> These surfaces are empty or Microsoft-only on an ordinary machine:
/// they are the ones with no supported extensibility story left. The scan that produced 4538
/// autostart items on a real desktop found nothing here at all. That is what makes them worth
/// flagging - a list that is normally empty is a list somebody will actually read.
///
/// <b>What is deliberately not on the list.</b> Run keys, startup folders, scheduled tasks, services
/// and COM registrations are where ordinary software lives, in their thousands. Flagging every
/// non-Microsoft signer there would produce a report nobody opens, which is the failure this
/// project keeps guarding against.
/// </remarks>
public static class PrivilegedSurfaceTriage
{
    /// <summary>
    /// Whether <paramref name="vector"/> loads code into a privileged or universal host process.
    /// </summary>
    public static bool IsPrivilegedSurface(AutostartVector vector) => vector switch
    {
        // Loaded into every process that links user32 - which is most of them.
        AutostartVector.AppInitDll => true,
        // Loaded into every process created through CreateProcess.
        AutostartVector.AppCertDll => true,
        // Loaded into LSASS, which holds the machine's secrets.
        AutostartVector.LsaPackage or AutostartVector.SecurityProvider => true,
        // Loaded by the logon UI, as SYSTEM, before anybody has authenticated.
        AutostartVector.CredentialProvider => true,
        // Loaded into the print spooler, which runs as SYSTEM.
        AutostartVector.PrintMonitor or AutostartVector.PrintProvider => true,
        // Loaded into the time service.
        AutostartVector.TimeProvider => true,
        // Run by the session manager before the Win32 subsystem exists.
        AutostartVector.BootExecute => true,
        // Loaded by netsh, which an administrator runs elevated.
        AutostartVector.NetshHelper => true,
        // Winlogon's own userinit/shell chain, and WMI event consumers running as SYSTEM.
        AutostartVector.Winlogon or AutostartVector.WmiSubscription => true,
        // A .NET profiler is loaded into whichever managed process the setting reaches - every one
        // of them for the machine environment, or one chosen SYSTEM service for a per-service
        // block. A legitimate APM agent looks exactly like this, which is the point: an operator
        // should be told an agent is injecting into their processes, and be able to recognise it.
        AutostartVector.ProfilerInjection => true,
        _ => false,
    };

    /// <summary>
    /// Whether <paramref name="entry"/> is somebody else's code registered to load into a
    /// privileged host - valid signature and all.
    /// </summary>
    /// <remarks>
    /// Only entries whose signature actually validated reach a true here. An unsigned or untrusted
    /// image is already adverse for its own reason, and one that could not be checked is unverified
    /// rather than adverse: this must add a finding about <i>where trusted third-party code is
    /// running</i>, not restate one the signature model already made.
    /// </remarks>
    public static bool IsForeignCodeInAPrivilegedHost(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return IsPrivilegedSurface(entry.Vector)
            && entry.Signature.State == SignatureState.SignedTrusted
            && !CertificateSubject.IsMicrosoft(entry.Signature);
    }
}
