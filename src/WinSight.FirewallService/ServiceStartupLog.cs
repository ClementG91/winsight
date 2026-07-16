using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Reports why the privileged host refused to start, somewhere an operator can actually see it.
/// </summary>
/// <remarks>
/// The storage trust gate runs before the host is built, so it cannot use the host's logger, and
/// a Windows service has no console to fall back on. An earlier version wrote these refusals to
/// stderr: they reached nobody, and the only symptom was SCM error 1053 with an empty event log,
/// which cost more diagnosis time than the defect behind it.
///
/// Every message carries a stable <c>[FW_*]</c> marker and, where one exists, the deciding
/// <see cref="PathTrustCode"/> — an enum name says <em>which</em> rule refused without saying
/// which path or which principal tripped it. Following the convention the rest of the service
/// uses, the exception is never handed to the logger: native failures carry paths and SIDs in
/// their text, and the VM protocol checks the event log for exactly that.
/// </remarks>
public sealed partial class ServiceStartupLog
{
    private readonly ILogger _logger;

    public ServiceStartupLog(ILogger logger) =>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    [LoggerMessage(
        Level = LogLevel.Critical,
        Message = "[FW_STORAGE_PROVISIONING_FAILED] Policy storage was refused by the trust inspection [{code}]; the service will not start.")]
    public partial void StorageProvisioningRefused(PathTrustCode code);

    [LoggerMessage(
        Level = LogLevel.Critical,
        Message = "[FW_STORAGE_PROVISIONING_FAILED] Policy storage could not be provisioned; the service will not start.")]
    public partial void StorageProvisioningFailed();

    [LoggerMessage(
        Level = LogLevel.Critical,
        Message = "[FW_STORAGE_UNTRUSTED] Policy storage failed its trust check on load; the service will not start.")]
    public partial void StorageUntrusted();

    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "[FW_HOST_READY] Policy storage is trusted; the service is starting in {mode} mode.")]
    public partial void HostReady(OutboundFirewallMode mode);
}
