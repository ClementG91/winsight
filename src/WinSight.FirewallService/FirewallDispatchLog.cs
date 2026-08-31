using Microsoft.Extensions.Logging;
using WinSight.Firewall;

namespace WinSight.FirewallService;

/// <summary>
/// Writes only the dispatcher's sanitized command/failure tuple. It intentionally accepts no
/// Exception: native messages can contain executable paths and security principals, while the
/// stable transition code is enough to diagnose a failed state-machine step.
/// </summary>
public sealed partial class FirewallDispatchLog
{
    private readonly ILogger<FirewallDispatchLog> _logger;

    public FirewallDispatchLog(ILogger<FirewallDispatchLog> logger) =>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public void Failure(FirewallDispatchFailure failure) =>
        LogFailure(failure.Command, failure.Kind, failure.Code ?? "None");

    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "[FW_COMMAND_FAILED] Firewall command failed. Command={Command}; Failure={Failure}; Code={Code}.")]
    private partial void LogFailure(
        FirewallCommand command,
        FirewallDispatchFailureKind failure,
        string code);
}
