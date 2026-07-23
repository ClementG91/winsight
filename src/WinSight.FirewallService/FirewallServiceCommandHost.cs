using System.ComponentModel;

namespace WinSight.FirewallService;

/// <summary>
/// The complete capability needed by the install command. Path-trust probes never receive this
/// interface, so they cannot resolve the running executable, test elevation or reach SCM.
/// </summary>
public interface IFirewallServiceInstallCapability
{
    bool IsElevated();
    string? GetProcessPath();
    void Install(string executablePath);
}

/// <summary>
/// Result of the single command-host route. Unhandled verbs are returned to Program without
/// reparsing so the existing service, status and diagnostic verbs can continue unchanged.
/// </summary>
public sealed record FirewallServiceCommandDispatch(
    FirewallServiceVerb Verb,
    bool Handled,
    int ExitCode);

/// <summary>
/// Public CLI composition root for parsing, install/probe routing, arity, fixed result mapping and
/// stdout/stderr selection. Tests and Program execute this same route.
/// </summary>
public sealed class FirewallServiceCommandHost
{
    private readonly InstallCommandHandler _installHandler;
    private readonly PathTrustProbeCommandHandler _pathTrustProbeHandler;

    public FirewallServiceCommandHost(
        IFirewallServiceInstallCapability installCapability,
        IServicePathTrustInspector pathTrustInspector)
    {
        _installHandler = new InstallCommandHandler(
            installCapability ?? throw new ArgumentNullException(nameof(installCapability)));
        _pathTrustProbeHandler = new PathTrustProbeCommandHandler(
            pathTrustInspector ?? throw new ArgumentNullException(nameof(pathTrustInspector)));
    }

    /// <summary>
    /// Parses and dispatches one command. Handled commands write exactly one closed result to the
    /// selected writer; unhandled commands write nothing and return the parsed verb to Program.
    /// </summary>
    public FirewallServiceCommandDispatch Execute(
        IReadOnlyList<string>? arguments,
        TextWriter standardOutput,
        TextWriter standardError)
    {
        ArgumentNullException.ThrowIfNull(standardOutput);
        ArgumentNullException.ThrowIfNull(standardError);

        var verb = FirewallServiceCommandLine.Parse(arguments);
        CommandResult? result = verb switch
        {
            FirewallServiceVerb.Install => _installHandler.Execute(),
            FirewallServiceVerb.InstallPathTrustCheck => _pathTrustProbeHandler.Execute(arguments),
            _ => null,
        };

        if (result is null)
        {
            return new FirewallServiceCommandDispatch(verb, Handled: false, ExitCode: 0);
        }

        if (result.StandardOutput is not null)
        {
            standardOutput.WriteLine(result.StandardOutput);
        }
        if (result.StandardError is not null)
        {
            standardError.WriteLine(result.StandardError);
        }
        return new FirewallServiceCommandDispatch(verb, Handled: true, result.ExitCode);
    }

    private sealed class InstallCommandHandler(IFirewallServiceInstallCapability capability)
    {
        private const string ElevationRequired =
            "Installing the WinSight firewall service requires an elevated (Administrator) console.";
        private const string ProcessPathUnavailable = "Could not resolve the service executable path.";
        private const string InstallFailed = "[FW_INSTALL_FAILED]";

        public CommandResult Execute()
        {
            try
            {
                if (!capability.IsElevated())
                {
                    return CommandResult.Failure(ElevationRequired);
                }

                var executablePath = capability.GetProcessPath();
                if (string.IsNullOrEmpty(executablePath))
                {
                    return CommandResult.Failure(ProcessPathUnavailable);
                }

                capability.Install(executablePath);
                var output =
                    $"Installed '{FirewallServiceInstaller.DisplayName}' (demand-start; enforcement is opt-in and runtime state is reported separately).{Environment.NewLine}" +
                    $"Start it with:  sc start {FirewallServiceInstaller.ServiceName}";
                return new CommandResult(0, StandardOutput: output);
            }
            catch (ServicePathTrustException refusal)
            {
                return CommandResult.Failure(
                    ServicePathTrustDiagnosticCodes.ForInstallDenial(refusal.Code));
            }
            // Deliberately unfiltered, matching the probe handler. A narrower filter only holds
            // while the call graph below happens not to throw anything else, and the failure mode
            // when that changes is the CLR printing the type, message and stack trace - including
            // the executable path - to stderr. Typed trust refusals are already handled above, so
            // everything reaching here is an install failure with nothing safe to say about it.
            catch (Exception)
            {
                return CommandResult.Failure(InstallFailed);
            }
        }
    }

    /// <summary>
    /// This handler intentionally owns only inspection capability. In particular it has no install,
    /// elevation, process-path, SCM or WFP dependency.
    /// </summary>
    private sealed class PathTrustProbeCommandHandler(IServicePathTrustInspector pathTrustInspector)
    {
        public CommandResult Execute(IReadOnlyList<string>? arguments)
        {
            if (arguments is null ||
                arguments.Count != 2 ||
                string.IsNullOrWhiteSpace(arguments[1]))
            {
                return CommandResult.Failure(ServicePathTrustDiagnosticCodes.InspectionFailed);
            }

            try
            {
                _ = FirewallServiceInstaller.InspectAndRevalidateExecutable(
                    arguments[1],
                    pathTrustInspector);
                return new CommandResult(
                    0,
                    StandardOutput: ServicePathTrustDiagnosticCodes.Trusted);
            }
            catch (ServicePathTrustException refusal)
            {
                return CommandResult.Failure(
                    ServicePathTrustDiagnosticCodes.ForInstallDenial(refusal.Code));
            }
            catch (Exception)
            {
                return CommandResult.Failure(ServicePathTrustDiagnosticCodes.InspectionFailed);
            }
        }
    }

    private sealed record CommandResult(
        int ExitCode,
        string? StandardOutput = null,
        string? StandardError = null)
    {
        public static CommandResult Failure(string diagnostic) =>
            new(1, StandardError: diagnostic);
    }
}

/// <summary>Production install capability constructed once by Program.</summary>
internal sealed class WindowsFirewallServiceInstallCapability : IFirewallServiceInstallCapability
{
    public bool IsElevated() => FirewallServiceInstaller.IsElevated();
    public string? GetProcessPath() => Environment.ProcessPath;
    public void Install(string executablePath) => FirewallServiceInstaller.Install(executablePath);
}
