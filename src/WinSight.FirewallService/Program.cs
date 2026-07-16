using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using WinSight.Firewall;
using WinSight.FirewallService;
using WinSight.NetMonitor;

// WinSight outbound-firewall service host. Least-privilege and audit-only: it hosts the
// authenticated named-pipe endpoint over the shared library and never mutates WFP.
//
// Verbs:
//   run         host the service (how the SCM and console debugging start it) [default]
//   install     register the Windows service (Administrator required)
//   uninstall   remove the Windows service (Administrator required)
//   status      report whether the service is installed
//
// The service is opt-in: the per-user application setup never installs it.

return await (FirewallServiceCommandLine.Parse(args) switch
{
    FirewallServiceVerb.Install => Task.FromResult(Install()),
    FirewallServiceVerb.Uninstall => Task.FromResult(Uninstall()),
    FirewallServiceVerb.Status => Task.FromResult(Status()),
    FirewallServiceVerb.WfpSelfTest => Task.FromResult(WfpProbe()),
    FirewallServiceVerb.WfpProvision => Task.FromResult(DisabledLowLevelMutation(WfpProvision)),
    FirewallServiceVerb.WfpDeprovision => Task.FromResult(DisabledLowLevelMutation(WfpDeprovision)),
    FirewallServiceVerb.WfpStatus => Task.FromResult(WfpStatusVerb()),
    FirewallServiceVerb.WfpFilterAdd => Task.FromResult(DisabledLowLevelMutation(WfpFilterAdd)),
    FirewallServiceVerb.WfpFilterRemove => Task.FromResult(DisabledLowLevelMutation(WfpFilterRemove)),
    FirewallServiceVerb.WfpBlockAdd => Task.FromResult(DisabledLowLevelMutation(() => WfpBlockAdd(args))),
    FirewallServiceVerb.WfpBlockRemove => Task.FromResult(DisabledLowLevelMutation(() => WfpBlockRemove(args))),
    FirewallServiceVerb.WfpBlockStatus => Task.FromResult(WfpBlockStatus(args)),
    FirewallServiceVerb.EnforceStatus => EnforceStatusAsync(),
    FirewallServiceVerb.EnforceEnable => Task.FromResult(DisabledLowLevelMutation(() => EnforceEnableAsync().GetAwaiter().GetResult())),
    FirewallServiceVerb.EnforceDisable => Task.FromResult(DisabledLowLevelMutation(() => EnforceDisableAsync().GetAwaiter().GetResult())),
    FirewallServiceVerb.BlockApp => Task.FromResult(DisabledLowLevelMutation(() => SetAppPolicyAsync(args, OutboundAction.Block).GetAwaiter().GetResult())),
    FirewallServiceVerb.AllowApp => Task.FromResult(DisabledLowLevelMutation(() => SetAppPolicyAsync(args, OutboundAction.Allow).GetAwaiter().GetResult())),
    FirewallServiceVerb.Unknown => Task.FromResult(Usage()),
    _ => RunHostAsync(),
}).ConfigureAwait(false);

static int Install()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine(
            "Installing the WinSight firewall service requires an elevated (Administrator) console.");
        return 1;
    }

    var executable = Environment.ProcessPath;
    if (string.IsNullOrEmpty(executable))
    {
        Console.Error.WriteLine("Could not resolve the service executable path.");
        return 1;
    }

    try
    {
        FirewallServiceInstaller.Install(executable);
        Console.WriteLine(
            $"Installed '{FirewallServiceInstaller.DisplayName}' (demand-start, audit-only, installs no WFP filter).");
        Console.WriteLine($"Start it with:  sc start {FirewallServiceInstaller.ServiceName}");
        return 0;
    }
    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
    {
        Console.Error.WriteLine("[FW_INSTALL_FAILED]");
        return 1;
    }
}

static int DisabledLowLevelMutation(Func<int> suppressedBackend)
{
    ArgumentNullException.ThrowIfNull(suppressedBackend);
    Console.Error.WriteLine("[FW_DIRECT_MUTATION_DISABLED]");
    return 1;
}

static int Uninstall()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine(
            "Removing the WinSight firewall service requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        FirewallServiceInstaller.Uninstall();
        Console.WriteLine($"Removed '{FirewallServiceInstaller.DisplayName}'.");
        return 0;
    }
    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
    {
        Console.Error.WriteLine("[FW_UNINSTALL_FAILED]");
        return 1;
    }
}

static int Status()
{
    Console.WriteLine(FirewallServiceInstaller.IsInstalled()
        ? $"{FirewallServiceInstaller.DisplayName} is installed."
        : $"{FirewallServiceInstaller.DisplayName} is not installed.");
    return 0;
}

static int WfpProbe()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("The WFP self-test requires an elevated (Administrator) console.");
        return 1;
    }

    var result = WfpSelfTest.Run();
    if (result.EngineOpened && result.ErrorCode == 0)
    {
        Console.WriteLine(
            $"WFP engine opened. Existing filters visible: {result.FilterCount}. Read-only: no filter, provider or sublayer was added or changed.");
        return 0;
    }

    Console.Error.WriteLine("[FW_WFP_READ_FAILED]");
    return 1;
}

static int WfpProvision()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Creating the WFP provider/sublayer requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        WfpProvisioning.Provision();
        Console.WriteLine(
            "WinSight WFP provider and sublayer created (containers only: no filter, nothing is blocked). Non-persistent: a reboot removes them.");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_MUTATION_FAILED]");
        return 1;
    }
}

static int WfpDeprovision()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Removing the WFP provider/sublayer requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        WfpProvisioning.Deprovision();
        Console.WriteLine("WinSight WFP provider and sublayer removed.");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_CLEANUP_FAILED]");
        return 1;
    }
}

static int WfpStatusVerb()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Reading the WFP provider/sublayer status requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        var (provider, sublayer, permit) = WfpProvisioning.Status();
        Console.WriteLine(
            $"WinSight WFP provider: {Present(provider)}, sublayer: {Present(sublayer)}, permit-filter: {Present(permit)}. Per-app blocks are queried with wfp-block-status <path>.");
        return 0;

        static string Present(bool value) => value ? "present" : "absent";
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_READ_FAILED]");
        return 1;
    }
}

static int WfpBlockStatus(string[] arguments)
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Reading a WFP block status requires an elevated (Administrator) console.");
        return 1;
    }
    if (arguments.Length < 2 || string.IsNullOrWhiteSpace(arguments[1]))
    {
        Console.Error.WriteLine("Usage: winsight-firewall-service wfp-block-status <full path to an executable>");
        return 2;
    }

    try
    {
        var blocked = WfpProvisioning.IsBlocked(arguments[1]);
        Console.WriteLine(blocked ? "[FW_APP_BLOCKED]" : "[FW_APP_NOT_BLOCKED]");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_READ_FAILED]");
        return 1;
    }
}

static int WfpBlockAdd(string[] arguments)
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Adding a WFP block filter requires an elevated (Administrator) console.");
        return 1;
    }
    if (arguments.Length < 2 || string.IsNullOrWhiteSpace(arguments[1]))
    {
        Console.Error.WriteLine("Usage: winsight-firewall-service wfp-block-add <full path to an executable>");
        return 2;
    }

    var executable = arguments[1];
    try
    {
        WfpProvisioning.AddBlockFilter(executable);
        Console.WriteLine("[FW_APP_BLOCK_APPLIED]");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_MUTATION_FAILED]");
        return 1;
    }
}

static int WfpBlockRemove(string[] arguments)
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Removing a WFP block filter requires an elevated (Administrator) console.");
        return 1;
    }
    if (arguments.Length < 2 || string.IsNullOrWhiteSpace(arguments[1]))
    {
        Console.Error.WriteLine("Usage: winsight-firewall-service wfp-block-remove <full path to an executable>");
        return 2;
    }

    try
    {
        WfpProvisioning.RemoveBlockFilter(arguments[1]);
        Console.WriteLine("[FW_APP_BLOCK_REMOVED]");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_CLEANUP_FAILED]");
        return 1;
    }
}

static int WfpFilterAdd()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Adding the WFP permit filter requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        WfpProvisioning.AddPermitFilter();
        Console.WriteLine(
            "Added a non-blocking PERMIT filter to the WinSight sublayer. It authorizes outbound connects (already the default), so nothing is blocked.");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_MUTATION_FAILED]");
        return 1;
    }
}

static int WfpFilterRemove()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Removing the WFP permit filter requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        WfpProvisioning.RemovePermitFilter();
        Console.WriteLine("Removed the WinSight PERMIT filter.");
        return 0;
    }
    catch (Win32Exception)
    {
        Console.Error.WriteLine("[FW_WFP_CLEANUP_FAILED]");
        return 1;
    }
}

static async Task<int> EnforceStatusAsync()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Reading enforcement status requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        using var coordinator = CreateCoordinator();
        var mode = await coordinator.GetModeAsync().ConfigureAwait(false);
        Console.WriteLine($"Enforcement mode: {mode}.");
        return 0;
    }
    catch (PolicyStorageTrustException refusal)
    {
        // Two outputs, two audiences. The marker stays invariant because scripts parse it and
        // because that sink must never carry variable text. The rule that refused goes through
        // the structured log instead, which is leak-tested and, for a console run, prints here.
        StartupLog().StorageProvisioningRefused(refusal.Code);
        Console.Error.WriteLine("[FW_ENFORCEMENT_STATUS_UNAVAILABLE]");
        return 1;
    }
    catch (Exception ex) when (ex is Win32Exception or InvalidDataException or IOException or InvalidOperationException)
    {
        Console.Error.WriteLine("[FW_ENFORCEMENT_STATUS_UNAVAILABLE]");
        return 1;
    }
}

static async Task<int> EnforceEnableAsync()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Enabling enforcement requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        using var coordinator = CreateCoordinator();
        await coordinator.EnableAsync().ConfigureAwait(false);
        // Auto-start so a reboot re-launches the service, which reinstalls the blocks.
        var installed = FirewallServiceInstaller.TrySetAutoStart(autoStart: true);
        Console.WriteLine(installed
            ? "Enforcement enabled. Stored Block policies are applied and the service is now auto-start, so blocks survive a reboot."
            : "Enforcement enabled and applied. Install the service (install) so it auto-starts and reapplies blocks after a reboot.");
        return 0;
    }
    catch (Exception ex) when (ex is Win32Exception or InvalidDataException or IOException or InvalidOperationException)
    {
        Console.Error.WriteLine("[FW_ENFORCEMENT_TRANSITION_FAILED]");
        return 1;
    }
}

static async Task<int> EnforceDisableAsync()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Disabling enforcement requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        using var coordinator = CreateCoordinator();
        await coordinator.DisableAsync().ConfigureAwait(false);
        // Back to demand-start: no reason to auto-launch a service that enforces nothing.
        _ = FirewallServiceInstaller.TrySetAutoStart(autoStart: false);
        Console.WriteLine("Enforcement disabled. Every WinSight block was lifted and the mode is audit-only.");
        return 0;
    }
    catch (Exception ex) when (ex is Win32Exception or InvalidDataException or IOException or InvalidOperationException)
    {
        Console.Error.WriteLine("[FW_ENFORCEMENT_TRANSITION_FAILED]");
        return 1;
    }
}

static async Task<int> SetAppPolicyAsync(string[] arguments, OutboundAction action)
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Setting an application policy requires an elevated (Administrator) console.");
        return 1;
    }
    if (arguments.Length < 2 || string.IsNullOrWhiteSpace(arguments[1]))
    {
        Console.Error.WriteLine("[FW_POLICY_USAGE]");
        return 2;
    }

    try
    {
        using var coordinator = CreateCoordinator();
        await coordinator.SetPolicyAsync(arguments[1], action).ConfigureAwait(false);
        Console.WriteLine("[FW_POLICY_APPLIED]");
        return 0;
    }
    catch (Exception ex) when (ex is Win32Exception or InvalidDataException or IOException or InvalidOperationException)
    {
        Console.Error.WriteLine("[FW_POLICY_MUTATION_FAILED]");
        return 1;
    }
}

/// <summary>
/// Logging for the refusals that happen before the host is built. A service writes to the event
/// log, which is where an operator looks after an SCM failure; a human running the host directly
/// gets the console. AddWindowsService gives the built host the same event-log sink, so a refusal
/// and a running service report to the same place under the same source name.
/// </summary>
/// <summary>
/// A one-shot startup log for the console verbs. The factory owns the sink, so this leaks it
/// deliberately for the lifetime of a short-lived verb rather than threading it through; the
/// host path builds and disposes its own.
/// </summary>
static ServiceStartupLog StartupLog() =>
    new(CreateStartupLoggerFactory().CreateLogger("WinSight.FirewallService.Startup"));

static ILoggerFactory CreateStartupLoggerFactory() =>
    LoggerFactory.Create(logging =>
    {
        if (WindowsServiceHelpers.IsWindowsService())
        {
            logging.AddEventLog(new EventLogSettings
            {
                SourceName = FirewallServiceInstaller.ServiceName,
                LogName = "Application",
            });
        }
        else
        {
            logging.AddSimpleConsole(options => options.SingleLine = true);
        }
    });

static EnforcementCoordinator CreateCoordinator()
{
    FirewallServicePaths.ProvisionDefaultDirectory();
    var store = CreateTrustedStore();
    return new EnforcementCoordinator(store, static () => new WfpOutboundFirewallEngine());
}

static FirewallPolicyStore CreateTrustedStore() => new(
    FirewallServicePaths.DefaultPolicyFile,
    allowEnforcement: true,
    storageTrustGuard: new FirewallStorageTrustGuard(
        new WindowsServicePathTrustInspector(),
        FirewallServicePaths.DefaultDirectory,
        FirewallServicePaths.DefaultPolicyFile));

static int Usage()
{
    Console.Error.WriteLine(
        "Usage: winsight-firewall-service [run|install|uninstall|status|wfp-selftest|wfp-provision|wfp-deprovision|wfp-status|wfp-filter-add|wfp-filter-remove|wfp-block-add <path>|wfp-block-remove <path>|wfp-block-status <path>|enforce-status|enforce-enable|enforce-disable|block-app <path>|allow-app <path>]");
    return 2;
}

static async Task<int> RunHostAsync()
{
    var builder = Host.CreateApplicationBuilder();

    builder.Services.AddWindowsService(options => options.ServiceName = FirewallServiceInstaller.ServiceName);

    // The gate below runs before the host exists, so it cannot use the host's logger, and a
    // service has no console: writing these refusals to stderr left the operator with SCM error
    // 1053 and an empty event log. This factory reaches the event log the same way the built
    // host would, and the console when a human ran the host directly.
    using var startupLoggerFactory = CreateStartupLoggerFactory();
    var startupLog = new ServiceStartupLog(startupLoggerFactory.CreateLogger("WinSight.FirewallService.Startup"));

    // Provisioning and verification are a mandatory trust boundary. Failure prevents
    // policy access and, crucially, construction of the native WFP backend.
    try
    {
        FirewallServicePaths.ProvisionDefaultDirectory();
    }
    catch (PolicyStorageTrustException refusal)
    {
        // Both sinks, because neither replaces the other: stderr carries the invariant code a
        // console run and its scripts parse, and the structured log carries the deciding rule to
        // the event log, which is all a service has. The exception itself reaches neither.
        startupLog.StorageProvisioningRefused(refusal.Code);
        Console.Error.WriteLine("[FW_STORAGE_PROVISIONING_FAILED]");
        return 1;
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
    {
        startupLog.StorageProvisioningFailed();
        Console.Error.WriteLine("[FW_STORAGE_PROVISIONING_FAILED]");
        return 1;
    }

    // The service is the privileged gate. Startup reads the mode only after storage trust;
    // the authority constructs the native backend lazily after its own fresh trusted load.
    var store = CreateTrustedStore();
    var loaded = await store.LoadOrAuditAsync().ConfigureAwait(false);
    if (!loaded.StorageTrusted)
    {
        startupLog.StorageUntrusted();
        Console.Error.WriteLine("[FW_STORAGE_UNTRUSTED]");
        return 1;
    }
    var enforcing = loaded.Configuration.Mode == OutboundFirewallMode.Enforcement;
    startupLog.HostReady(loaded.Configuration.Mode);

    builder.Services.AddSingleton(store);
    builder.Services.AddSingleton(sp => new EnforcementCoordinator(
        sp.GetRequiredService<FirewallPolicyStore>(),
        static () => new WfpOutboundFirewallEngine()));
    builder.Services.AddSingleton<IFirewallMutationAuthority>(sp =>
        sp.GetRequiredService<EnforcementCoordinator>());

    // Shared by the observer that fills it and the dispatcher that serves and prunes it.
    builder.Services.AddSingleton<PendingOutboundLog>();
    builder.Services.AddSingleton<OutboundConnectionWatcher>();

    builder.Services.AddSingleton(sp => new FirewallRequestDispatcher(
        sp.GetRequiredService<FirewallPolicyStore>(),
        sp.GetRequiredService<IFirewallMutationAuthority>(),
        sp.GetRequiredService<PendingOutboundLog>()));
    builder.Services.AddSingleton(sp => new FirewallConnectionHandler(
        sp.GetRequiredService<FirewallRequestDispatcher>()));
    builder.Services.AddSingleton<IFirewallServiceListener>(sp => new NamedPipeFirewallServer(
        sp.GetRequiredService<FirewallConnectionHandler>()));

    // Only when enforcing does the service reinstall the (non-persistent) block filters.
    if (enforcing)
    {
        builder.Services.AddHostedService<EnforcementStartupService>();
    }
    // Observation is reporting only and runs whatever the mode: telling the operator what reached
    // the network is worth as much in audit-only, where it is the only thing the tool can do.
    builder.Services.AddHostedService<OutboundObserverService>();
    builder.Services.AddHostedService<FirewallServiceWorker>();

    await builder.Build().RunAsync().ConfigureAwait(false);
    return 0;
}
