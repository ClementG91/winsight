using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WinSight.Firewall;
using WinSight.FirewallService;

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

return FirewallServiceCommandLine.Parse(args) switch
{
    FirewallServiceVerb.Install => Install(),
    FirewallServiceVerb.Uninstall => Uninstall(),
    FirewallServiceVerb.Status => Status(),
    FirewallServiceVerb.WfpSelfTest => WfpProbe(),
    FirewallServiceVerb.WfpProvision => WfpProvision(),
    FirewallServiceVerb.WfpDeprovision => WfpDeprovision(),
    FirewallServiceVerb.WfpStatus => WfpStatusVerb(),
    FirewallServiceVerb.WfpFilterAdd => WfpFilterAdd(),
    FirewallServiceVerb.WfpFilterRemove => WfpFilterRemove(),
    FirewallServiceVerb.WfpBlockAdd => WfpBlockAdd(args),
    FirewallServiceVerb.WfpBlockRemove => WfpBlockRemove(),
    FirewallServiceVerb.Unknown => Usage(),
    _ => RunHost(),
};

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
        Console.Error.WriteLine($"Install failed: {ex.Message}");
        return 1;
    }
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
        Console.Error.WriteLine($"Uninstall failed: {ex.Message}");
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

    Console.Error.WriteLine(
        $"WFP self-test failed (engineOpened={result.EngineOpened}, error 0x{result.ErrorCode:X8}). No change was made.");
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
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"WFP provision failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}");
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
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"WFP deprovision failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}");
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
        var (provider, sublayer, permit, block) = WfpProvisioning.Status();
        Console.WriteLine(
            $"WinSight WFP provider: {Present(provider)}, sublayer: {Present(sublayer)}, permit-filter: {Present(permit)}, block-filter: {Present(block)}.");
        return 0;

        static string Present(bool value) => value ? "present" : "absent";
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"WFP status failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}");
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
        Console.WriteLine(
            $"Blocking outbound connections for '{executable}'. Only that application is affected; everything else keeps working. Run wfp-block-remove to undo.");
        return 0;
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine(
            $"WFP block add failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}. Run wfp-provision first, and pass a full executable path.");
        return 1;
    }
}

static int WfpBlockRemove()
{
    if (!FirewallServiceInstaller.IsElevated())
    {
        Console.Error.WriteLine("Removing the WFP block filter requires an elevated (Administrator) console.");
        return 1;
    }

    try
    {
        WfpProvisioning.RemoveBlockFilter();
        Console.WriteLine("Removed the WinSight block filter.");
        return 0;
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"WFP block remove failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}");
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
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine(
            $"WFP filter add failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}. Run wfp-provision first.");
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
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"WFP filter remove failed (error 0x{ex.NativeErrorCode:X8}): {ex.Message}");
        return 1;
    }
}

static int Usage()
{
    Console.Error.WriteLine(
        "Usage: winsight-firewall-service [run|install|uninstall|status|wfp-selftest|wfp-provision|wfp-deprovision|wfp-status|wfp-filter-add|wfp-filter-remove|wfp-block-add <path>|wfp-block-remove]");
    return 2;
}

static int RunHost()
{
    var builder = Host.CreateApplicationBuilder();

    builder.Services.AddWindowsService(options => options.ServiceName = FirewallServiceInstaller.ServiceName);

    // Provision the ACL-protected policy directory. When not elevated (console
    // debugging) this can fail; the store still works against the path, so log and continue.
    var policyFile = FirewallServicePaths.DefaultPolicyFile;
    try
    {
        FirewallServicePaths.ProvisionDirectory(FirewallServicePaths.DefaultDirectory);
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
    {
        Console.Error.WriteLine(
            $"WinSight firewall: could not harden the policy directory ({ex.Message}). Continuing.");
    }

    builder.Services.AddSingleton(new FirewallPolicyStore(policyFile));
    builder.Services.AddSingleton<IOutboundFirewallEngine, AuditOnlyFirewallEngine>();
    builder.Services.AddSingleton(sp => new FirewallRequestDispatcher(
        sp.GetRequiredService<FirewallPolicyStore>(),
        sp.GetRequiredService<IOutboundFirewallEngine>()));
    builder.Services.AddSingleton(sp => new FirewallConnectionHandler(
        sp.GetRequiredService<FirewallRequestDispatcher>()));
    builder.Services.AddSingleton<IFirewallServiceListener>(sp => new NamedPipeFirewallServer(
        sp.GetRequiredService<FirewallConnectionHandler>()));
    builder.Services.AddHostedService<FirewallServiceWorker>();

    builder.Build().Run();
    return 0;
}
