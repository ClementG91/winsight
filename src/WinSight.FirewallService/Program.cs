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

static int Usage()
{
    Console.Error.WriteLine("Usage: winsight-firewall-service [run|install|uninstall|status]");
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
