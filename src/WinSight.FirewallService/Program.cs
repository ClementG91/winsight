using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinSight.Firewall;
using WinSight.FirewallService;

// WinSight outbound-firewall service host. Least-privilege and audit-only: it hosts the
// authenticated named-pipe endpoint over the shared library and never mutates WFP. It is
// intended to run as a Windows service (SYSTEM), which owns the ACL-protected policy
// directory; running it as a console app is supported for local debugging.

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "WinSight Firewall");

// Provision the ACL-protected policy directory. When not elevated (console debugging)
// this can fail; the store still works against the path, so log and continue.
var policyFile = FirewallServicePaths.DefaultPolicyFile;
try
{
    FirewallServicePaths.ProvisionDirectory(FirewallServicePaths.DefaultDirectory);
}
catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
{
    Console.Error.WriteLine($"WinSight firewall: could not harden the policy directory ({ex.Message}). Continuing.");
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

var host = builder.Build();
host.Run();
