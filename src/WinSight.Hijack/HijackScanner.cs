using Microsoft.Win32;

namespace WinSight.Hijack;

/// <summary>Where the services to check come from.</summary>
/// <param name="Name">The service name.</param>
/// <param name="CommandLine">Its registered <c>ImagePath</c>.</param>
public readonly record struct RegisteredService(string Name, string CommandLine);

/// <summary>Reads the machine's registered services. A seam, so the scan is testable.</summary>
public interface IServiceRegistry
{
    IEnumerable<RegisteredService> Enumerate();
}

/// <summary>
/// Reads services from <c>HKLM\SYSTEM\CurrentControlSet\Services</c>. No elevation: the key is
/// readable by any user, which is the whole reason this check can ship in the default mode.
/// </summary>
public sealed class RegistryServiceSource : IServiceRegistry
{
    private const string Root = @"SYSTEM\CurrentControlSet\Services";

    public IEnumerable<RegisteredService> Enumerate()
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var services = baseKey.OpenSubKey(Root);
        if (services is null)
        {
            yield break;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            string? image = null;
            try
            {
                using var service = services.OpenSubKey(name);
                image = service?.GetValue("ImagePath") as string;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException
                                         or UnauthorizedAccessException
                                         or IOException)
            {
                // One unreadable service must not cost the rest of the sweep.
            }
            if (!string.IsNullOrWhiteSpace(image))
            {
                yield return new RegisteredService(name, image);
            }
        }
    }
}

/// <summary>
/// Finds services whose registered command line can be pre-empted by planting an executable earlier
/// in the path Windows searches.
/// </summary>
/// <remarks>
/// This is a privilege-escalation check, not a persistence one, and it is the reason it belongs in
/// a Windows tool specifically: the vector does not exist on macOS, so nothing in the Objective-See
/// family has an equivalent. A service usually runs as SYSTEM and starts before anyone logs in, so
/// a writable earlier candidate is a straight path from "ordinary user" to "SYSTEM at boot".
/// </remarks>
public sealed class HijackScanner(IServiceRegistry? services = null, IWritabilityProbe? probe = null)
{
    private readonly IServiceRegistry _services = services ?? new RegistryServiceSource();
    private readonly HijackTriage _triage = new(probe);

    public IReadOnlyList<HijackFinding> Scan(CancellationToken cancellationToken = default)
    {
        var findings = new List<HijackFinding>();
        foreach (var service in _services.Enumerate())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_triage.Assess(service.Name, service.CommandLine) is { } finding)
            {
                findings.Add(finding);
            }
        }
        // Worst first: an occupied candidate is already a file on disk, an exploitable one is one
        // write away, and a latent one is a hygiene note.
        return findings
            .OrderBy(f => f.Exposure switch
            {
                HijackExposure.Occupied => 0,
                HijackExposure.Exploitable => 1,
                _ => 2,
            })
            .ThenBy(f => f.Service, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
