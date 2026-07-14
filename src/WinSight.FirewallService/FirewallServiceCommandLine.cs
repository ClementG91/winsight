namespace WinSight.FirewallService;

/// <summary>The verb the service executable was launched with.</summary>
public enum FirewallServiceVerb
{
    /// <summary>Run the host (how the SCM and console debugging start it).</summary>
    Run,

    /// <summary>Register the Windows service (requires elevation).</summary>
    Install,

    /// <summary>Remove the Windows service (requires elevation).</summary>
    Uninstall,

    /// <summary>Print whether the service is installed.</summary>
    Status,

    /// <summary>Read-only WFP interop probe (opens the engine, counts filters, changes nothing).</summary>
    WfpSelfTest,

    /// <summary>Unrecognized verb.</summary>
    Unknown,
}

/// <summary>Parses the service executable's command-line verb. Pure and unit-tested.</summary>
public static class FirewallServiceCommandLine
{
    public static FirewallServiceVerb Parse(IReadOnlyList<string>? args)
    {
        if (args is null || args.Count == 0)
        {
            return FirewallServiceVerb.Run;
        }

        return args[0].ToLowerInvariant() switch
        {
            "run" => FirewallServiceVerb.Run,
            "install" => FirewallServiceVerb.Install,
            "uninstall" or "remove" => FirewallServiceVerb.Uninstall,
            "status" => FirewallServiceVerb.Status,
            "wfp-selftest" => FirewallServiceVerb.WfpSelfTest,
            _ => FirewallServiceVerb.Unknown,
        };
    }
}
