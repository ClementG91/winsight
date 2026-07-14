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

    /// <summary>Create the WinSight WFP provider and sublayer (containers only, no filter).</summary>
    WfpProvision,

    /// <summary>Remove the WinSight WFP provider and sublayer.</summary>
    WfpDeprovision,

    /// <summary>Report whether the WinSight WFP provider and sublayer exist.</summary>
    WfpStatus,

    /// <summary>Add a non-blocking PERMIT filter to the WinSight sublayer (blocks nothing).</summary>
    WfpFilterAdd,

    /// <summary>Remove the non-blocking PERMIT filter.</summary>
    WfpFilterRemove,

    /// <summary>Block one application's outbound connections (matched by executable path).</summary>
    WfpBlockAdd,

    /// <summary>Remove the per-application BLOCK filter.</summary>
    WfpBlockRemove,

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
            "wfp-provision" => FirewallServiceVerb.WfpProvision,
            "wfp-deprovision" => FirewallServiceVerb.WfpDeprovision,
            "wfp-status" => FirewallServiceVerb.WfpStatus,
            "wfp-filter-add" => FirewallServiceVerb.WfpFilterAdd,
            "wfp-filter-remove" => FirewallServiceVerb.WfpFilterRemove,
            "wfp-block-add" => FirewallServiceVerb.WfpBlockAdd,
            "wfp-block-remove" => FirewallServiceVerb.WfpBlockRemove,
            _ => FirewallServiceVerb.Unknown,
        };
    }
}
