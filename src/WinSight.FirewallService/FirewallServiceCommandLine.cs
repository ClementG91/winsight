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

    /// <summary>Disabled compatibility alias; direct WFP mutation is refused.</summary>
    WfpProvision,

    /// <summary>Disabled compatibility alias; direct WFP mutation is refused.</summary>
    WfpDeprovision,

    /// <summary>Report whether the WinSight WFP provider and sublayer exist.</summary>
    WfpStatus,

    /// <summary>Disabled compatibility alias; direct WFP mutation is refused.</summary>
    WfpFilterAdd,

    /// <summary>Disabled compatibility alias; direct WFP mutation is refused.</summary>
    WfpFilterRemove,

    /// <summary>Disabled compatibility alias; policy mutation must use authenticated IPC.</summary>
    WfpBlockAdd,

    /// <summary>Disabled compatibility alias; policy mutation must use authenticated IPC.</summary>
    WfpBlockRemove,

    /// <summary>Report whether a given application is currently blocked.</summary>
    WfpBlockStatus,

    /// <summary>Report the persisted enforcement mode.</summary>
    EnforceStatus,

    /// <summary>Disabled compatibility alias; enforcement mutation must use authenticated IPC.</summary>
    EnforceEnable,

    /// <summary>Disabled compatibility alias; enforcement mutation must use authenticated IPC.</summary>
    EnforceDisable,

    /// <summary>Disabled compatibility alias; policy mutation must use authenticated IPC.</summary>
    BlockApp,

    /// <summary>Disabled compatibility alias; policy mutation must use authenticated IPC.</summary>
    AllowApp,

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
            "wfp-block-status" => FirewallServiceVerb.WfpBlockStatus,
            "enforce-status" => FirewallServiceVerb.EnforceStatus,
            "enforce-enable" => FirewallServiceVerb.EnforceEnable,
            "enforce-disable" => FirewallServiceVerb.EnforceDisable,
            "block-app" => FirewallServiceVerb.BlockApp,
            "allow-app" => FirewallServiceVerb.AllowApp,
            _ => FirewallServiceVerb.Unknown,
        };
    }
}
