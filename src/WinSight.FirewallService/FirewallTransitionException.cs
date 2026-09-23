using WinSight.Firewall;

namespace WinSight.FirewallService;

public sealed class FirewallTransitionException : IOException, IFirewallFailureCode
{
    public FirewallTransitionException(string code, Exception innerException)
        : base("The firewall transition failed.", innerException) => Code = code;
    public string Code { get; }
}
