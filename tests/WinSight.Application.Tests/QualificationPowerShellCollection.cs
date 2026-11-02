using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// These fixtures start native Windows PowerShell children and parse the qualification drivers.
/// Keep them apart from other collections so process startup does not compete with the full suite
/// on native Arm64 runners. Their per-child deadlines and recovery assertions remain unchanged.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class QualificationPowerShellCollection
{
    public const string Name = "qualification-powershell";
}
