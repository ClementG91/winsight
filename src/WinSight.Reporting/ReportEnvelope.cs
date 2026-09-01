namespace WinSight.Reporting;

/// <summary>
/// The versioned wrapper around every <c>--json</c> emission.
/// </summary>
/// <remarks>
/// <b>Why a bare array was not enough.</b> The contract is consumed by the MCP server, by the VM
/// qualification kit, by <c>scripts/Test-CfaProvider.ps1</c>, and by whatever an operator wires up
/// on top of a scan they schedule. A bare array carries no way to say which version of the contract
/// produced it, so a consumer written against one shape and fed another has to guess: the only
/// signal available was a property appearing or disappearing, which is exactly what happened when
/// <c>unverifiedCount</c> was added and the CFA provider script - which asserts the report's
/// property set exactly, deliberately - had no way to know it was reading a newer contract.
///
/// A version is a promise about how it changes. Within a major version, properties are added and
/// never removed or repurposed, so a consumer that reads what it knows and ignores the rest keeps
/// working. Removing a property, renaming one, or changing what a value means is a new
/// <see cref="SchemaVersion"/>, which lets a consumer refuse rather than silently misread.
///
/// <b>Why now.</b> A version added after there are consumers is a version nobody can rely on, since
/// its absence has to be tolerated for ever. Added before, it costs one line in each of the four
/// readers that exist today.
/// </remarks>
/// <param name="SchemaVersion">
/// The contract version. Incremented only for a change a consumer cannot absorb silently.
/// </param>
/// <param name="GeneratedAt">
/// When the scan was rendered, in UTC. A report is a statement about a machine at a moment, and a
/// stored one is evidence: without this, a file in an evidence folder cannot say when it was true.
/// </param>
/// <param name="Reports">The reports, in the order the tools ran.</param>
public sealed record ReportEnvelope(
    int SchemaVersion,
    DateTimeOffset GeneratedAt,
    IReadOnlyList<ToolReport> Reports)
{
    /// <summary>The version this build emits.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Wraps reports for emission, stamped with the current time in UTC.</summary>
    public static ReportEnvelope For(IReadOnlyList<ToolReport> reports) =>
        new(CurrentSchemaVersion, DateTimeOffset.UtcNow, reports);
}
