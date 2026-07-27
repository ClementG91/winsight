using System.Management;
using System.Runtime.InteropServices;

namespace WinSight.Ransomware;

/// <summary>
/// Reads which security products Windows itself considers registered, without changing anything.
/// </summary>
/// <remarks>
/// <b>Why this exists.</b> WinSight could report Microsoft Defender's Controlled Folder Access posture
/// and nothing else. On a machine whose antivirus is Norton, Bitdefender or CrowdStrike, that reads as
/// "the ransomware shield is not protecting you" while saying nothing about the product that actually
/// is — an accurate sentence that leaves a false impression, which is the failure mode this project
/// treats as worse than silence.
///
/// Windows Security Center is the vendor-neutral answer: every antivirus that wants Windows to stop
/// nagging registers here, so <c>root\SecurityCenter2</c> is the one place that knows what is really
/// protecting the machine. Reading it makes WinSight correct on any machine rather than only on one
/// where Microsoft won.
///
/// Read-only, and unelevated: this reader enumerates and never registers, unregisters or configures a
/// product.
/// </remarks>
public sealed class SecurityCenterReader
{
    private readonly ISecurityCenterDataSource _dataSource;

    public SecurityCenterReader()
        : this(new WmiSecurityCenterDataSource())
    {
    }

    /// <summary>Internal composition seam for deterministic tests and host-independent callers.</summary>
    internal SecurityCenterReader(ISecurityCenterDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    /// <summary>
    /// Enumerates the registered products. A provider failure degrades to an unavailable inventory;
    /// caller-requested cancellation always propagates.
    /// </summary>
    public SecurityProductInventory Read(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var rows = _dataSource.Read(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return ToInventory(rows);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return SecurityProductInventory.Unavailable;
        }
        catch (Exception ex) when (ex is ManagementException
                                     or UnauthorizedAccessException
                                     or COMException
                                     or TimeoutException
                                     or InvalidOperationException
                                     or ArgumentException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Includes the namespace simply not existing, which is the normal state on Windows Server
            // editions: Security Center is a client feature. "Could not read" is the honest answer
            // there, and it is deliberately distinct from "no antivirus is installed".
            return SecurityProductInventory.Unavailable;
        }
    }

    /// <summary>
    /// Turns raw rows into the inventory. A row with no usable display name is dropped rather than
    /// shown as a blank product; a row whose state cannot be decoded is kept, because "a product is
    /// registered and we could not read its state" is information the operator needs.
    /// </summary>
    internal static SecurityProductInventory ToInventory(IReadOnlyList<SecurityCenterRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var products = new List<SecurityProduct>(rows.Count);
        foreach (var row in rows)
        {
            if (string.IsNullOrWhiteSpace(row.DisplayName))
            {
                continue;
            }
            var (state, signatures) = row.ProductState is { } raw
                ? SecurityProductTriage.Decode(raw)
                : (SecurityProductState.Unknown, SecurityProductSignatures.Unknown);
            products.Add(new SecurityProduct(
                row.Kind,
                row.DisplayName.Trim(),
                state,
                signatures,
                row.ProductState ?? 0));
        }
        return new SecurityProductInventory(SecurityCenterReading.Available, products);
    }
}

/// <summary>Internal, injectable raw acquisition seam.</summary>
internal interface ISecurityCenterDataSource
{
    IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken);
}

/// <summary>One un-interpreted Security Center registration.</summary>
internal sealed record SecurityCenterRow(SecurityProductKind Kind, string? DisplayName, int? ProductState);

internal sealed class WmiSecurityCenterDataSource : ISecurityCenterDataSource
{
    private const string SecurityCenterScope = @"\\.\root\SecurityCenter2";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    private static readonly (SecurityProductKind Kind, string ClassName)[] Classes =
    [
        (SecurityProductKind.AntiVirus, "AntiVirusProduct"),
        (SecurityProductKind.AntiSpyware, "AntiSpywareProduct"),
        (SecurityProductKind.Firewall, "FirewallProduct"),
    ];

    public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scope = new ManagementScope(SecurityCenterScope);
        var rows = new List<SecurityCenterRow>();
        foreach (var (kind, className) in Classes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Only the two fields this reader reasons about are selected. pathToSignedProductExe and
            // the reporting GUIDs are deliberately not read: they are not needed to answer "what is
            // protecting this machine", and a report should not carry evidence it has no use for.
            using var searcher = CreateSearcher(scope, $"SELECT displayName, productState FROM {className}");
            foreach (ManagementBaseObject row in searcher.Get())
            {
                using (row)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    rows.Add(new SecurityCenterRow(kind, row["displayName"] as string, ToInt(row["productState"])));
                }
            }
        }
        return rows;
    }

    // productState is uint32 in the class definition, but the CIM layer has been observed handing it
    // back as several integral types; narrowing is explicit rather than an unchecked cast.
    private static int? ToInt(object? value) => value switch
    {
        byte number => number,
        sbyte number => number,
        short number => number,
        ushort number => number,
        int number => number,
        uint number when number <= int.MaxValue => (int)number,
        long number when number is >= int.MinValue and <= int.MaxValue => (int)number,
        ulong number when number <= int.MaxValue => (int)number,
        _ => null,
    };

    private static ManagementObjectSearcher CreateSearcher(ManagementScope scope, string query) => new(
        scope,
        new ObjectQuery(query),
        new System.Management.EnumerationOptions
        {
            Timeout = QueryTimeout,
            ReturnImmediately = false,
            Rewindable = false,
        });
}
