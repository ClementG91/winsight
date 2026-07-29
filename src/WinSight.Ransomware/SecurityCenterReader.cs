using System.Buffers;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace WinSight.Ransomware;

/// <summary>
/// Reads the antivirus products Windows Security Center considers registered, without changing them.
/// </summary>
/// <remarks>
/// Production acquisition uses Microsoft's documented <c>IWSCProductList</c>/<c>IWscProduct</c>
/// interfaces with only <c>WSC_SECURITY_PROVIDER_ANTIVIRUS</c>. It does not infer security posture
/// from the undocumented <c>root\SecurityCenter2</c> <c>productState</c> bit layout.
///
/// The API is supported on Windows desktop clients beginning with Windows 8 and has no supported
/// Windows Server target. Activation, initialization or enumeration failure therefore becomes an
/// explicit unavailable inventory, never a false zero-product inventory.
/// </remarks>
public sealed class SecurityCenterReader
{
    private const int UnknownRawValue = -1;
    private const int LegacyRawProductStateSentinel = 0;
    private const int MaximumDisplayNameLength = 256;
    private const int MaximumInspectedDisplayNameLength = 1024;
    private const string UnnamedAntiVirus = "(unnamed antivirus)";

    private readonly ISecurityCenterDataSource _dataSource;

    public SecurityCenterReader()
        : this(new ComSecurityCenterDataSource())
    {
    }

    /// <summary>Internal composition seam for deterministic tests and host-independent callers.</summary>
    internal SecurityCenterReader(ISecurityCenterDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    /// <summary>The exact source selected by default composition, exposed only to friend test assemblies.</summary>
    internal ISecurityCenterDataSource DataSource => _dataSource;

    /// <summary>
    /// Enumerates registered antivirus products. Provider failure degrades to unavailable;
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
        catch (Exception ex) when (ex is COMException
                                     or System.Management.ManagementException
                                     or UnauthorizedAccessException
                                     or TimeoutException
                                     or InvalidCastException
                                     or InvalidOperationException
                                     or ArgumentException
                                     or TypeLoadException
                                     or MemberAccessException
                                     or PlatformNotSupportedException
                                     or NotSupportedException
                                     or System.Security.SecurityException
                                     or System.Reflection.TargetInvocationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecurityProductInventory.Unavailable;
        }
    }

    /// <summary>
    /// Maps documented raw COM values and neutralizes product-controlled display input. A blank or
    /// malformed name remains visible as an unnamed registration instead of becoming false absence.
    /// </summary>
    internal static SecurityProductInventory ToInventory(IReadOnlyList<SecurityCenterRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var products = new List<SecurityProduct>(rows.Count);
        foreach (var row in rows)
        {
            var mappedState = row.ProductState ?? UnknownRawValue;
            var mappedSignature = row.SignatureStatus ?? UnknownRawValue;
            products.Add(new SecurityProduct(
                row.Kind,
                NormalizeDisplayName(row.DisplayName),
                SecurityProductTriage.MapProductState(mappedState),
                SecurityProductTriage.MapSignatureStatus(mappedSignature),
                LegacyRawProductStateSentinel)
            {
                RawActivityState = row.ProductState,
                RawSignatureStatus = row.SignatureStatus,
            });
        }
        return new SecurityProductInventory(SecurityCenterReading.Available, products);
    }

    private static string NormalizeDisplayName(string? displayName)
    {
        if (string.IsNullOrEmpty(displayName))
        {
            return UnnamedAntiVirus;
        }

        var inspectedLength = Math.Min(displayName.Length, MaximumInspectedDisplayNameLength);
        var input = displayName.AsSpan(0, inspectedLength);
        var normalized = new StringBuilder(Math.Min(inspectedLength, MaximumDisplayNameLength));
        var separatorPending = false;
        var offset = 0;
        while (offset < input.Length && normalized.Length < MaximumDisplayNameLength)
        {
            var status = Rune.DecodeFromUtf16(input[offset..], out var rune, out var consumed);
            if (status != OperationStatus.Done)
            {
                offset++;
                continue;
            }
            offset += consumed;

            if (Rune.IsWhiteSpace(rune))
            {
                separatorPending = normalized.Length > 0;
                continue;
            }

            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format)
            {
                continue;
            }

            var requiredLength = rune.Utf16SequenceLength + (separatorPending ? 1 : 0);
            if (normalized.Length + requiredLength > MaximumDisplayNameLength)
            {
                break;
            }
            if (separatorPending)
            {
                normalized.Append(' ');
                separatorPending = false;
            }
            normalized.Append(rune.ToString());
        }

        return normalized.Length == 0 ? UnnamedAntiVirus : normalized.ToString();
    }
}

/// <summary>Internal, injectable raw acquisition seam.</summary>
internal interface ISecurityCenterDataSource
{
    IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken);
}

/// <summary>One uninterpreted antivirus registration returned by the documented COM interface.</summary>
internal sealed record SecurityCenterRow(
    SecurityProductKind Kind,
    string? DisplayName,
    int? ProductState,
    int? SignatureStatus)
{
    /// <summary>Compatibility constructor for callers that do not yet carry signature evidence.</summary>
    internal SecurityCenterRow(SecurityProductKind kind, string? displayName, int? productState)
        : this(kind, displayName, productState, null)
    {
    }
}

/// <summary>Creates one independently owned managed product-list wrapper.</summary>
internal interface ISecurityCenterProductListFactory
{
    ISecurityCenterProductList Create();
}

/// <summary>Elemental managed projection of <c>IWSCProductList</c>, suitable for sequence testing.</summary>
internal interface ISecurityCenterProductList : IDisposable
{
    void Initialize(uint provider);

    int GetCount();

    ISecurityCenterProduct GetItem(uint index);
}

/// <summary>Elemental managed projection of one <c>IWscProduct</c>.</summary>
internal interface ISecurityCenterProduct : IDisposable
{
    string? GetProductName();

    int GetProductState();

    int GetSignatureStatus();
}

internal sealed class ComSecurityCenterDataSource : ISecurityCenterDataSource
{
    internal const uint AntiVirusProvider = 0x4;
    internal const int MaximumProducts = 64;

    private readonly ISecurityCenterProductListFactory _productListFactory;

    internal ComSecurityCenterDataSource()
        : this(new ComSecurityCenterProductListFactory())
    {
    }

    internal ComSecurityCenterDataSource(ISecurityCenterProductListFactory productListFactory)
    {
        _productListFactory = productListFactory
            ?? throw new ArgumentNullException(nameof(productListFactory));
    }

    internal ISecurityCenterProductListFactory ProductListFactory => _productListFactory;

    public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var productList = _productListFactory.Create()
            ?? throw new InvalidOperationException("Windows Security Center returned a null product list.");
        cancellationToken.ThrowIfCancellationRequested();
        productList.Initialize(AntiVirusProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var count = productList.GetCount();
        if (count is < 0 or > MaximumProducts)
        {
            throw new InvalidOperationException("Windows Security Center returned an invalid product count.");
        }

        var rows = new List<SecurityCenterRow>(count);
        for (uint index = 0; index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var product = productList.GetItem(index)
                ?? throw new InvalidOperationException("Windows Security Center returned a null product.");
            cancellationToken.ThrowIfCancellationRequested();
            var name = product.GetProductName();
            cancellationToken.ThrowIfCancellationRequested();
            var state = product.GetProductState();
            cancellationToken.ThrowIfCancellationRequested();
            var signatures = product.GetSignatureStatus();
            rows.Add(new SecurityCenterRow(
                SecurityProductKind.AntiVirus,
                name,
                state,
                signatures));
        }
        return rows;
    }
}

internal sealed class ComSecurityCenterProductListFactory : ISecurityCenterProductListFactory
{
    internal static readonly Guid ProductListClassId = new("17072F7B-9ABE-4A74-A261-1EB76B55107A");

    private readonly IComClassActivator _activator;
    private readonly IComReferenceReleaser _releaser;

    internal ComSecurityCenterProductListFactory()
        : this(new RuntimeComClassActivator(), new MarshalComReferenceReleaser())
    {
    }

    internal ComSecurityCenterProductListFactory(
        IComClassActivator activator,
        IComReferenceReleaser releaser)
    {
        _activator = activator ?? throw new ArgumentNullException(nameof(activator));
        _releaser = releaser ?? throw new ArgumentNullException(nameof(releaser));
    }

    internal IComClassActivator Activator => _activator;

    internal IComReferenceReleaser Releaser => _releaser;

    public ISecurityCenterProductList Create()
    {
        object? instance = null;
        try
        {
            instance = _activator.Activate(ProductListClassId)
                ?? throw new InvalidOperationException("Windows Security Center product-list activation failed.");
            var productList = instance as IWscProductList
                ?? throw new InvalidCastException("Windows Security Center product-list interface is unavailable.");
            return new ComSecurityCenterProductList(instance, productList, _releaser);
        }
        catch
        {
            if (instance is not null)
            {
                new ComOwnedReference(instance, _releaser).Dispose();
            }
            throw;
        }
    }
}

internal sealed class ComSecurityCenterProductList : ISecurityCenterProductList
{
    private readonly ComOwnedReference _ownedReference;
    private readonly IComReferenceReleaser _releaser;
    private IWscProductList? _productList;

    internal ComSecurityCenterProductList(
        object ownedReference,
        IWscProductList productList,
        IComReferenceReleaser releaser)
    {
        ArgumentNullException.ThrowIfNull(ownedReference);
        _productList = productList ?? throw new ArgumentNullException(nameof(productList));
        _releaser = releaser ?? throw new ArgumentNullException(nameof(releaser));
        _ownedReference = new ComOwnedReference(ownedReference, releaser);
    }

    public void Initialize(uint provider) => Current.Initialize(provider);

    public int GetCount() => Current.GetCount();

    public ISecurityCenterProduct GetItem(uint index)
    {
        var product = Current.GetItem(index)
            ?? throw new InvalidOperationException("Windows Security Center returned a null product.");
        return new ComSecurityCenterProduct(product, product, _releaser);
    }

    public void Dispose()
    {
        _ = Interlocked.Exchange(ref _productList, null);
        _ownedReference.Dispose();
    }

    private IWscProductList Current =>
        Volatile.Read(ref _productList)
        ?? throw new ObjectDisposedException(nameof(ComSecurityCenterProductList));
}

internal sealed class ComSecurityCenterProduct : ISecurityCenterProduct
{
    private readonly ComOwnedReference _ownedReference;
    private IWscProduct? _product;

    internal ComSecurityCenterProduct(
        object ownedReference,
        IWscProduct product,
        IComReferenceReleaser releaser)
    {
        ArgumentNullException.ThrowIfNull(ownedReference);
        _product = product ?? throw new ArgumentNullException(nameof(product));
        ArgumentNullException.ThrowIfNull(releaser);
        _ownedReference = new ComOwnedReference(ownedReference, releaser);
    }

    public string? GetProductName() => Current.GetProductName();

    public int GetProductState() => Current.GetProductState();

    public int GetSignatureStatus() => Current.GetSignatureStatus();

    public void Dispose()
    {
        _ = Interlocked.Exchange(ref _product, null);
        _ownedReference.Dispose();
    }

    private IWscProduct Current =>
        Volatile.Read(ref _product)
        ?? throw new ObjectDisposedException(nameof(ComSecurityCenterProduct));
}

/// <summary>Activates one COM class and returns the caller-owned RCW reference.</summary>
internal interface IComClassActivator
{
    object Activate(Guid classId);
}

/// <summary>Releases one caller-owned RCW reference.</summary>
internal interface IComReferenceReleaser
{
    void Release(object instance);
}

/// <summary>Default COM activation used by production composition.</summary>
internal sealed class RuntimeComClassActivator : IComClassActivator
{
    public object Activate(Guid classId)
    {
        var type = Type.GetTypeFromCLSID(classId, throwOnError: true)
            ?? throw new TypeLoadException("Windows Security Center product-list COM class is unavailable.");
        return System.Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Windows Security Center product-list activation failed.");
    }
}

/// <summary>
/// Production release policy. Every reference passed here is an owned RCW, so release is
/// unconditional: a failed ownership assumption must surface instead of silently leaking it.
/// </summary>
internal sealed class MarshalComReferenceReleaser : IComReferenceReleaser
{
    public void Release(object instance)
    {
        ArgumentNullException.ThrowIfNull(instance);
        _ = Marshal.ReleaseComObject(instance);
    }
}

/// <summary>
/// Owns exactly one reference until disposal. The reference is atomically made inaccessible before
/// the release callback runs, making duplicate disposal harmless and release ordering observable.
/// </summary>
internal sealed class ComOwnedReference : IDisposable
{
    private readonly IComReferenceReleaser _releaser;
    private object? _reference;

    internal ComOwnedReference(object reference, IComReferenceReleaser releaser)
    {
        _reference = reference ?? throw new ArgumentNullException(nameof(reference));
        _releaser = releaser ?? throw new ArgumentNullException(nameof(releaser));
    }

    internal object Value =>
        Volatile.Read(ref _reference)
        ?? throw new ObjectDisposedException(nameof(ComOwnedReference));

    public void Dispose()
    {
        var reference = Interlocked.Exchange(ref _reference, null);
        if (reference is not null)
        {
            _releaser.Release(reference);
        }
    }
}

[ComImport]
[Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface IWscProductList
{
    void Initialize(uint provider);

    int GetCount();

    [return: MarshalAs(UnmanagedType.Interface)]
    IWscProduct? GetItem(uint index);
}

[ComImport]
[Guid("8C38232E-3A45-4A27-92B0-1A16A975F669")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface IWscProduct
{
    [return: MarshalAs(UnmanagedType.BStr)]
    string? GetProductName();

    int GetProductState();

    int GetSignatureStatus();
}
