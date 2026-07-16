using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSight.Firewall;

/// <summary>The service operating mode persisted with outbound policies.</summary>
public enum OutboundFirewallMode
{
    AuditOnly,
    Enforcement,
}

/// <summary>
/// A validated snapshot of outbound policies. Persisting enforcement is guarded by
/// an explicit store option; a stored value never enables WFP by itself.
/// </summary>
public sealed record OutboundFirewallConfiguration(
    OutboundFirewallMode Mode,
    IReadOnlyList<AppFirewallPolicy> Policies)
{
    public static OutboundFirewallConfiguration Empty { get; } =
        new(OutboundFirewallMode.AuditOnly, []);
}

/// <summary>The result of loading policies without ever carrying enforcement through an error.</summary>
public sealed record FirewallPolicyLoadResult(
    OutboundFirewallConfiguration Configuration,
    bool RecoveredToAuditOnly,
    string? Diagnostic = null,
    bool StorageTrusted = true);

public sealed class FirewallStorageTrustException : IOException
{
    public FirewallStorageTrustException(string code)
        : base("Privileged firewall storage is not trusted.") => Code = code;

    public string Code { get; }
}

public sealed record FirewallStorageTrustLease(bool Trusted, string Code, object? Evidence = null);

public interface IFirewallStorageTrustGuard
{
    FirewallStorageTrustLease Inspect();
    FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease);
}

/// <summary>
/// Durable JSON policy storage for the future privileged service. Writes use a
/// flushed temporary file in the destination directory followed by an atomic
/// same-volume replacement. The service must place this file in a service-owned,
/// ACL-protected directory; the dashboard must access it only through authenticated
/// IPC.
/// </summary>
public sealed class FirewallPolicyStore
{
    public const int CurrentSchemaVersion = 1;
    public const int MaxPolicyCount = 4096;
    public const int MaxFileBytes = 1024 * 1024;
    public const int MaxTotalPathUtf8Bytes = 256 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        AllowDuplicateProperties = false,
        MaxDepth = 16,
        Converters =
        {
            new JsonStringEnumConverter<OutboundFirewallMode>(),
            new JsonStringEnumConverter<OutboundAction>(),
        },
    };

    private readonly string _path;
    private readonly bool _allowEnforcement;
    private readonly Func<(bool Trusted, string Code)>? _storageTrust;
    private readonly IFirewallStorageTrustGuard? _storageTrustGuard;

    public FirewallPolicyStore(
        string path,
        bool allowEnforcement = false,
        Func<(bool Trusted, string Code)>? storageTrust = null,
        IFirewallStorageTrustGuard? storageTrustGuard = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("Firewall policy storage path must be absolute.", nameof(path));
        }

        _path = Path.GetFullPath(path);
        _allowEnforcement = allowEnforcement;
        _storageTrust = storageTrust;
        _storageTrustGuard = storageTrustGuard;
    }

    public async Task<OutboundFirewallConfiguration> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        var trustLease = DemandTrustedStorage();
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(_path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            RevalidateTrustedStorage(trustLease);
            return OutboundFirewallConfiguration.Empty;
        }

        RejectReparsePoint(_path, "policy file", attributes);
        await using var stream = new FileStream(
            _path,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            });
        RevalidateTrustedStorage(trustLease);
        if (stream.Length is <= 0 or > MaxFileBytes)
        {
            throw new InvalidDataException(
                $"Firewall policy file size must be between 1 and {MaxFileBytes} bytes.");
        }

        try
        {
            var document = await JsonSerializer.DeserializeAsync<PolicyDocument>(
                stream,
                SerializerOptions,
                cancellationToken).ConfigureAwait(false);
            return Validate(document ?? throw new InvalidDataException("Firewall policy file is empty."));
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Firewall policy file is not valid strict JSON.", ex);
        }
    }

    /// <summary>
    /// Loads a snapshot and converts malformed, inaccessible or unsafe storage into
    /// an empty audit-only configuration. Cancellation still propagates.
    /// </summary>
    public async Task<FirewallPolicyLoadResult> LoadOrAuditAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            return new FirewallPolicyLoadResult(
                await LoadAsync(cancellationToken).ConfigureAwait(false),
                RecoveredToAuditOnly: false);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            var storageTrusted = ex is not FirewallStorageTrustException;
            return new FirewallPolicyLoadResult(
                OutboundFirewallConfiguration.Empty,
                RecoveredToAuditOnly: true,
                storageTrusted ? "PolicyContentInvalid" : ((FirewallStorageTrustException)ex).Code,
                storageTrusted);
        }
    }

    public async Task SaveAsync(
        OutboundFirewallConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var trustLease = DemandTrustedStorage();
        var validated = Validate(new PolicyDocument(
            CurrentSchemaVersion,
            configuration.Mode,
            configuration.Policies?.ToArray()
                ?? throw new ArgumentException("Policies cannot be null.", nameof(configuration))));
        var document = new PolicyDocument(
            CurrentSchemaVersion,
            validated.Mode,
            validated.Policies.ToArray());
        var payload = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
        if (payload.Length > MaxFileBytes)
        {
            throw new InvalidDataException(
                $"Serialized firewall policy file exceeds {MaxFileBytes} bytes.");
        }

        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Firewall policy path has no parent directory.");
        Directory.CreateDirectory(directory);
        RejectReparsePoint(directory, "policy directory");
        if (File.Exists(_path))
        {
            RejectReparsePoint(_path, "policy file");
        }

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.Asynchronous | FileOptions.WriteThrough,
                }))
            {
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            RevalidateTrustedStorage(trustLease);
            File.Move(temporaryPath, _path, overwrite: true);
            _ = DemandTrustedStorage();
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private FirewallStorageTrustLease DemandTrustedStorage()
    {
        if (_storageTrustGuard is not null)
        {
            var lease = _storageTrustGuard.Inspect();
            Demand(lease);
            return lease;
        }
        if (_storageTrust is null)
        {
            return new(true, "StorageTrustNotConfigured");
        }
        var decision = _storageTrust();
        if (!decision.Trusted)
        {
            throw new FirewallStorageTrustException(NormalizeCode(decision.Code));
        }
        return new(true, NormalizeCode(decision.Code));
    }

    private void RevalidateTrustedStorage(FirewallStorageTrustLease lease)
    {
        if (_storageTrustGuard is not null)
        {
            Demand(_storageTrustGuard.Revalidate(lease));
        }
    }

    private static void Demand(FirewallStorageTrustLease lease)
    {
        if (!lease.Trusted) throw new FirewallStorageTrustException(NormalizeCode(lease.Code));
    }

    private static string NormalizeCode(string? code) =>
        string.IsNullOrWhiteSpace(code) ? "StorageInspectionFailed" : code;

    private OutboundFirewallConfiguration Validate(PolicyDocument document)
    {
        if (document.SchemaVersion != CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"Unsupported firewall policy schema {document.SchemaVersion}.");
        }
        if (!Enum.IsDefined(document.Mode))
        {
            throw new InvalidDataException("Firewall policy mode is invalid.");
        }
        if (document.Mode == OutboundFirewallMode.Enforcement && !_allowEnforcement)
        {
            throw new InvalidDataException(
                "Enforcement policy loading requires an explicitly enabled service gate.");
        }
        if (document.Policies is null || document.Policies.Length > MaxPolicyCount)
        {
            throw new InvalidDataException(
                $"Firewall policy count must not exceed {MaxPolicyCount}.");
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var policies = new List<AppFirewallPolicy>(document.Policies.Length);
        var totalPathBytes = 0;
        foreach (var policy in document.Policies)
        {
            if (policy is null || !Enum.IsDefined(policy.Action))
            {
                throw new InvalidDataException("Firewall policy entry is invalid.");
            }

            string path;
            try
            {
                path = OutboundPolicyEvaluator.CanonicalPath(policy.ExecutablePath);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                throw new InvalidDataException("Firewall policy executable path is invalid.", ex);
            }
            if (path.Length > short.MaxValue
                || path.Any(char.IsControl)
                || !paths.Add(path))
            {
                throw new InvalidDataException(
                    path.Length > short.MaxValue
                        ? "Firewall policy executable path is too long."
                        : path.Any(char.IsControl)
                            ? "Firewall policy executable path contains control characters."
                        : $"Duplicate firewall policy for '{path}'.");
            }
            totalPathBytes += Encoding.UTF8.GetByteCount(path);
            if (totalPathBytes > MaxTotalPathUtf8Bytes)
            {
                throw new InvalidDataException(
                    $"Firewall policy paths exceed the {MaxTotalPathUtf8Bytes}-byte budget.");
            }
            policies.Add(policy with { ExecutablePath = path });
        }

        return new OutboundFirewallConfiguration(document.Mode, policies.AsReadOnly());
    }

    private static void RejectReparsePoint(
        string path,
        string description,
        FileAttributes? knownAttributes = null)
    {
        if (((knownAttributes ?? File.GetAttributes(path)) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Refusing a reparse-point {description}: '{path}'.");
        }
    }

    private sealed record PolicyDocument(
        int SchemaVersion,
        OutboundFirewallMode Mode,
        AppFirewallPolicy[] Policies);
}
