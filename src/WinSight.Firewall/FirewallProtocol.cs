using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSight.Firewall;

/// <summary>Commands accepted by the future local firewall service.</summary>
public enum FirewallCommand
{
    GetStatus = 1,
    ListPolicies = 2,
    UpsertPolicy = 3,
    RemovePolicy = 4,
    EmergencyDisable = 5,
    EnableEnforcement = 6,
    ListPending = 7,
}

/// <summary>Stable machine-readable service errors; no exception detail crosses IPC.</summary>
public enum FirewallProtocolError
{
    None,
    InvalidRequest,
    UnsupportedVersion,
    Unauthorized,
    NotSupported,
    InternalFailure,
}

public sealed record FirewallCommandRequest(
    int ProtocolVersion,
    Guid RequestId,
    FirewallCommand Command,
    AppFirewallPolicy? Policy = null,
    string? ExecutablePath = null,
    int? Offset = null,
    int? Limit = null);

/// <param name="UnrecordedApps">
/// Applications seen reaching the network that could not be recorded because the pending log was
/// full. Carried so a caller can say "and more were not recorded" rather than present a truncated
/// list as complete: a tool that hides its own blind spot is worse than one without the feature.
/// </param>
public sealed record FirewallServiceStatus(
    OutboundFirewallMode Mode,
    bool EngineSupported,
    bool EnforcementEnabled,
    int UnrecordedApps = 0);

public sealed record FirewallCommandResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    FirewallProtocolError Error = FirewallProtocolError.None,
    FirewallServiceStatus? Status = null,
    AppFirewallPolicy[]? Policies = null,
    int? NextOffset = null,
    PendingOutboundApp[]? Pending = null);

/// <summary>An invalid, unsupported or over-sized local protocol frame.</summary>
public sealed class FirewallProtocolException : IOException
{
    public FirewallProtocolException(FirewallProtocolError error, string message)
        : base(message) => Error = error;

    public FirewallProtocolException(
        FirewallProtocolError error,
        string message,
        Exception innerException)
        : base(message, innerException) => Error = error;

    public FirewallProtocolError Error { get; }
}

/// <summary>
/// Strict length-prefixed JSON framing for authenticated local IPC. This codec
/// deliberately does not authenticate a caller: the named-pipe host must use a
/// restrictive ACL and validate the impersonated Windows identity before decoding
/// or executing any command.
/// </summary>
public static class FirewallProtocolCodec
{
    public const int CurrentVersion = 1;
    public const int MaxMessageBytes = 64 * 1024;
    public const int MaxPoliciesPerMessage = 128;
    public const int MaxPathUtf8BytesPerMessage = 32 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        AllowDuplicateProperties = false,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 16,
        Converters =
        {
            new JsonStringEnumConverter<FirewallCommand>(),
            new JsonStringEnumConverter<FirewallProtocolError>(),
            new JsonStringEnumConverter<OutboundFirewallMode>(),
            new JsonStringEnumConverter<OutboundAction>(),
        },
    };

    public static Task WriteRequestAsync(
        Stream stream,
        FirewallCommandRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        return WriteFrameAsync(stream, request, cancellationToken);
    }

    public static async Task<FirewallCommandRequest> ReadRequestAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        var request = await ReadFrameAsync<FirewallCommandRequest>(
            stream,
            cancellationToken).ConfigureAwait(false);
        ValidateRequest(request);
        return request;
    }

    public static Task WriteResponseAsync(
        Stream stream,
        FirewallCommandResponse response,
        CancellationToken cancellationToken = default)
    {
        ValidateResponse(response);
        return WriteFrameAsync(stream, response, cancellationToken);
    }

    public static async Task<FirewallCommandResponse> ReadResponseAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        var response = await ReadFrameAsync<FirewallCommandResponse>(
            stream,
            cancellationToken).ConfigureAwait(false);
        ValidateResponse(response);
        return response;
    }

    private static async Task WriteFrameAsync<T>(
        Stream stream,
        T message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanWrite)
        {
            throw new ArgumentException("Protocol stream must be writable.", nameof(stream));
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(message, SerializerOptions);
        if (payload.Length is <= 0 or > MaxMessageBytes)
        {
            throw new FirewallProtocolException(
                FirewallProtocolError.InvalidRequest,
                $"Protocol message exceeds the {MaxMessageBytes}-byte limit.");
        }

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> ReadFrameAsync<T>(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("Protocol stream must be readable.", nameof(stream));
        }

        var header = new byte[sizeof(int)];
        try
        {
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException ex)
        {
            throw InvalidFrame("Protocol frame header is truncated.", ex);
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxMessageBytes)
        {
            throw new FirewallProtocolException(
                FirewallProtocolError.InvalidRequest,
                $"Protocol frame length must be between 1 and {MaxMessageBytes} bytes.");
        }

        var payload = new byte[length];
        try
        {
            await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException ex)
        {
            throw InvalidFrame("Protocol frame payload is truncated.", ex);
        }

        try
        {
            return JsonSerializer.Deserialize<T>(payload, SerializerOptions)
                ?? throw InvalidFrame("Protocol message is empty.");
        }
        catch (JsonException ex)
        {
            throw InvalidFrame("Protocol message is not valid strict JSON.", ex);
        }
    }

    private static void ValidateRequest(FirewallCommandRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateEnvelope(request.ProtocolVersion, request.RequestId);
        if (!Enum.IsDefined(request.Command))
        {
            throw InvalidFrame("Protocol command is invalid.");
        }

        switch (request.Command)
        {
            case FirewallCommand.GetStatus:
            case FirewallCommand.EmergencyDisable:
            case FirewallCommand.EnableEnforcement:
                if (HasPayload(request) || HasPaging(request))
                {
                    throw InvalidFrame("Protocol command contains an unexpected payload.");
                }
                break;
            case FirewallCommand.ListPolicies:
            case FirewallCommand.ListPending:
                if (HasPayload(request)
                    || request.Offset is not >= 0
                    || request.Limit is not > 0 or > MaxPoliciesPerMessage)
                {
                    throw InvalidFrame(
                        $"A list command requires an offset and a limit up to {MaxPoliciesPerMessage}.");
                }
                break;
            case FirewallCommand.UpsertPolicy:
                if (request.Policy is null || request.ExecutablePath is not null || HasPaging(request))
                {
                    throw InvalidFrame("UpsertPolicy requires exactly one policy payload.");
                }
                ValidatePolicy(request.Policy);
                break;
            case FirewallCommand.RemovePolicy:
                if (request.Policy is not null
                    || string.IsNullOrWhiteSpace(request.ExecutablePath)
                    || HasPaging(request))
                {
                    throw InvalidFrame("RemovePolicy requires exactly one executable path.");
                }
                ValidatePath(request.ExecutablePath);
                break;
        }
    }

    private static void ValidateResponse(FirewallCommandResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ValidateEnvelope(response.ProtocolVersion, response.RequestId);
        if (!Enum.IsDefined(response.Error)
            || (response.Success && response.Error != FirewallProtocolError.None)
            || (!response.Success && response.Error == FirewallProtocolError.None)
            || (!response.Success
                && (response.Status is not null
                    || response.Policies is not null
                    || response.NextOffset is not null
                    || response.Pending is not null)))
        {
            throw InvalidFrame("Protocol response status is inconsistent.");
        }
        if (response.Status is { } status
            && (!Enum.IsDefined(status.Mode)
                || (status.Mode == OutboundFirewallMode.AuditOnly && status.EnforcementEnabled)
                || (status.EnforcementEnabled && !status.EngineSupported)
                || status.UnrecordedApps < 0))
        {
            throw InvalidFrame("Protocol service status is inconsistent.");
        }
        if (response.Policies is { Length: > MaxPoliciesPerMessage }
            || response.Pending is { Length: > MaxPoliciesPerMessage })
        {
            throw InvalidFrame("Protocol response contains too many entries.");
        }
        // A page can carry policies or pending apps, never both: one offset cannot page two lists.
        if (response.Policies is not null && response.Pending is not null)
        {
            throw InvalidFrame("Protocol response mixes two paged lists.");
        }
        if (response.NextOffset is < 0
            || (response.NextOffset is not null && response.Policies is null && response.Pending is null))
        {
            throw InvalidFrame("Protocol response pagination is inconsistent.");
        }
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalPathBytes = 0;
        foreach (var policy in response.Policies ?? [])
        {
            var path = policy is null ? null : ValidatePolicy(policy);
            if (path is null || !paths.Add(path))
            {
                throw InvalidFrame("Protocol response contains an invalid or duplicate policy.");
            }
            totalPathBytes += Encoding.UTF8.GetByteCount(path);
            if (totalPathBytes > MaxPathUtf8BytesPerMessage)
            {
                throw InvalidFrame("Protocol response policy paths exceed the message budget.");
            }
        }

        var pendingPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pendingPathBytes = 0;
        foreach (var app in response.Pending ?? [])
        {
            var path = app is null ? null : ValidatePendingApp(app);
            if (path is null || !pendingPaths.Add(path))
            {
                throw InvalidFrame("Protocol response contains an invalid or duplicate pending app.");
            }
            pendingPathBytes += Encoding.UTF8.GetByteCount(path);
            if (pendingPathBytes > MaxPathUtf8BytesPerMessage)
            {
                throw InvalidFrame("Protocol response pending paths exceed the message budget.");
            }
        }
    }

    /// <summary>
    /// A pending app is evidence an operator acts on, so it is held to the same identity rule as a
    /// policy: the path must canonicalize, because that is what any decision will be keyed on.
    /// </summary>
    private static string ValidatePendingApp(PendingOutboundApp app)
    {
        if (string.IsNullOrWhiteSpace(app.LastRemote)
            || app.Observations <= 0
            || app.LastSeenUtc < app.FirstSeenUtc)
        {
            throw InvalidFrame("Protocol pending app is inconsistent.");
        }
        return ValidatePath(app.ExecutablePath);
    }

    private static void ValidateEnvelope(int version, Guid requestId)
    {
        if (version != CurrentVersion)
        {
            throw new FirewallProtocolException(
                FirewallProtocolError.UnsupportedVersion,
                $"Unsupported firewall protocol version {version}.");
        }
        if (requestId == Guid.Empty)
        {
            throw InvalidFrame("Protocol request id cannot be empty.");
        }
    }

    private static bool HasPayload(FirewallCommandRequest request) =>
        request.Policy is not null || request.ExecutablePath is not null;

    private static bool HasPaging(FirewallCommandRequest request) =>
        request.Offset is not null || request.Limit is not null;

    private static string ValidatePolicy(AppFirewallPolicy policy)
    {
        if (!Enum.IsDefined(policy.Action))
        {
            throw InvalidFrame("Protocol policy action is invalid.");
        }
        return ValidatePath(policy.ExecutablePath);
    }

    private static string ValidatePath(string path)
    {
        try
        {
            var canonical = OutboundPolicyEvaluator.CanonicalPath(path);
            if (canonical.Length > short.MaxValue)
            {
                throw InvalidFrame("Protocol executable path is too long.");
            }
            return canonical;
        }
        catch (FirewallProtocolException)
        {
            throw;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw InvalidFrame("Protocol executable path is invalid.", ex);
        }
    }

    private static FirewallProtocolException InvalidFrame(string message) =>
        new(FirewallProtocolError.InvalidRequest, message);

    private static FirewallProtocolException InvalidFrame(string message, Exception innerException) =>
        new(FirewallProtocolError.InvalidRequest, message, innerException);
}
