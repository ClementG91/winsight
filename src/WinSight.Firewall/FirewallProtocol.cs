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

public sealed record FirewallServiceStatus(
    OutboundFirewallMode Mode,
    bool EngineSupported,
    bool EnforcementEnabled);

public sealed record FirewallCommandResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    FirewallProtocolError Error = FirewallProtocolError.None,
    FirewallServiceStatus? Status = null,
    AppFirewallPolicy[]? Policies = null,
    int? NextOffset = null);

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
                if (HasPayload(request) || HasPaging(request))
                {
                    throw InvalidFrame("Protocol command contains an unexpected payload.");
                }
                break;
            case FirewallCommand.ListPolicies:
                if (HasPayload(request)
                    || request.Offset is not >= 0
                    || request.Limit is not > 0 or > MaxPoliciesPerMessage)
                {
                    throw InvalidFrame(
                        $"ListPolicies requires an offset and a limit up to {MaxPoliciesPerMessage}.");
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
                    || response.NextOffset is not null)))
        {
            throw InvalidFrame("Protocol response status is inconsistent.");
        }
        if (response.Status is { } status
            && (!Enum.IsDefined(status.Mode)
                || (status.Mode == OutboundFirewallMode.AuditOnly && status.EnforcementEnabled)
                || (status.EnforcementEnabled && !status.EngineSupported)))
        {
            throw InvalidFrame("Protocol service status is inconsistent.");
        }
        if (response.Policies is { Length: > MaxPoliciesPerMessage })
        {
            throw InvalidFrame("Protocol response contains too many policies.");
        }
        if (response.NextOffset is < 0 || (response.NextOffset is not null && response.Policies is null))
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
