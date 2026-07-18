using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinSight.Firewall;

/// <summary>Commands accepted by the local firewall service.</summary>
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
    SnapshotChanged,
}

/// <summary>
/// Effective enforcement state observed by the running privileged service. This is deliberately
/// independent of the durable desired mode: persisted <c>Enforcement</c> does not mean that WFP
/// filters were successfully applied during this service lifetime.
/// </summary>
public enum FirewallEnforcementState
{
    AuditOnly,
    Active,
    Degraded,
}

public sealed record FirewallCommandRequest(
    int ProtocolVersion,
    Guid RequestId,
    FirewallCommand Command,
    AppFirewallPolicy? Policy = null,
    string? ExecutablePath = null,
    int? Offset = null,
    int? Limit = null,
    string? SnapshotVersion = null);

/// <param name="UnrecordedApps">
/// Applications seen reaching the network that could not be recorded because the pending log was
/// full. Carried so a caller can say "and more were not recorded" rather than present a truncated
/// list as complete: a tool that hides its own blind spot is worse than one without the feature.
/// </param>
public sealed record FirewallServiceStatus(
    OutboundFirewallMode Mode,
    bool EngineSupported,
    bool EnforcementEnabled,
    int UnrecordedApps = 0,
    FirewallEnforcementState EffectiveState = FirewallEnforcementState.AuditOnly);

public sealed record FirewallCommandResponse(
    int ProtocolVersion,
    Guid RequestId,
    bool Success,
    FirewallProtocolError Error = FirewallProtocolError.None,
    FirewallServiceStatus? Status = null,
    AppFirewallPolicy[]? Policies = null,
    int? NextOffset = null,
    PendingOutboundApp[]? Pending = null,
    string? SnapshotVersion = null,
    int? SnapshotCount = null);

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
/// The connected peer could not be proven to be the expected LocalSystem service, or
/// its response was not bound to the request that was sent. The message is deliberately
/// fixed: ownership and protocol details must not cross the dashboard boundary.
/// </summary>
public sealed class FirewallPeerValidationException : IOException
{
    public const string FixedMessage = "The WinSight firewall service peer could not be validated.";

    public FirewallPeerValidationException()
        : base(FixedMessage)
    {
    }
}

/// <summary>
/// An authenticated peer closed a version probe before writing any response byte. This
/// is the only legacy-service signal that permits a read-only v1 retry; partial, malformed
/// or timed-out responses remain failures and must never trigger protocol downgrade.
/// </summary>
public sealed class FirewallLegacyPeerClosedException : IOException
{
    public const string FixedMessage =
        "The WinSight firewall service closed the protocol probe without a response.";

    public FirewallLegacyPeerClosedException()
        : base(FixedMessage)
    {
    }
}

/// <summary>
/// Strict length-prefixed JSON framing for authenticated local IPC. This codec does
/// not authenticate either peer: the client must prove the connected pipe owner is
/// LocalSystem, while the host must use a restrictive ACL and validate the impersonated
/// Windows identity before decoding or executing any command.
/// </summary>
public static class FirewallProtocolCodec
{
    /// <summary>
    /// Version 3 binds every paginated page to one complete immutable snapshot. Version 2 carries
    /// runtime enforcement proof and version 1 remains conservative for staged upgrades.
    /// </summary>
    public const int CurrentVersion = 3;
    public const int RuntimeProofVersion = 2;
    public const int LegacyVersion = 1;
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
            new JsonStringEnumConverter<FirewallEnforcementState>(),
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
        // Version 1 clients reject unmapped JSON members. Never send effectiveState to one:
        // legacy protocol has no runtime proof and must remain conservative at the new client.
        return response.ProtocolVersion switch
        {
            LegacyVersion => WriteFrameAsync(stream, LegacyResponse.From(response), cancellationToken),
            RuntimeProofVersion => WriteFrameAsync(stream, RuntimeProofResponse.From(response), cancellationToken),
            _ => WriteFrameAsync(stream, response, cancellationToken),
        };
    }

    public static async Task<FirewallCommandResponse> ReadResponseAsync(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        var frame = await ReadFrameAsync<JsonElement>(
            stream,
            cancellationToken,
            classifyEmptyResponse: true).ConfigureAwait(false);
        var version = ReadProtocolVersion(frame);
        var response = version switch
        {
            LegacyVersion => LegacyResponse.ToCurrent(Deserialize<LegacyResponse>(frame)),
            RuntimeProofVersion => RuntimeProofResponse.ToCurrent(Deserialize<RuntimeProofResponse>(frame)),
            _ => Deserialize<FirewallCommandResponse>(frame),
        };
        ValidateResponse(response);
        return response;
    }

    private static int ReadProtocolVersion(JsonElement frame)
    {
        if (frame.ValueKind != JsonValueKind.Object
            || !frame.TryGetProperty("protocolVersion", out var version)
            || !version.TryGetInt32(out var value))
        {
            throw InvalidFrame("Protocol response version is invalid.");
        }
        return value;
    }

    private static T Deserialize<T>(JsonElement frame)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(frame.GetRawText(), SerializerOptions)
                ?? throw InvalidFrame("Protocol message is empty.");
        }
        catch (JsonException ex)
        {
            throw InvalidFrame("Protocol message is not valid strict JSON.", ex);
        }
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
        CancellationToken cancellationToken,
        bool classifyEmptyResponse = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("Protocol stream must be readable.", nameof(stream));
        }

        var header = new byte[sizeof(int)];
        try
        {
            var firstByteCount = await stream.ReadAsync(
                header.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (firstByteCount == 0)
            {
                if (classifyEmptyResponse)
                {
                    throw new FirewallLegacyPeerClosedException();
                }
                throw new EndOfStreamException();
            }
            await stream.ReadExactlyAsync(header.AsMemory(1), cancellationToken).ConfigureAwait(false);
        }
        catch (FirewallLegacyPeerClosedException)
        {
            throw;
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
                    || request.Limit is not > 0 or > MaxPoliciesPerMessage
                    || (request.ProtocolVersion == CurrentVersion
                        && ((request.Offset == 0 && request.SnapshotVersion is not null)
                            || (request.Offset > 0 && !IsSnapshotVersion(request.SnapshotVersion))))
                    || (request.ProtocolVersion != CurrentVersion && request.SnapshotVersion is not null))
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
            || (response.Error == FirewallProtocolError.SnapshotChanged
                && response.ProtocolVersion != CurrentVersion)
            || (response.Success && response.Error != FirewallProtocolError.None)
            || (!response.Success && response.Error == FirewallProtocolError.None)
            || (!response.Success
                && (response.Status is not null
                    || response.Policies is not null
                    || response.NextOffset is not null
                    || response.Pending is not null
                    || response.SnapshotVersion is not null
                    || response.SnapshotCount is not null)))
        {
            throw InvalidFrame("Protocol response status is inconsistent.");
        }
        if (response.Status is { } status
            && (!Enum.IsDefined(status.Mode)
                || !Enum.IsDefined(status.EffectiveState)
                || (status.Mode == OutboundFirewallMode.AuditOnly && status.EnforcementEnabled)
                || (status.EnforcementEnabled && (!status.EngineSupported
                    || status.EffectiveState != FirewallEnforcementState.Active))
                || (status.EffectiveState == FirewallEnforcementState.Active
                    && (status.Mode != OutboundFirewallMode.Enforcement
                        || !status.EnforcementEnabled))
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
        var hasList = response.Policies is not null || response.Pending is not null;
        if (response.ProtocolVersion == CurrentVersion)
        {
            if (hasList
                && (!IsSnapshotVersion(response.SnapshotVersion)
                    || response.SnapshotCount is not >= 0
                    || response.SnapshotCount < (response.Policies?.Length ?? response.Pending?.Length ?? 0)
                    || response.NextOffset > response.SnapshotCount)
                || (!hasList && (response.SnapshotVersion is not null || response.SnapshotCount is not null)))
            {
                throw InvalidFrame("Protocol snapshot pagination is inconsistent.");
            }
        }
        else if (response.SnapshotVersion is not null
                 || response.SnapshotCount is not null
                 || response.NextOffset is not null)
        {
            throw InvalidFrame("Legacy protocol response contains unsupported pagination metadata.");
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
        if (version is not LegacyVersion and not RuntimeProofVersion and not CurrentVersion)
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
        request.Offset is not null || request.Limit is not null || request.SnapshotVersion is not null;

    public static bool IsSnapshotVersion(string? value) =>
        value is { Length: 64 } && value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

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

    // Deliberately private wire DTOs: protocol v1 did not define effectiveState, and keeping it
    // absent is required for already-deployed strict v1 dashboards.
    private sealed record LegacyStatus(
        OutboundFirewallMode Mode,
        bool EngineSupported,
        bool EnforcementEnabled,
        int UnrecordedApps = 0);

    private sealed record LegacyResponse(
        int ProtocolVersion,
        Guid RequestId,
        bool Success,
        FirewallProtocolError Error = FirewallProtocolError.None,
        LegacyStatus? Status = null,
        AppFirewallPolicy[]? Policies = null,
        int? NextOffset = null,
        PendingOutboundApp[]? Pending = null)
    {
        public static LegacyResponse From(FirewallCommandResponse response)
        {
            var status = response.Status;
            var active = status?.EffectiveState == FirewallEnforcementState.Active;
            return new(response.ProtocolVersion, response.RequestId, response.Success, response.Error,
                status is not null
                    ? new LegacyStatus(
                        active ? OutboundFirewallMode.Enforcement : OutboundFirewallMode.AuditOnly,
                        status.EngineSupported,
                        EnforcementEnabled: active,
                        status.UnrecordedApps)
                    : null,
                response.Policies, response.NextOffset, response.Pending);
        }

        public static FirewallCommandResponse ToCurrent(LegacyResponse response) =>
            new(response.ProtocolVersion, response.RequestId, response.Success, response.Error,
                response.Status is { } status
                    // A v1 service only reported desired enforcement. Its reply is deliberately
                    // projected as degraded: a v2 presentation must not claim live filters
                    // without v2 runtime proof.
                    ? new FirewallServiceStatus(
                        status.Mode,
                        status.EngineSupported,
                        EnforcementEnabled: false,
                        UnrecordedApps: status.UnrecordedApps,
                        EffectiveState: status.Mode == OutboundFirewallMode.Enforcement
                            ? FirewallEnforcementState.Degraded
                            : FirewallEnforcementState.AuditOnly)
                    : null,
                response.Policies, response.NextOffset, response.Pending);
    }

    // Protocol v2 carries effective runtime proof but predates snapshot-bound pagination. A
    // dedicated DTO keeps v3 members absent for strict independently upgraded v2 peers.
    private sealed record RuntimeProofResponse(
        int ProtocolVersion,
        Guid RequestId,
        bool Success,
        FirewallProtocolError Error = FirewallProtocolError.None,
        FirewallServiceStatus? Status = null,
        AppFirewallPolicy[]? Policies = null,
        int? NextOffset = null,
        PendingOutboundApp[]? Pending = null)
    {
        public static RuntimeProofResponse From(FirewallCommandResponse response) =>
            new(response.ProtocolVersion, response.RequestId, response.Success, response.Error,
                response.Status, response.Policies, response.NextOffset, response.Pending);

        public static FirewallCommandResponse ToCurrent(RuntimeProofResponse response) =>
            new(response.ProtocolVersion, response.RequestId, response.Success, response.Error,
                response.Status, response.Policies, response.NextOffset, response.Pending);
    }
}
