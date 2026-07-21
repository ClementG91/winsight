namespace WinSight.Attribution;

/// <summary>
/// A source of attributed write observations.
/// </summary>
/// <remarks>
/// Exists so the host above it can be tested without a kernel trace session and without
/// Administrator. The same reasoning as the capture-device reader: a component whose only
/// implementation needs elevation is a component whose lifecycle nobody ever exercises, and an
/// untested lifecycle around a security monitor is how a monitor comes to be silently dead.
/// </remarks>
public interface IWriteWatcher
{
    /// <summary>
    /// Reports writes until cancelled. Blocking. Throws <see cref="UnauthorizedAccessException"/>
    /// when the caller lacks the privilege the implementation needs.
    /// </summary>
    /// <param name="onWrite">Called for each write that could be attributed.</param>
    /// <param name="onUnattributed">Called for each write that could not, with the reason.</param>
    /// <param name="token">Stops the watch.</param>
    void Watch(
        Action<WriteObservation> onWrite,
        Action<UnattributedWrite>? onUnattributed,
        CancellationToken token);
}
