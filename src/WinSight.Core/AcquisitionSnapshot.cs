namespace WinSight.Core;

/// <summary>
/// A scanner acquisition plus the coverage it could not obtain. An empty item list is a valid
/// observation only when both counters are zero; callers must surface incomplete coverage rather
/// than turn an access/provider failure into a clean result.
/// </summary>
public sealed record AcquisitionSnapshot<T>
{
    public AcquisitionSnapshot(
        IReadOnlyList<T> items,
        int unreadableSources = 0,
        int unreadableItems = 0)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentOutOfRangeException.ThrowIfNegative(unreadableSources);
        ArgumentOutOfRangeException.ThrowIfNegative(unreadableItems);

        Items = items;
        UnreadableSources = unreadableSources;
        UnreadableItems = unreadableItems;
    }

    public IReadOnlyList<T> Items { get; }

    public int UnreadableSources { get; }

    public int UnreadableItems { get; }

    public bool IsComplete => UnreadableSources == 0 && UnreadableItems == 0;
}
