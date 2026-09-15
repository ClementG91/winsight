using WinSight.Core;

namespace WinSight.AvMonitor;

/// <summary>
/// A part of the consent store a read could not see: a whole capability store
/// (<see cref="App"/> and <see cref="Packaged"/> null), the desktop-app subtree
/// (<see cref="App"/> null, <see cref="Packaged"/> false), or one application key.
/// </summary>
public sealed record CapabilityGap(DeviceKind Kind, CapabilityStore Store, string? App = null, bool? Packaged = null)
{
    /// <summary>Whether an observation of this app in this store could be hidden by the gap.</summary>
    public bool MayHide(DeviceKind kind, CapabilityStore store, string app, bool packaged) =>
        Kind == kind
        && Store == store
        && (App is null
            ? Packaged is null || Packaged == packaged
            : string.Equals(App, app, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Capture-device usage with the provenance needed to reason about partial reads: which store each
/// observation came from and exactly which parts could not be read.
/// </summary>
/// <remarks>
/// A count of unreadable sources says that something is hidden, not what. Without provenance, "this
/// app is stopped in one store" cannot be told apart from "this app is stopped here but still capturing
/// in the store that just became unreadable", and the monitor announced a stop the evidence did not
/// support. <see cref="ProvenanceKnown"/> is false for readers that only report counts; the monitor
/// then treats every incomplete read as possibly hiding anything.
/// </remarks>
public sealed record CapabilityAccessSnapshot(
    IReadOnlyList<DeviceUsage> Items,
    IReadOnlyList<CapabilityGap> Gaps,
    bool ProvenanceKnown = true,
    int UnattributedSources = 0,
    int UnattributedItems = 0)
{
    public bool IsComplete => Gaps.Count == 0 && UnattributedSources == 0 && UnattributedItems == 0;

    /// <summary>Whether an observation keyed by these values may have been hidden by this read.</summary>
    public bool MayHide(DeviceKind kind, CapabilityStore? store, string app, bool packaged) =>
        !IsComplete
        && (!ProvenanceKnown
            || store is not { } known
            || UnattributedSources > 0
            || UnattributedItems > 0
            || Gaps.Any(gap => gap.MayHide(kind, known, app, packaged)));

    /// <summary>The count-only view the health display and older callers use.</summary>
    public AcquisitionSnapshot<DeviceUsage> ToCoverage() => new(
        Items,
        UnattributedSources + Gaps.Count(gap => gap is { App: null, Packaged: null }),
        UnattributedItems + Gaps.Count(gap => gap is not { App: null, Packaged: null }));

    /// <summary>Wraps a count-only snapshot, whose gaps cannot be attributed.</summary>
    public static CapabilityAccessSnapshot FromCoverage(AcquisitionSnapshot<DeviceUsage> coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        return new(coverage.Items, [], ProvenanceKnown: false,
            coverage.UnreadableSources, coverage.UnreadableItems);
    }
}
