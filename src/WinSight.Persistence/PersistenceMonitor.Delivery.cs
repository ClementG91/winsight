namespace WinSight.Persistence;

/// <summary>
/// Delivery: arrivals and coverage-gain notices are queued, handed to every subscriber at least once,
/// and kept out of the saved baseline until they have been.
/// </summary>
public sealed partial class PersistenceMonitor
{
    private void EnqueueLocked(IReadOnlyList<PersistenceEvent> detected)
    {
        foreach (var ev in detected)
        {
            _undelivered.RemoveAll(pending => pending.Event.Identity == ev.Identity);
            _undelivered.Add(new PendingNotification(ev));
        }
    }

    private void EnqueueGainLocked(PersistenceCoverageGain? gain)
    {
        if (gain is not null)
        {
            _undeliveredGains.Add(new PendingCoverageGain(gain));
        }
    }

    /// <summary>
    /// Persists the baseline minus arrivals whose delivery has not completed. Delivery is
    /// at-least-once: a crash after delivery can repeat an alert, but a shutdown, subscriber failure
    /// or crash before delivery never turns an arrival into a silently known entry.
    /// </summary>
    private void TrySaveBaseline()
    {
        if (_baselineStore is null)
        {
            return;
        }
        lock (_saveGate)
        {
            IReadOnlyCollection<PersistenceIdentity> snapshot;
            PersistenceCoverageMap? coverage;
            lock (_gate)
            {
                var undelivered = _undelivered.Select(pending => pending.Event.Identity)
                    .Concat(_undeliveredGains.SelectMany(pending => pending.Gain.Entries.Select(PersistenceIdentity.FromEntry)))
                    .ToHashSet();
                snapshot = undelivered.Count == 0
                    ? _core.CurrentBaseline
                    : _core.CurrentBaseline.Where(id => !undelivered.Contains(id)).ToArray();
                coverage = _core.CurrentCoverage;
            }
            try
            {
                _baselineStore.Save(snapshot, coverage);
                lock (_gate)
                {
                    _saveRetryNeeded = false;
                }
            }
            catch (Exception ex) when (!IsCatastrophic(ex))
            {
                lock (_gate)
                {
                    _saveRetryNeeded = true;
                }
                RecordFault(PersistenceMonitorOperation.BaselineSave, ex);
            }
        }
    }

    private void PublishPending()
    {
        // UI handlers may synchronously dispatch. Never hold a lock Dispose waits for here; this gate
        // only keeps two publishers from delivering the same arrival concurrently.
        var delivered = false;
        lock (_publishGate)
        {
            List<PendingNotification> batch;
            lock (_gate)
            {
                if (_disposed)
                {
                    return;
                }
                batch = [.. _undelivered.Where(pending => pending.Attempts < MaxDeliveryAttempts)];
            }
            var handlers = Detected?.GetInvocationList() ?? [];
            foreach (var pending in batch)
            {
                lock (_gate)
                {
                    if (_disposed)
                    {
                        return;
                    }
                    if (!_undelivered.Contains(pending))
                    {
                        continue;
                    }
                    pending.Attempts++;
                }
                var complete = true;
                foreach (var handler in handlers)
                {
                    if (pending.DeliveredTo.Contains(handler))
                    {
                        continue;
                    }
                    try
                    {
                        ((EventHandler<PersistenceDetectedEventArgs>)handler)(
                            this, new PersistenceDetectedEventArgs(pending.Event));
                        pending.DeliveredTo.Add(handler);
                    }
                    catch (Exception ex) when (!IsCatastrophic(ex))
                    {
                        complete = false;
                        RecordFault(PersistenceMonitorOperation.Notification, ex);
                    }
                }
                if (complete)
                {
                    lock (_gate)
                    {
                        _undelivered.Remove(pending);
                    }
                    delivered = true;
                }
            }
            delivered |= PublishCoverageGainsLocked();
        }
        bool disposed;
        lock (_gate)
        {
            disposed = _disposed;
        }
        if (delivered && !disposed)
        {
            // Delivered arrivals may now be acknowledged durably. Saves are serialized and each
            // snapshots the latest state, so this cannot overwrite a newer baseline with an older one.
            TrySaveBaseline();
        }
    }

    /// <summary>
    /// Delivers pending coverage-gain notices; the caller holds the publish gate. True when at least
    /// one notice completed, so its entries may now be saved.
    /// </summary>
    private bool PublishCoverageGainsLocked()
    {
        List<PendingCoverageGain> batch;
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }
            batch = [.. _undeliveredGains.Where(pending => pending.Attempts < MaxDeliveryAttempts)];
        }
        var handlers = CoverageGained?.GetInvocationList() ?? [];
        var delivered = false;
        foreach (var pending in batch)
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return delivered;
                }
                pending.Attempts++;
            }
            var complete = true;
            foreach (var handler in handlers)
            {
                if (pending.DeliveredTo.Contains(handler))
                {
                    continue;
                }
                try
                {
                    ((EventHandler<PersistenceCoverageGainEventArgs>)handler)(
                        this, new PersistenceCoverageGainEventArgs(pending.Gain));
                    pending.DeliveredTo.Add(handler);
                }
                catch (Exception ex) when (!IsCatastrophic(ex))
                {
                    complete = false;
                    RecordFault(PersistenceMonitorOperation.Notification, ex);
                }
            }
            if (complete)
            {
                lock (_gate)
                {
                    _undeliveredGains.Remove(pending);
                }
                delivered = true;
            }
        }
        return delivered;
    }

    private sealed class PendingNotification(PersistenceEvent ev)
    {
        public PersistenceEvent Event { get; } = ev;
        public int Attempts { get; set; }
        public HashSet<Delegate> DeliveredTo { get; } = [];
    }

    private sealed class PendingCoverageGain(PersistenceCoverageGain gain)
    {
        public PersistenceCoverageGain Gain { get; } = gain;
        public int Attempts { get; set; }
        public HashSet<Delegate> DeliveredTo { get; } = [];
    }
}
