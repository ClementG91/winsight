using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using WinSight.Application;
using WinSight.Attribution;
using WinSight.AvMonitor;
using WinSight.Persistence;
using WinSight.Ransomware;
using WinSight.Reporting;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace WinSight.Dashboard;

public partial class MainWindow
{
    /// <summary>
    /// Begins real-time persistence monitoring (Guardian) for as long as the dashboard runs. Seeding
    /// the baseline is a full persistence scan, so it runs off the UI thread to keep startup snappy;
    /// a genuinely new startup item then raises a tray balloon.
    /// </summary>
    private void StartGuardian()
    {
        StartCameraMicWatch();
        StartAttribution();
        SweepOrphanedDecoys();
        _guardian.Detected += OnGuardianDetected;
        Task.Run(() =>
        {
            try
            {
                _guardian.Start();
                _guardianStarted = true;
            }
            catch (OperationCanceledException) when (_disposed)
            {
                // Closing the dashboard cancels the initial scan.
            }
            catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
            {
                // Monitoring is best-effort: if the initial scan or watcher arming fails, the
                // dashboard still works and the on-demand persistence scan is unaffected. It is no
                // longer silent, though: the protection badge reports the monitor as failed. The
                // filter is broad because a narrow one let other failures skip the restore below.
                _guardianStartFailed = true;
            }
            finally
            {
                Dispatcher.BeginInvoke(RestoreRansomwareProtection);
            }
        });
    }

    /// <summary>
    /// Removes decoys a previous run left behind, before anything else touches them.
    /// </summary>
    /// <remarks>
    /// This used to run only from <c>RansomwareMonitor.Start</c>, i.e. only when protection was
    /// switched on. Since the switch was never remembered either, rebooting Windows with protection
    /// on left hidden decoys in the operator's folders that nothing would ever clean up: the next
    /// launch came back off, so the sweep never ran. Doing it at application start closes that,
    /// whatever the operator chooses next.
    /// </remarks>
    private void SweepOrphanedDecoys() => Task.Run(() =>
    {
        try
        {
            CanaryManager.RemoveOrphans(CanaryManager.DefaultDirectories());
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // A decoy that cannot be deleted is retried on the next launch.
        }
    });

    /// <summary>
    /// Puts the toggle back where the operator left it, and turns protection back on if it was on.
    /// </summary>
    /// <remarks>
    /// Setting IsChecked raises Checked, which is what actually restarts protection; the guard on
    /// _ransomware keeps that idempotent. Restoring silently would be wrong for the one feature that
    /// writes to the operator's folders, so the protection badge reflects the result either way.
    /// </remarks>
    private void RestoreRansomwareProtection()
    {
        if (_disposed)
        {
            return;
        }
        if (_protectionSettings.RansomwareProtectionEnabled)
        {
            RansomwareProtection.IsChecked = true;
        }
        RefreshProtectionHealth();
        _protectionHealthTimer.Start();
    }

    private void RefreshProtectionHealthOnTick(object? sender, EventArgs e) => RefreshProtectionHealth();

    /// <summary>
    /// Begins watching registry writes so a persistence alert can name the program that installed
    /// the entry, when the dashboard is elevated enough to open a kernel trace session.
    /// </summary>
    /// <remarks>
    /// Started only when elevated, deliberately. Starting it regardless would open a privileged
    /// session on every launch just to have it refused, and the refusal would be indistinguishable
    /// from a quiet machine. Unelevated, the alert simply carries no author — which is the honest
    /// answer, and never blocks the detection itself.
    /// </remarks>
    private void StartAttribution()
    {
        if (!AttributionHost.IsElevated())
        {
            return;
        }
        // The watcher records every registry write, but files only where it is told to look: a busy
        // machine writes thousands of files a second and the correlation index is small on purpose.
        // The scope names the two sets a detection can actually ask about — the startup folders and,
        // once protection plants them, the ransomware decoys.
        _attribution = new AttributionHost(new WriteAttributionWatcher(_attributionScope.ShouldRecord));
        _attribution.Start();
    }

    /// <summary>
    /// Begins real-time camera/microphone watching for as long as the dashboard runs.
    /// </summary>
    /// <remarks>
    /// The detector existed but nothing hosted it, so "your webcam just turned on" — the signal an
    /// OverSight-class monitor exists to give — never reached anyone using the app. Only activations
    /// raise a balloon; a device being released is not a security event, though both are journalled
    /// so the record shows how long something was watching or listening.
    /// </remarks>
    private void StartCameraMicWatch()
    {
        _avWatch.Detected += OnCameraMicDetected;
        _avWatch.Start();
        _cameraMicStarted = true;
    }

    private void OnCameraMicDetected(object? sender, DeviceEvent e)
    {
        var usage = e.Usage;
        // Journal first, for the same reason as every other detection: Windows may drop the balloon
        // and a detection that leaves no trace is indistinguishable from no detection.
        var alert = new SecurityAlert(
            DateTimeOffset.Now,
            "Camera/Mic",
            $"{usage.Kind}{(e.Kind == AvEventKind.Activated ? "Activated" : "Deactivated")}",
            usage.App);
        _ = AlertJournal.TryAppend(alert); // a failed write is counted and shown in protection health

        if (e.Kind != AvEventKind.Activated)
        {
            return;
        }

        var message = usage.Kind == DeviceKind.Webcam
            ? Text["AvWebcamActivated"]
            : Text["AvMicrophoneActivated"];
        // Asynchronous: the detection thread must not wait for the UI thread, which during shutdown
        // is itself waiting for that detection thread to stop.
        Dispatcher.BeginInvoke(() =>
        {
            if (_disposed)
            {
                return;
            }
            _balloonAlert = alert;
            _trayIcon.ShowBalloonTip(
                5000,
                Text["AvBalloonTitle"],
                $"{UntrustedDisplayText.Neutralize(AvPresenter.DisplayName(usage))} — {message}",
                Forms.ToolTipIcon.Warning);
        });
    }

    /// <summary>
    /// Turns on ransomware protection. This is opt-in because it is the only WinSight feature that
    /// writes into the operator's own folders: it sweeps decoys orphaned by an earlier crash, plants
    /// fresh hidden ones, and watches them. Planting is file I/O, so it runs off the UI thread.
    /// </summary>
    private void RansomwareProtection_Checked(object sender, RoutedEventArgs e)
    {
        if (_initializing || _disposed || _ransomware is not null)
        {
            return;
        }

        var monitor = RansomwareHost.CreateDefault();
        monitor.Detected += OnRansomwareDetected;
        _ransomware = monitor;
        _protectionSettings.SetRansomwareProtectionEnabled(true);
        Task.Run(() =>
        {
            try
            {
                monitor.Start();
                // Only now do the decoy paths exist, so only now can attribution be told to watch
                // them. Without this the alert names what was touched and never who touched it,
                // which is the difference between "something is wrong" and "kill this process".
                _attributionScope.WatchCanaries(monitor.Canaries);
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                // Best-effort: a folder we cannot write leaves protection partial, not broken - and
                // "partial" is now something the operator can see rather than a green tick.
            }
            Dispatcher.BeginInvoke(RefreshProtectionHealth);
        });
    }

    /// <remarks>
    /// The choice is persisted here and not in <see cref="StopRansomwareProtection"/>, which
    /// <see cref="Dispose"/> also calls: closing the dashboard removes the decoys but must not be
    /// read as the operator turning protection off.
    /// </remarks>
    private void RansomwareProtection_Unchecked(object sender, RoutedEventArgs e)
    {
        if (!_initializing)
        {
            _protectionSettings.SetRansomwareProtectionEnabled(false);
        }
        StopRansomwareProtection();
        RefreshProtectionHealth();
    }

    /// <summary>
    /// Recomputes what the real-time protections are actually doing and renders it.
    /// </summary>
    /// <remarks>
    /// Guardian's armed-location count, the ransomware watcher's directory count and its dropped-event
    /// counters all existed before this and were read nowhere, so a monitor that started and saw
    /// nothing rendered exactly like one that was working. This is the one place that difference
    /// becomes visible.
    /// </remarks>
    private void RefreshProtectionHealth()
    {
        if (_disposed)
        {
            return;
        }

        var guardianCoverage = _guardian.WatchCoverage;
        var guardianDiagnostics = _guardian.Diagnostics;
        JournalNewGuardianFault(guardianDiagnostics.LastFault);
        var ransomware = _ransomware;
        var monitors = new List<MonitorHealth>
        {
            GuardianHost.Health(_guardianStarted, _guardianStartFailed, guardianCoverage, guardianDiagnostics),
            _avWatch.Health(enabled: _cameraMicStarted),
            RansomwareHost.Health(ransomware, requestedWhenOff: 0),
        };
        var attributionHealth = _attribution?.Health;
        if (attributionHealth is not null)
        {
            monitors.Add(AttributionNote.Monitor(attributionHealth));
        }

        var health = new RealTimeProtectionHealth(monitors);
        ProtectionHealthDot.Fill = new System.Windows.Media.SolidColorBrush(
            health.Overall switch
            {
                ProtectionState.Active => System.Windows.Media.Color.FromRgb(0x4A, 0xDE, 0x80),
                ProtectionState.Partial => System.Windows.Media.Color.FromRgb(0xFB, 0xBF, 0x24),
                ProtectionState.Failed => System.Windows.Media.Color.FromRgb(0xF8, 0x71, 0x71),
                _ => System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8),
            });
        ProtectionHealthText.Text = string.Format(
            System.Globalization.CultureInfo.CurrentCulture,
            Text["ProtectionHealthSummary"],
            health.HealthyCount,
            health.RunningCount);
        var tooltip = health.Lines().ToList();
        if (GuardianHost.DiagnosticsLine(guardianDiagnostics) is { } guardianLine)
        {
            tooltip.Add(guardianLine);
        }
        if (attributionHealth is not null)
        {
            tooltip.Add(AttributionNote.DiagnosticsLine(attributionHealth));
        }
        if (AlertJournal.WriteFailures > 0)
        {
            tooltip.Add($"Alert journal: {AlertJournal.WriteFailures} write failure(s); last: "
                + (AlertJournal.LastWriteFailure?.GetType().Name ?? "unknown"));
        }
        ProtectionHealthBadge.ToolTip = string.Join(Environment.NewLine, tooltip);
        _retryGuardianTrayItem.Visible = GuardianHost.CanRetry(guardianDiagnostics);
    }

    private PersistenceMonitorFault? _journaledGuardianFault;

    private void RetryGuardian()
    {
        if (_disposed)
        {
            return;
        }
        _guardian.RetryNow();
        RefreshProtectionHealth();
    }

    /// <summary>
    /// Records a contained Guardian failure once. The failing operation can be the journal itself, so
    /// this is best-effort and never throws into the health refresh.
    /// </summary>
    private void JournalNewGuardianFault(PersistenceMonitorFault? fault)
    {
        if (fault is null || ReferenceEquals(fault, _journaledGuardianFault))
        {
            return;
        }
        _journaledGuardianFault = fault;
        try
        {
            AlertJournal.Append(GuardianHost.FaultAlert(fault));
        }
        catch (Exception ex) when (!WinSight.NetMonitor.EtwFailure.IsCatastrophic(ex))
        {
            // Still visible in the protection badge tooltip as a partial Guardian.
        }
    }

    /// <summary>Stops protection and removes every planted decoy. Safe to call when already off.</summary>
    private void StopRansomwareProtection()
    {
        var monitor = _ransomware;
        _ransomware = null;
        if (monitor is null)
        {
            return;
        }
        monitor.Detected -= OnRansomwareDetected;
        // Stop recording writes to decoys that are about to stop existing, so the correlation index
        // is not held open on paths nothing will ever ask about again.
        _attributionScope.ForgetCanaries();
        monitor.Dispose(); // removes the decoys
    }

    private void OnRansomwareDetected(object? sender, RansomwareDetectedEventArgs e)
    {
        // Journal FIRST, balloon second. Windows may suppress the balloon entirely (Focus Assist, or
        // its throttling of an app posting several toasts quickly), and a detection that leaves no
        // trace is indistinguishable from no detection at all.
        var alert = new SecurityAlert(
            DateTimeOffset.Now,
            "Ransomware",
            e.Kind.ToString(),
            RansomwarePresenter.AlertDetail(
                e.Kind,
                e.Path,
                _attribution is { } attribution ? attribution.Attribute : null,
                detectedAtUtc: null,
                // Carried so a nameless alert says why it is nameless. "Not elevated" and "watching
                // and saw nothing" call for different responses, and a silent absence reads as the
                // second when it is usually the first.
                health: _attribution?.Health));
        _ = AlertJournal.TryAppend(alert); // a failed write is counted and shown in protection health

        Dispatcher.BeginInvoke(() =>
        {
            if (_disposed)
            {
                return;
            }
            _balloonAlert = alert;
            // Louder and longer than a persistence alert: this is the one event where minutes matter.
            _trayIcon.ShowBalloonTip(
                10000,
                Text["RansomwareBalloonTitle"],
                $"{Text[RansomwarePresenter.AlertMessageKey(e.Kind)]}\n"
                + UntrustedDisplayText.Neutralize(RansomwarePresenter.Detail(e.Kind, e.Path)),
                RansomwarePresenter.IsCritical(e.Kind) ? Forms.ToolTipIcon.Error : Forms.ToolTipIcon.Warning);
        });
    }

    private void OnGuardianDetected(object? sender, PersistenceDetectedEventArgs e)
    {
        var detection = e.Detected;
        var detail = PersistenceMonitorPresenter.AlertDetail(
            detection,
            _attribution is { } attribution ? attribution.Attribute : null,
            _attribution?.Health);
        // An Allow rule silences the interruption, never the record: the arrival is journalled either
        // way, naming the rule, so a rule planted by software running as this user cannot make a
        // persistence item vanish. The rule store fails open, so an unreadable store announces.
        var allowedBy = _alertPresenter.SuppressingRule(detection.Entry);
        var alert = new SecurityAlert(
            DateTimeOffset.Now,
            "Guardian",
            detection.Entry.Vector.ToString(),
            allowedBy is null ? detail : PersistenceMonitorPresenter.SuppressedDetail(detail, allowedBy.Id));
        var journaled = AlertJournal.TryAppend(alert);

        // The operator already decided on an allowed item: it is recorded above and not announced.
        if (allowedBy is null)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_disposed)
                {
                    return;
                }
                // A retried arrival (after a journal failure) must not appear twice in one balloon batch.
                _pendingDetections.RemoveAll(pending => pending.Identity == detection.Identity);
                _pendingDetections.Add(detection);
                _pendingAlert = alert;
                // Restarting the timer coalesces a burst: the balloon is raised once arrivals stop.
                _guardianBalloonTimer.Stop();
                _guardianBalloonTimer.Start();
            });
        }

        if (!journaled)
        {
            // An announced arrival still reaches the operator, but no arrival - announced or allowed -
            // may be absorbed without a durable record. Failing the notification keeps it
            // unacknowledged: Guardian retries it and, if the journal stays unwritable, reports it
            // again on the next launch.
            throw new IOException("The alert journal could not be written; the arrival stays unacknowledged.",
                AlertJournal.LastWriteFailure);
        }
    }

    /// <summary>
    /// Announces the detections that arrived together as one balloon.
    /// </summary>
    /// <remarks>
    /// Guardian raised one balloon per new autostart entry, and an ordinary software installation
    /// writes several at once - a service, a scheduled task, a Run key, a COM registration. Six
    /// balloons in a few seconds for one act by the operator is not six times the information; it is
    /// the mechanism by which somebody learns to dismiss this product's alerts without reading them,
    /// and the alert that matters then arrives in the same shape as the five that did not.
    ///
    /// Nothing is dropped: every detection was already journalled before this ran, and every one
    /// still appears in the alerts view. Only the number of balloons changes.
    /// </remarks>
    private void FlushGuardianBalloon(object? sender, EventArgs e)
    {
        _guardianBalloonTimer.Stop();
        if (_disposed || _pendingDetections.Count == 0)
        {
            return;
        }

        var batch = GuardianAlertBatcher.Describe(_pendingDetections);
        // A single arrival gets a decision window (Allow / Block / Decide later), BlockBlock-style. A
        // burst keeps the coalesced balloon, as does a single arrival once enough windows are open.
        if (batch.IsSingle && TryShowAlertWindow(batch.Single!))
        {
            _balloonAlert = _pendingAlert;
            _pendingDetections.Clear();
            return;
        }

        var body = batch.IsSingle
            ? $"{batch.Single!.Entry.Vector}/"
                + UntrustedDisplayText.Neutralize(batch.Single.Entry.Name) + " — "
                + Text[GuardianAlertBatcher.BalloonMessageKey(batch)]
            : string.Format(
                System.Globalization.CultureInfo.CurrentCulture,
                Text[GuardianAlertBatcher.BalloonMessageKey(batch)],
                batch.Count,
                batch.NotableCount);

        _balloonAlert = _pendingAlert;
        _pendingDetections.Clear();
        _trayIcon.ShowBalloonTip(
            5000,
            Text["GuardianBalloonTitle"],
            body,
            batch.IsNotable ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    /// <summary>
    /// Opens a decision window for one arrival. True when the arrival is now on screen (a new window,
    /// or the one already open for this item); false when the caller must fall back to the balloon.
    /// </summary>
    private bool TryShowAlertWindow(PersistenceEvent detection)
    {
        if (_openAlertWindows.ContainsKey(detection.Identity))
        {
            return true; // its window is already showing; a re-announcement needs no second one
        }
        if (_openAlertWindows.Count >= MaxOpenAlertWindows)
        {
            return false;
        }
        try
        {
            var window = new AlertWindow(detection.Entry, _alertPresenter);
            window.Closed += (_, _) => _openAlertWindows.Remove(detection.Identity);
            _openAlertWindows[detection.Identity] = window;
            window.Show();
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException
                                     or System.Windows.Markup.XamlParseException)
        {
            // The window could not be created; the balloon still carries the alert.
            _openAlertWindows.Remove(detection.Identity);
            return false;
        }
    }

    private static LocalizationManager Text => LocalizationManager.Instance;

    private static Drawing.Icon? TryLoadApplicationIcon()
    {
        try
        {
            return string.IsNullOrWhiteSpace(Environment.ProcessPath)
                ? null
                : Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath);
        }
        catch (Exception ex) when (ex is ArgumentException or ExternalException or FileNotFoundException)
        {
            return null;
        }
    }
}
