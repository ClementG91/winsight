using WinSight.Attribution;
using WinSight.AvMonitor;
using WinSight.Core;
using WinSight.InputHooks;
using WinSight.NetMonitor;
using WinSight.Reporting;
using WinSight.Response;

namespace WinSight.Application;

public static partial class Adapters
{
    /// <summary>Runs the live camera/mic monitor, printing transitions until Ctrl+C.</summary>
    public static int WatchCameraMic()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.WriteLine("Watching camera/mic, Ctrl+C to stop.");
        // Event driven: a consent-store change is read at once, with the poll as the fallback.
        var locator = new CaptureDeviceProcessLocator(new RunningImageSource(), new Win32ProcessInspector());
        new CameraMicMonitor(changeSignalFactory: () => new ConsentStoreChangeSignal()).Watch(OnEvent, cts.Token);
        return 0;

        void OnEvent(DeviceEvent e)
        {
            var device = e.Usage.Kind == DeviceKind.Webcam ? "webcam" : "mic";
            var verb = e.Kind == AvEventKind.Activated ? "ON " : "OFF";
            Console.WriteLine(
                $"  [{verb}] {device}, {UntrustedDisplayText.Neutralize(e.Usage.App)}");
            if (e.Kind != AvEventKind.Activated)
            {
                return;
            }
            // Name the process behind the application, so "who is using the camera" is answerable.
            var match = locator.Locate(e.Usage);
            if (match.Processes.Count == 0)
            {
                Console.WriteLine($"        process: {match.Reason}");
                return;
            }
            foreach (var process in match.Processes)
            {
                Console.WriteLine($"        process: pid {process.Identity.Pid} "
                    + UntrustedDisplayText.Neutralize(System.IO.Path.GetFileName(process.ImagePath)));
            }
        }
    }

    /// <summary>
    /// Runs the live input-filter watcher, printing keyboard/mouse class filters as they appear or
    /// disappear until Ctrl+C. The ReiKey-style "a tap was just installed" signal, user-mode and
    /// read-only.
    /// </summary>
    public static int WatchInputFilters()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var watcher = new InputFilterWatcher();
        watcher.Changed += alerts =>
        {
            foreach (var alert in alerts)
            {
                var verb = alert.Kind == InputFilterChangeKind.Added ? "ADDED  " : "REMOVED";
                Console.WriteLine($"  [{verb}] {alert.Filter.Stack} {alert.Filter.Position} filter: "
                    + UntrustedDisplayText.Neutralize(alert.Filter.Name));
            }
        };
        if (!watcher.Start())
        {
            Console.Error.WriteLine("could not watch the keyboard/mouse class keys");
            return CliContract.ObservationFailed;
        }
        Console.WriteLine("Watching keyboard/mouse input filters, Ctrl+C to stop.");
        cts.Token.WaitHandle.WaitOne();
        return CliContract.Clean;
    }


    /// <summary>
    /// Runs the live write-attribution watcher, printing who writes what until Ctrl+C.
    /// </summary>
    /// <remarks>
    /// The observation vehicle for attribution: a detection says a Run key appeared, this says which
    /// program wrote it. File writes are narrowed to the startup folders, because the point is to
    /// show persistence being installed, not to print every file the machine touches.
    /// </remarks>
    public static int WatchAttribution()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Shared with the dashboard rather than spelled out again here. The rule this replaced
        // compared the kernel's raw path against the full DOS folder, which cannot match once the
        // volume is spelled \Device\HarddiskVolumeN — the failure being total and silent, since a
        // startup-folder write would simply never be recorded and the watch would look quiet.
        var scope = new AttributionScope();
        var watcher = new WriteAttributionWatcher(scope.ShouldRecord);

        Console.WriteLine("Watching registry writes and startup-folder writes (ETW), Ctrl+C to stop.");
        var attributed = 0;
        var unknownProcess = 0;
        var unresolvedTarget = 0;
        return RunEtwWatch(
            () =>
            {
                watcher.Watch(
                    observation =>
                    {
                        attributed++;
                        Console.WriteLine(
                            $"  {UntrustedDisplayText.Neutralize(Path.GetFileName(observation.ExecutablePath))} "
                            + $"(pid {observation.ProcessId})  →  "
                            + UntrustedDisplayText.Neutralize(observation.Target));
                    },
                    // Printed as well as counted: a watcher that only shows what it managed to
                    // attribute cannot be told apart from one that is missing everything.
                    miss =>
                    {
                        if (miss.Reason == UnattributedReason.UnknownProcess)
                        {
                            unknownProcess++;
                            Console.WriteLine(
                                $"  [unknown process {miss.ProcessId}]  →  "
                                + UntrustedDisplayText.Neutralize(miss.Target));
                        }
                        else
                        {
                            unresolvedTarget++;
                            Console.WriteLine(miss.Target is null
                                ? $"  [unannounced key handle, pid {miss.ProcessId}]"
                                : $"  [untranslatable key, pid {miss.ProcessId}]  →  "
                                    + UntrustedDisplayText.Neutralize(miss.Target));
                        }
                    },
                    cts.Token);
                Console.WriteLine(
                    $"attributed {attributed}, unknown process {unknownProcess}, unresolved target {unresolvedTarget}");
            },
            Console.Error,
            cts.Token,
            () => watcher.SensorHealth);
    }

    /// <summary>Runs the live DNS (ETW) watcher, printing queries until Ctrl+C.</summary>
    public static int WatchDns()
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        var watcher = new DnsEtwWatcher();
        Console.WriteLine("Watching DNS queries (ETW), Ctrl+C to stop.");
        return RunEtwWatch(
            () => watcher.Watch(
                e => Console.WriteLine(
                    $"  {e.Type,-5} {UntrustedDisplayText.Neutralize(e.Name)}  (pid {e.ProcessId})"),
                cts.Token),
            Console.Error,
            cts.Token,
            () => watcher.SensorHealth);
    }

    /// <summary>
    /// Closes the CLI ETW exception boundary without exposing localized native messages, paths or
    /// stacks. Internal so deterministic tests can inject failures without opening a real session.
    /// </summary>
    internal static int RunEtwWatch(
        Action watch,
        TextWriter error,
        CancellationToken cancellationToken,
        Func<SensorHealthSnapshot>? sensorHealth = null)
    {
        ArgumentNullException.ThrowIfNull(watch);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            watch();
            if (cancellationToken.IsCancellationRequested)
            {
                return CompleteEtwWatch(error, sensorHealth);
            }

            // A live ETW pump is expected to block until the caller cancels it. A spontaneous
            // return means observation ended unexpectedly and must not be reported as success.
            error.WriteLine(
                $"[{EtwFailure.Token(EtwFailureCode.Unexpected)}] Live ETW observation is unavailable.");
            // Not 1: that means "something notable was found". An observation that could not be made
            // is a failure, and a scheduled task had no way to tell the two apart.
            return CliContract.ObservationFailed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CompleteEtwWatch(error, sensorHealth);
        }
        catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
        {
            var failure = EtwFailure.Classify(ex);
            error.WriteLine($"[{EtwFailure.Token(failure)}] Live ETW observation is unavailable.");
            return CliContract.ObservationFailed;
        }
    }

    private static int CompleteEtwWatch(
        TextWriter error,
        Func<SensorHealthSnapshot>? sensorHealth)
    {
        if (sensorHealth is null)
        {
            return CliContract.Clean;
        }

        var health = sensorHealth();
        if (!health.CoverageIncomplete)
        {
            return CliContract.Clean;
        }

        error.WriteLine(
            $"[SENSOR_COVERAGE_INCOMPLETE] observed={health.ObservedEvents} "
            + $"lost={health.LostEvents} deliveryFailures={health.DeliveryFailures}");
        return CliContract.ObservationIncomplete;
    }

    /// <summary>
    /// Diagnostic: reports what the authenticated firewall pipe grants the caller's Windows identity,
    /// without changing machine state. Prints one stable token line for scripted VM checks. Exit code
    /// 0 when the service is reachable (any of read-only, can-mutate, or read-only-because-armed),
    /// 11 when it is not - so a multi-user gate can drive this exe under different tokens and assert
    /// that an unprivileged caller reads <c>outcome=CanReadOnly</c> while an elevated one may read
    /// <c>outcome=CanMutate</c>.
    /// </summary>
    public static async Task<int> FirewallIpcSelfTestAsync(CancellationToken cancellationToken = default)
    {
        var result = await FirewallIpcSelfTest.RunAsync(
            FirewallServiceAdapter.CreateGateway(), cancellationToken).ConfigureAwait(false);

        Console.WriteLine(
            "[IPC_SELFTEST] outcome={0} serviceAvailable={1} mode={2} effectiveState={3} mutation={4}",
            result.Outcome,
            result.ServiceAvailable.ToString().ToLowerInvariant(),
            result.Mode,
            result.EffectiveState,
            result.MutationProbe?.ToString() ?? "none");

        // One exit-code table for the whole CLI, so a caller never has to know which verb it ran to
        // read the result. The VM qualification kit only tests for non-zero, so the move from the
        // former bespoke 3 changes nothing it asserts.
        return result.Outcome == IpcSelfTestOutcome.ServiceUnavailable
            ? CliContract.ServiceUnavailable
            : CliContract.Clean;
    }
}
