using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

using WinSight.Core;
using WinSight.NetMonitor;

namespace WinSight.Attribution;

/// <summary>
/// Watches registry and file writes as they happen and reports each one already attributed to the
/// process that made it.
/// </summary>
/// <remarks>
/// <b>Why this needs Administrator.</b> A kernel trace session is privileged. WinSight is
/// deliberately unprivileged everywhere else, so this is opt-in and the caller surfaces the refusal
/// rather than silently reporting nothing.
///
/// <b>Why the process index and not a lookup.</b> Copied from the outbound-connection watcher, which
/// learned it the hard way: asking the operating system who owns a process id when the write event
/// arrives does not work, because ETW delivers a second or more late and the interesting case — a
/// dropper that writes a Run key and exits — is already gone. Process start carries the command
/// line, so the path is captured while the process is alive and is still there when the write
/// arrives on the same ordered stream.
///
/// <b>Why file writes are filtered at the source.</b> A busy machine performs thousands of file
/// writes a second. Feeding them all into a bounded correlation index would evict every useful
/// observation within seconds — the index would be full and useless at the exact moment a detection
/// asked it a question. The caller therefore says which paths matter; the default answer is none,
/// so nothing is recorded by accident. Registry writes are not filtered: they are orders of
/// magnitude rarer and are where persistence actually lives.
/// </remarks>
public sealed class WriteAttributionWatcher(Func<string, bool>? fileFilter = null) :
    IWriteWatcher, ISensorHealthSource
{
    private readonly Func<string, bool> _fileFilter = fileFilter ?? (static _ => false);
    private readonly EtwSensorHealthTracker _health = new("Write attribution ETW");

    public SensorHealthSnapshot SensorHealth => _health.SensorHealth;

    /// <summary>
    /// Opens the trace session and invokes <paramref name="onWrite"/> for each attributed write
    /// until cancelled. Blocking; run on its own thread. Throws
    /// <see cref="UnauthorizedAccessException"/> when not elevated.
    /// </summary>
    public void Watch(Action<WriteObservation> onWrite, CancellationToken token) =>
        Watch(onWrite, onUnattributed: null, token);

    /// <summary>
    /// As above, additionally reporting writes that were seen but could not be attributed.
    /// </summary>
    /// <remarks>
    /// Dropping an unattributable write is right; dropping it <i>silently</i> is how a monitor
    /// comes to look healthy while seeing nothing. A caller that wants to know its own blind spots
    /// passes <paramref name="onUnattributed"/>.
    /// </remarks>
    public void Watch(
        Action<WriteObservation> onWrite,
        Action<UnattributedWrite>? onUnattributed,
        CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(onWrite);
        token.ThrowIfCancellationRequested();

        TraceEventSession? session = null;
        try
        {
            // A private, collision-safe name, so WinSight never takes the shared NT Kernel Logger or
            // silently replaces another live WinSight owner.
            session = EtwSessionLifecycle.OpenNative(EtwSessionProfile.Attribution);
            _health.Running(session);
            WatchSession(session, onWrite, onUnattributed, token);
            if (token.IsCancellationRequested)
            {
                _health.Stopped();
            }
            else
            {
                _health.FailedUnexpectedReturn();
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            _health.Stopped();
            throw;
        }
        catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
        {
            _health.Failed(ex);
            throw;
        }
        finally
        {
            session?.Dispose();
        }
    }

    private void WatchSession(
        TraceEventSession session,
        Action<WriteObservation> onWrite,
        Action<UnattributedWrite>? onUnattributed,
        CancellationToken token)
    {
        var processes = new ProcessPathIndex();
        var normalizer = new KernelPathNormalizer(
            VolumeMap.Current(), CurrentUserSid(), CurrentControlSet());
        using var stop = token.Register(() =>
        {
            try
            {
                session.Stop();
            }
            catch (Exception)
            {
                // Session already gone, nothing to do.
            }
        });
        token.ThrowIfCancellationRequested();

        // Process gives the command line attribution depends on; Registry and FileIOInit give the
        // writes. One session, so they arrive in order and a write is never seen before the process
        // that made it.
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process
            | KernelTraceEventParser.Keywords.Registry
            | KernelTraceEventParser.Keywords.FileIOInit);
        token.ThrowIfCancellationRequested();

        // The start group covers processes already running when the session opens, not just new
        // ones, so a long-lived program's writes are attributed from the first event.
        session.Source.Kernel.ProcessStartGroup += process =>
        {
            var path = ProcessCommandLine.ExtractExecutablePath(process.CommandLine, process.ImageFileName);
            if (path is not null)
            {
                processes.Started(process.ProcessID, path);
            }
            // No readable path is not the same as no identity. Measured live, this is where
            // powershell.exe, "cmd /c …" and node land — launched by bare name through the search
            // path, which is precisely how living-off-the-land attacks run. Dropping them meant a
            // dropper that ran as `reg add` could never be named at all.
            else if (!string.IsNullOrWhiteSpace(process.ImageFileName))
            {
                processes.StartedWithoutPath(process.ProcessID, process.ImageFileName);
            }
        };
        session.Source.Kernel.ProcessStop += process =>
        {
            processes.Stopped(process.ProcessID, process.TimeStamp.ToUniversalTime());
            processes.Prune(process.TimeStamp.ToUniversalTime());
        };

        void PublishMiss(UnattributedWrite miss)
        {
            _health.Observed();
            try
            {
                onUnattributed?.Invoke(miss);
            }
            catch
            {
                _health.DeliveryFailed();
                throw;
            }
        }

        void PublishWrite(WriteObservation observation)
        {
            _health.Observed();
            try
            {
                onWrite(observation);
            }
            catch
            {
                _health.DeliveryFailed();
                throw;
            }
        }

        void Record(int processId, DateTime timeStamp, string? target)
        {
            var whenUtc = timeStamp.ToUniversalTime();
            if (target is null)
            {
                PublishMiss(
                    new UnattributedWrite(whenUtc, processId, null, UnattributedReason.UnresolvedTarget));
                return;
            }
            // An unknown process means it was never announced, or its write reached us before its
            // start event did. Naming it anyway would be worse than staying quiet: the whole value
            // of attribution is that the name is right. It is still reported as unattributed, so
            // the blind spot is visible rather than silent.
            if (processes.ResolveImage(processId) is { } image)
            {
                PublishWrite(new WriteObservation(
                    whenUtc, processId, image.Value, target, PathIsExact: image.IsFullPath));
            }
            else
            {
                PublishMiss(
                    new UnattributedWrite(whenUtc, processId, target, UnattributedReason.UnknownProcess));
            }
        }

        // A write event names a key control block, not a key. The kernel announces the full path
        // once — on open, and in the rundown for keys already open — so those announcements have to
        // be kept to make any live write resolvable at all.
        var keys = new RegistryKeyResolver();
        session.Source.Kernel.RegistryKCBCreate += e => keys.Track(e.KeyHandle, e.KeyName);
        session.Source.Kernel.RegistryKCBRundownBegin += e => keys.Track(e.KeyHandle, e.KeyName);
        session.Source.Kernel.RegistryKCBRundownEnd += e => keys.Track(e.KeyHandle, e.KeyName);
        session.Source.Kernel.RegistryKCBDelete += e => keys.Forget(e.KeyHandle);

        void RecordRegistry(Microsoft.Diagnostics.Tracing.Parsers.Kernel.RegistryTraceData e)
        {
            // Two different failures hide behind "no target", and telling them apart is the whole
            // point of reporting misses: a handle the kernel never announced is a coverage gap in
            // the key bookkeeping, while a key that resolved but would not translate is a gap in
            // the path mapping. Carrying the kernel's own spelling through lets the caller see
            // which, instead of both looking like silence.
            var kernelKey = keys.Resolve(e.KeyHandle, e.KeyName);
            if (kernelKey is null)
            {
                PublishMiss(new UnattributedWrite(
                    e.TimeStamp.ToUniversalTime(), e.ProcessID, null, UnattributedReason.UnresolvedTarget));
                return;
            }
            var target = normalizer.NormalizeRegistryKey(kernelKey);
            if (target is null)
            {
                PublishMiss(new UnattributedWrite(
                    e.TimeStamp.ToUniversalTime(), e.ProcessID, kernelKey, UnattributedReason.UnresolvedTarget));
                return;
            }
            Record(e.ProcessID, e.TimeStamp, target);
        }

        // Writes only. Opening or querying a key is not a change, and recording reads would drown
        // the index in exactly the traffic it must not hold.
        session.Source.Kernel.RegistrySetValue += RecordRegistry;
        session.Source.Kernel.RegistryCreate += RecordRegistry;
        session.Source.Kernel.RegistryDeleteValue += RecordRegistry;
        session.Source.Kernel.RegistrySetInformation += RecordRegistry;

        session.Source.Kernel.FileIOCreate += e =>
        {
            if (CreateCanWrite(e.CreateDisposition) && _fileFilter(e.FileName))
            {
                Record(e.ProcessID, e.TimeStamp, normalizer.NormalizeFilePath(e.FileName));
            }
        };
        session.Source.Kernel.FileIOWrite += e =>
        {
            if (_fileFilter(e.FileName))
            {
                Record(e.ProcessID, e.TimeStamp, normalizer.NormalizeFilePath(e.FileName));
            }
        };
        session.Source.Kernel.FileIORename += e =>
        {
            if (_fileFilter(e.FileName))
            {
                Record(e.ProcessID, e.TimeStamp, normalizer.NormalizeFilePath(e.FileName));
            }
        };

        session.Source.Process(); // blocks until the session is stopped
    }

    /// <summary>
    /// Whether a file create can itself change the file: every disposition except opening one that
    /// already exists.
    /// </summary>
    /// <remarks>
    /// Recording every create recorded every open. Measured in the VM (gate 25): right after a
    /// program drops a shortcut into the Startup folder, the shell (<c>sihost.exe</c>) and Defender
    /// (<c>MsMpEng.exe</c>) open it to look at it, and those opens were logged as writes. The index
    /// answers with the newest write before a detection, so Guardian would have named the shell or
    /// the antivirus as the author of the persistence it was reporting - a wrong name, which is worse
    /// than none. A program that opens an existing file and then writes to it is still seen: its
    /// write events carry the name the kernel resolved on that open.
    /// </remarks>
    internal static bool CreateCanWrite(Microsoft.Diagnostics.Tracing.Parsers.Kernel.CreateDisposition disposition) =>
        disposition != Microsoft.Diagnostics.Tracing.Parsers.Kernel.CreateDisposition.OPEN_EXISTING;

    /// <summary>
    /// The SID whose hive should read as <c>HKCU</c>. Null when it cannot be determined, which
    /// leaves user hives as <c>HKU\{sid}</c> — correct, just less recognisable.
    /// </summary>
    /// <summary>
    /// The active control set number, so a kernel write to <c>SYSTEM\ControlSet001\Services</c>
    /// can be matched against the <c>CurrentControlSet</c> path every enumerator reports.
    /// </summary>
    /// <remarks>
    /// World-readable, and null when it is not: an unknown control set leaves service and driver
    /// writes unattributed rather than folding a set that may not be the running one.
    /// </remarks>
    private static int? CurrentControlSet()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\Select");
            return key?.GetValue("Current") is int current and > 0 ? current : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return null;
        }
    }

    private static string? CurrentUserSid()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.User?.Value;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
