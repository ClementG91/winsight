using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

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
public sealed class WriteAttributionWatcher(Func<string, bool>? fileFilter = null) : IWriteWatcher
{
    private readonly Func<string, bool> _fileFilter = fileFilter ?? (static _ => false);

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

        var processes = new ProcessPathIndex();
        var normalizer = new KernelPathNormalizer(VolumeMap.Current(), CurrentUserSid());

        // A private name, so WinSight never takes the shared NT Kernel Logger from another tool.
        using var session = new TraceEventSession($"WinSight-Attribution-{Environment.ProcessId}");
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

        // Process gives the command line attribution depends on; Registry and FileIOInit give the
        // writes. One session, so they arrive in order and a write is never seen before the process
        // that made it.
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process
            | KernelTraceEventParser.Keywords.Registry
            | KernelTraceEventParser.Keywords.FileIOInit);

        // The start group covers processes already running when the session opens, not just new
        // ones, so a long-lived program's writes are attributed from the first event.
        session.Source.Kernel.ProcessStartGroup += process =>
        {
            var path = ProcessCommandLine.ExtractExecutablePath(process.CommandLine, process.ImageFileName);
            if (path is not null)
            {
                processes.Started(process.ProcessID, path);
            }
        };
        session.Source.Kernel.ProcessStop += process =>
        {
            processes.Stopped(process.ProcessID, process.TimeStamp.ToUniversalTime());
            processes.Prune(process.TimeStamp.ToUniversalTime());
        };

        void Record(int processId, DateTime timeStamp, string? target)
        {
            var whenUtc = timeStamp.ToUniversalTime();
            if (target is null)
            {
                onUnattributed?.Invoke(
                    new UnattributedWrite(whenUtc, processId, null, UnattributedReason.UnresolvedTarget));
                return;
            }
            // An unknown process means it was never announced, or its write reached us before its
            // start event did. Naming it anyway would be worse than staying quiet: the whole value
            // of attribution is that the name is right. It is still reported as unattributed, so
            // the blind spot is visible rather than silent.
            if (processes.Resolve(processId) is { } image)
            {
                onWrite(new WriteObservation(whenUtc, processId, image, target));
            }
            else
            {
                onUnattributed?.Invoke(
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
                onUnattributed?.Invoke(new UnattributedWrite(
                    e.TimeStamp.ToUniversalTime(), e.ProcessID, null, UnattributedReason.UnresolvedTarget));
                return;
            }
            var target = normalizer.NormalizeRegistryKey(kernelKey);
            if (target is null)
            {
                onUnattributed?.Invoke(new UnattributedWrite(
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
            if (_fileFilter(e.FileName))
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
    /// The SID whose hive should read as <c>HKCU</c>. Null when it cannot be determined, which
    /// leaves user hives as <c>HKU\{sid}</c> — correct, just less recognisable.
    /// </summary>
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
