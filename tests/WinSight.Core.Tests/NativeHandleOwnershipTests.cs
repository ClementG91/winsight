using System.Runtime;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

using Xunit;

namespace WinSight.Core.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class NativeHandleOwnershipCollection
{
    public const string Name = "Native handle ownership";
}

[Collection(NativeHandleOwnershipCollection.Name)]
public sealed class NativeHandleOwnershipTests
{
    private static readonly byte[] OriginalPayload = [10, 20];
    private static readonly byte[] AppendedPayload = [10, 20, 120];

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void RejectedTimestampAcquisitionReleasesTheDataHandleImmediately(int operation)
    {
        using var fixture = new Fixture();
        fixture.SetUnrepresentableCreationTime();
        Assert.Equal(0, NativeDeleteOpenError(fixture.Path)); // A real DELETE open is possible before the attempted acquisition.
        try
        {
            // Finalization must not hide an orphaned DATA handle before its immediate sharing witness.
            Assert.True(GC.TryStartNoGCRegion(64 * 1024 * 1024), "The no-GC oracle precondition was not established.");
            Observation observed;
            int deleteError;
            bool noGcHeld;
            try
            {
                observed = Attempt(fixture.Path, operation);
                deleteError = NativeDeleteOpenError(fixture.Path);
                noGcHeld = GCSettings.LatencyMode == GCLatencyMode.NoGCRegion;
            }
            finally
            {
                if (GCSettings.LatencyMode == GCLatencyMode.NoGCRegion) { GC.EndNoGCRegion(); }
            }
            Assert.True(noGcHeld, "The no-GC oracle was interrupted; this is not a product regression result.");
            Assert.True(observed.Refused);
            Assert.False(observed.Missing);
            // The error was captured before EndNoGCRegion, so later collection cannot turn this into a pass.
            Assert.Equal(0, deleteError);
            Assert.Equal(OriginalPayload, File.ReadAllBytes(fixture.Path));
        }
        finally
        {
            // Any baseline orphan is reclaimed for fixture cleanup only. This runs after the
            // immutable sharing witness and assertions, never as a remedy for the product call.
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void OrdinaryTimestampAcquisitionsStillSucceedAndReleaseTheirDataHandles(int operation)
    {
        using var fixture = new Fixture();
        Assert.Equal(0, NativeDeleteOpenError(fixture.Path));
        var observed = Attempt(fixture.Path, operation);
        Assert.False(observed.Refused);
        Assert.False(observed.Missing);
        Assert.Equal(0, NativeDeleteOpenError(fixture.Path));
        Assert.Equal(operation == 2 ? AppendedPayload : OriginalPayload, File.ReadAllBytes(fixture.Path));
    }

    private static Observation Attempt(string path, int operation)
    {
        if (operation == 0)
        {
            using var lease = AutomaticFileAccess.TryAcquireStableRead(path, out var missing);
            return new(lease is null, missing);
        }
        if (operation == 1)
        {
            using var lease = AutomaticFileAccess.TryAcquireForDelete(path, out var missing);
            return new(lease is null, missing);
        }
        Assert.Equal(2, operation);
        return new(!AutomaticFileAccess.TryAppendFile(path, "x"u8), false);
    }

    private sealed record Observation(bool Refused, bool Missing);

    private static int NativeDeleteOpenError(string path)
    {
        using var handle = Native.CreateFileW(path, Native.DeleteAccess, Native.ShareAll,
            IntPtr.Zero, Native.OpenExisting, Native.OpenReparsePoint | Native.OpenNoRecall, IntPtr.Zero);
        var error = Marshal.GetLastPInvokeError();
        return handle.IsInvalid ? error == 0 ? -1 : error : 0;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Directory.CreateTempSubdirectory("winsight-io1-owned-").FullName;
        private Native.FileTime _originalCreation;

        internal Fixture()
        {
            Path = System.IO.Path.Combine(_root, "owned.bin");
            try
            {
                File.WriteAllBytes(Path, OriginalPayload);
                using var handle = OpenAttributes();
                Assert.True(Native.GetFileTime(handle, out _originalCreation, IntPtr.Zero, IntPtr.Zero),
                    "The owned fixture's original FILETIME could not be captured.");
            }
            catch
            {
                Directory.Delete(_root, recursive: true);
                throw;
            }
        }

        internal string Path { get; }

        internal void SetUnrepresentableCreationTime()
        {
            var candidate = new Native.FileTime { Low = uint.MaxValue, High = 0x7fffffff };
            using (var handle = OpenAttributes())
            {
                Assert.True(Native.SetFileTime(handle, ref candidate, IntPtr.Zero, IntPtr.Zero),
                    "The filesystem did not establish the raw FILETIME prerequisite; this is not a regression RED.");
            }
            // The creating handle is closed. Confirm exact raw persistence through another open.
            using var reopened = OpenAttributes();
            Assert.True(Native.GetFileTime(reopened, out var actual, IntPtr.Zero, IntPtr.Zero));
            Assert.Equal(candidate.Low, actual.Low);
            Assert.Equal(candidate.High, actual.High);
            Assert.Throws<ArgumentOutOfRangeException>(() => DateTime.FromFileTimeUtc(((long)actual.High << 32) | actual.Low));
        }

        private SafeFileHandle OpenAttributes()
        {
            var handle = Native.CreateFileW(Path, Native.ReadAttributes | Native.WriteAttributes,
                Native.ShareAll, IntPtr.Zero, Native.OpenExisting,
                Native.OpenReparsePoint | Native.OpenNoRecall, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw new IOException("Owned attribute handle unavailable", error);
            }
            return handle;
        }

        public void Dispose()
        {
            using (var handle = OpenAttributes())
            {
                Assert.True(Native.SetFileTime(handle, ref _originalCreation, IntPtr.Zero, IntPtr.Zero),
                    "The owned fixture's original timestamp could not be restored.");
            }
            Directory.Delete(_root, recursive: true);
        }
    }

    private static class Native
    {
        internal const uint DeleteAccess = 0x00010000;
        internal const uint ReadAttributes = 0x00000080;
        internal const uint WriteAttributes = 0x00000100;
        internal const uint ShareAll = 1 | 2 | 4;
        internal const uint OpenExisting = 3;
        internal const uint OpenReparsePoint = 0x00200000;
        internal const uint OpenNoRecall = 0x00100000;

        [StructLayout(LayoutKind.Sequential)]
        internal struct FileTime { internal uint Low; internal uint High; }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileTime(SafeFileHandle handle, ref FileTime creation, IntPtr access, IntPtr write);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileTime(SafeFileHandle handle, out FileTime creation, IntPtr access, IntPtr write);
    }
}
