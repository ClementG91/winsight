using System.Net;
using System.Runtime.InteropServices;

namespace WinSight.NetMonitor;

/// <summary>
/// Reads the active TCP/UDP tables natively via IP Helper (GetExtendedTcpTable /
/// GetExtendedUdpTable), structured, fast, and locale-independent, unlike parsing
/// netstat text. Rows are all fixed DWORDs (MIB_*ROW_OWNER_PID), so marshalling is
/// straightforward. ConnectionMonitor falls back to netstat if these entry points are
/// unavailable.
/// </summary>
public static class NativeConnectionReader
{
    private const int AfInet = 2;                 // IPv4
    private const int AfInet6 = 23;               // IPv6
    private const int TcpTableOwnerPidAll = 5;    // TCP_TABLE_OWNER_PID_ALL
    private const int UdpTableOwnerPid = 1;       // UDP_TABLE_OWNER_PID

    // Custom delegate (not Func<>) because the size parameter is `ref`.
    private delegate uint ExtendedTableFn(
        IntPtr table, ref int size, bool sort, int ipVersion, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

    // Fields are populated by Marshal at runtime, so the compiler sees them as never
    // assigned (CS0649), expected for interop structs.
#pragma warning disable CS0649
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr, LocalPort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId, LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId, RemotePort, State, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId, LocalPort, OwningPid;
    }
#pragma warning restore CS0649

    /// <summary>Snapshots the current TCP + UDP tables (IPv4 and IPv6) with owning PIDs.</summary>
    public static IReadOnlyList<NetstatRow> Read()
    {
        var rows = new List<NetstatRow>();
        ReadTcp(rows);
        ReadTcp6(rows);
        ReadUdp(rows);
        ReadUdp6(rows);
        return rows;
    }

    private static void ReadTcp(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibTcpRowOwnerPid>(GetExtendedTcpTable, AfInet, TcpTableOwnerPidAll))
        {
            rows.Add(new NetstatRow(
                "TCP",
                FormatEndpoint(r.LocalAddr, r.LocalPort),
                FormatEndpoint(r.RemoteAddr, r.RemotePort),
                TcpStateName(r.State),
                (int)r.OwningPid));
        }
    }

    private static void ReadTcp6(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibTcp6RowOwnerPid>(GetExtendedTcpTable, AfInet6, TcpTableOwnerPidAll))
        {
            rows.Add(new NetstatRow(
                "TCP",
                FormatEndpoint6(r.LocalAddr, r.LocalScopeId, r.LocalPort),
                FormatEndpoint6(r.RemoteAddr, r.RemoteScopeId, r.RemotePort),
                TcpStateName(r.State),
                (int)r.OwningPid));
        }
    }

    private static void ReadUdp(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibUdpRowOwnerPid>(GetExtendedUdpTable, AfInet, UdpTableOwnerPid))
        {
            rows.Add(new NetstatRow(
                "UDP", FormatEndpoint(r.LocalAddr, r.LocalPort), "*:*", string.Empty, (int)r.OwningPid));
        }
    }

    private static void ReadUdp6(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibUdp6RowOwnerPid>(GetExtendedUdpTable, AfInet6, UdpTableOwnerPid))
        {
            rows.Add(new NetstatRow(
                "UDP", FormatEndpoint6(r.LocalAddr, r.LocalScopeId, r.LocalPort), "*:*", string.Empty, (int)r.OwningPid));
        }
    }

    // Shared two-call (size, then fill) buffer walk. The table is a leading DWORD
    // count followed by a packed array of T rows. The table can grow between the size
    // and fill calls (TOCTOU), in which case the fill returns ERROR_INSUFFICIENT_BUFFER
    //, retried with the fresh size instead of silently dropping every connection.
    private static IEnumerable<T> Enumerate<T>(ExtendedTableFn api, int addressFamily, int tableClass) where T : struct
    {
        const uint ErrorInsufficientBuffer = 122;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var size = 0;
            api(IntPtr.Zero, ref size, false, addressFamily, tableClass, 0);
            if (size <= 0)
            {
                yield break;
            }

            var rows = new List<T>();
            uint result;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                result = api(buffer, ref size, false, addressFamily, tableClass, 0);
                if (result == 0)
                {
                    var count = Marshal.ReadInt32(buffer);
                    var rowSize = Marshal.SizeOf<T>();
                    var rowPtr = IntPtr.Add(buffer, sizeof(int));
                    for (var i = 0; i < count; i++)
                    {
                        rows.Add(Marshal.PtrToStructure<T>(IntPtr.Add(rowPtr, i * rowSize)));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            if (result == 0)
            {
                foreach (var row in rows)
                {
                    yield return row;
                }
                yield break;
            }
            if (result != ErrorInsufficientBuffer)
            {
                yield break; // hard failure, the caller's netstat fallback covers it
            }
        }
    }

    /// <summary>Formats a network-byte-order IPv4 address + port DWORD as "ip:port".</summary>
    public static string FormatEndpoint(uint address, uint port) =>
        $"{new IPAddress(address)}:{NetworkToHostPort(port)}";

    /// <summary>Formats an IPv6 address (16 bytes) + scope id + port DWORD as "[ip]:port".</summary>
    public static string FormatEndpoint6(byte[] address, uint scopeId, uint port) =>
        $"[{new IPAddress(address, scopeId)}]:{NetworkToHostPort(port)}";

    /// <summary>Host-order port from the low 16 bits (network byte order) of a DWORD.</summary>
    public static int NetworkToHostPort(uint port) =>
        (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));

    public static string TcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    };
}
