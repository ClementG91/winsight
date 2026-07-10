using System.Net;
using System.Runtime.InteropServices;

namespace WinSight.NetMonitor;

/// <summary>
/// Reads the active TCP/UDP tables natively via IP Helper (GetExtendedTcpTable /
/// GetExtendedUdpTable) — structured, fast, and locale-independent, unlike parsing
/// netstat text. Rows are all fixed DWORDs (MIB_*ROW_OWNER_PID), so marshalling is
/// straightforward. ConnectionMonitor falls back to netstat if these entry points are
/// unavailable.
/// </summary>
public static class NativeConnectionReader
{
    private const int AfInet = 2;                 // IPv4
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

    /// <summary>Snapshots the current IPv4 TCP + UDP tables with owning PIDs.</summary>
    public static IReadOnlyList<NetstatRow> Read()
    {
        var rows = new List<NetstatRow>();
        ReadTcp(rows);
        ReadUdp(rows);
        return rows;
    }

    private static void ReadTcp(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibTcpRowOwnerPid>(GetExtendedTcpTable, TcpTableOwnerPidAll))
        {
            rows.Add(new NetstatRow(
                "TCP",
                FormatEndpoint(r.LocalAddr, r.LocalPort),
                FormatEndpoint(r.RemoteAddr, r.RemotePort),
                TcpStateName(r.State),
                (int)r.OwningPid));
        }
    }

    private static void ReadUdp(List<NetstatRow> rows)
    {
        foreach (var r in Enumerate<MibUdpRowOwnerPid>(GetExtendedUdpTable, UdpTableOwnerPid))
        {
            rows.Add(new NetstatRow(
                "UDP", FormatEndpoint(r.LocalAddr, r.LocalPort), "*:*", string.Empty, (int)r.OwningPid));
        }
    }

    // Shared two-call (size, then fill) buffer walk. The table is a leading DWORD
    // count followed by a packed array of T rows.
    private static IEnumerable<T> Enumerate<T>(ExtendedTableFn api, int tableClass) where T : struct
    {
        var size = 0;
        api(IntPtr.Zero, ref size, false, AfInet, tableClass, 0);
        if (size <= 0)
        {
            yield break;
        }
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (api(buffer, ref size, false, AfInet, tableClass, 0) != 0)
            {
                yield break;
            }
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<T>();
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            for (var i = 0; i < count; i++)
            {
                yield return Marshal.PtrToStructure<T>(IntPtr.Add(rowPtr, i * rowSize));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Formats a network-byte-order IPv4 address + port DWORD as "ip:port".</summary>
    public static string FormatEndpoint(uint address, uint port) =>
        $"{new IPAddress(address)}:{NetworkToHostPort(port)}";

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
