# WinSight MCP server

`winsight.exe mcp` lets an MCP-compatible AI client inspect WinSight's local,
read-only security observations. It is included in both installers and portable
archives starting with WinSight 0.7.0.

## Security boundary

The server uses MCP over standard input/output. The AI client starts one child
process for one session; WinSight does not open a port, bind to localhost, accept
remote clients or install a background MCP service.

All exposed tools are declared read-only, idempotent, non-destructive and
closed-world. MCP never exposes process termination, file deletion, quarantine,
registry editing, firewall mutation or WFP policy changes. VirusTotal and every
other network lookup are disabled inside MCP scans even when `WINSIGHT_VT_KEY` is
present in the parent environment.

The process opens one channel, and only one. `winsight_outbound_firewall` connects
to the local WinSight firewall service over its authenticated named pipe to read
posture, sending status and list commands only. The privileged service authorises by
the caller's Windows identity and refuses every mutation to an unelevated caller, so
the MCP process has exactly the reach an unelevated dashboard has and no path to arm
or disarm the machine. Inside WinSight the tool is handed a posture-only interface
rather than the full service gateway, so the restriction does not rest on nobody
adding the wrong call later. The capability document declares this channel as
`firewallServiceIpc`.

Remember that the configured AI client may send tool results to its model provider.
That transfer is controlled by the AI client, not by WinSight. Review the client's
privacy policy and tool-confirmation UI before enabling evidence access.

## Configure a client

Point the MCP client's `command` at the installed executable. A common JSON shape is:

```json
{
  "mcpServers": {
    "winsight": {
      "command": "C:\\Users\\YOUR-NAME\\AppData\\Local\\Programs\\WinSight\\winsight.exe",
      "args": ["mcp"]
    }
  }
}
```

The exact settings filename and UI vary by MCP client. For a portable installation,
use the absolute path to the extracted `winsight.exe` with the `mcp` argument. Do not wrap the server in
PowerShell, `cmd.exe`, an HTTP relay or a network tunnel.

## Exposed tools

| Tool | Purpose | Default disclosure |
|---|---|---|
| `winsight_get_capabilities` | Lists scanners and active privacy controls without scanning. | Product metadata only. |
| `winsight_overview` | Runs the balanced seven-scanner overview. | Summaries/counts; noteworthy-only. |
| `winsight_scan` | Runs one named scanner, including large opt-in inventories. | Summaries/counts; noteworthy-only. |
| `winsight_alerts` | Reads WinSight's own real-time detection journal (persistence and ransomware activity its background protection flagged, including while unattended). History, not a live scan. | Summaries/counts; noteworthy-only. |
| `winsight_outbound_firewall` | Reads the posture of WinSight's own opt-in outbound firewall service: reachability, requested mode, effective runtime state, applications awaiting a decision and stored per-application policies. Distinct from the `firewall` scanner, which inventories Microsoft Defender Firewall rules. | Posture summary and counts. |

Two fields of the posture report are deliberately separate and must not be merged
into one sentence. `mode` is what an operator requested; `effectiveState` is what is
running. Traffic is filtered only when `effectiveState` is `Active`; `Degraded` means
enforcement was requested and is not filtering. When `available` is `False`, WinSight
could not verify the service, which is not a finding that outbound filtering is off.

The server also publishes `winsight://capabilities` and
`winsight://security-model` as MCP resources.

`includeEvidence=true` is required for item-level results. Evidence is capped at
200 items per report, user-profile paths are replaced with environment placeholders,
and command/command-line fields are omitted. Only one scan runs at a time and a scan
has a 90-second safety limit.

Raw sensitive fields require two independent choices:

1. The user starts the MCP server with `WINSIGHT_MCP_ALLOW_SENSITIVE=1`.
2. The individual call sets both `includeEvidence=true` and
   `includeSensitive=true`.

Do not enable this globally unless the selected AI client and model endpoint are
trusted to receive local paths and command lines.

## Protocol and compatibility

As verified on **2026-07-30**, WinSight speaks the current MCP revision,
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28), through
version **2.0.0** of the
[official C# MCP SDK](https://github.com/modelcontextprotocol/csharp-sdk).

The server deliberately does not pin a single revision. `2026-07-28` removed the
`initialize` handshake in favour of a stateless model where a client declares its
version per request, so offering that revision alone would answer every client still
on `2025-11-25` or earlier with `Protocol version '2026-07-28' is not available
through the initialize handshake` - unreachable rather than modern. The specification
expects both sides to support several revisions at once, so the SDK negotiates:
`server/discover` advertises `2026-07-28` and carries the protocol version, client
capabilities and client identity in `_meta`, while the handshake continues to serve
older clients.

Packaging and installer tests exercise both paths on native x64 and Arm64 runners:
a stateless `server/discover` and `tools/list`, then a real `2025-11-25`
initialization, listing every tool, verifying the read-only annotations and invoking
the capability, scan, alert and posture tools. Covering only one path would hide
exactly the failure described above.

The MCP surface follows the same report semantics as the CLI and dashboard. A
`notable` item is evidence worth investigating, not proof of compromise and not a
claim that WinSight remediated anything.
