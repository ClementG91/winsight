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
| `winsight_overview` | Runs the balanced overview: the scanners the capability catalog marks as in-overview. | Summaries/counts; noteworthy-only. |
| `winsight_scan` | Runs one named scanner, including large opt-in inventories. | Summaries/counts; noteworthy-only. |
| `winsight_process` | Everything WinSight knows about one pid — image, signature, parent, loaded-module counts with the unsigned ones named, and live external connections — gathered in one view. | Summary and counts. |
| `winsight_alerts` | Reads WinSight's own real-time detection journal (persistence and ransomware activity its background protection flagged, including while unattended). History, not a live scan. | Summaries/counts; noteworthy-only. |
| `winsight_outbound_firewall` | Reads the posture of WinSight's own opt-in outbound firewall service: reachability, requested mode, effective runtime state, applications awaiting a decision and stored per-application policies. Distinct from the `firewall` scanner, which inventories Microsoft Defender Firewall rules. | Posture summary and counts. |

Two fields of the posture report are deliberately separate and must not be merged
into one sentence. `mode` is what an operator requested; `effectiveState` is what is
running. Traffic is filtered only when `effectiveState` is `Active`; `Degraded` means
enforcement was requested and is not filtering. When `available` is `False`, WinSight
could not verify the service, which is not a finding that outbound filtering is off.

The set of scanners `winsight_scan` accepts travels in the tool's **JSON Schema**, as an
enumeration, rather than in its prose description. That is deliberate and it is a correction: the
description was previously hand-maintained and listed ten of the fifteen scanners, so `input`,
`integrity`, `drivers`, `hijack` and `presence` were reachable by a client that already knew their
names and invisible to one reading the schema — which is how a model decides what it may ask for.
Tests now pin the published enumeration, the capability catalog and WinSight's own dispatcher to
each other, and the packaged-installer contract asserts the enumeration on both architectures.

`winsight_process` is the pivot for following up a process another scanner named. It is the same
per-process view as `winsight process <pid>` on the command line: taking it from the dedicated tool
avoids re-running the processes, modules and connections scanners and joining them by hand, which
is both slow and easy to get wrong. It shares the single-scan gate, so it queues behind a running
scan rather than adding a second signature-verification pass to the machine. A pid that is not
running is reported as not running — a different answer from a process that is running and has
nothing notable — and `pid 0`, the System Idle Process, is refused rather than described.

### Resources

| Resource | Contents |
|---|---|
| `winsight://capabilities` | The machine-readable capability document, including every channel this process opens. |
| `winsight://security-model` | Read-only boundaries and privacy defaults. |
| `winsight://verdict-model` | How to read a finding without overstating it. |

`winsight://verdict-model` exists because several WinSight verdicts have an accurate reading and a
natural-sounding one, and the natural-sounding one is a stronger claim than the evidence supports:
`FileMissing` means the signature was **never checked**, not that the file is unsigned; a
persistence item can be notable because of its command line while its signature is perfectly valid;
and an alert with no named author says *why* it has none. It is published as a resource rather than
folded into the server instructions because it is reference material to consult when describing a
specific finding, not context every request should carry.

### Prompts

| Prompt | What it is for |
|---|---|
| `winsight_triage_machine` | An end-to-end posture review in a sensible tool order, with the reporting rules attached. Takes an optional focus. |
| `winsight_explain_alert` | Explains a real-time detection, what to check, and what it does not prove. |

Both encode a failure whose output reads as a confident, well-formed answer: reporting traffic as
blocked when nothing is filtering, and reporting "nobody knows who wrote this" when the truth is
"WinSight was not allowed to look". Server instructions already carry these rules, but instructions
are advisory context a model may compress or lose behind a long conversation, whereas a prompt is
selected by the user at the moment they ask and puts the rule in the same turn as the request.

`includeEvidence=true` is required for item-level results. Evidence is capped at
200 items per report, user-profile paths are replaced with environment placeholders,
and command/command-line fields are omitted. Only one scan runs at a time and a scan
has a 90-second safety limit.

The gate withholds fields by name, so a finding's human-readable *detail* has to be built so it
never carries a command line. Persistence details previously fell back to the raw command whenever
the image could not be resolved - which is exactly the encoded-interpreter case the gate exists for,
so the payload crossed with neither choice below made. The detail now names the executable only; the
arguments stay in the withheld field.

Raw sensitive fields require two independent choices:

1. The user starts the MCP server with `WINSIGHT_MCP_ALLOW_SENSITIVE=1`.
2. The individual call sets both `includeEvidence=true` and
   `includeSensitive=true`.

Do not enable this globally unless the selected AI client and model endpoint are
trusted to receive local paths and command lines.

## Protocol and compatibility

As verified on **2026-07-30**, WinSight speaks the current MCP revision,
[`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28), through
version **2.2.0** of the
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
