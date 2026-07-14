# WinSight — architecture

Status: accepted and implemented for Phase 1. Phase 2 details live in
[`WFP_DESIGN.md`](WFP_DESIGN.md).

## Shape

A shared **core** + independent **tool modules** + one **dashboard/tray** shell.
Each tool is usable standalone (like Objective-See's), but they share the core so
signatures, process attribution and reputation are computed once.

```text
winsight/
  src/
    WinSight.Core/         # signatures, hashes, opt-in reputation
    WinSight.Reporting/    # stable shared report contract
    WinSight.Application/  # scanner orchestration shared by CLI + dashboard
    WinSight.Persistence/  # autostart enumeration
    WinSight.AvMonitor/    # camera/mic history + live transitions
    WinSight.NetMonitor/   # IP Helper connections + DNS cache/ETW
    WinSight.Firewall/     # rules + Phase 2 policy contracts
    WinSight.Cli/          # scriptable unified entry point
    WinSight.Dashboard/    # WPF dashboard + system tray
    WinSight.Mcp/          # local read-only MCP stdio server for AI clients
  tests/                   # pure unit tests + Windows integration smoke tests
  installer/               # least-privilege multilingual Windows installer
  scripts/                 # audited packaging, SBOM and installer validation
  drivers/         # (Phase 3/4) minifilter / WFP callout (needs EV cert)
  docs/
```

## Windows primitives per tool (the real engineering)

- **Persistence** — read the full autostart surface: `HKLM/HKCU ...\Run`,
  `RunOnce`, Scheduled Tasks (Task Scheduler COM / `\Windows\System32\Tasks`),
  Services (`HKLM\SYSTEM\CurrentControlSet\Services`), WMI `__EventFilter` /
  `CommandLineEventConsumer`, startup folders, `Winlogon` (Shell/Userinit),
  `AppInit_DLLs`, print monitors, drivers. Verdict each via **WinVerifyTrust**
  (Authenticode). This is the same surface Autoruns covers — but OSS and scriptable.
- **Camera/Mic** — activation signal from ETW providers and the
  `CapabilityAccessManager\ConsentStore\{webcam,microphone}` registry (per-app
  `LastUsedTimeStart/Stop`), cross-checked with `MMDevice`/audio session state.
  Attribute to the owning process; alert on transition to active.
- **Net + DNS** — connection table via **IPHelper** (`GetExtendedTcpTable`/Udp),
  live events + DNS via ETW (`Microsoft-Windows-DNS-Client`,
  `Microsoft-Windows-Kernel-Network`). Map socket → PID → signed binary.
- **Firewall (Phase 2)** — **WFP** (Windows Filtering Platform) user-mode filters
  keyed by app id; a prompt-on-new-connection UX. WFP alone (no driver) covers
  most of LuLu's outbound-control use case.
- **Guardian (Phase 3/4)** — real-time persistence + ransomware. Monitoring is
  ETW/user-mode; *blocking* needs a **minifilter** (`FltRegisterFilter`) or WFP
  callout **driver** → EV cert + attestation signing. Explicitly deferred.

## Why .NET for user-mode (recommended)

- Broadest, best-documented Win32 surface via **CsWin32** (source-generated
  P/Invoke) — persistence, IPHelper, WinVerifyTrust are all a struct away.
- **TraceEvent** (Microsoft) is the mature ETW consumer library — the backbone of
  the av/net/dns monitors — with no hand-rolled ETW plumbing.
- Tray apps, notifications and the WPF dashboard are first-class.
- Fast to an installable MVP. Perf-critical bits can drop to Rust/C++ later without
  reworking the shell.

Alternatives considered: **Rust** (`windows-rs`) — great for a small, dependency-light
signed agent and the eventual driver, steeper ETW ergonomics; **C++/WDF** — mandatory
for the kernel driver, overkill for the user-mode MVP. Recommendation: **.NET 10 LTS
for the supported user-mode suite, Rust/C++ reserved for the driver and any perf
agent.**

## Non-negotiables

- **Local-only, no telemetry.** A security tool that phones home is a contradiction.
- **Every network/VT lookup is opt-in and user-keyed.**
- **Reproducible releases** with signed Git commits/tags, SHA-256, build provenance
  and SPDX SBOM attestations. Authenticode signing is mandatory once a public
  code-signing certificate is available; the unsigned-publisher limitation is
  disclosed until then.
- **Least privilege**: run tools with the minimum rights; elevate only the specific
  operation that needs it.
- **AI is not an authority boundary**: MCP is local stdio, summary-first and
  read-only. No model receives a mutation primitive or silently enables network
  enrichment; sensitive evidence requires an explicit server-side gate.

## Decisions resolved

1. The user-mode application stack is C# / .NET 10 LTS with WPF for the dashboard.
2. Phase 1 is user-mode and read-only; kernel enforcement remains deferred.
3. The repository is GPL-3.0-or-later.
4. A pinned .NET SDK defines the build. Native x64 and Arm64 Windows runners execute
   their own packaged binaries and installers; the x64 runner also gates formatting
   and dependency auditing.
5. The AI integration uses the official MCP C# SDK, pinned to protocol `2025-11-25`,
   with no HTTP transport. See [`MCP.md`](MCP.md).
