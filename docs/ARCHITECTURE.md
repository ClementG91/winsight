# WinSight, architecture

Status: accepted and implemented for the current user-mode suite. Privileged outbound-firewall
details live in [`WFP_DESIGN.md`](WFP_DESIGN.md).

## Shape

A shared **core** + independent **tool modules** + one **dashboard/tray** shell.
Each tool is usable standalone (like Objective-See's), but they share the core so
signatures, process attribution and reputation are computed once.

```text
winsight/
  src/
    WinSight.Core/            # signatures (embedded, catalog, MSIX package content), hashes, opt-in reputation
    WinSight.Reporting/       # stable shared report contract
    WinSight.Application/     # scanner orchestration and hosts shared by CLI, dashboard and MCP
    WinSight.Persistence/     # autostart enumeration and Guardian real-time monitoring
    WinSight.Ransomware/      # decoys, burst/entropy detection
    WinSight.AvMonitor/       # camera/mic history + live transitions
    WinSight.NetMonitor/      # IP Helper connections + DNS cache/ETW
    WinSight.Attribution/     # elevated ETW write attribution
    WinSight.Processes/       # process inventory
    WinSight.Modules/         # loaded-module inventory
    WinSight.Browser/         # browser extensions
    WinSight.Certificates/    # trusted-root audit
    WinSight.Hosts/           # hosts file
    WinSight.InputHooks/      # keyboard/mouse filter drivers
    WinSight.Drivers/         # registered kernel drivers
    WinSight.CodeIntegrity/   # driver signing, memory integrity, Secure Boot posture
    WinSight.Hijack/          # service path, search-order and phantom-import exposure
    WinSight.Presence/        # resume timeline
    WinSight.Firewall/        # firewall contracts, IPC protocol and client
    WinSight.FirewallService/ # LocalSystem WFP service
    WinSight.Cli/             # scriptable unified entry point
    WinSight.Dashboard/       # WPF dashboard + system tray
    WinSight.Mcp/             # local read-only MCP stdio server for AI clients
  tests/                      # unit tests, real-Windows tests and validation probes
  installer/                  # least-privilege multilingual Windows installer
  scripts/                    # audited packaging, SBOM, coverage and qualification scripts
  evals/                      # optional developer-only AI-surface evaluation harness  docs/
```

The dashboard keeps detection evidence separate from localized presentation.
`WinSight.Application` emits stable structured fields for CLI, JSON and MCP, while
the dashboard presenter translates only WinSight-owned labels and explanations.
Paths, process names, domains and other forensic values are never rewritten.

## Windows primitives per tool (the real engineering)

- **Processes + modules**, WMI process inventory and accessible `Process.Modules` snapshots. Cross-
  snapshot joins use PID plus UTC process-creation time; PID-only module/connection rows and recycled
  parent/child candidates are excluded rather than attributed to the current owner of that PID.
- **Persistence**, read the full autostart surface: `HKLM/HKCU ...\Run`,
  `RunOnce`, Scheduled Tasks (Task Scheduler COM / `\Windows\System32\Tasks`),
  Services (`HKLM\SYSTEM\CurrentControlSet\Services`), WMI `__EventFilter` /
  `CommandLineEventConsumer`, startup folders, `Winlogon` (Shell/Userinit),
  `AppInit_DLLs`, print monitors/providers, credential providers, browser helper objects,
  Windows Load/Run values and drivers. Verdict each via **WinVerifyTrust**
  (Authenticode). This is the same surface Autoruns covers, but OSS and scriptable.
- **Camera/Mic**, activation history and transitions from the
  `CapabilityAccessManager\ConsentStore\{webcam,microphone}` registry (per-app
  `LastUsedTimeStart/Stop`), watched with registry notifications plus bounded polling.
  Application/process matching is best-effort; WinSight does not currently cross-check ETW,
  `MMDevice` or live audio sessions and cannot prove every device capture.
- **Net + DNS**, connection table via **IPHelper** (`GetExtendedTcpTable`/Udp),
  live events + DNS via ETW (`Microsoft-Windows-DNS-Client`,
  `Microsoft-Windows-Kernel-Network`). Map socket → PID → signed binary. DNS caller delivery is
  isolated from the ETW callback through a bounded non-blocking queue; native and queue loss share
  the sensor-health coverage counter.
- **Firewall (Phase 2)**, **WFP** (Windows Filtering Platform) user-mode filters
  keyed by app id. A user-mode WFP filter cannot hold a connection while a user decides, so an unknown application is recorded as pending after it connects. The pending view is a bounded 128-app
  LRU window: later arrivals cannot be permanently excluded by pre-filling it, while capacity
  evictions and their aggregated observations are reported as incomplete coverage. A prompt-driven default-deny mode is planned in [`OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md`](OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md) (M4). WFP alone (no driver) covers
  most of LuLu's outbound-control use case.
- **Guardian (Phase 3/4)**, real-time persistence + ransomware. Phase 3 persistence
  monitoring is **implemented** (user-mode, in the dashboard): `RegNotifyChangeKeyValue`
  on the Run/Services/Winlogon keys and a `FileSystemWatcher` on the Startup folders and
  `\System32\Tasks` trigger a re-scan of the affected surface; a genuinely new autostart
  item is verdict-checked via the existing Authenticode path and raised as a tray balloon.
  The persistence enumerators stay the source of truth - watchers only trigger the diff. See
  `docs/GUARDIAN_DESIGN.md`. Phase 4 ransomware behavior is **also implemented** (user-mode,
  opt-in): visible machine-varied decoy files plus rename/delete bursts, entropy-on-write and bounded
  container-signature integrity heuristics over a
  `FileSystemWatcher`, with the same pure-core/thin-watcher split. See `docs/RANSOMWARE_DESIGN.md`.
  Registry/filesystem and ETW observers expose one provider-neutral sensor-health snapshot (lifecycle,
  requested/active sources, observations, native loss, recovery and delivery failures). Missing or
  failed persistence watches are retried and reconciled; ETW loss is surfaced through the dashboard,
  CLI and firewall status rather than reading as an idle sensor.
  Both stop at detect-and-alert: *blocking* the write, and *naming the process* responsible, need a
  **minifilter** (`FltRegisterFilter`) / WFP callout **driver** or an elevated ETW provider →
  EV cert + attestation signing for the driver route.

## Why .NET for user-mode (recommended)

- Broadest, best-documented Win32 surface: persistence, IPHelper and WinVerifyTrust are
  all a struct away. The declarations are hand-written `LibraryImport`/`DllImport` rather
  than source-generated by CsWin32, which was considered and not adopted - the interop
  surface is small and safety-critical, and a hand-written declaration is the thing that
  actually gets reviewed.
- **TraceEvent** (Microsoft) is the ETW consumer for elevated write attribution, DNS and the
  firewall service's outbound observer. Camera/mic monitoring is registry-based and ordinary
  connection inventory uses IP Helper.
- Tray apps, notifications and the WPF dashboard are first-class.
- Fast to an installable MVP. Perf-critical bits can drop to Rust/C++ later without
  reworking the shell.

Alternatives considered: **Rust** (`windows-rs`), great for a small, dependency-light
signed agent and the eventual driver, steeper ETW ergonomics; **C++/WDF**, mandatory
for the kernel driver, overkill for the user-mode MVP. Recommendation: **.NET 10 LTS
for the supported user-mode suite, Rust/C++ reserved for the driver and any perf
agent.**

## Non-negotiables

- **Local-only, no telemetry.** A security tool that phones home is a contradiction.
- **Every network/VT lookup is opt-in and user-keyed.**
- Interactive VirusTotal credentials are protected per Windows user with DPAPI;
  managed automation may use `WINSIGHT_VT_KEY`. Neither path is exposed to MCP or
  report serialization.
- Community quotas are enforced by a fail-closed per-user counter shared across
  WinSight processes (rolling minute plus UTC day/month); HTTP quota responses are
  not retried.
- **Reproducible releases** with signed Git commits/tags, SHA-256, build provenance
  and SPDX SBOM attestations. Authenticode signing is mandatory once a public
  code-signing certificate is available; the unsigned-publisher limitation is
  disclosed until then.
- **Least privilege**: run tools with the minimum rights; elevate only the specific
  operation that needs it.
- **AI is not an authority boundary**: MCP is local stdio, summary-first and
  read-only. No model receives a mutation primitive or silently enables network
  enrichment; sensitive evidence requires an explicit server-side gate.

## Response layer decisions (proposed, ADR)

The response layer in [`OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md`](OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md)
rests on these decisions. They are recorded here so the boundaries are reviewable before the
consumers are built.

- **D1 - where actions run.** Same-user actions (the user's own processes, HKCU persistence, per-user
  startup files) run in the unprivileged dashboard. Machine-wide actions (services, HKLM, all-users
  items, a machine-wide network block) run in the existing LocalSystem service under a new,
  administrator-only response command family, separate from the firewall commands and with its own
  dispatcher and authority.
- **D2 - alerts carry decisions** through a WinSight-owned alert window (topmost, keyboard-accessible,
  localized), with the tray balloon as a fallback. No dependency on Windows toast activation.
- **D3 - always-on** is an opt-in "start at sign-in" per-user Run entry launching the dashboard in
  tray mode; Guardian recognises its own entry. Not a new service.
- **D4 - rule store.** One versioned, atomically written, mutex-serialized per-user JSON store
  (`WinSight.Response.RuleStore`) holds allow/ignore/block decisions for Guardian, ransomware and
  camera/microphone. Machine-wide network rules stay in the service-owned, ACL-protected policy store.
- **D5 - quarantine** (`WinSight.Response.Quarantine`) keeps a private-DACL per-user directory of
  removed items (manifest + payload, hash-verified on restore) so every removal is reversible.
- **D6 - no kernel driver** in the response layer; revisited only if the M9 measurements show a
  user-mode gap that matters.
- **D7 - process identity** is `(pid, start time, image path, image SHA-256)`, captured at alert time
  and revalidated immediately before acting (`WinSight.Response.ProcessIdentity`), so a reused pid or
  replaced image is refused rather than acted on.

## Decisions resolved

1. The user-mode application stack is C# / .NET 10 LTS with WPF for the dashboard.
2. Phase 1 is user-mode and read-only; kernel enforcement remains deferred.
3. The repository is GPL-3.0-or-later.
4. A pinned .NET SDK defines the build. Native x64 and Arm64 Windows runners execute
   their own packaged binaries and installers; the x64 runner also gates formatting
   and dependency auditing.
5. The AI integration uses the official MCP C# SDK over local stdio with no HTTP transport. The
   current SDK advertises the stateless `2026-07-28` revision and negotiates older initialize-based
   clients, including `2025-11-25`; it is not pinned to one revision. See [`MCP.md`](MCP.md).
