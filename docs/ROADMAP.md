# Roadmap and design history

Where WinSight came from, what is deliberately not built, and what is next. This is the development
narrative that used to live in the README; the README is now a product page.

## Why this exists

Windows has no equivalent of Objective-See: a coherent family of free, open-source, transparent
security tools aimed at a normal user rather than an enterprise SOC. What exists is either an
enterprise EDR (expensive, opaque, agent-heavy), a single-purpose utility with no common language for
its findings, or freeware with an unclear business model.

WinSight's bet is that the valuable part is not any one detection — most are documented Windows
mechanisms — but **one auditable roof** over them, with a shared report shape, a shared signature
verifier, and an explicit refusal to phone home.

## Scope decisions

Deliberate constraints, chosen to avoid building an EDR nobody asked for:

- **User-mode first, no kernel driver.** A production minifilter needs a signed certificate and a
  separate safety programme. Detect-and-alert without a driver is genuinely useful; a half-built
  driver is a liability on someone's boot path.
- **Observe, do not act.** Every tool reports. The firewall blocks only what the user chose;
  ransomware protection is the only feature that writes anything, and it is off by default.
- **One report shape.** Every scanner emits the same `ToolReport`, so the CLI, dashboard and MCP
  server render the same semantics without duplicating detection logic.
- **No account, no telemetry, no paywall.** Non-negotiable. A security tool that phones home is
  asking for trust it has not earned.
- **Small tools, one roof.** Each scanner stands alone and is testable alone.

## Phases

### Phase 1 — user-mode scanners *(shipped)*

Persistence scanner, camera and mic monitor, connection and DNS monitors, unified dashboard, shared
signature and reputation helper.

### Phase 2 — outbound firewall *(shipped, qualified on x64)*

Per-application outbound control on WFP: an unprivileged dashboard driving a privileged LocalSystem
service over authenticated local IPC. Opt-in enforcement that persists and survives reboot.
Qualified end to end on a clean VM — see [`validation/`](validation/README.md).

### Phase 3 — real-time persistence *(shipped, detect-and-alert)*

Guardian promotes the scanner to a live watcher: registry change notification plus Startup and Tasks
folder watching, verdict through the existing Authenticode path, tray alert, and reconciliation of
what changed while WinSight was not running.

*Blocking* the write still needs a minifilter. See [`GUARDIAN_DESIGN.md`](GUARDIAN_DESIGN.md).

### Phase 4 — ransomware canary *(shipped, opt-in)*

Hidden decoy files, rename/delete-burst detection, and entropy-on-write scoring gated so that saving
a `.docx` or a `.jpg` never trips it. Loud alert on detection.

*Interception* needs a minifilter. See [`RANSOMWARE_DESIGN.md`](RANSOMWARE_DESIGN.md).

## What is next

### Native Arm64 privileged qualification

The only work blocked on hardware. Build, PE architecture, packaging and the full installer lifecycle
are already verified on a **native** Arm64 runner on every CI run. What remains is the privileged
runtime — WFP, SCM, path trust, IPC — plus emulated-x64 application identity, the one behaviour with
no x64 analogue.

Nothing new needs writing: the protocol, scripts and binding method exist and ship inside the Arm64
package. The exact procedure is in [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

### Authenticode signing

Implemented and verified; waiting on a code-signing certificate. See [`RELEASE.md`](RELEASE.md).

### Broader write attribution

Naming the process behind *every* detection currently needs an ETW file/registry provider or a
driver. Today attribution works when WinSight runs elevated and says why it cannot when it does not.
See [`ATTRIBUTION_DESIGN.md`](ATTRIBUTION_DESIGN.md).

## Deliberately not planned

| Not building | Why |
|---|---|
| Kernel minifilter for blocking | Needs a signed driver and a safety programme; deferred, not abandoned |
| Cloud console / fleet management | Would require telemetry, which is the line this project will not cross |
| Signature-based malware detection | That is antivirus; WinSight is triage and visibility |
| Automatic remediation | A tool that deletes things on its own is a tool you cannot trust |

## Naming

`WinSight` is a working title (Objective-See → "see" what is happening; the Windows analogue).
Objective-See uses doubled names (KnockKnock, BlockBlock); per-tool names here can follow that or
stay descriptive.

## Stack

- **Application and user-mode tools:** C# on .NET 10 LTS, `CsWin32` for P/Invoke, `TraceEvent` for
  ETW, WPF for the dashboard and tray.
- **Performance-critical core, if ever needed:** Rust or C++.
- **Kernel driver, if the deferred phases are ever taken up:** C/C++ KMDF minifilter, or Rust
  `windows-drivers`.

Locked decisions and layering: [`ARCHITECTURE.md`](ARCHITECTURE.md).
