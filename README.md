<p align="center">
  <img src="assets/branding/winsight-logo.png" width="180" alt="WinSight — Windows security visibility" />
</p>

<h1 align="center">WinSight</h1>

[![CI](https://github.com/ClementG91/winsight/actions/workflows/ci.yml/badge.svg)](https://github.com/ClementG91/winsight/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/platform-Windows-informational)
![.NET 10 LTS](https://img.shields.io/badge/.NET-10.0_LTS-512bd4)

> Free, open-source, transparent security tools for Windows — in the spirit of
> [Objective-See](https://objective-see.org/tools.html) for macOS.

**Goal:** let a normal Windows user *see and control* what is actually happening on
their machine — what persists, what watches the camera/mic, what phones home — with
small, single-purpose, auditable tools under one roof. No telemetry, no account, no
paywall.

## Why this exists (verified prior-art check, 2026-07)

Objective-See's macOS suite has **no unified open-source equivalent on Windows.**
The building blocks exist but are scattered, and the best of them is closed-source:

| Objective-See (macOS) | Function | Windows: what exists today | Gap |
|---|---|---|---|
| KnockKnock | enumerate persistence | **Autoruns** (Sysinternals) — *closed source* | OSS gap |
| BlockBlock | real-time persistence alert/block | — | **no OSS** |
| LuLu | outbound firewall | simplewall, Portmaster (OSS, standalone) | integration gap |
| OverSight | camera/mic use alerts | — (a little closed freeware) | **no OSS** |
| RansomWhere? | ransomware behavior stop | — (research only) | **no OSS** |
| TaskExplorer | process inspector | Process Hacker / System Informer (OSS) | covered |
| Netiquette | live connections | TCPView (Sysinternals) — *closed* | OSS gap |
| DNSMonitor | DNS queries | — | **no OSS** |
| What's Your Sign | signature check | Sigcheck (Sysinternals) — *closed* | OSS gap |

**Takeaway:** don't re-clone Sysinternals or Process Hacker. The real value is the
**four "no OSS" gaps** (cam/mic, ransomware behavior, real-time persistence,
DNS visibility) **+ a single, friendly, transparent suite UX**.

## Scope decisions (senior, anti-over-engineering)

- **User-mode first.** Everything in the MVP is user-mode, built on **ETW**
  (Event Tracing for Windows), **WFP** (Windows Filtering Platform), IPHelper,
  Authenticode and the registry. It ships without a kernel driver.
- **Kernel driver is Phase 2, and expensive.** Real-time *blocking* (BlockBlock,
  RansomWhere-grade file interception) needs a minifilter / WFP callout driver,
  which on modern Windows requires an **EV code-signing certificate + Microsoft
  attestation signing** (real money + process, Secure Boot / driver-signing
  enforcement). We do NOT gate the MVP on it. Monitoring/alerting is fully doable
  in user-mode via ETW; blocking-grade enforcement comes later, deliberately.
- **Small, independent tools** sharing one core + one dashboard — not a monolith.
- **No vendor lock-in, no SaaS.** Local-only. Optional VirusTotal lookups are
  opt-in and keyed by the user.

## MVP (Phase 1 — user-mode, no driver, ships fast)

1. **Persistence Scanner** (KnockKnock-class) — enumerate every autostart vector
   (Run keys, Scheduled Tasks, Services, WMI event subs, startup folders, drivers,
   winlogon/AppInit, etc.), verify Authenticode signatures, flag the unsigned/odd.
2. **Camera & Mic Monitor** (OverSight-class) — tray alerts when the webcam/mic go
   active, with per-process attribution (ETW + `CapabilityAccessManager` registry).
3. **Connection & DNS Monitor** (Netiquette + DNSMonitor-class) — live outbound
   connections (IPHelper) and DNS queries (ETW `Microsoft-Windows-DNS-Client`).
4. **Unified dashboard** + a shared **signature/reputation** helper (What's Your
   Sign-class) used by all tools.

## Roadmap (later phases)

- **Phase 2 — Firewall** (LuLu-class) on **WFP**, per-app outbound control.
- **Phase 3 — Real-time persistence** (BlockBlock-class): promote the scanner to a
  live watcher; optional minifilter for blocking (cert required).
- **Phase 4 — Ransomware canary** (RansomWhere-class): canary files + entropy/rename
  heuristics; minifilter for true interception (cert required).

## Stack (locked — see `docs/ARCHITECTURE.md`)

- **App + user-mode tools:** C# / **.NET 10 LTS**, `CsWin32` for P/Invoke, `TraceEvent`
  for ETW, WPF tray/dashboard. Fastest path with the broadest Win32
  coverage.
- **Perf-critical core / future agent:** Rust or C++ if/when needed.
- **Kernel driver (Phase 3/4):** C/C++ KMDF minifilter (or Rust `windows-drivers`).

## Install

Download the installer matching the PC from the
[latest release](https://github.com/ClementG91/winsight/releases/latest):

- Intel/AMD 64-bit Windows: `winsight-vX.Y.Z-win-x64-setup.exe`
- Windows on Arm: `winsight-vX.Y.Z-win-arm64-setup.exe`

The installer is per-user and does not require .NET or administrator privileges.
Portable ZIPs are published for both architectures. See
[`docs/INSTALLATION.md`](docs/INSTALLATION.md) for the support matrix, checksum and
provenance verification, silent deployment and the current Authenticode limitation.

## Build from source

WinSight targets Windows and .NET 10 LTS. Install the .NET 10 SDK, then run:

```powershell
dotnet restore winsight.sln
dotnet build winsight.sln -c Release
dotnet test winsight.sln -c Release --no-build
dotnet run --project src/WinSight.Dashboard
```

`global.json` pins the supported SDK feature band. GitHub Actions builds, formats,
tests and audits NuGet dependencies. Release candidates are packaged and installed
end-to-end on native x64 and native Arm64 Windows runners. To reproduce the complete
release payload locally:

```powershell
./scripts/Build-Release.ps1 -Version 0.7.1
```

The build script restores the pinned Microsoft SBOM tool and installs the pinned
Inno Setup compiler after verifying both its official SHA-256 and Authenticode
signature.

## Naming

`WinSight` is a working title (Objective-See → "see" what's happening; the Windows
analog). Objective-See's tools use doubled names (KnockKnock, BlockBlock); the
per-tool names here can follow that or stay descriptive. Rename freely before code.

## Status

Phase 1 is feature-complete for the first beta. CI gates quality on x64 and executes
the packaged application and installer on native x64 and native Arm64 Windows.
Modular tool libraries are available through the `winsight` CLI (subcommands
`persistence | av | net | dns | firewall | processes | modules | extensions | certs |
hosts | all`, `--flagged`, `--json`, `--version`, `--help`)
the `winsight-dashboard` WPF/tray application, and a local `winsight mcp` server for
MCP-compatible AI clients:

All three surfaces use the shared `WinSight.Application` orchestration layer;
detection logic and report semantics are not duplicated in UI or protocol code.

The MCP server is local `stdio` only: it opens no network listener and exposes three
read-only tools plus capability/security resources. Summary-only output is the
default, evidence is bounded and privacy-redacted, sensitive command lines require a
server-side opt-in, and network reputation lookup is always disabled for MCP scans.
See [`docs/MCP.md`](docs/MCP.md) for client configuration and the threat model.

The dashboard is designed for non-technical users: each check explains what it
observes and what an alert means, the overview reports progress between independent
scanners, and reports can be exported or copied. Actions are deliberately safe:
WinSight can reveal an item's validated file location or open the corresponding
trusted Windows console, but it never deletes, kills or blocks automatically.

The interface is available in **English, French and Spanish**. It follows the
Windows display language on first launch, falls back to English for unsupported
cultures, remembers an explicit selection, and can switch language from the header
without restarting. Packaged-language startup is verified by CI for all three
cultures; raw Windows paths, process names and other forensic evidence are never
translated or altered.

The language can also be selected explicitly for managed deployments, for example
`winsight-dashboard --language es` (supported values: `en`, `fr`, `es`).

- **Persistence** (KnockKnock-class) — 18 autostart surfaces: Run/RunOnce/RunServices/
  Policies\Explorer\Run (HKLM+HKCU × 64/32-bit), Services & drivers (incl. svchost
  `ServiceDll` payloads), Winlogon Shell/Userinit (HKLM+HKCU), Scheduled Tasks (Tasks
  XML), AppInit_DLLs, IFEO debuggers, SilentProcessExit monitors, Active Setup,
  BootExecute, WMI event subscriptions, Startup folders (.lnk-resolved), LSA packages,
  Print monitors, Netsh helpers, COM hijacks (HKCU CLSID), AppCertDLLs, Time
  providers, Screensaver — each signature-checked, resilient per-surface scan.
- **Camera/Mic** (OverSight-class) — which apps used the webcam/mic and what is live
  now (CapabilityAccessManager ConsentStore), plus real-time `av --watch` alerts the
  instant a device turns on/off.
- **Connections** (Netiquette-class) — active TCP/UDP (IPv4 + IPv6) via native IP
  Helper tables (GetExtendedTcpTable/Udp), attributed to the owning process + its
  signature; flags external, established, unsigned owners.
- **DNS** (DNSMonitor-class) — recently resolved domains from the resolver cache, plus
  real-time `dns --watch` (live ETW queries, Administrator).
- **Firewall** (LuLu-class, read-only) — lists Windows Defender Firewall rules
  (`winsight firewall`). An enforcing per-app firewall is a later phase.
- **Processes** (TaskExplorer-class) — every running process with its image path,
  parent, command line and Authenticode signature (`winsight processes` / `ps`);
  flags unsigned or untrusted running images. Read-only.
- **Modules** (DLL-injection audit) — the DLLs loaded into every accessible process,
  signature-checked (`winsight modules` / `dll`); flags unsigned/untrusted DLLs
  side-loaded or injected into running processes. Read-only.
- **Extensions** (browser supply-chain) — installed extensions across the
  Chromium-family browsers with their declared permissions (`winsight extensions` /
  `ext`); flags extensions holding broad-reach permissions. Read-only.
- **Certificates** (rogue-CA detection) — audits the trusted-root stores
  (`winsight certs`); flags roots holding a private key, weak signatures (SHA-1/MD5)
  or undersized RSA keys — the silent-TLS-interception signal. Read-only.
- **Hosts** (DNS-override hijack) — parses the hosts file (`winsight hosts`); flags
  external redirects (phishing/MITM) and blackholed security/update domains (AV /
  Windows Update block), leaving benign ad-blocklist sinks alone. Read-only.

**Signatures** are verified catalog-aware (`ISignatureVerifier` /
`AuthenticodeVerifier`): native WinVerifyTrust first, then a batched
`Get-AuthenticodeSignature` (via `-EncodedCommand`) that correctly recognises
catalog-signed Windows binaries and flags tampering (HashMismatch). A file whose
signature genuinely *cannot* be verified is reported `Unknown` — never a fabricated
`Unsigned` — so the tools fail safe and never cry wolf. All tools emit a shared report shape
(`WinSight.Reporting`) as human text or a stable `--json` contract for
GUI/automation. Native x64 and Arm64 Windows CI runners are the execution record.
Central Package Management + `.editorconfig`.

**Reputation is opt-in.** WinSight is local-only by default; the *only* network call
is an optional VirusTotal lookup for flagged items, enabled solely by setting your own
`WINSIGHT_VT_KEY`. No key → no network, no telemetry.

See [CHANGELOG.md](CHANGELOG.md) for step-by-step progress.

The exact evidence sources, notable-signal rules, verdict semantics and known blind
spots are maintained in [`docs/DETECTIONS.md`](docs/DETECTIONS.md). WinSight is a
triage and visibility tool, not antivirus or EDR; a notable result is evidence to
investigate rather than proof of malware.

**Current next step:** Phase 2 outbound control. Path-scoped `allow/block/ask`
contracts, atomic versioned policy storage, fail-open audit recovery and a strict
bounded IPC framing protocol are implemented and tested. The privileged service
host, named-pipe ACL/identity authentication, WFP audit engine and prompt flow
remain. See
[`docs/WFP_DESIGN.md`](docs/WFP_DESIGN.md). Native `WTGetSignatureInfo` remains a
signature-performance optimization. Driver-backed BlockBlock/RansomWhere features
remain deliberately deferred because production drivers require signing and a
separate safety program.

## License

**GPL-3.0-or-later** — Objective-See's tools are open; copyleft keeps a security tool
auditable and forkable. The complete license text is included in [`LICENSE`](LICENSE).
