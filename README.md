# WinSight

[![CI](https://github.com/ClementG91/winsight/actions/workflows/ci.yml/badge.svg)](https://github.com/ClementG91/winsight/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/platform-Windows-informational)
![.NET 8](https://img.shields.io/badge/.NET-8.0-512bd4)

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

- **App + user-mode tools:** C# / **.NET 8**, `CsWin32` for P/Invoke, `TraceEvent`
  for ETW, WinUI 3 (or WPF) tray/dashboard. Fastest path with the broadest Win32
  coverage.
- **Perf-critical core / future agent:** Rust or C++ if/when needed.
- **Kernel driver (Phase 3/4):** C/C++ KMDF minifilter (or Rust `windows-drivers`).

## Build constraint (today)

This repo is scaffolded from a **Linux** dev box. The docs, architecture, module
layout and CI config are portable, but the .NET/Windows code must be built and
tested on **Windows** (a Windows CI runner or VM). Nothing Windows-native is
compiled here yet — this commit is the foundation + plan.

## Naming

`WinSight` is a working title (Objective-See → "see" what's happening; the Windows
analog). Objective-See's tools use doubled names (KnockKnock, BlockBlock); the
per-tool names here can follow that or stay descriptive. Rename freely before code.

## Status

Phase 1 underway — CI green on `windows-latest`. Modular tool libraries behind one
signed `winsight` binary (subcommands `persistence | av | net | dns | all`,
`--flagged`, `--json`, `--version`, `--help`):

- **Persistence** (KnockKnock-class) — 8 autostart surfaces: Run/RunOnce/RunServices/
  Policies\Explorer\Run (HKLM+HKCU × 64/32-bit), Services & drivers, Winlogon
  Shell/Userinit, Scheduled Tasks (Tasks XML), AppInit_DLLs, IFEO debuggers, Active
  Setup, BootExecute — each signature-checked, resilient per-surface scan.
- **Camera/Mic** (OverSight-class) — which apps used the webcam/mic and what is live
  now (CapabilityAccessManager ConsentStore), plus real-time `av --watch` alerts the
  instant a device turns on/off.
- **Connections** (Netiquette-class) — active TCP/UDP (IPv4 + IPv6) via native IP
  Helper tables (GetExtendedTcpTable/Udp), attributed to the owning process + its
  signature; flags external, established, unsigned owners.
- **DNS** (DNSMonitor-class) — recently resolved domains + answers from the resolver
  cache (MSFT_DNSClientCache).

**Signatures** are verified catalog-aware (`ISignatureVerifier` /
`AuthenticodeVerifier`): a batched `Get-AuthenticodeSignature` correctly recognises
catalog-signed Windows binaries and flags tampering (HashMismatch), with a managed
fallback that never throws. All tools emit a shared report shape
(`WinSight.Reporting`) as human text or a stable `--json` contract for a future
GUI/automation. Authored on Linux; CI on `windows-latest` is the compiler of record.
Central Package Management + `.editorconfig`.

See [CHANGELOG.md](CHANGELOG.md) for step-by-step progress.

Next: ETW DNS monitoring, the WFP firewall (LuLu-class), a GUI/tray shell over the
`--json` contract, and more persistence vectors (WMI subscriptions, startup folders).
A native `WTGetSignatureInfo` verifier is the eventual signature-perf swap behind
`ISignatureVerifier`. Driver-backed tools (BlockBlock/RansomWhere) are a later phase
(needs an EV certificate).

## License

**GPL-3.0-or-later** — Objective-See's tools are open; copyleft keeps a security tool
auditable and forkable. (Full GPLv3 text to be vendored into `LICENSE` before first
release.)
