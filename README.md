<p align="center">
  <img src="assets/branding/winsight-logo.png" width="180" alt="WinSight, Windows security visibility" />
</p>

<h1 align="center">WinSight</h1>

<p align="center">
  <strong>See and control what is actually happening on your Windows machine.</strong><br />
  Free, open source, no telemetry, no account, no paywall.
</p>

<p align="center">
  <a href="https://github.com/ClementG91/winsight/actions/workflows/ci.yml"><img src="https://github.com/ClementG91/winsight/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3" /></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-informational" alt="Platform: Windows" />
  <img src="https://img.shields.io/badge/.NET-10.0_LTS-512bd4" alt=".NET 10 LTS" />
  <img src="https://img.shields.io/badge/x64-production%20ready-success" alt="x64 production ready" />
</p>

WinSight is a suite of small, single-purpose, auditable security tools under one roof — in the spirit
of [Objective-See](https://objective-see.org/tools.html) for macOS, for Windows.

It shows you what **persists** across reboots, what **watches** your camera and microphone, what
**phones home**, and what could be **hijacked** — and it lets you block any application's outbound
traffic at the kernel filtering layer.

> **Everything observes and reports.** Nothing acts on its own. The two exceptions are explicit and
> opt-in: the firewall blocks only what you tell it to, and ransomware protection is the one feature
> that writes anything (its decoy files), which is why it stays off until you turn it on — and removes
> them when you turn it off.

---

## What it does

| Tool | Objective-See equivalent | What it tells you |
|---|---|---|
| **Persistence scanner** | KnockKnock | 22 autostart surfaces, catalog-aware Authenticode verdicts, optional VirusTotal enrichment |
| **Outbound firewall** | LuLu | Per-application block/allow enforced through the Windows Filtering Platform; audit-only until you arm it |
| **Guardian** | BlockBlock | Live tray alert the moment a new startup item appears, plus reconciliation of what changed while WinSight was not running |
| **Ransomware detection** | RansomWhere? | Hidden decoy files, rename/delete-burst and entropy-on-write heuristics |
| **Camera & mic monitor** | OverSight | Which process turned the webcam or microphone on |
| **Connections & DNS** | Netiquette, DNSMonitor | Live outbound connections and DNS queries, attributed to processes |
| **Signature verification** | What's Your Sign? | Authenticode verdicts with catalog fallback, used by every tool |
| **Hijack scan** | DHS | Unquoted service paths, writable service directories and PATH entries, and phantom DLL imports — each graded by whether it is exploitable on *this* machine |

Beyond the macOS originals: **write attribution** names the program behind a persistence or
ransomware alert when running elevated (`written by setup.exe (pid 4242)`) and says why it cannot when
it is not, rather than staying silent. **Per-process drill-down** (`winsight process <pid>`) and
**physical-access detection** (`winsight presence`) have no Objective-See counterpart.

Full detection inventory: [`docs/DETECTIONS.md`](docs/DETECTIONS.md). Tool-by-tool comparison:
[`docs/OBJECTIVE_SEE_PARITY.md`](docs/OBJECTIVE_SEE_PARITY.md).

## Three ways to use it

- **Dashboard** — a WPF desktop and tray application, in **English, French and Spanish**. Every check
  explains what it observes and what an alert means.
- **Command line** — 17 verbs, with `--flagged` and `--json`. Exits non-zero when anything is
  notable, so it drops straight into a scheduled task:

  ```
  winsight [persistence|av|net|dns|all]   run checks (default: all)
  winsight firewall | processes | modules | extensions | certs | hosts
  winsight input | integrity | drivers | hijack
  winsight process <pid>                  one process: lineage, modules, connections
  winsight presence                       when this machine woke, and whether anyone was there
  winsight av --watch | dns --watch | attribution --watch
  ```
- **MCP server** — `winsight mcp`, local stdio only, read-only, for MCP-compatible AI clients. No
  network listener. See [`docs/MCP.md`](docs/MCP.md).

All three share one orchestration layer; detection logic is never duplicated in UI or protocol code.

## Install

Download the installer for your machine from the
[latest release](https://github.com/ClementG91/winsight/releases/latest):

| Machine | File |
|---|---|
| Intel / AMD 64-bit | `winsight-vX.Y.Z-win-x64-setup.exe` |
| Windows on Arm | `winsight-vX.Y.Z-win-arm64-setup.exe` |

The default install is **per-user** and needs no administrator rights and no .NET runtime. Portable
ZIPs are published for both architectures.

**Verify what you downloaded before running it** — checksums, SBOM and GitHub build provenance:

```powershell
Get-FileHash winsight-vX.Y.Z-win-x64.zip -Algorithm SHA256
gh attestation verify winsight-vX.Y.Z-win-x64.zip --repo ClementG91/winsight
```

> Released binaries are **not yet Authenticode-signed** — the project holds no code-signing
> certificate, so Windows will warn on first run. The signing chain is implemented and activates the
> moment a certificate is supplied. See [`docs/RELEASE.md`](docs/RELEASE.md).

The **outbound firewall service is deliberately not installed by setup**: it registers a LocalSystem
service and mutates WFP, which should be an explicit decision. See
[`docs/ADMINISTRATION.md`](docs/ADMINISTRATION.md).

## Security posture

- **No telemetry, no analytics, no account.** The only outbound connection is an explicit,
  user-initiated VirusTotal hash lookup — a hash, never file contents.
- **The privileged boundary is an authenticated named-pipe channel**, not the UI. The dashboard is an
  unprivileged IPC client and cannot change policy on its own; an unelevated administrator is refused
  exactly like a standard user.
- **Enforcement is opt-in and starts audit-only.** Nothing is filtered until an elevated operator
  arms it, and there is no command-line path to arming — that is the security property, not a missing
  feature.
- **Desired intent and effective state are reported separately, and never conflated.** WinSight
  distinguishes the *desired* mode you persisted from the *effective* runtime state it can actually
  prove against the live filtering engine. If it cannot verify enforcement exactly, it reports
  `Degraded` rather than claiming `Active` — a security tool that overstates its own protection is
  worse than one that admits a gap.
- **Enforcement survives reboots** through service boot persistence, and the state is re-verified on
  every status read rather than assumed from what was persisted.
- **The service refuses to install from any path an unprivileged principal can write**, and re-checks
  the file's 128-bit NTFS identity before use so it cannot be swapped in between.
- **No kernel driver.** Driver-backed interception is deferred rather than half-built, because a
  production driver needs signing and a separate safety programme.

Threat model, trust boundaries and what is explicitly out of scope:
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Reporting a vulnerability:
[`SECURITY.md`](SECURITY.md).

## Production readiness

| Target | Status |
|---|---|
| **x64** | **Production ready**, with two stated limitations |
| **Arm64 (native)** | Build, packaging and installer verified on native hardware; **privileged runtime unqualified** |

The privileged behaviour CI cannot reach — real WFP enforcement and rollback, SCM lifecycle,
adversarial path-trust/TOCTOU, and the multi-user IPC boundary — has been qualified on a clean x64 VM,
each run bound to a commit and to the CI run that built it so anyone can re-verify:

| Gate | Result | Record |
|---|---|---|
| WFP enforcement, SCM, rollback, per-app scoping | 25 checks, 0 failures | [record](docs/validation/2026-07-23-wfp-qualification-f0a3f16.md) |
| Service-path trust, adversarial TOCTOU | 11 checks, 0 failures | [record](docs/validation/2026-07-23-trust-boundary-f84ac36.md) |
| Multi-user IPC capability boundary | 7 checks, 0 failures | [record](docs/validation/2026-07-23-ipc-boundary-c9177cd.md) |

The authoritative statement, with every limitation named:
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).

## Documentation

| For | Document |
|---|---|
| Installing and deploying | [INSTALLATION.md](docs/INSTALLATION.md), [ADMINISTRATION.md](docs/ADMINISTRATION.md) |
| Something is wrong now | [RECOVERY.md](docs/RECOVERY.md) |
| What it detects | [DETECTIONS.md](docs/DETECTIONS.md) |
| Security | [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| How it is built | [ARCHITECTURE.md](docs/ARCHITECTURE.md), [WFP_DESIGN.md](docs/WFP_DESIGN.md) |
| Releasing and verifying | [RELEASE.md](docs/RELEASE.md) |
| Evidence | [validation/](docs/validation/README.md) |
| Where it is going | [ROADMAP.md](docs/ROADMAP.md) |

## Build from source

Requires the .NET 10 SDK on Windows. `global.json` pins the supported SDK feature band.

```powershell
dotnet restore winsight.sln
dotnet build winsight.sln -c Release
dotnet test winsight.sln -c Release --no-build
dotnet run --project src/WinSight.Dashboard
```

To reproduce the full release payload, including SBOM, installer and signing stage:

```powershell
./scripts/Build-Release.ps1 -Version 0.10.3
```

The build script restores the pinned Microsoft SBOM tool and installs the pinned Inno Setup compiler
after verifying **both** its official SHA-256 and its Authenticode signature.

## Contributing

Issues and pull requests are welcome. CI enforces formatting, a dependency vulnerability audit, the
full test suite on two Windows images, an 80% line-coverage floor on every detection-engine library,
and a packaged install/uninstall lifecycle on native x64 **and** native Arm64.

Security issues go through [private reporting](SECURITY.md), not public issues.

## License

**GPL-3.0-or-later.** Objective-See's tools are open; copyleft keeps a security tool auditable by the
people who depend on it.
