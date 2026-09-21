<p align="center">
  <img src="assets/branding/winsight-logo.png" width="180" alt="WinSight, Windows security visibility" />
</p>

<h1 align="center">WinSight</h1>

<p align="center">
  <strong>See and control what is actually happening on your Windows machine.</strong><br />
  Free, open source, no telemetry, no account, no paywall.
</p>

<p align="center">
  <a href="https://winsight.edeveloppe.com/"><strong>winsight.edeveloppe.com</strong></a>
</p>

<p align="center">
  <a href="https://github.com/ClementG91/winsight/actions/workflows/ci.yml"><img src="https://github.com/ClementG91/winsight/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3" /></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2022H2%2B%20%2F%2011-informational" alt="Platform: Windows 10 22H2 or later" />
  <img src="https://img.shields.io/badge/.NET-10.0_LTS-512bd4" alt=".NET 10 LTS" />
  <img src="https://img.shields.io/badge/production%20readiness-not%20established-critical" alt="Production readiness not established" />
</p>

WinSight is a suite of small, single-purpose, auditable security tools under one roof - in the spirit
of [Objective-See](https://objective-see.org/tools.html) for macOS, for Windows.

It shows you what **persists** across reboots, what **watches** your camera and microphone, what
**phones home**, and what could be **hijacked** - and it lets you block any application's outbound
traffic at the kernel filtering layer.

> **Nothing acts on its own.** Every check observes and reports. The few things that change the
> machine happen only when you choose them, are revalidated first, are recorded in an append-only
> journal (`winsight actions`), and can be undone: blocking a startup item from a Guardian alert
> (restorable with `winsight restore`), allowing one (revocable with `winsight revoke`), and
> suspending, resuming or terminating a process (`--confirm` required). Beyond those, one feature
> writes to disk, and says so here:
>
> - **Ransomware protection** creates its decoy files. It stays off until you turn it on. Cleanup
>   removes only files whose recorded identity and original content still match; modified,
>   replaced or unverifiable legacy files are preserved. The decoys are
>   ordinary visible files in Documents, Desktop, Pictures, Downloads, Videos and Music - they are
>   not hidden, because a good many ransomware families skip hidden files and a decoy that is
>   skipped is not a decoy.
>
> The hijack scan no longer writes anything. It used to create and delete a probe file in every
> directory it graded; it now asks Windows (`AccessCheck`) whether the current user, without
> elevation, could create a file or folder there. Run as SYSTEM or with UAC disabled, where no
> non-elevated token exists, it reads the directory ACL for the well-known unprivileged groups
> instead and says so in the report.
>
> The firewall blocks only what you tell it to.

---

## What it does

| Tool | Objective-See equivalent | What it tells you |
|---|---|---|
| **Persistence scanner** | KnockKnock | 27 autostart surfaces, catalog-aware Authenticode verdicts, command-line triage for signed interpreters handed someone else's payload, optional VirusTotal enrichment |
| **Outbound firewall** | LuLu | Per-application block/allow enforced through the Windows Filtering Platform; audit-only until you arm it |
| **Guardian** | BlockBlock | A decision window the moment a new startup item appears - Allow, Block (quarantined, restorable) or decide later - plus reconciliation of what changed while WinSight was not running |
| **Ransomware detection** | RansomWhere? | Visible machine-varied decoys, rename/delete bursts, entropy-on-write, and bounded container-signature integrity checks |
| **Camera & mic monitor** | OverSight | ConsentStore activation history/transitions with per-store read coverage and best-effort application/process matching |
| **Connections & DNS** | Netiquette, DNSMonitor | TCP/UDP connection-table snapshots plus live DNS queries, attributed to processes where Windows exposes an owner |
| **Signature verification** | What's Your Sign? | Authenticode, catalog and verified MSIX package verdicts, used by every tool - and for any file from File Explorer's "Check signature with WinSight" (an out-of-process window: verdict, signer, trust caveats, MD5/SHA-1/SHA-256) or `winsight sign` |
| **Hijack scan** | DHS | Unquoted service paths, writable service directories and PATH entries, and phantom DLL imports - each graded by whether it is exploitable on *this* machine |

Beyond the macOS originals: **write attribution** names the program behind a persistence or
ransomware alert when running elevated (`written by setup.exe (pid 4242)`) and says why it cannot when
it is not, rather than staying silent. **Per-process drill-down** (`winsight process <pid>`) and
**physical-access evidence** (`winsight presence`) are Windows counterparts to TaskExplorer and
DoNotDisturb, with narrower live UI and physical-access coverage respectively. And because
WinSight's decoys *detect* ransomware but cannot *block* it without a driver, the overview also
**reports its configured and observed operational posture** - read-only, including explicit
unavailability when Defender cannot be queried. It points to the Windows control; WinSight never
changes that setting itself and does not guarantee enforcement of an individual write.

Full detection inventory: [`docs/DETECTIONS.md`](docs/DETECTIONS.md). Tool-by-tool comparison:
[`docs/OBJECTIVE_SEE_PARITY.md`](docs/OBJECTIVE_SEE_PARITY.md).

## Three ways to use it

- **Dashboard** - a WPF desktop and tray application, in **English, French and Spanish**. Every check
  explains what it observes and what an alert means.
- **Command line** - 28 verbs, with `--flagged` and `--json`. Exits non-zero when anything is
  notable, so it drops straight into a scheduled task. `--json` emits a versioned envelope -
  `{ "schemaVersion": 1, "generatedAt": ..., "reports": [...] }` - so a stored report says when it
  was true and a consumer can tell which contract produced it:

  ```
  winsight [persistence|av|net|dns|all]   run checks (default: all)
  winsight firewall | processes | modules | extensions | certs | hosts
  winsight input | integrity | drivers | hijack
  winsight process <pid>                  one process: lineage, modules, connections
  winsight sign <path>                    one file: Authenticode standing + identification hashes
  winsight holders <path>                 which processes hold this file open
  winsight alerts                         alert journal: Guardian, ransomware, camera/mic
  winsight actions                        response-action history (read-only), newest first
  winsight [suspend|resume|terminate] <pid>  act on a process (needs --confirm)
  winsight rules                          allow rules in force (read-only)
  winsight [restore|revoke] <id>          undo a block or an allow (needs --confirm)
  winsight presence                       when this machine woke, and whether anyone was there
  winsight av --watch | dns --watch | attribution --watch | input --watch
  ```

  The response commands - the process actions and the two undo verbs - do nothing without
  `--confirm`, and every change they make is recorded in an append-only journal readable with
  `winsight actions`. Three maintenance verbs that setup and uninstall run also change the current
  user's state without `--confirm`: `register-signature-verb` and `unregister-signature-verb` add and
  remove the File Explorer entry, and `remove-decoys` deletes ransomware decoys whose content is
  still unchanged. A process action revalidates that the target is still the same process and
  refuses protected and WinSight processes; a restore refuses if something else now occupies the
  item's original location.

  `--unsigned` and `--nonmicrosoft` narrow any scan to unsigned/untrusted items, or to items not
  proven to carry Microsoft's own signature (an exact Microsoft signing identity on a chain the
  machine trusts, not a signer name that merely reads "Microsoft"); they stack with each other and
  with `--flagged`.
- **MCP server** - `winsight mcp`, local stdio only, read-only, for MCP-compatible AI clients. Six
  tools, three resources and two guided prompts; no network listener. See
  [`docs/MCP.md`](docs/MCP.md).

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

Two consequences of that default, stated here rather than left to be discovered:

- **The outbound firewall is unavailable.** A per-user install lands under
  `%LOCALAPPDATA%\Programs`, which the user can write, and the service deliberately refuses to
  register from any path an unprivileged principal can modify. Install for all users (elevated) if
  you want the firewall.
- **WinSight's own binaries are replaceable by the adversary in its threat model.** Anything running
  as that user can overwrite them. An all-users install puts them somewhere it cannot.

**Verify what you downloaded before running it** - checksums, SBOM and GitHub build provenance:

```powershell
Get-FileHash winsight-vX.Y.Z-win-x64.zip -Algorithm SHA256
gh attestation verify winsight-vX.Y.Z-win-x64.zip --repo ClementG91/winsight
```

> Released binaries are **not Authenticode-signed** - the project holds no code-signing certificate
> and currently uses an explicit unsigned-release policy, so Windows will warn on first run. Verify
> SHA-256 and GitHub attestations before execution. See [`docs/RELEASE.md`](docs/RELEASE.md).

The **outbound firewall service is deliberately not installed by setup**: it registers a LocalSystem
service and mutates WFP, which should be an explicit decision. See
[`docs/ADMINISTRATION.md`](docs/ADMINISTRATION.md).

## Security posture

- **No telemetry, no analytics, no account.** The only outbound connection is an explicit,
  user-initiated VirusTotal hash lookup - a hash, never file contents. It is enabled by the
  presence of a `WINSIGHT_VT_KEY` environment variable, so a shell or a scheduled task that
  inherits one makes an otherwise local scan reach the network; pass `--no-network` to refuse
  regardless.
- **The privileged boundary is an authenticated named-pipe channel**, not the UI. The dashboard is an
  unprivileged IPC client and cannot change policy on its own; an unelevated administrator is refused
  exactly like a standard user.
- **Enforcement is opt-in and starts audit-only.** Nothing is filtered until an elevated operator
  arms it, and there is no command-line path to arming - that is the security property, not a missing
  feature.
- **Desired intent and effective state are reported separately, and never conflated.** WinSight
  distinguishes the *desired* mode you persisted from the *effective* runtime state it can actually
  prove against the live filtering engine. If it cannot verify enforcement exactly, it reports
  `Degraded` rather than claiming `Active` - a security tool that overstates its own protection is
  worse than one that admits a gap.
- **Unknown outbound applications cannot permanently poison the pending view by arriving first.**
  The service keeps a bounded 128-app least-recently-used window, admits later arrivals, and reports
  evicted identities and their aggregated observations as incomplete coverage. Capacity-pressure
  logging is exponentially sampled so a distinct-path flood cannot create unbounded event-log spam.
- **Enforcement survives reboots** through service boot persistence, and the state is re-verified on
  every status read rather than assumed from what was persisted.
- **The service refuses to install from any path an unprivileged principal can write**, and re-checks
  the file's 128-bit NTFS identity before use so it cannot be swapped in between.
- **No kernel driver.** Driver-backed interception is deferred rather than half-built, because a
  production driver needs signing and a separate safety programme.

Threat model, trust boundaries and what is explicitly out of scope:
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Reporting a vulnerability:
[`SECURITY.md`](SECURITY.md). What leaves your machine, in full:
[`PRIVACY.md`](PRIVACY.md).

### Code signing

Releases are **not Authenticode-signed**, so Windows shows an unknown-publisher warning on first run -
that warning is accurate. SignPath Foundation declined the free-program application on 2026-07-29
because the project does not yet have enough public adoption signals. The current release policy is
therefore explicitly unsigned, not silently downgraded.

Every release carries SHA-256 checksums plus GitHub **build provenance** and **SBOM** attestations,
which bind the bytes to this repository's release workflow at a named commit. They do not provide a
Windows publisher identity; verify them before running anything.

Both attestations cover both artifacts - the portable `.zip` and the `-setup.exe`. The SBOM is
generated from the package directory that Inno Setup is then handed as its source, so it is the same
component inventory either way. Releases published before this covered the `.zip` alone.

Who may authorise a signature, what one would and would not prove, and how to check a release
yourself: [`docs/CODE_SIGNING.md`](docs/CODE_SIGNING.md).

## Production readiness

| Target | Status |
|---|---|
| **x64** | **Current production readiness is not established.** The September security audit found defects outside the historical qualification scenarios. The corrected candidate needs fresh CI and isolated VM qualification; Authenticode remains excluded from this verdict |
| **Arm64 (native)** | Build, tests, packaging and installer are delegated to native Arm64 CI; privileged runtime remains a VM gate; **product readiness not established** |

> **CodeQL runs through GitHub's default setup, not a workflow in this repository.** The run IDs
> above are real, but nothing under `.github/workflows/` configures the analysis, so it cannot be
> audited from a clone and does not run on forks.

The privileged behaviour CI cannot reach has historical qualification evidence from clean x64 VMs,
each run bound to the commit and CI run that built it:

| Gate | Result | Record |
|---|---|---|
| Published v0.12.0 downloads, supply chain, x64 install/MCP/EN-FR-ES smoke and cleanup | PASS | [record](docs/validation/2026-09-01-v0.12.0-published-release.md) |
| Historical v0.12.0 x64 installer, ETW, WFP/SCM, trust, local/Network IPC and cleanup | PASS | [record](docs/validation/2026-09-01-x64-qualification-dbaded1.md) |
| WFP enforcement, SCM, rollback, per-app scoping | 25 checks, 0 failures | [record](docs/validation/2026-07-23-wfp-qualification-f0a3f16.md) |
| Service-path trust, adversarial TOCTOU | 11 checks, 0 failures | [record](docs/validation/2026-07-23-trust-boundary-f84ac36.md) |
| Multi-user IPC capability boundary | 7 checks, 0 failures | [record](docs/validation/2026-07-23-ipc-boundary-c9177cd.md) |
| Historical v0.11.6 x64 ETW, WFP/SCM, trust, local/Network IPC, installer and cleanup | 19/19 ETW, 35/35 WFP, 13/13 trust, 7/7 local IPC, 7/7 Network Logon, 3/3 observer | [record](docs/validation/2026-08-23-x64-qualification-8486155.md) |
| Exact dashboard settings layout, posture interpretation, installer and EN/FR/ES smoke | PASS | [record](docs/validation/2026-08-25-ui-windows-posture-3912d67.md) |

Each record covers its named checks on its exact binaries; none covers the defects identified in
the September audit or qualifies the corrected working tree. The 2026-08-23 campaign closed the
former IPC-path, Network Logon and host-control gaps; the 2026-08-25 record
qualifies only the changed dashboard/package surface and does not pretend to rerun those privileged
gates. Native Arm64 privileged gates, x64-on-Arm64 identity and independent EN/FR/ES review remain
open; the latter is recommended rather than a technical publication gate.
Unsigned distribution is an accepted visible limitation, not a claim that signing has passed.

The authoritative statement, with every limitation named:
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).

## Documentation

| For | Document |
|---|---|
| An overview, in English, French or Spanish | [winsight.edeveloppe.com](https://winsight.edeveloppe.com/) |
| Installing and deploying | [INSTALLATION.md](docs/INSTALLATION.md), [ADMINISTRATION.md](docs/ADMINISTRATION.md) |
| Something is wrong now | [RECOVERY.md](docs/RECOVERY.md) |
| What it detects | [DETECTIONS.md](docs/DETECTIONS.md) |
| Security | [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Privacy and code signing | [PRIVACY.md](PRIVACY.md), [CODE_SIGNING.md](docs/CODE_SIGNING.md) |
| How it is built | [ARCHITECTURE.md](docs/ARCHITECTURE.md), [WFP_DESIGN.md](docs/WFP_DESIGN.md) |
| Contributing code | [CODING_STANDARDS.md](docs/CODING_STANDARDS.md) |
| Releasing and verifying | [RELEASE.md](docs/RELEASE.md) |
| Evidence | [validation/](docs/validation/README.md) |
| Security and architecture audit (September 2026, in French) | [AUDIT.md](docs/AUDIT.md) |
| Where it is going | [ROADMAP.md](docs/ROADMAP.md), [OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md](docs/OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md) |

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
[xml]$props = Get-Content Directory.Build.props
./scripts/Build-Release.ps1 `
  -Version $props.Project.PropertyGroup.Version `
  -Architectures x64 `
  -DisableSignature
```

The build script restores the pinned Microsoft SBOM tool and installs the pinned Inno Setup compiler
after verifying **both** its official SHA-256 and its Authenticode signature.
Native Arm64 build, tests and packaging run on the `windows-11-vs2026-arm` CI runner; an x64 workstation
does not substitute a cross-published binary for that native evidence.

## Contributing

Issues and pull requests are welcome. The rules this codebase actually enforces are in
[CODING_STANDARDS.md](docs/CODING_STANDARDS.md), and most of them are checked by CI rather than by
review: formatting, a dependency vulnerability audit, the full test suite on **three** Windows images
including native Arm64, an 80% line-coverage floor on every detection-engine library and on the
hand-written half of the privileged service, and a packaged install/uninstall lifecycle on native x64
**and** native Arm64.

Security issues go through [private reporting](SECURITY.md), not public issues.

## License

**GPL-3.0-or-later.** Objective-See's tools are open; copyleft keeps a security tool auditable by the
people who depend on it.
