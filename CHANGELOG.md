# Changelog

Step-by-step progress log. Newest first. Every CI-green step lands here.

## Phase 1 — user-mode tools

### Persistence — WMI event subscriptions
- `WmiSubscriptionEnumerator` surfaces permanent WMI subscription consumers
  (CommandLine + ActiveScript) from root\subscription — a stealthy, fileless
  persistence technique. Adds the `System.Management` dependency; access-denied /
  missing-namespace degrade to empty (never throws). 9 autostart surfaces now.

### CLI polish
- `winsight --version` and `winsight --help` / `-h`.

## Repo — collaboration & release readiness
- Full GPL-3.0 `LICENSE` text; `CODE_OF_CONDUCT` (Contributor Covenant 2.1),
  `CONTRIBUTING`, `SECURITY` (private vulnerability reporting); issue templates
  (bug/feature) + config, PR template, `CODEOWNERS`, Dependabot (NuGet + Actions),
  `.gitattributes`, README badges. A `release` workflow publishes a self-contained
  `winsight.exe` to a GitHub Release on `v*` tags.

## Phase 1 — user-mode tools

### Connections — native IP Helper tables
- `NativeConnectionReader` reads the TCP/UDP tables via GetExtendedTcpTable /
  GetExtendedUdpTable (structured, fast, locale-independent) with owning PIDs,
  replacing the netstat text spawn (kept as a fallback). Endianness/state mapping is
  pure + unit-tested; the real native call is exercised by the connections
  integration test on Windows CI.

### Camera/Mic — real-time monitor (OverSight-class)
- `CameraMicMonitor` raises Activated/Deactivated events the moment an app turns the
  webcam/mic on or off, via a pure unit-tested snapshot Diff over a polling loop
  (driver-free; RegNotifyChangeKeyValue is the future event-driven optimization).
  `winsight av --watch` prints live alerts until Ctrl+C.

### Integration tests — proving each part functions on real Windows
- Integration tests execute the real pipeline on the CI Windows runner: persistence
  scan (registry + signature batch), ConsentStore read, connection snapshot, and
  catalog-signed-binary verification. First proof the blind-authored code FUNCTIONS,
  not just compiles. `AuthenticodeVerifier` now matches PowerShell output back to
  inputs by normalised full path (robust to path-string form differences).

### Signature hardening — catalog-aware Authenticode
- `ISignatureVerifier` abstraction + `AuthenticodeVerifier`: one batched
  `Get-AuthenticodeSignature` per scan, catalog + embedded aware, detects tampering
  (HashMismatch), managed fallback that never throws. Persistence + Connections now
  batch-verify. Fixes false "unsigned" on catalog-signed Windows binaries and the
  signed-then-tampered false negative. Native `WTGetSignatureInfo` kept as a future
  perf swap behind the interface.

### Pro/maintainable foundation + CLI consolidation
- Central Package Management (`Directory.Packages.props`) + `.editorconfig`.
- Collapsed the 3 per-tool CLIs into one signed `winsight` binary with subcommands.
- New `WinSight.Reporting` layer: tool-agnostic report shape rendered as text or a
  stable camelCase `--json` contract (for the future GUI/automation). Tools stay pure
  data producers; presentation lives once in `Cli/Adapters`.

### Module 3 — Connections (Netiquette-class)
- Active TCP/UDP snapshot attributed to the owning process + its signature; flags
  external, established connections owned by unsigned/unresolved processes.
  (Interim: `netstat -ano` parse; native `GetExtendedTcpTable` is next.)

### Module 2 — Camera/Mic (OverSight-class)
- CapabilityAccessManager ConsentStore reader: which apps used the webcam/mic and
  what is live right now.

### Module 1 — Persistence (KnockKnock-class)
- 8 autostart surfaces: Run/RunOnce/RunServices/Policies\Explorer\Run (HKLM+HKCU ×
  64/32-bit), Services & drivers, Winlogon Shell/Userinit, Scheduled Tasks (Tasks
  XML), AppInit_DLLs, IFEO debuggers, Active Setup, BootExecute. Managed Authenticode
  triage (later replaced by the catalog-aware verifier), resilient per-surface scan.

### Bootstrap
- Prior-art check (no unified OSS Objective-See equivalent on Windows), architecture,
  GPL-3.0, GitHub Actions `windows-latest` CI (auto-discovers all projects).
