# Changelog

Step-by-step progress log. Newest first. Every CI-green step lands here.

## v0.7.1 — 2026-07-14

### Unified WinSight visual identity
- Add an original geometric vision-and-telemetry logo with a transparent high-resolution
  source, an optimized 256 px UI asset and a nine-resolution Windows ICO.
- Replace the dashboard's placeholder letter and generic system shield with the WinSight
  mark in the header, window chrome, taskbar and notification area.
- Embed the same icon in both native CLI/dashboard executables and the Windows installer,
  so Start menu, desktop shortcuts, Explorer and Add/Remove Programs share one identity.
- Display the brand in the repository README and ship the complete, documented asset set
  in x64/Arm64 ZIPs and installations. Release validation now checks alpha, dimensions,
  every ICO frame and the icons actually embedded in both executables.

## v0.7.0 — 2026-07-14

### Local read-only MCP integration
- Ship a `winsight mcp` mode in the existing native x64 and Arm64 CLI binary,
  using the official MCP C# SDK and the stable `2025-11-25` protocol over local
  standard input/output only. No HTTP endpoint, network listener or background MCP
  service is created, and no third self-contained runtime is duplicated in packages.
- Expose capability discovery, one-scanner execution and the balanced overview as
  read-only, idempotent, non-destructive and closed-world tools, plus machine-readable
  capability and security-model resources.
- Keep AI disclosure summary-only and noteworthy-only by default. Bound evidence to
  200 items per report, serialize scans through one execution gate, apply a 90-second
  safety limit, redact user-profile paths and omit raw command fields.
- Require both the server-side `WINSIGHT_MCP_ALLOW_SENSITIVE=1` gate and explicit
  per-call evidence flags before raw paths or command lines can leave the scanner.
  Disable VirusTotal and every other network-enrichment path for MCP scans even when
  the parent process has an API key.
- Add projection/privacy tests and a real MCP subprocess integration test. Extend
  release packaging and native installer lifecycle tests to negotiate the installed
  server, inspect every tool annotation and invoke structured capability discovery.
- Document AI-client configuration, data-flow privacy, interpretation rules and the
  explicit ban on MCP remediation primitives.

## v0.6.0 — 2026-07-14

### Fail-open firewall service foundation
- Add a versioned durable policy store for the future privileged service. Policy
  paths are canonicalized and deduplicated, counts and file sizes are bounded,
  unknown or duplicate JSON members are rejected, and enforcement values require an
  explicit service-side gate.
- Require literal absolute executable identities across the privilege boundary;
  environment variables are no longer expanded under the future service account.
- Persist through a write-through temporary file and atomic same-volume replacement,
  reject reparse-point storage, and expose a recovery API that converts malformed or
  inaccessible state into an empty audit-only configuration instead of carrying an
  old blocking decision forward.
- Add a strict 64 KiB length-prefixed local protocol for status, policy and emergency
  disable commands. Validate exact protocol versions, request IDs, command payloads,
  paths, enum values and response invariants before a future service can act.
- Add 25 security-focused tests covering round trips, corrupt/future/oversized state,
  atomic preservation, enforcement gating, duplicate or unknown JSON, truncated and
  oversized frames, bounded pagination, relative-path rejection and contradictory
  service status.
- Keep WFP mutation and the named-pipe host disabled. The protocol codec is not an
  authentication boundary; the future service must enforce pipe ACLs and verify the
  impersonated Windows identity before decoding or executing a request.

## v0.5.1 — 2026-07-14

### Supported runtime baseline
- Move every user-mode component and both self-contained distributions to .NET 10
  LTS, extending the supported runtime lifecycle through November 2028 while
  preserving the Windows 10 22H2, Windows 11, x64 and Arm64 support matrix.
- Pin the reproducible build to SDK 10.0.301 and align `System.Management` with the
  serviced .NET 10 line. Remove the obsolete standalone Registry compatibility
  package now supplied by the Windows target framework.
- Make the minimum Windows API contract explicit in the target framework and update
  CI, release automation, contributor instructions and user-facing examples to the
  same runtime and release baseline.
- Adapt the Authenticode signer extraction path to .NET 10's certificate-loader
  diagnostics without weakening the existing WinVerifyTrust verification or
  catalog-aware fallback.
- Apply the .NET 10 analyzer's concrete-collection optimization to dashboard report
  selection without changing the UI contract.

## v0.5.0 — 2026-07-14

### Native Windows distribution and documented detection contract
- Ship separate self-contained x64 and Arm64 portable archives and per-user Windows
  installers. Each installer selects English, French or Spanish, creates normal
  Start-menu/uninstall entries, requests no elevation by default and rejects the
  wrong processor architecture instead of silently installing an emulated build.
- Add a pinned, checksum- and Authenticode-verified Inno Setup bootstrap plus one
  reproducible release script for local builds, CI and tagged releases.
- Exercise the complete install/start/uninstall lifecycle on native x64 and native
  Arm64 GitHub-hosted Windows runners, including real WPF startup in all three UI
  languages and PE-machine validation for both executables.
- Publish SPDX 2.2 SBOMs, SHA-256 files, build-provenance attestations and SBOM
  attestations for every architecture alongside installers and portable archives.
- Document the supported Windows baseline, processor selection, silent deployment,
  integrity verification, complete detection inventory, verdict semantics and
  important blind spots. Explicitly disclose that public binaries are not yet
  Authenticode-signed because the project has no public code-signing certificate.
- Update project, security and contributor documentation to cover the dashboard,
  packages, installer supply chain and dual-architecture release gate.

## v0.4.0 — 2026-07-14

### Runtime multilingual dashboard
- Localize the complete dashboard chrome, safety guidance, progress, errors, tray
  menu and analysis catalog in English, French and Spanish using standard .NET
  satellite resources with English as the safe fallback.
- Detect the Windows UI culture, remember the user's explicit choice and allow
  language switching from the header without restarting or interrupting a scan.
- Localize overview report names and severity labels while preserving raw Windows
  evidence exactly as collected for forensic accuracy.
- Add exhaustive resource-key coverage, culture fallback and catalog localization
  tests. CI and release pipelines now smoke-test all three packaged languages.

## v0.3.0 — 2026-07-14

### Understandable dashboard and supply-chain hardening
- Replace the technical tool picker with a guided French dashboard: plain-language
  descriptions, contextual safety advice, clearer priority labels and explicit
  read-only/privacy messaging for non-technical users.
- Add real overview progress, cooperative stop-between-steps, selected-finding
  details, JSON export, clipboard copy, validated file-location opening and trusted
  Windows management-tool shortcuts. No untrusted finding value is executed.
- Add a reusable progress contract and tests for overview membership, cancellation
  before work starts and percentage calculation.
- Pin every GitHub Action to an immutable commit SHA, make the NuGet vulnerability
  audit fail closed, and attach GitHub build-provenance attestations to release ZIPs.
- Enable the latest recommended .NET analyzers across the solution.
- Update TraceEvent and the test SDK/runner packages; retain the .NET 8 line for
  Windows framework packages instead of mixing .NET 10 assets into this LTS target.

## v0.2.1 — 2026-07-14

### Dashboard startup hotfix
- Override invariant globalization for the WPF frontend. WPF resolves XAML binding
  languages to a specific culture during layout; inheriting the libraries' invariant
  mode caused `Cannot find non-neutral culture related to 'en-us'` and terminated the
  packaged dashboard just after launch.
- Add `winsight-dashboard --smoke-test`, which loads the real XAML, bindings, layout
  and tray integration before exiting. Both CI and the tag-release workflow now run
  this packaged-executable smoke test, preventing a file-exists-only false green.

## v0.2.0 — 2026-07-14

### Dashboard/tray, Phase 2 contracts, and release hardening
- **WPF dashboard + system tray**: `winsight-dashboard` consumes the same shared
  reports as the CLI, runs scans off the UI thread, filters noteworthy findings and
  exposes every snapshot tool without duplicating detection logic.
- **Reusable application entry point**: CLI adapters now expose canonical single-tool
  and overview runners; the CLI and dashboard therefore share verifier caches,
  report semantics and future module additions.
- **Clean application boundary**: scanner orchestration now lives in the dedicated
  `WinSight.Application` library. The dashboard no longer references the CLI
  executable, so both frontends depend on a testable application layer.
- **Phase 2 firewall foundation**: path-scoped `allow` / `block` / `ask` policies,
  a pure policy evaluator and the privileged WFP-engine boundary are implemented and
  unit-tested. Enforcement remains disabled until the service, authenticated IPC,
  audit mode and recovery path in `docs/WFP_DESIGN.md` exist.
- **Reproducible build graph**: added `winsight.sln`, a pinned .NET 8 SDK and a
  central 0.2.0 version. CI now restores once, verifies formatting, builds/tests the
  solution, audits NuGet packages, smoke-publishes both Windows executables and
  retains test/release artifacts.
- **Deterministic integration tests**: machine-wide module, process and persistence
  enumeration tests use injected signature verdicts; focused Authenticode tests still
  exercise the real catalog/native chain without repeatedly scanning thousands of
  host-specific files or timing out shared runners.
- **Frontend and dispatch coverage**: application-command and dashboard-catalog
  tests ensure every scanner remains reachable exactly once; firewall-policy tests
  now reject relative executable paths before they can cross the privileged boundary.
- **Release integrity**: tagged releases package both the CLI and dashboard and
  publish a SHA-256 checksum alongside the archive.
- README and architecture records now reflect the completed DNS/WMI/startup-folder
  work, the shipped dashboard, the real Windows build flow and the current WFP plan.

## Phase 1 — user-mode tools

### Core — catalog signatures actually work now (major false-positive fix)
Running the tools against a real Windows box exposed a signal-destroying bug and
several large false-positive sources. A security tool that cries wolf is worse than
none, so this pass makes the verdicts trustworthy:
- **Catalog verification was silently failing.** The catalog-aware fallback fed its
  script to `powershell -Command -` over stdin, which produced NO output from a
  non-interactive child process — so every catalog-signed system binary (cmd.exe,
  DWrite.dll, every driver…) read as *Unsigned*. Switched to `-EncodedCommand`
  (base64 UTF-16LE). Result on a clean machine: modules unsigned **3097 → ~750**,
  processes **73 → ~32**, persistence flagged **258 → 4**.
- **New `Unknown` signature state.** A file whose signature *cannot be checked* (the
  catalog probe failed, e.g. under heavy load) is now reported `Unknown` — never a
  fabricated `Unsigned`. Only a definitive check yields `Unsigned`, so the tool
  fails safe (silent) instead of failing loud (false alarms). `Unknown` is never a
  flag-worthy signal.
- **Chunking + retry.** Signature batches are split by script length (so the encoded
  command never overflows the OS arg limit) and each chunk retries until every path
  is covered, so a transient PowerShell hiccup no longer downgrades a whole chunk to
  false "unsigned". The progress/error streams are silenced and drained so nothing
  leaks to the terminal mid-scan.
- **Certificates: no more SHA-1-self-signed false positives.** A root is *self-signed*,
  so its own SHA-1 signature is not a trust input — nearly every established public
  root (DigiCert, Baltimore, Comodo…) is SHA-1 self-signed. Weak-signature is now
  flagged only on a NON-self-signed cert in the root store. Flagged roots **40 → 10**
  (the remainder are genuine 1024-bit legacy roots).
- **Persistence: driver ImagePaths resolve.** `\SystemRoot\…`, `\??\C:\…` and bare
  `system32\drivers\x.sys` NT paths are normalised to real files, and the default
  Winlogon shell (`explorer.exe`, which lives in `%windir%`) resolves — so ~150
  legitimate Windows drivers and the default shell are no longer flagged "no image".

### Persistence — svchost ServiceDll payloads, HKCU Winlogon, SilentProcessExit
- **ServiceDll resolution**: for svchost-hosted services the ImagePath is just
  svchost.exe (signed Microsoft) — the real payload is `Parameters\ServiceDll`. That
  DLL is now surfaced and signature-checked as its own entry, closing the classic
  "malicious service DLL rides under a trusted host" blind spot.
- **Winlogon HKCU**: Shell/Userinit are now also read from HKCU — the per-user,
  no-admin variant of the logon hijack was previously invisible.
- **SilentProcessExit monitors** (MITRE T1546.012): a MonitorProcess registered under
  IFEO silent-exit monitoring launches every time its target exits — the quiet
  companion of the IFEO Debugger hijack. New enumerator; 18 autostart surfaces now.
- VirusTotal enrichment cap lowered 8 → 4 to match the free-tier rate limit
  (requests past 4 were guaranteed 429s that burned quota for nothing).

### Core — security hardening pass
- **Binary-planting resistance**: the PowerShell (signature fallback) and netstat
  (connection fallback) child processes are now launched by absolute `System32` path,
  never resolved through the search path — a security tool running elevated must not
  be hijackable via a planted `powershell.exe`/`netstat.exe`.
- **No more unbounded child waits**: both spawns read stdout asynchronously and kill
  the process tree on timeout. Previously a hung child blocked `ReadToEnd()` forever
  (the `WaitForExit` timeout was unreachable) and leaked a zombie process.
- **VirusTotal input validation**: `Lookup` refuses anything that is not a
  well-formed SHA-256 (64 hex chars), so no attacker-influenced string can alter the
  request URL. The `HttpClient` is now injectable for testing.
- **Resource-exhaustion guard**: the Scheduled Tasks enumerator skips files over
  1 MB under `\Tasks` instead of reading them whole into memory.
- **Connection-table TOCTOU**: `GetExtendedTcpTable/UdpTable` retries on
  `ERROR_INSUFFICIENT_BUFFER` (table grew between the size and fill calls) instead of
  silently returning zero connections.
- **Fewer false positives**: IPv4/IPv6 multicast (SSDP, mDNS), broadcast and
  `0.0.0.0/8` destinations are no longer classified as external.
- CLI: `--help` now documents `dns --watch`; `all` includes the certificate audit.

### Hosts — hosts-file hijack / AV-block detection
- `HostsReader` parses the Windows hosts file and flags the two malware patterns: an
  entry redirecting a hostname to a non-sink external address (phishing/MITM hijack),
  or one blackholing a security/update domain (AV / Windows Update block). Benign
  ad/tracker sink entries (`0.0.0.0`/`127.0.0.1`) are left unflagged. New `winsight
  hosts` subcommand, included in `all`. Parsing is a pure static, unit-tested; the
  real-file read is smoke-tested. Read-only.

### Persistence — screensaver hijack (SCRNSAVE.EXE)
- `ScreensaverEnumerator` surfaces the per-user screensaver executable (a `.scr` is
  just a PE Windows runs on idle — MITRE T1546.002). Reads `SCRNSAVE.EXE` from
  `HKCU\Control Panel\Desktop` and its Group Policy twin, each signature-checked. 17
  autostart surfaces now.

### Certificates — trusted-root store audit (rogue-CA detection)
- `CertStoreAuditor` reads the machine + user trusted-root stores (`X509Store`,
  read-only) and flags rogue-CA signals: a trusted root that holds a **private key**
  (arbitrary trusted certs can be minted locally — Superfish/eDellRoot class), a
  **weak signature** (SHA-1/MD5/MD2) or an **undersized RSA key** (<2048-bit). New
  `winsight certs` subcommand. Risk classification is pure and unit-tested; a Windows
  integration test asserts the real store read returns well-formed roots. Read-only.

### Extensions — browser extension audit (supply-chain)
- `ExtensionScanner` reads the Chromium-family profiles (Chrome, Edge, Brave, Vivaldi,
  Opera) for installed extensions and parses each manifest — name (with `__MSG_`
  locale resolution), version and declared permissions/host_permissions. Extensions
  declaring broad-reach permissions (`<all_urls>`, `tabs`, `webRequest`, `cookies`,
  `nativeMessaging`, `debugger`, `scripting`, wildcard hosts, …) are flagged high-risk.
  New `winsight extensions` (alias `ext`) subcommand, included in `all`. Read-only,
  roots injectable so parsing is unit-tested against a fixture (no browser needed).

### Modules — loaded-DLL audit (injection / side-load detection)
- `ModuleLister` enumerates the DLLs loaded into every accessible running process
  (System.Diagnostics) and batch-verifies each distinct module's Authenticode
  signature through the shared verifier. Unsigned or untrusted DLLs loaded into a
  running process — the classic injection / search-order-hijack signal — are reported
  as notable; the summary carries the totals (loaded modules across N processes, M
  unsigned). New `winsight modules` (alias `dll`) subcommand. Processes that can't be
  opened (protected, cross-bitness, exited) are skipped, never guessed. Read-only.

### Processes — running-process viewer (TaskExplorer-class)
- `ProcessLister` snapshots every running process via `Win32_Process` (System.Management):
  pid, name, full image path, parent pid and command line, then batch-verifies each
  distinct image's Authenticode signature through the shared verifier — so unsigned or
  untrusted running code surfaces as notable. New `winsight processes` (alias `ps`)
  subcommand; `--flagged` shows only unsigned/untrusted images, `--json` for the GUI.
  Read-only, no admin needed for the basics. Integration test asserts a non-empty,
  well-formed snapshot (incl. the test process) and honours the injected verifier.

### DNS — real-time ETW watch
- `DnsEtwWatcher` opens an ETW session on Microsoft-Windows-DNS-Client for live DNS
  visibility: `winsight dns --watch` prints every name a process resolves as it
  happens, complementing the one-shot cache reader. Requires Administrator (ETW
  session); the session stops cleanly on Ctrl+C and a clear message is shown when not
  elevated. Adds the `Microsoft.Diagnostics.Tracing.TraceEvent` dependency.

### Signatures — native WinVerifyTrust (perf, tamper)
- `NativeSignatureVerifier` verifies the embedded Authenticode signature via
  WinVerifyTrust (native, no process spawn) — fast, and detects tampering directly.
  Files with no embedded signature (catalog-signed OS binaries) defer to the
  catalog-aware `AuthenticodeVerifier`; any native failure defers too, so a verdict is
  never fabricated. Wired as the default (behind the cache). Uses only the stable
  WINTRUST struct layouts; `MapResult` unit-tested + the native->catalog chain covered
  by a Windows integration test.

### Reputation — opt-in VirusTotal
- Optional VirusTotal file-reputation for flagged persistence items: set
  `WINSIGHT_VT_KEY` (your own API key) and each flagged, resolvable binary is SHA-256
  hashed and looked up (capped for rate limits) — malicious/total counts + a report
  link in text and `--json`. STRICTLY opt-in and the ONLY network call; without a key
  WinSight stays 100% local. `HashUtil` + `VirusTotalClient` (ParseStats unit-tested).

### Performance — shared signature-verdict cache
- `CachingSignatureVerifier` (decorator) caches verdicts by path + last-write time and
  is shared across tools, so the same system binaries checked by persistence and
  connections in one `winsight all` run are verified once; cache auto-invalidates on
  file change.

### Persistence — AppCertDLLs + time providers
- `AppCertDllsEnumerator` (DLLs injected into processes that call CreateProcess/etc.,
  MITRE T1546.009) and `TimeProviderEnumerator` (W32Time provider DllNames). 16
  autostart surfaces now.

### Persistence — COM hijacking (HKCU CLSID)
- `ComHijackEnumerator` surfaces per-user COM server registrations
  (HKCU\Software\Classes\CLSID\{clsid}\InprocServer32) — COM hijacking (MITRE
  T1546.015). HKCU-scoped for high signal (vs the thousands of legit HKLM system
  CLSIDs). 14 autostart surfaces now.

### Persistence — print monitors + netsh helpers
- `PrintMonitorEnumerator` (spooler-loaded Driver DLLs, run as SYSTEM) and
  `NetshHelperEnumerator` (DLLs loaded when netsh runs) — two more classic ASEPs.
  13 autostart surfaces now.

### Persistence — LSA packages + System32 module resolution
- `LsaPackagesEnumerator` surfaces LSA Security/Authentication/Notification packages
  (DLLs loaded into LSASS — a classic SSP / password-filter persistence + credential
  theft vector). `CommandLine.ExtractExecutable` now resolves bare module names
  against System32 (adding `.dll`), so LSA/AppInit/driver DLLs signature-check
  properly. 11 autostart surfaces now.

### Persistence — Startup folders
- `StartupFolderEnumerator` surfaces items in the per-user and all-users Startup
  folders, resolving `.lnk` targets via WScript.Shell (COM, best-effort) so the
  signature check sees the real binary. 10 autostart surfaces now.

### Firewall — program + ports per rule
- `FirewallRuleReader` now enriches each rule with its bound program
  (MSFT_NetFirewallApplicationFilter) and protocol/ports (MSFT_NetFirewallPortFilter),
  joined by InstanceID — the LuLu-relevant "which app, which ports". Best-effort:
  degrades to name-only if the filters aren't present.

### Firewall — rule viewer (LuLu-class, read-only phase 1)
- `FirewallRuleReader` lists Windows Defender Firewall rules (MSFT_NetFirewallRule
  via System.Management) — see what your firewall allows/blocks. New `winsight
  firewall` subcommand. Per-rule program/port enrichment and an enforcing,
  prompt-on-connection firewall are later phases.

### Connections — IPv6 support (audit fix)
- `NativeConnectionReader` now reads the IPv6 TCP/UDP tables (AF_INET6,
  MIB_*6ROW_OWNER_PID) alongside IPv4, and `IsExternal` treats IPv6 ULA (fc00::/7)
  as private. A connection monitor that ignored IPv6 would miss modern C2/exfil.

### DNS — resolver-cache visibility (DNSMonitor-class)
- `DnsCacheReader` surfaces recently resolved domains + answers from the resolver
  cache (MSFT_DNSClientCache via System.Management — managed, no admin, no process
  spawn). New `winsight dns` subcommand, included in `all`. Real-time ETW
  (Microsoft-Windows-DNS-Client) is the future enhancement.

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
