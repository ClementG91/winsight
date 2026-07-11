# Changelog

Step-by-step progress log. Newest first. Every CI-green step lands here.

## Phase 1 — user-mode tools

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
