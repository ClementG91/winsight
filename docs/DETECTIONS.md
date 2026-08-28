# Detection coverage and limits

WinSight is a read-only visibility and triage suite. A **notable** result is a signal
to investigate, not proof of malware. Except for an explicitly configured optional
VirusTotal lookup, analysis stays on the device.

## What is detected today

| Area | Evidence and notable signals | User action |
|---|---|---|
| Persistence | 26 Windows autostart families, including registry Run keys, services/drivers and `ServiceDll`, scheduled tasks, Winlogon, AppInit, IFEO/SilentProcessExit, WMI subscriptions, startup folders, LSA packages, print monitors/providers, credential providers, browser helper objects, Windows Load/Run values, COM hijacks and screensavers. Images are Authenticode checked. | Inspect details, reveal the validated file location, or open Windows Startup apps. |
| Autostart command lines | A Windows-signed interpreter (`rundll32`, `mshta`, `regsvr32`, `powershell`, `wscript`, `regsvr32`, `msbuild`, … ) handed a payload its signature does not cover: fetched from a URL or share (`RemotePayload`), read from a per-user or temporary location (`PerUserPayload`), carried inline or encoded (`EncodedCommand`), or run through a scriptlet registration (`ScriptletCom`). Reported in `commandLineConcern`. | Read the entry's full command line, and identify what the interpreter is being pointed at. |
| Camera and microphone | Current and historical Capability Access usage; live CLI transitions. | Identify the application and open Windows privacy settings. |
| Network connections | IPv4/IPv6 TCP and UDP owner, process image and signature; external established connections with unsigned/untrusted owners are notable. | Inspect the executable and open Resource Monitor. |
| DNS | Resolver-cache records and administrator-only live ETW queries. | Correlate domains with activity and open Windows network settings. |
| Browser extensions | Chromium-family extension identity and high-reach permissions such as all-sites, cookies, debugger or native messaging. | Review the extension and open Windows installed apps when relevant. |
| Hosts file | External redirects and blackholed security/update domains; common local ad-block sinks are ignored. | Open the validated location and review the mapping. |
| Trusted roots | Private keys in a trusted root, weak non-self-signed algorithms and undersized RSA keys. | Review the certificate in Windows certificate management. |
| Processes | Process path, parent, command line and Authenticode status. | Investigate unsigned or untrusted images and open Task Manager. |
| Loaded modules | Unsigned/untrusted DLLs loaded by accessible processes. | Investigate injection or side-loading and open Task Manager; protected processes may be inaccessible. |
| Firewall rules | Enabled Windows Defender Firewall rules, program and port filters when available. | Review in the Windows Firewall console. |
| Antivirus protection | Antivirus products returned by the documented **Windows Security Center** `IWSCProductList`/`IWscProduct` interface: `On`, `Off`, `Snoozed`, `Expired`, signature currency, and explicit unknown future values. Unknown activity or signature evidence stays indeterminate and notable; it is never strengthened into active, inactive, current or stale. | Open Windows Security or the product's own console. The API is supported on Windows desktop clients, not Windows Server; provider failure is reported as unavailable, distinct from a successful zero-product result. |

The default **Overview** intentionally runs the balanced, lower-noise set:
persistence, camera/microphone, connections, DNS, extensions, hosts, certificates,
input-path drivers, code integrity and hijack exposure. Large process, module and
firewall inventories remain explicit checks in the dashboard and CLI.

Note that `hijack` is in that set and **writes**: it creates and immediately deletes a uniquely
named temporary file in each directory whose writability it reports on. See the note at the top of
the README.

## Verdict model

Persistence results deliberately separate file discovery from signature checking:

- `FileMissing`: WinSight normalized the command to the path Windows would load,
  but no file exists there. The signature was **not checked**. This commonly means
  an orphaned registration and is not proof of an active infection.
- `AccessDenied`: the target could not be inspected because Windows denied or
  prevented access. The signature was **not checked**.
- `SignatureValid`: Windows validated the embedded or catalog signature.
- `Unsigned`: verification completed and Windows reported `NotSigned`.
- `InvalidSignature`: Windows reported an invalid/untrusted signature, including
  hash mismatch, explicit distrust or `UnknownError`.
- `VerificationError`: the command could not be resolved or verification could not
  complete, including unsupported/incompatible file formats. WinSight never converts
  this into a fabricated unsigned verdict.

The lower-level JSON `signature` field is null when no check was possible, while
`signatureChecked` says so explicitly. Persistence consumers should use `status`,
`fileStatus`, `image`, `expectedImage`, `signatureChecked` and `signature` together.
VirusTotal is attempted only for a present, flagged image because an absent file has
no bytes to hash.

### A valid signature does not clear the command line

The verdicts above are all facts about a **file**, and that model is blind by construction to the
technique that dominates Windows persistence today: the file is genuinely Microsoft's and genuinely
signed, and the payload is in the arguments. A Run key holding
`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval(…)` resolves to
`C:\Windows\System32\rundll32.exe` and verifies as `SignatureValid`.

Such an entry is now flagged, and carries `commandLineConcern` beside its unchanged `status`. Both
halves are reported together, because "signature valid" on its own reads as an all-clear on exactly
the entries the check exists to catch.

**The gate is the interpreter, not the pattern.** Ordinary software passes profile paths and URLs on
its command line constantly; what is not ordinary is a program whose whole purpose is to execute
what it is handed being pointed at a per-user location, at the network, or at an encoded body. Both
halves must hold. Measured on a real desktop: 4 351 autostart items, 15 of which resolve to one of
the interpreters, and **zero findings** — the intended shape on a healthy machine, which is why the
rule has tests that make it fire against synthetic entries instead.

**Known limits, stated rather than implied.** Hidden-window and no-profile switches (`-w hidden`,
`-nop`) are deliberately not sufficient on their own: legitimate deployment tooling uses them
constantly. An interpreter handed a payload that is neither remote, per-user nor encoded — a planted
DLL under `Program Files`, say — is not visible here; that is the writability question the `hijack`
scanner answers. The rule reads the command line as recorded, so a payload assembled at runtime is
out of reach of static analysis.

Scheduled tasks previously reported the `<Command>` of an Exec action and discarded its
`<Arguments>`, which reduced every interpreter-based task to a bare, signed, unremarkable binary.
Measured on the same desktop, **58 of 81** scheduled-task entries carry arguments; none of them was
visible before. The surface most used for modern persistence was reporting the least evidence.

### Example: orphaned WinSetupMon driver registration

Microsoft includes `WinSetupMon.sys` in
[Windows Setup/Safe OS dynamic updates](https://support.microsoft.com/en-gb/topic/kb5074111-safe-os-dynamic-update-for-windows-11-versions-24h2-and-25h2-january-29-2026-7d2ab6bf-c62d-467e-a1cb-240bf5ef96ac).
Some
machines retain `HKLM\SYSTEM\CurrentControlSet\Services\WinSetupMon` after the
driver file has been removed. For an `ImagePath` such as
`system32\DRIVERS\WinSetupMon.sys`, WinSight normalizes the expected target to
`%SystemRoot%\System32\drivers\WinSetupMon.sys`.

If that target is absent, the result is `FileMissing` and “signature not checked”,
not `Unsigned`. If it exists, the actual bytes are checked normally; a valid
Microsoft signature is strong benign evidence, while an unsigned, invalid or
hash-mismatched same-name file needs investigation. Do not delete the service solely
because it is orphaned: confirm Windows Update/Setup state and keep a recovery path.

Raw paths, process names, command lines and other forensic evidence are preserved
verbatim even when the interface is translated.

The CLI and dashboard preserve that forensic evidence. MCP is intentionally more
conservative because an AI client may forward results to a model provider: it starts
summary-only, bounds item output, redacts user-profile paths and omits command fields
unless the user enabled the separate sensitive-evidence gate. MCP scans also disable
VirusTotal regardless of the CLI/dashboard opt-in key.

## Important limits

- WinSight does not claim to be antivirus or EDR and does not guarantee detection
  of malware, kernel rootkits, memory-only implants or every persistence technique.
- Access-controlled, protected, exited or cross-architecture processes can prevent
  some module/process evidence from being read; those results are skipped, not
  guessed.
- DNS cache data is historical visibility and does not by itself attribute every
  query to a process. Live DNS ETW needs elevation.
- Browser coverage is currently Chromium-family; Firefox is not yet covered.
- **Certificate revocation is checked against the local cache only.** WinSight promises that the
  optional VirusTotal lookup is its only outbound connection, so `WinVerifyTrust` runs with
  `WTD_CACHE_ONLY_URL_RETRIEVAL`: a certificate Windows has already learned is revoked is reported
  as untrusted, and one whose CRL or OCSP response was never fetched is reported as trusted with the
  revocation state undetermined rather than being downgraded.
- **Autostart surfaces not yet enumerated**, named rather than left implicit: Winsock LSP catalog
  entries (the DLL path sits inside a packed binary blob), shell extension handlers,
  `Winlogon\Notify` (which modern Windows no longer executes), Group Policy scripts, and Office
  add-ins.
- **WMI `__EventFilter` and `__FilterToConsumerBinding` are read for coverage but not reported as
  entries.** Neither names an image, and every entry in a persistence report is graded by the image
  model, so reporting them would flag the filter Windows itself ships on every machine. Consumers -
  the side that actually runs something - are reported in full.
- **A COM-handler scheduled task whose CLSID resolves to no file is counted, not reported.** Windows
  ships such tasks; reporting the bare GUID would flag them everywhere. They appear in the
  unreadable-locations count instead.
- **Per-user registry hives are read only for accounts that are logged on.** A profile whose
  `NTUSER.DAT` is not loaded is counted as a location this scan could not read; loading it is a
  privileged, machine-modifying act a read-only tool will not perform.
- Defender Firewall inventory is read-only. The separate opt-in LocalSystem service can
  enforce stored per-application outbound policies only through authenticated IPC and an
  explicit elevated transition. Direct WFP mutation aliases are disabled. Desired mode is
  not runtime proof: the dashboard reports filtering only from the service's effective
  `Active` state. Native SCM, IPC, DACL and WFP behavior remains unqualified until the
  isolated-VM protocol passes.
- Real-time persistence blocking and ransomware interception require a separately
  signed and safety-reviewed driver and are not shipped. WinSight's own ransomware
  feature therefore detects and alerts but does not block. It does, however, **report**
  whether Windows' separate ransomware control - Microsoft Defender **Controlled Folder
  Access** - configured and operational posture can be read. Controlled Folder Access is
  independent from Core isolation, Memory integrity and Secure Boot: one being enabled says
  nothing about the others. The `integrity` check uses
  Defender WMI (unelevated) and distinguishes Disabled, Audit, block/audit disk-modification-only,
  and a fully observed Enabled posture. The latter requires Defender `AMRunningMode=Normal`,
  antivirus enabled and real-time protection enabled. Every operating mode Defender documents -
  `Normal`, `Passive`, `Passive Mode`, `SxS Passive Mode`, `EDR Block Mode` and `Not running` - counts
  as a successful read; `Not running` reports as **Defender not running** rather than as a configured
  mode, because Controlled Folder Access is a Defender feature and no configured value protects
  anything while the antivirus is stopped. Only genuinely missing or undocumented provider/runtime
  evidence remains a notable unavailable result.

  **This verdict is reported beside the machine's real antivirus, never alone.** Controlled Folder
  Access is a Microsoft Defender feature, so on a machine protected by another vendor it is legitimately
  inactive. Reporting only "the ransomware shield is not protecting you" would be accurate and would
  leave a false impression, so the `integrity` scan also reads Windows Security Center and, when another
  antivirus reports both `On` **and** `UpToDate`, the CFA line names it and says this can be a normal
  third-party configuration rather than a fault - while pointing out that WinSight cannot read that
  product's own ransomware protection and the operator should confirm it is on. An `On` product whose
  signatures are `Unknown` or `OutOfDate` is notable and never receives that reassurance. The antivirus
  inventory uses Microsoft's documented
  Windows Security Center COM product interface, queries only the antivirus provider, preserves raw
  activity/signature values, bounds and neutralizes vendor-controlled names, and treats unknown
  evidence as indeterminate. WinSight only reads and reports this setting; it never enables,
  disables or otherwise configures Controlled Folder Access - the operator changes it in Windows.
- VirusTotal is opt-in and user-keyed. WinSight enforces Community ceilings across
  its processes (4/rolling minute, 500/UTC day, 15,500/UTC month), never retries a
  quota response, and documents that Community access is non-commercial. Sending a
  hash to a third party has privacy implications and is never enabled automatically.

These limits are product boundaries, not hidden failures. The changelog records
coverage changes and false-positive fixes release by release.
