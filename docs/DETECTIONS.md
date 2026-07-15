# Detection coverage and limits

WinSight is a read-only visibility and triage suite. A **notable** result is a signal
to investigate, not proof of malware. Except for an explicitly configured optional
VirusTotal lookup, analysis stays on the device.

## What is detected today

| Area | Evidence and notable signals | User action |
|---|---|---|
| Persistence | 22 Windows autostart families, including registry Run keys, services/drivers and `ServiceDll`, scheduled tasks, Winlogon, AppInit, IFEO/SilentProcessExit, WMI subscriptions, startup folders, LSA packages, print monitors/providers, credential providers, browser helper objects, Windows Load/Run values, COM hijacks and screensavers. Images are Authenticode checked. | Inspect details, reveal the validated file location, or open Windows Startup apps. |
| Camera and microphone | Current and historical Capability Access usage; live CLI transitions. | Identify the application and open Windows privacy settings. |
| Network connections | IPv4/IPv6 TCP and UDP owner, process image and signature; external established connections with unsigned/untrusted owners are notable. | Inspect the executable and open Resource Monitor. |
| DNS | Resolver-cache records and administrator-only live ETW queries. | Correlate domains with activity and open Windows network settings. |
| Browser extensions | Chromium-family extension identity and high-reach permissions such as all-sites, cookies, debugger or native messaging. | Review the extension and open Windows installed apps when relevant. |
| Hosts file | External redirects and blackholed security/update domains; common local ad-block sinks are ignored. | Open the validated location and review the mapping. |
| Trusted roots | Private keys in a trusted root, weak non-self-signed algorithms and undersized RSA keys. | Review the certificate in Windows certificate management. |
| Processes | Process path, parent, command line and Authenticode status. | Investigate unsigned or untrusted images and open Task Manager. |
| Loaded modules | Unsigned/untrusted DLLs loaded by accessible processes. | Investigate injection or side-loading and open Task Manager; protected processes may be inaccessible. |
| Firewall rules | Enabled Windows Defender Firewall rules, program and port filters when available. | Review in the Windows Firewall console. |

The default **Overview** intentionally runs the balanced, lower-noise set:
persistence, camera/microphone, connections, DNS, extensions, hosts and certificates.
Large process, module and firewall inventories remain explicit checks in the
dashboard and CLI.

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
- Firewall inspection is read-only. The strict protocol framing and fail-open policy
  store do not enable enforcement; the authenticated service host, WFP audit engine
  and recovery path in `WFP_DESIGN.md` must still be completed and independently
  safety-tested.
- Real-time persistence blocking and ransomware interception require a separately
  signed and safety-reviewed driver and are not shipped.
- VirusTotal is opt-in and user-keyed. WinSight enforces Community ceilings across
  its processes (4/rolling minute, 500/UTC day, 15,500/UTC month), never retries a
  quota response, and documents that Community access is non-commercial. Sending a
  hash to a third party has privacy implications and is never enabled automatically.

These limits are product boundaries, not hidden failures. The changelog records
coverage changes and false-positive fixes release by release.
