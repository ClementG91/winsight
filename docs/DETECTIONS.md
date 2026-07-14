# Detection coverage and limits

WinSight is a read-only visibility and triage suite. A **notable** result is a signal
to investigate, not proof of malware. Except for an explicitly configured optional
VirusTotal lookup, analysis stays on the device.

## What is detected today

| Area | Evidence and notable signals | User action |
|---|---|---|
| Persistence | 18 Windows autostart families, including registry Run keys, services/drivers and `ServiceDll`, scheduled tasks, Winlogon, AppInit, IFEO/SilentProcessExit, WMI subscriptions, startup folders, LSA packages, COM hijacks and screensavers. Images are Authenticode checked. | Inspect details and reveal the validated file location. |
| Camera and microphone | Current and historical Capability Access usage; live CLI transitions. | Identify the application and review Windows privacy settings. |
| Network connections | IPv4/IPv6 TCP and UDP owner, process image and signature; external established connections with unsigned/untrusted owners are notable. | Inspect the executable and open trusted Windows management tools. |
| DNS | Resolver-cache records and administrator-only live ETW queries. | Correlate domains with the owning activity. |
| Browser extensions | Chromium-family extension identity and high-reach permissions such as all-sites, cookies, debugger or native messaging. | Review or remove the extension in its browser. |
| Hosts file | External redirects and blackholed security/update domains; common local ad-block sinks are ignored. | Open the validated location and review the mapping. |
| Trusted roots | Private keys in a trusted root, weak non-self-signed algorithms and undersized RSA keys. | Review the certificate in Windows certificate management. |
| Processes | Process path, parent, command line and Authenticode status. | Investigate unsigned or untrusted images. |
| Loaded modules | Unsigned/untrusted DLLs loaded by accessible processes. | Investigate injection or side-loading; protected processes may be inaccessible. |
| Firewall rules | Enabled Windows Defender Firewall rules, program and port filters when available. | Review in the Windows Firewall console. |

The default **Overview** intentionally runs the balanced, lower-noise set:
persistence, camera/microphone, connections, DNS, extensions, hosts and certificates.
Large process, module and firewall inventories remain explicit checks in the
dashboard and CLI.

## Verdict model

- `Trusted`: Windows validated the embedded or catalog signature.
- `Unsigned`: verification completed and no trusted signature exists.
- `Untrusted`/`HashMismatch`: a signature exists but Windows does not trust it or
  the file no longer matches it.
- `Unknown`: verification could not complete. WinSight never converts this into a
  fabricated unsigned verdict.

Raw paths, process names, command lines and other forensic evidence are preserved
verbatim even when the interface is translated.

## Important limits

- WinSight does not claim to be antivirus or EDR and does not guarantee detection
  of malware, kernel rootkits, memory-only implants or every persistence technique.
- Access-controlled, protected, exited or cross-architecture processes can prevent
  some module/process evidence from being read; those results are skipped, not
  guessed.
- DNS cache data is historical visibility and does not by itself attribute every
  query to a process. Live DNS ETW needs elevation.
- Browser coverage is currently Chromium-family; Firefox is not yet covered.
- Firewall inspection is read-only. Enforcement remains disabled until the
  service, authenticated IPC, audit mode and recovery path in `WFP_DESIGN.md` are
  completed and independently safety-tested.
- Real-time persistence blocking and ransomware interception require a separately
  signed and safety-reviewed driver and are not shipped.
- VirusTotal is opt-in, user-keyed and rate-limited. Sending a hash to a third party
  has privacy implications and is never enabled automatically.

These limits are product boundaries, not hidden failures. The changelog records
coverage changes and false-positive fixes release by release.
