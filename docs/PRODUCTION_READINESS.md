# Production readiness

This is the authoritative status as of 2026-09-01. Evidence is candidate-bound: a successful result
for one commit or package does not qualify different executable bytes.

| Target | Verdict |
|---|---|
| **x64** | **The published v0.12.0 release is production-ready under the documented unsigned-distribution policy.** Exact candidate `dbaded1` passed CI, installer, WFP/SCM, trust, local/Network IPC, ETW recovery and final cleanup; the published downloads separately passed checksum, attestation, architecture and installer-smoke verification. |
| **Arm64 (native)** | **Not fully qualified** - native build, tests, packaging and installer run only in GitHub's native Arm64 CI; privileged WFP/SCM/trust/IPC/session behavior still needs an isolated Arm64 VM |
| **x64 on Arm64** | **Not qualified** - emulated application identity and privileged runtime behavior need Arm64 hardware |

Authenticode is an accepted distribution limitation and is not counted as a blocker here. Public
binaries remain deliberately unsigned and Windows therefore cannot establish a publisher identity.

## Qualified v0.12.0 x64 candidate

`Directory.Build.props` now targets v0.12.0 because the candidate replaces the public `--json` bare
array with a versioned envelope and contains a substantial security and detection delta. Reusing the
already published v0.11.6 version for different bytes and an incompatible contract would be
misleading.

Exact candidate `dbaded1feac9803d4fa3ffd122036b176ab6d47c` from CI run `33416259797`
passed the complete native-x64 VM campaign. The campaign covered the installer twice from clean S0,
WFP/SCM 35/35, trust 13/13, local IPC 7/7, real second-VM Network Logon 7/7 plus observer 3/3,
dashboard and service ETW orphan recovery, DNS Ctrl+C, HTTPS connectivity, immutable candidate
files, and final cleanup. CodeQL `33416257089` also passed. The authoritative candidate statement
is:

```text
production_ready=true
```

The exact artifact hashes and the validation-harness correction discovered by the real Network
Logon gate are recorded in
[`validation/2026-09-01-x64-qualification-dbaded1.md`](validation/2026-09-01-x64-qualification-dbaded1.md).
This statement qualifies the named CI candidate. It does not pre-qualify differently hashed release
assets or privileged Arm64 behavior.

## Published v0.12.0 verification

Release workflow `33497585184` passed and published tag `v0.12.0` from main commit
`b1c46eef53dbdc33d8da5498c6fae3a74bcad027`. All six downloaded artifacts matched their published
SHA-256 files. SLSA provenance and SPDX 2.2 attestation verification passed for both ZIPs and both
installers. Extracted x64 and Arm64 executables had their expected PE identities, and the downloaded
x64 setup passed installation, exact version, MCP, EN/FR/ES dashboard smoke, uninstall and
no-residue checks in the native Windows 11 VM. The exact hashes and method are recorded in
[`validation/2026-09-01-v0.12.0-published-release.md`](validation/2026-09-01-v0.12.0-published-release.md).

## Last fully qualified x64 runtime baseline

The exact runtime candidate is commit
`8486155b5d09b57e424c513863b0b15498e4a472`. It was built locally as v0.11.6, protected by exact
SHA-256 values, and exercised on a native-x64 Windows 11 VM with a separate isolated control VM.

The campaign passed:

- native x64 PE checks, installer install/uninstall, MCP stdio and EN/FR/ES dashboard smoke;
- WFP contract 26/26 and its expected one-failure negative control;
- pre-arm cleanup 17/17 and full WFP/SCM transition 35/35;
- hostile path/ACL/TOCTOU trust boundary 13/13 with no skip;
- elevated/restricted local IPC 7/7;
- real remote Network Logon IPC 7/7 plus independent target observer 3/3;
- ETW lifecycle 19/19: collision safety, tray semantics, forced-kill orphan recovery, DNS Ctrl+C,
  SCM automatic recovery, final zero sessions and zero `.NET Runtime` crash events;
- final candidate immutability, AuditOnly state, empty WFP namespace and HTTPS connectivity.

The Network Logon leg used a temporary account over WinRM HTTPS on a host-only network scoped to the
two VM addresses. The real token contained `S-1-5-2` (Network), excluded `S-1-5-4` (Interactive),
received `ServiceUnavailable`, performed no mutation, and left the observed service PID/path intact.
The temporary secret is not retained.

The full record, including artifact and evidence hashes, is
[`validation/2026-08-23-x64-qualification-8486155.md`](validation/2026-08-23-x64-qualification-8486155.md).

## Exact UI/package successor qualification

Commit `3912d675dc0917a57c8c05e0bd9c4a2adaa5463b` changes dashboard layout, localization and
VirusTotal settings behavior on top of the already qualified privileged runtime. Its exact x64 ZIP
and dashboard executable were exercised on the same native-x64 Windows 11 VM. EN, FR and ES smoke
tests exited successfully; the French settings dialog remained within its minimum supported width,
presented four equal-width buttons in a 2-by-2 grid, and the local-analysis badge was centred.
The VM also returned the expected, independent Windows-security readings for Memory integrity,
Secure Boot, antivirus and Controlled Folder Access.

The exact candidate passed 1,964 serial Release tests, strict formatting, dependency-vulnerability
audit, release build, installer lifecycle, MCP contract and local EN/FR/ES smoke. The complete record
and hashes are in
[`validation/2026-08-25-ui-windows-posture-3912d67.md`](validation/2026-08-25-ui-windows-posture-3912d67.md).

The post-`8486155` delta also includes validation tooling, tests, CI runner selection and
documentation. The ETW module retries only the observed transient Windows `0x800705AA` result, at
most eight times with a fixed 250 ms delay; every other nonzero result and exhausted retry remains
fail-closed. The WFP contract harness has coherent bounded process/test budgets and terminates a
timed-out PowerShell process tree instead of leaking it into sibling tests.

This distinction prevents the UI/package run from being misrepresented as a repeat of privileged
WFP/SCM qualification. Successor commit
`eed27a173dd70458b816f7f0142a56a9aa15af15` passed CI run `32664937545` across Windows 2022,
Windows 2025 and native ARM64, including both installer packages. CodeQL run `32664935397` passed its
C# and Actions analyses. Dashboard/package successor `8230aa91c3a26e08967124cf3a1a47028a2e2df6`
passed CI run `32789592412` across Windows 2022, Windows 2025 and native ARM64, including both
installer packages. CodeQL run `32789591166` passed its C# and Actions analyses.

## Remaining gates

- independent human EN/FR/ES presentation review remains recommended; the project owner has reviewed
  the French flow interactively, while EN/ES have automated layout/resource and smoke coverage;
- native Arm64 privileged WFP/SCM/trust/IPC/session qualification when suitable hardware is available;
- x64-on-Arm64 application-identity qualification when suitable hardware is available;
- the signed Authenticode path if and when a publisher certificate is configured.

Branch protection still requires green CI on the final merge state. The Arm64-specific hardware
items gate Arm64 privileged-runtime claims, not CI-built native Arm64 artifacts or the already
executed x64 security/runtime result. The absence of a certificate is explicitly accepted for now
but must remain visible to users.

## Historical evidence

Earlier candidate-bound records remain under [`validation/`](validation/README.md). Records predating
the current `dbaded1` campaign are useful regression history but do not qualify v0.12.0. The invalid
early 18/18 transcript remains marked as superseded and is not evidence.

## Authenticode policy

SignPath Foundation declined the free application on 2026-07-29 because public adoption signals
were insufficient. Repository policy is therefore deliberately `REQUIRE_SIGNED_RELEASE=false`:

- all four release targets must report `NotSigned`, with no signer or timestamp;
- users must verify SHA-256 checksums and GitHub provenance/SBOM attestations;
- an absent or malformed workflow policy fails the release;
- unsigned mode disables opportunistic signing even if credentials exist;
- re-enabling signing requires a complete publisher/timestamp validation run.

Unsigned distribution does not make the binaries signed by implication; it shifts artifact
authentication to the documented hashes and attestations.
