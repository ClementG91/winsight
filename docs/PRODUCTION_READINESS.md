# Production readiness

One authoritative statement, per architecture, with a reproducible record behind every claim. A gate
is closed only when someone can re-run it and get the same answer.

| Target | Verdict |
|---|---|
| **x64** | **Not production-ready** — the current candidate needs WFP/SCM requalification and release-level gates remain open |
| **Arm64 (native)** | **Not production-ready** — build, unit tests and packaging verified in CI on every pull request, privileged runtime behaviour unverified |

## x64

### Historical candidate-bound evidence

| Gate | Result | Candidate | CI run |
|---|---|---|---|
| WFP enforcement, SCM lifecycle, rollback, connectivity, per-app scoping | 25 checks, 0 failures | `f0a3f16` | `30024427883` |
| Service-path trust, adversarial TOCTOU, hostile ACLs | 11 checks, 0 failures | `f84ac36` | `30032903041` |
| Multi-user IPC capability boundary | 7 checks, 0 failures | `c9177cd` | `30046318762` |

Records: [`docs/validation/`](validation/README.md). Each ran on a clean Windows 11 VM under Windows
PowerShell 5.1, elevated, using the protocol script shipped **inside the same package** as the binary
under test.

Each record qualifies only the exact candidate named in its row. Before applying one to a later
revision, perform a candidate-aware delta review of the relevant service, trust-boundary or IPC
surface. If that surface changed or the impact is uncertain, rerun its gate and bind the new record
to the new candidate. These records are not an automatic inheritance rule or a product-wide
production-readiness verdict.

The current candidate changed the WFP/SCM runtime surface after `f0a3f16`. Its 25-check record is
therefore invalidated for current-candidate readiness and must be rerun in an isolated x64 VM. The
trust and IPC rows remain historical evidence bound to their named commits, not a blanket current
candidate approval.

### Automated CI evidence

- Full suite, both explicitly pinned `windows-2025` and `windows-2022`
- Engine-library line coverage gate: every engine library at or above 80%
- Formatting, dependency vulnerability audit, whitespace
- Installer lifecycle: install, version, MCP contract, dashboard smoke in en/fr/es, SBOM and asset
  presence, uninstall, and verified removal
- PE machine field read from the header — not inferred from the file name
- Branding and embedded icons
- Localization: every key translated in fr/es, and no undeclared untranslated string
- Signed commits enforced on `main`, including for administrators, verified by an actually-rejected
  direct push

Repository security features are enabled: GitHub private vulnerability reporting, Dependabot alerts
and CodeQL default setup. CodeQL run `30204877420` independently completed successfully for C# and
Actions at `4359e87`, with zero open CodeQL or Dependabot alerts. That evidence is candidate-bound:
a new candidate still needs its own green scan.

The unsigned public v0.10.5 release pipeline was exercised successfully: it published x64 and Arm64
assets with GitHub build-provenance and SBOM attestations. CI packaging and installer lifecycle also
prove that generated packages can install, run their automated smoke contracts and uninstall on the
runners. This does not prove the signed Authenticode production chain, safe external deployment or
human operator acceptance.

### Product-level gates that remain open

1. **Authenticode is not closed.** The released v0.10.5 artifacts are unsigned under the second and
   final waiver and are not production-ready. The repository variable `REQUIRE_SIGNED_RELEASE=true`
   was restored after publication, so the release workflow fails closed when signing is unavailable. Neither
   `WINSIGHT_SIGNING_CERT_BASE64` nor `WINSIGHT_SIGNING_CERT_PASSWORD` is configured, so a signed
   release remains blocked while the project awaits the SignPath Foundation response and until a
   real certificate-backed candidate is configured and verified. See
   [`RELEASE.md`](RELEASE.md).
2. **Three commits in history are unsigned** (`214a25f`, `d5ee120`, `e964779`), from a pull request
   merged with `--rebase`. They are deliberately not re-signed: doing so changes their hashes and
   every descendant hash, including the three commits a real VM qualified, which would either orphan
   the validation records or require editing them to hashes that did not exist when the VM ran. The
   hole is closed going forward by `enforce_admins`.
3. **Some privileged identity cases remain live-test gaps.** The foreign-owner-SID trust case needs
   a second standard account. Dedicated unelevated-administrator and network-logon IPC sessions are
   represented by a capability-equivalent SAFER token and a DACL unit test, not by those exact live
   logons.
4. **Presentation attestation and release gates.** A user-supplied attestation dated 2026-07-26 says
   that EN/FR/ES human presentation was completed. This is not independent validation evidence.
   The signed Authenticode production chain has never been exercised end to end and remains blocking;
   the successful unsigned v0.10.5 public release does not close that gate. The exact corrected
   antivirus candidate still needs its own CI, CodeQL and package lifecycle evidence.
5. **Current-candidate privileged evidence is incomplete.** WFP/SCM must be rerun on x64 because its
   runtime surface changed. Native Arm64 WFP, SCM, trust, IPC/session and emulated-x64 identity gates
   remain unexecuted.
Until these gates close, the honest x64 verdict is not production-ready.

## Arm64

### Verified on native Arm64 hardware, every CI run

The `package (arm64, windows-11-arm)` job runs on a **native Arm64 runner**
(`Image: windows-11-arm64`), and `Test-Installer.ps1` refuses to run unless the host architecture is
native — so this cannot be satisfied by emulation:

- Arm64 build from source
- `winsight.exe is a valid arm64 PE image` — machine field `0xAA64` read from the PE header
- Branding and embedded icons
- SBOM generation
- Inno Setup installer compilation
- Full installer lifecycle: install, version, MCP contract, dashboard smoke (Spanish), SBOM and asset
  presence, uninstall, verified removal

Evidence: run `30050233431`, job `89350546954`.

Earlier documentation claimed Arm64 "has no hardware to run on". That was true when written and is
not any more.

### Not verified on Arm64

Everything requiring an elevated, isolated VM — a CI runner cannot safely install a SYSTEM service
and cut real traffic — remains `NOT_RUN` under an accepted deferral because no native Arm64 hardware
is currently available for that privileged validation:

- WFP enforcement, rollback, per-app scoping
- Real SCM service lifecycle
- Service-path trust and the TOCTOU race
- Multi-user IPC capability boundary
- **Emulated-x64 application identity.** WFP app-id resolution for an emulated x64 process on Arm64 is
  the one behaviour with no x64 analogue, so the x64 records say nothing about it.

The native Arm64 build and installer lifecycle remain CI-verified; that evidence does not promote the
deferred privileged WFP, SCM, trust, IPC/session or emulated-x64 gates.

### What a future native Arm64 run needs

Nothing new has to be written. The protocol, scripts and binding method already exist and ship in the
Arm64 package:

1. A clean native Arm64 Windows VM.
2. `winsight-win-arm64` from a green CI run, bound by `head_sha` — the procedure is identical to x64
   and is in [`validation/VM_QUALIFICATION_KIT.md`](validation/VM_QUALIFICATION_KIT.md).
3. Record the OS architecture with `Win32_Processor` (must read `ARM64`), **not**
   `$env:PROCESSOR_ARCHITECTURE` — an emulated x64 process reports `AMD64` there and would satisfy a
   naive check while proving nothing.
4. Run, in order: `-ContractSelfTest`, its negative control, `-SkipEnforcement`, the full protocol,
   `Test-TrustBoundary.ps1`, `Test-IpcBoundary.ps1`.
5. Expect `24/24 + exit 1`, `16`, `25`, `11`, `7`. Record the transcript in `docs/validation/` bound to
   the commit and CI run.

That run would close the named Arm64 privileged-runtime gates, and not before. It would not by itself
change the product-wide verdict while signing, release and human-review gates remain open.

## How to challenge any claim here

Every closed gate names a candidate commit and a CI run. Verify the binding, then re-run the gate:

```powershell
gh api repos/ClementG91/winsight/actions/runs/<run> --jq '.head_sha, .conclusion'
```

If a number in this file cannot be reproduced that way, it is a defect in this file — report it.
