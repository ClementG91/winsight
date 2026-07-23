# Production readiness

One authoritative statement, per architecture, with a reproducible record behind every claim. A gate
is closed only when someone can re-run it and get the same answer.

| Target | Verdict |
|---|---|
| **x64** | **Ready**, with the two named limitations below |
| **Arm64 (native)** | **Not qualified** — build and packaging verified on native hardware, privileged runtime behaviour unverified |

## x64

### Closed, with a reproducible record

| Gate | Result | Candidate | CI run |
|---|---|---|---|
| WFP enforcement, SCM lifecycle, rollback, connectivity, per-app scoping | 25 checks, 0 failures | `f0a3f16` | `30024427883` |
| Service-path trust, adversarial TOCTOU, hostile ACLs | 11 checks, 0 failures | `f84ac36` | `30032903041` |
| Multi-user IPC capability boundary | 7 checks, 0 failures | `c9177cd` | `30046318762` |

Records: [`docs/validation/`](validation/README.md). Each ran on a clean Windows 11 VM under Windows
PowerShell 5.1, elevated, using the protocol script shipped **inside the same package** as the binary
under test.

### Closed in CI, every commit

- Full suite, both `windows-latest` and `windows-2022`
- Engine-library line coverage gate: every engine library at or above 80%
- Formatting, dependency vulnerability audit, whitespace
- Installer lifecycle: install, version, MCP contract, dashboard smoke in en/fr/es, SBOM and asset
  presence, uninstall, and verified removal
- PE machine field read from the header — not inferred from the file name
- Branding and embedded icons
- Localization: every key translated in fr/es, and no undeclared untranslated string
- Signed commits enforced on `main`, including for administrators, verified by an actually-rejected
  direct push

### Limitations that remain on x64

1. **Released binaries are unsigned.** The Authenticode chain is implemented and verified — it signs,
   timestamps and independently verifies — but the project holds no code-signing certificate. Windows
   will warn on first run. Supplying `WINSIGHT_SIGNING_CERT_BASE64` activates it; see
   [`RELEASE.md`](RELEASE.md).
2. **Three commits in history are unsigned** (`214a25f`, `d5ee120`, `e964779`), from a pull request
   merged with `--rebase`. They are deliberately not re-signed: doing so changes their hashes and
   every descendant hash, including the three commits a real VM qualified, which would either orphan
   the validation records or require editing them to hashes that did not exist when the VM ran. The
   hole is closed going forward by `enforce_admins`.

Neither prevents x64 production use; both are stated so nobody discovers them by surprise.

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
and cut real traffic:

- WFP enforcement, rollback, per-app scoping
- Real SCM service lifecycle
- Service-path trust and the TOCTOU race
- Multi-user IPC capability boundary
- **Emulated-x64 application identity.** WFP app-id resolution for an emulated x64 process on Arm64 is
  the one behaviour with no x64 analogue, so the x64 records say nothing about it.

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

Then this file's Arm64 verdict changes, and not before.

## How to challenge any claim here

Every closed gate names a candidate commit and a CI run. Verify the binding, then re-run the gate:

```powershell
gh api repos/ClementG91/winsight/actions/runs/<run> --jq '.head_sha, .conclusion'
```

If a number in this file cannot be reproduced that way, it is a defect in this file — report it.
