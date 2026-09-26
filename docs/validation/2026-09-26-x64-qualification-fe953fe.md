# x64 VM qualification with the rebuilt harness - 2026-09-25/26

**Result: PASS for the product code released as v0.14.0, qualified as local unsigned candidates
`fe953fe` (every gate but 36) and `711ded0` (gates 17 and 36).**

This record is bound to commits `fe953fee5ad71d586e946d7a90b47467da8754d7` and
`711ded09434ce4f776bde9081d9b90fc132b5543` and to the exact artifacts below. Both were built locally
with `Build-Release.ps1 -Version 0.13.0 -Architectures x64 -DisableSignature`, before the version
bump: they are **not** CI builds, carry version 0.13.0 in their names and binaries, and are unsigned.
The published v0.14.0 binaries are a CI build of the same product code, with one difference: the
hijack scan's notice that writability was graded for the well-known groups became `Unverified`
(WS-86). That notice is emitted only when the process has no non-elevated token, which never
happens in these runs: the harness runs elevated with UAC on. The SBOM tool also moved to 4.1.13.

## Candidate identity

| Candidate | Artifact | SHA-256 |
|---|---|---|
| `fe953fe` | `winsight-v0.13.0-win-x64-setup.exe` | `ED1AD6DA7A5F94AABD23986D06208F5FF807A6064E5046A1FEBAE0AA8EB1273C` |
| `fe953fe` | `winsight-v0.13.0-win-x64.zip` | `85EED5D8D603741FB0B83392996F2E93CAD81BFAB7307F9A83F704541FBEB1CB` |
| `fe953fe` | `winsight-v0.13.0-win-x64.spdx.json` | `DE5AC661057465D16FF7E647224FBE26FE2D3576494E4B96B163EF4CFB348B41` |
| `711ded0` | `winsight-v0.13.0-win-x64-setup.exe` | `098E3457E11378498C1BCC3354EF61B29A5531E63C67C954ED85F7CFFE203047` |
| `711ded0` | `winsight-v0.13.0-win-x64.zip` | `57353D5AE872B136E8F95D6D05B3250D34E919E0FB5E160BD624191D564515A8` |
| `711ded0` | `winsight-v0.13.0-win-x64.spdx.json` | `133A0D15415B17DBE6C2E738C55882BE43A7DF15B8C13F06DA125E49C3722650` |

The product code (`src`, `installer`) is identical at both commits; `711ded0` changed only the
Cloud Files probe that gate 17 uses (WS-82).

## Harness and provenance

The harness is `scripts/validation/hyperv` at the candidate's own commit (RA-01): a long-lived
elevated runner that reads requests without ever writing or deleting in the request folder, copies
a closed list of harness files and the candidate into an administrators-only root, and re-hashes
them before each action. VM storage and sealed evidence are administrators-only too.
`Verify-QualificationProvenance.ps1`, run as an ordinary user after each run, passed **11/11** for
all three runs: the seal, the harness blob ids against the commit, the candidate scripts against the
candidate's commit, the artifacts the guest checked against those staged, and refused writes to the
evidence, the protected harness and candidates, the VM storage and the protected root.

Target: `WinSight-Qualification-HV`, Windows 11 Pro 10.0.26200 (Hyper-V generation 2, 4 GB for the
full run, 3 GB beside the control VM). Control: `WinSight-Control-HV` (2 GB), on a private Hyper-V
switch neither the host nor the Internet can reach.

## Runs

| Run | Candidate | Gates | Result |
|---|---|---|---|
| `head-fe953fe` | `fe953fe` | all but 36 | **32 gates, 0 failures**; 36 NOT_RUN by design (separate two-VM run) |
| `gate17-711ded0` | `711ded0` | 01, 17, 99 | **3/3 PASS** |
| `net-711ded0b` | `711ded0` | 01, 36, 99 | **gate 36 10/10**: Network Logon 7/7 from the control VM, target observer 3/3; control 7/7 |

`head-fe953fe` (2026-09-25, 52 minutes in the guest) covered: identity and protected root,
architecture and the accepted unsigned posture, the CLI contract, the installer lifecycle, the
read-only MCP contract, the read-only scanners, MSIX package evidence, the process response verbs
(journalled, refused without `--confirm`, protected targets refused), holders, the signature verb
and window, Guardian Block/restore and Allow/silence/revoke, the dashboard in EN/FR/ES, the all-users
installer with an injected service-removal failure (RA-05: nothing removed, then completed), the
upgrade from the published v0.13.0, Cloud Files, interpreter triage (WS-74: `powershell -enc` in a
Run value flagged `EncodedCommand`), the ETW session lifecycle (dashboard, DNS, outbound service,
pre-opened write attribution, final cleanup), the WFP contract, negative control, pre-arm and full
enforcement, the path trust boundary against a real non-administrator account, local IPC and a
clean residue check.

### Gate 17: Cloud Files

The probe registers a disposable sync root with the documented Cloud Files API, connects with
`CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO`, records the process behind every download (`FETCH_DATA`)
request and fails each request at once over the whole file, so that no request stays pending and
every read, by any process, arrives as a request of its own (WS-82). In `gate17-711ded0`: hydrated
placeholders were read with matching hashes and no request; the cloud-only file was refused in
161 ms with no request; no request at all during the 30 seconds after the Run value naming it was
written, nor during the persistence scan over it (22 s, entry listed, image refused). The
primitives show the measurement works: each no-recall read by its own `powershell.exe` arrived as
two requests named after that process and failed at once (error 389,
`ERROR_CLOUD_FILE_UNSUCCESSFUL`).

### Gate 36: Network Logon

A disposable standard account, created on the target from a password the operator typed in the
Windows credential dialog, logged on from the control VM over WinRM HTTPS (Basic only inside TLS).
Its token carried `S-1-5-2` (Network) without `S-1-5-4` (Interactive); it could not open the
authenticated pipe, received `ServiceUnavailable` and performed no mutation. The target observer saw
the same service instance before and after. Both VMs were restored to their clean checkpoints.

## Earlier attempts, retained

`head-72c48a7` (lost to WS-80), `head-771a67b` (30 of 32; gate 17 saw a download request it could
not attribute, WS-82), `net-771a67b` (not started, WS-81), `head-bf9aad9` (runner stopped, WS-83)
and `net-fe953fe` (operator away, control VM gave up after 60 minutes) are recorded in
[`AUDIT.md` §17.4](../AUDIT.md). Each defect found in the harness was fixed with a failing-first
contract test and a Windows PowerShell 5.1 self-check.

## Not covered

- CI provenance and signing: local unsigned builds, not the published CI artifacts.
- Native Arm64 and x64-on-Arm64 privileged behavior.
- Soak, ETW throughput and multi-user machines.
